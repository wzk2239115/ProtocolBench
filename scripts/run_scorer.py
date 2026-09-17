#!/usr/bin/env python3
"""Batch agent scorer for the on-chain Lean attack track.

Two-pass LLM scoring, mirroring ExploitGym's `agent_scorer`:

  1. scorer agent reads the task (spec, required goals, final.lean/verdict.json/
     attack_report.md, trajectory), runs Lean, and writes `scorer_result.json`;
  2. judge agent validates every evidence quote with `grep -F`, re-runs Lean, and
     corrects the JSON.

The scorer runs inside the Lean-enabled agent image (`protocolbench/agent:latest`)
with the static CLI runtime mounted at `/data`.

Usage:
    python3 scripts/run_scorer.py out/onchain_run/<run> \
        --model deepseek/deepseek-v4.1-flash \
        --workers 4 --timeout 900 --out-dir out/scores
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

REPO = pathlib.Path(__file__).resolve().parents[1]
PROMPT = REPO / "agent_scorer" / "prompt.md"
JUDGE_PROMPT = REPO / "agent_scorer" / "judge_prompt.md"
DEFAULT_RUNTIME = REPO / "data" / "runtime"
CLAUDE_BIN = "/data/node/bin/claude-code.sh"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)


def load_glm_env() -> None:
    path = REPO / ".glm_env"
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def find_tasks(root: pathlib.Path, success_only: bool) -> list[pathlib.Path]:
    out = []
    for result in sorted(root.rglob("result.json")):
        td = result.parent
        if not (td / "outputs" / "final.lean").exists():
            continue
        if success_only:
            try:
                rec = json.loads(result.read_text())
                if not any(c.get("score", 0) > 0 for c in rec.get("checks", [])):
                    continue
            except Exception:
                continue
        out.append(td)
    return out


def build_cmd(prompt_path: str, log_name: str, model: str, timeout: int) -> str:
    return (
        f"cat {prompt_path} | timeout {timeout} {CLAUDE_BIN} "
        f"--model {model} --verbose --output-format=stream-json "
        f"--permission-mode=bypassPermissions 2>&1 | tee /scoring/output/{log_name}"
    )


def score_one(task_dir: pathlib.Path, *, model: str, timeout: int, api_base_url: str | None,
              api_key: str, output_dir: pathlib.Path, root: pathlib.Path,
              agent_image: str, runtime_dir: pathlib.Path, overwrite: bool) -> dict:
    rel = task_dir.resolve().relative_to(root.resolve())
    flat = str(rel).replace("/", "__")
    dest = output_dir / flat
    if (dest / "scorer_result.json").exists() and not overwrite:
        return {"task": flat, "status": "skipped"}
    dest.mkdir(parents=True, exist_ok=True)

    cname = f"pbscore-{flat[:40]}-{uuid.uuid4().hex[:8]}"
    env = {
        "PATH": "/data/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/tmp/agent-home",
        "CLAUDE_CONFIG_DIR": "/tmp/agent-config",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "API_TIMEOUT_MS": "3000000",
        "CLAUDE_CODE_MAX_RETRIES": "10",
        "IS_SANDBOX": "1",
    }
    if api_base_url:
        env.update({
            "ANTHROPIC_BASE_URL": api_base_url,
            "ANTHROPIC_MODEL": model,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
            "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": model,
            "CLAUDE_CODE_SUBAGENT_MODEL": model,
        })
    if api_key:
        env["ANTHROPIC_API_KEY"] = api_key

    with tempfile.TemporaryDirectory(prefix="pbscore-") as tmp:
        tmp_out = pathlib.Path(tmp) / "output"
        tmp_out.mkdir()
        dm = ["docker", "run", "-d", "--name", cname, "--entrypoint", "tail",
              "-v", f"{runtime_dir.resolve()}:/data:ro",
              "-v", f"{task_dir.resolve()}:/scoring/task:ro",
              "-v", f"{tmp_out}:/scoring/output",
              "-v", f"{PROMPT.resolve()}:/scoring/prompt.md:ro",
              "-v", f"{JUDGE_PROMPT.resolve()}:/scoring/judge_prompt.md:ro",
              "-w", "/scoring"]
        for k, v in env.items():
            dm += ["-e", f"{k}={v}"]
        dm += [agent_image, "-f", "/dev/null"]
        try:
            subprocess.run(dm, check=True, capture_output=True, text=True)
            subprocess.run(["docker", "exec", cname, "sh", "-c",
                            "mkdir -p /tmp/agent-config /tmp/agent-home /scoring/output"],
                           capture_output=True)
            subprocess.run(["docker", "exec", cname, "bash", "-c",
                            build_cmd("/scoring/prompt.md", "scorer.log", model, timeout)],
                           capture_output=True, text=True, timeout=timeout + 60)
            if (tmp_out / "scorer_result.json").exists():
                subprocess.run(["docker", "exec", cname, "bash", "-c",
                                build_cmd("/scoring/judge_prompt.md", "judge.log", model, timeout)],
                               capture_output=True, text=True, timeout=timeout + 60)
        except Exception as e:
            logger.error("[%s] scorer error: %s", flat, e)
        finally:
            subprocess.run(["docker", "rm", "-f", cname], capture_output=True)

        if (tmp_out / "scorer_result.json").exists():
            data = json.loads((tmp_out / "scorer_result.json").read_text())
            data["scorer_model"] = model
            data["scorer_task_dir"] = str(task_dir.resolve())
            (dest / "scorer_result.json").write_text(json.dumps(data, indent=2, ensure_ascii=False))
            for log in ("scorer.log", "judge.log"):
                if (tmp_out / log).exists():
                    shutil.copy2(tmp_out / log, dest / log)
            return {"task": flat, "status": "success", "score": data.get("score"),
                    "attack_valid": data.get("attack_valid"), "reward_hacking": data.get("reward_hacking")}
        for log in ("scorer.log", "judge.log"):
            if (tmp_out / log).exists():
                shutil.copy2(tmp_out / log, dest / log)
        return {"task": flat, "status": "no_output"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=pathlib.Path, nargs="?", default=None)
    ap.add_argument("--task-list", type=pathlib.Path, default=None)
    ap.add_argument("--out-dir", type=pathlib.Path, required=True)
    ap.add_argument("--model", default=os.environ.get("GLM_MODEL", "deepseek/deepseek-v4.1-flash"))
    ap.add_argument("--api-base-url", default=os.environ.get("GLM_API_BASE", "https://api.360.cn"))
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--agent-image", default="protocolbench/agent:latest")
    ap.add_argument("--runtime-dir", type=pathlib.Path, default=DEFAULT_RUNTIME)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--include-failures", action="store_true", help="also score tasks with score 0")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    load_glm_env()
    api_key = args.api_key or os.environ.get("GLM_API_KEY") or os.environ.get("API_KEY", "")
    if not api_key and not args.dry_run:
        logger.error("no API key (set GLM_API_KEY/API_KEY or --api-key; .glm_env is auto-loaded)")
        return 2

    if args.task_list:
        tasks = [pathlib.Path(l.strip()) for l in args.task_list.read_text().splitlines() if l.strip()]
        root = args.root or pathlib.Path(os.path.commonpath([str(t) for t in tasks]))
    else:
        if not args.root:
            ap.error("provide a run root or --task-list")
        root = args.root
        tasks = find_tasks(root, success_only=not args.include_failures)

    if not tasks:
        logger.info("no tasks found")
        return 0
    logger.info("scoring %d tasks, %d workers, model=%s", len(tasks), args.workers, args.model)
    if args.dry_run:
        for t in tasks:
            print(t)
        return 0

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(score_one, t, model=args.model, timeout=args.timeout,
                          api_base_url=args.api_base_url, api_key=api_key,
                          output_dir=args.out_dir, root=root, agent_image=args.agent_image,
                          runtime_dir=args.runtime_dir, overwrite=args.overwrite): t
                for t in tasks}
        for i, f in enumerate(as_completed(futs), 1):
            r = f.result()
            results.append(r)
            logger.info("[%d/%d] %s %s", i, len(tasks), r.get("task"), r.get("status"))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "total": len(results),
        "success": sum(1 for r in results if r["status"] == "success"),
        "skipped": sum(1 for r in results if r["status"] == "skipped"),
        "no_output": sum(1 for r in results if r["status"] == "no_output"),
        "attack_valid": sum(1 for r in results if r.get("attack_valid")),
        "reward_hacking": sum(1 for r in results if r.get("reward_hacking")),
        "mean_score": (sum(r["score"] for r in results if isinstance(r.get("score"), (int, float)))
                       / max(1, sum(1 for r in results if isinstance(r.get("score"), (int, float))))),
        "results": results,
    }
    (args.out_dir / "scorer_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    logger.info("done: %s", {k: v for k, v in summary.items() if k != "results"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
