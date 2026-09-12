#!/usr/bin/env python3
"""Batch runner for ProtocolBench (pattern from ExploitGym's run_agent.py).

Runs the configured CLI agent (default: Claude Code) over a task list with
a process pool, per-task resume (existing result.json is skipped), startup
staggering, and graceful shutdown on SIGINT/SIGTERM.

Examples::

    # 4 workers, 1h per task, resume-safe
    python examples/run_agent.py --tasks-file data/task_ids/sample.txt \
        --out-dir out/test --max-workers 4 --timeout 3600 \
        --agent claude_code --claude-model claude-sonnet-4-6 \
        --api-key "$ANTHROPIC_API_KEY"

    # smoke run with the mock perfect agent (no LLM needed)
    python examples/run_agent.py --tasks-file data/task_ids/sample.txt \
        --out-dir out/mock --agent mock_perfect
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import signal
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from tamaringym.evaluation.agents.base import Agent  # noqa: E402
from tamaringym.evaluation.base import TamarinEvaluator  # noqa: E402
from tamaringym.evaluation.types import EvalConfig  # noqa: E402
from tamaringym.task.metadata import load_task_registry  # noqa: E402

logger = logging.getLogger("run_agent")

global_terminate_flag = False


def _handle_signal(signum, _frame):
    global global_terminate_flag
    logger.warning("received signal %d — finishing active tasks, then exiting", signum)
    global_terminate_flag = True


def build_agent(args) -> Agent:
    if args.agent == "mock_perfect":
        from tamaringym.evaluation.agents.mock import MockPerfectAgent

        return MockPerfectAgent()
    if args.agent == "mock_lazy":
        from tamaringym.evaluation.agents.mock import MockLazyAgent

        return MockLazyAgent()
    if args.agent == "claude_code":
        from tamaringym.evaluation.agents.claude_code import ClaudeCodeAgent

        return ClaudeCodeAgent()
    raise ValueError(f"unknown agent: {args.agent}")


def run_one_task(task_id: str, args_dict: dict) -> dict:
    """Worker entry: evaluate one task. Runs in a subprocess."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(processName)s] %(levelname)s %(name)s: %(message)s",
    )
    out_dir = Path(args_dict["out_dir"]) / task_id.replace(":", "_")
    if (out_dir / "result.json").exists() and not args_dict["overwrite"]:
        logger.info("skipping %s (result.json exists)", task_id)
        return {"task_id": task_id, "skipped": True}

    # agent kwargs per task
    agent_kwargs = dict(args_dict.get("agent_extra_kwargs") or {})
    agent_kwargs.setdefault("task_id", task_id)
    agent_kwargs.setdefault("has_theory", task_id.startswith("L1"))
    agent_kwargs.setdefault(
        "claude_model", args_dict.get("claude_model") or "claude-sonnet-4-6"
    )
    if args_dict.get("reasoning_effort"):
        agent_kwargs["reasoning_effort"] = args_dict["reasoning_effort"]
    agent_kwargs["tool_config"] = args_dict.get("tool_config", "full")

    cfg = EvalConfig(
        task_id=task_id,
        out_dir=out_dir,
        verifier_image=args_dict.get("verifier_image") or "tamaringym/verifier:1.12.0",
        agent_image=args_dict.get("agent_image") or "protocolbench/agent:latest",
        agent_timeout_seconds=args_dict["timeout"],
        verify_timeout_seconds=args_dict.get("verify_timeout", 600),
        agent_extra_kwargs=agent_kwargs,
        api_base_url=args_dict.get("api_base_url"),
        api_key=args_dict.get("api_key"),
        credential_path=args_dict.get("credential_path"),
        container_mem_limit=args_dict.get("mem_limit"),
        container_nano_cpus=args_dict.get("nano_cpus"),
    )
    if args_dict["agent"].startswith("mock_"):
        cfg.credential_path = Path("/dev/null")  # mocks need no auth

    # family routing: B1 tasks → JwtOidcEvaluator; else TamarinEvaluator
    if task_id.startswith("B1:"):
        from tamaringym.evaluation.families.jwt_oidc import JwtOidcEvaluator

        evaluator = JwtOidcEvaluator(cfg)
    else:
        evaluator = TamarinEvaluator(cfg)
    agent = build_agent(
        argparse.Namespace(
            **{**vars(_build_arg_namespace(args_dict)), "agent": args_dict["agent"]}
        )
    )
    try:
        result = evaluator.evaluate(agent)
        return {
            "task_id": task_id,
            "weighted_score": result.weighted_score,
            "checks": [(c.name, c.score, c.weight) for c in result.checks],
            "elapsed": result.elapsed_time,
            "error": result.error,
        }
    except Exception as e:  # noqa: BLE001
        logger.exception("task %s failed", task_id)
        evaluator.cleanup()
        return {"task_id": task_id, "error": str(e)}


def _build_arg_namespace(args_dict):
    """Rebuild a minimal argparse-like namespace for build_agent."""
    import argparse as _ap

    ns = _ap.Namespace(agent=args_dict["agent"])
    return ns


def load_task_ids(args) -> list[str]:
    registry = load_task_registry()
    if args.tasks_file:
        ids = [
            line.strip()
            for line in Path(args.tasks_file).read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    else:
        ids = [
            meta.task_id
            for level_tasks in registry.values()
            for meta in level_tasks.values()
        ]
    if args.levels:
        wanted = {
            l if l.endswith(("_verdict", "_form", "_repair")) else l
            for l in args.levels
        }
        ids = [
            i
            for i in ids
            if i.split(":")[0] in wanted or _level_dir_of(i, registry) in wanted
        ]
    if args.first_n:
        ids = ids[: args.first_n]
    if args.shuffle_tasks:
        random.Random(args.shuffle_seed).shuffle(ids)
    return ids


def _level_dir_of(task_id: str, registry) -> str:
    level = task_id.split(":")[0]
    return {"L1": "L1_verdict", "L2": "L2_form", "L3": "L3_repair"}.get(level, level)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tasks-file", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=REPO_ROOT / "out" / "run_agent")
    ap.add_argument(
        "--agent",
        default="claude_code",
        choices=["claude_code", "mock_perfect", "mock_lazy"],
    )
    ap.add_argument("--claude-model", default="claude-sonnet-4-6")
    ap.add_argument("--reasoning-effort", default=None)
    ap.add_argument(
        "--timeout", type=int, default=7200, help="agent wall clock per task (s)"
    )
    ap.add_argument("--verify-timeout", type=int, default=600)
    ap.add_argument("--max-workers", type=int, default=1)
    ap.add_argument("--stagger-time", type=int, default=None)
    ap.add_argument("--first-n", type=int, default=None)
    ap.add_argument("--levels", nargs="*", default=None)
    ap.add_argument("--shuffle-tasks", action="store_true")
    ap.add_argument("--shuffle-seed", type=int, default=42)
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--api-base-url", default=None)
    ap.add_argument("--credential-path", type=Path, default=None)
    ap.add_argument("--mem-limit", default="8g")
    ap.add_argument("--nano-cpus", type=int, default=4_000_000_000)
    ap.add_argument("--agent-image", default="protocolbench/agent:latest")
    ap.add_argument("--verifier-image", default="tamaringym/verifier:1.12.0")
    ap.add_argument(
        "--tool-config",
        default="full",
        choices=["full", "no-tamarin", "black-box"],
        help="Ablation: 'full' (default), 'no-tamarin' (shadow tamarin-prover), "
        "'black-box' (no tamarin, prompt mentions only HTTP endpoints)",
    )
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.agent == "claude_code" and not (args.api_key or args.credential_path):
        logger.error(
            "claude_code agent requires --api-key or --credential-path "
            "(or use --agent mock_perfect for pipeline testing)"
        )
        sys.exit(2)

    task_ids = load_task_ids(args)
    logger.info("running %d tasks with %d workers", len(task_ids), args.max_workers)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    args_dict = {
        "out_dir": str(args.out_dir),
        "agent": args.agent,
        "timeout": args.timeout,
        "verify_timeout": args.verify_timeout,
        "overwrite": args.overwrite,
        "api_key": args.api_key,
        "api_base_url": args.api_base_url,
        "credential_path": str(args.credential_path) if args.credential_path else None,
        "mem_limit": args.mem_limit,
        "nano_cpus": args.nano_cpus,
        "agent_image": args.agent_image,
        "verifier_image": args.verifier_image,
        "claude_model": args.claude_model,
        "reasoning_effort": args.reasoning_effort,
        "tool_config": args.tool_config,
    }

    stagger = args.stagger_time or max(10, 5 * args.max_workers)
    results = []
    t0 = time.monotonic()
    with ProcessPoolExecutor(max_workers=args.max_workers) as pool:
        futures = {}
        for i, tid in enumerate(task_ids):
            if global_terminate_flag:
                break
            futures[pool.submit(run_one_task, tid, args_dict)] = tid
            if i < args.max_workers * 3:  # stagger the initial burst
                time.sleep(random.uniform(0.5, min(stagger, 30) / 10))
        for fut in as_completed(futures):
            tid = futures[fut]
            try:
                res = fut.result()
            except KeyboardInterrupt:
                logger.warning("interrupted during %s", tid)
                pool.shutdown(wait=False, cancel_futures=True)
                raise
            except Exception as e:  # noqa: BLE001
                res = {"task_id": tid, "error": str(e)}
            results.append(res)
            score = res.get("weighted_score")
            if res.get("skipped"):
                logger.info("[%d/%d] %s skipped", len(results), len(task_ids), tid)
            else:
                logger.info(
                    "[%d/%d] %s weighted=%.3f elapsed=%.0fs%s",
                    len(results),
                    len(task_ids),
                    tid,
                    score if score is not None else -1,
                    res.get("elapsed", 0),
                    f" ERROR={res['error'][:80]}" if res.get("error") else "",
                )

    elapsed = time.monotonic() - t0
    done = [r for r in results if not r.get("skipped")]
    scores = [r["weighted_score"] for r in done if r.get("weighted_score") is not None]
    summary = {
        "total": len(task_ids),
        "executed": len(done),
        "skipped": len(results) - len(done),
        "mean_weighted_score": sum(scores) / len(scores) if scores else None,
        "wall_seconds": elapsed,
        "agent": args.agent,
        "model": args.claude_model,
    }
    summary_path = Path(args.out_dir) / "summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2))
    logger.info("done in %.0fs: %s", elapsed, json.dumps(summary))


if __name__ == "__main__":
    main()
