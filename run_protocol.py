#!/usr/bin/env python3
"""ProtocolBench runner — analyze protocols with an LLM agent.

Supports: model selection, concurrency, and a protocol list file.

Examples::

    # Run all 581 protocols with DeepSeek V4 Flash, 10 concurrent
    python run_protocol.py --model deepseek/deepseek-v4-flash \
        --concurrency 10 --protocols data/task_ids/v1.txt

    # Run 4 B1 OIDC tasks with GLM-5.3
    python run_protocol.py --model z-ai/glm-5.3 \
        --concurrency 1 --protocols data/task_ids/b1_sample.txt

    # Smoke test: first 5 tasks, mock agent
    python run_protocol.py --model mock --concurrency 1 \
        --protocols data/task_ids/v1.txt --first-n 5
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

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from tamaringym.evaluation.agents.base import Agent  # noqa: E402
from tamaringym.evaluation.types import EvalConfig  # noqa: E402

logger = logging.getLogger("run_protocol")

global_terminate_flag = False

DEFAULT_API_KEY = "fk3478068563.wS9T_IONT6Qkh3IC2Ket6zbvbZi7jH37058071ba"
DEFAULT_API_BASE = "https://api.360.cn"
DEFAULT_AGENT_IMAGE = "protocolbench/agent:latest"
DEFAULT_TIMEOUT = 3600
DEFAULT_VERIFY_TIMEOUT = 120
DEFAULT_MEM_LIMIT = "8g"
DEFAULT_NANO_CPUS = 4_000_000_000


def _handle_signal(signum, _frame):
    global global_terminate_flag
    logger.warning("signal %d — finishing active tasks", signum)
    global_terminate_flag = True


def build_agent(agent_type: str) -> Agent:
    if agent_type == "mock_perfect":
        from tamaringym.evaluation.agents.mock import MockPerfectAgent
        return MockPerfectAgent()
    if agent_type == "mock_lazy":
        from tamaringym.evaluation.agents.mock import MockLazyAgent
        return MockLazyAgent()
    if agent_type == "claude_code":
        from tamaringym.evaluation.agents.claude_code import ClaudeCodeAgent
        return ClaudeCodeAgent()
    raise ValueError(f"unknown agent: {agent_type}")


def run_one_task(task_id: str, args_dict: dict) -> dict:
    """Worker entry: evaluate one task in a subprocess."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(processName)s] %(levelname)s %(name)s: %(message)s",
    )
    out_dir = Path(args_dict["out_dir"]) / task_id.replace(":", "_")
    if (out_dir / "result.json").exists() and not args_dict["overwrite"]:
        logger.info("skip %s (exists)", task_id)
        return {"task_id": task_id, "skipped": True}

    agent_kwargs = dict(args_dict.get("agent_extra_kwargs") or {})
    agent_kwargs.setdefault("task_id", task_id)
    agent_kwargs.setdefault("has_theory", task_id.startswith("L1"))
    agent_kwargs.setdefault("claude_model", args_dict.get("claude_model"))
    if args_dict.get("reasoning_effort"):
        agent_kwargs["reasoning_effort"] = args_dict["reasoning_effort"]
    agent_kwargs["tool_config"] = args_dict.get("tool_config", "full")

    cfg = EvalConfig(
        task_id=task_id,
        out_dir=out_dir,
        verifier_image=args_dict.get("verifier_image", "tamaringym/verifier:1.12.0"),
        agent_image=args_dict.get("agent_image", DEFAULT_AGENT_IMAGE),
        agent_timeout_seconds=args_dict["timeout"],
        verify_timeout_seconds=args_dict.get("verify_timeout", DEFAULT_VERIFY_TIMEOUT),
        agent_extra_kwargs=agent_kwargs,
        api_base_url=args_dict.get("api_base_url"),
        api_key=args_dict.get("api_key"),
        credential_path=args_dict.get("credential_path"),
        container_mem_limit=args_dict.get("mem_limit", DEFAULT_MEM_LIMIT),
        container_nano_cpus=args_dict.get("nano_cpus", DEFAULT_NANO_CPUS),
    )
    if args_dict["agent"].startswith("mock_"):
        cfg.credential_path = Path("/dev/null")

    # routing: B1 → JwtOidcEvaluator; L1/L2/L3 → LeanEvaluator
    if task_id.startswith("B1:"):
        from tamaringym.evaluation.families.jwt_oidc import JwtOidcEvaluator
        evaluator = JwtOidcEvaluator(cfg)
    else:
        from tamaringym.evaluation.lean_eval import LeanEvaluator
        evaluator = LeanEvaluator(cfg)

    agent = build_agent(args_dict["agent"])
    try:
        result = evaluator.evaluate(agent)
        return {
            "task_id": task_id,
            "weighted_score": result.weighted_score,
            "checks": [(c.name, c.score, c.weight) for c in result.checks],
            "elapsed": result.elapsed_time,
            "error": result.error,
        }
    except Exception as e:
        logger.exception("task %s failed", task_id)
        evaluator.cleanup()
        return {"task_id": task_id, "error": str(e)}


def _parse_duration(s: str) -> int:
    """Parse '2h', '30m', '90s', '3600' → seconds (int)."""
    s = s.strip().lower()
    if not s:
        return DEFAULT_TIMEOUT
    mult = 1
    if s.endswith("h"):
        mult = 3600; s = s[:-1]
    elif s.endswith("m") and not s.endswith("mi"):
        mult = 60; s = s[:-1]
    elif s.endswith("s"):
        s = s[:-1]
    return int(float(s) * mult)


def load_task_ids(args) -> list[str]:
    if args.protocols:
        ids = [
            line.strip()
            for line in Path(args.protocols).read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    else:
        from tamaringym.task.metadata import load_task_registry
        registry = load_task_registry()
        ids = [
            meta.task_id
            for level_tasks in registry.values()
            for meta in level_tasks.values()
        ]
    if args.first_n:
        ids = ids[: args.first_n]
    if args.shuffle:
        random.Random(args.shuffle_seed).shuffle(ids)
    return ids


def main() -> None:
    ap = argparse.ArgumentParser(
        description="ProtocolBench runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # core params
    ap.add_argument("--model", "-m", default="deepseek/deepseek-v4-flash",
                    help="LLM model ID (e.g. deepseek/deepseek-v4-flash)")
    ap.add_argument("--concurrency", "-c", type=int, default=1,
                    help="number of parallel workers")
    ap.add_argument("--protocols", "-p", type=Path, default=None,
                    help="protocol list file (one task ID per line)")
    ap.add_argument("--out-dir", "-o", type=Path,
                    default=Path("/tmp/opencode/protocol_run"),
                    help="output directory")
    ap.add_argument("--first-n", type=int, default=None,
                    help="run only first N tasks")
    ap.add_argument("--shuffle", action="store_true",
                    help="shuffle task order")
    ap.add_argument("--shuffle-seed", type=int, default=42)
    ap.add_argument("--overwrite", action="store_true",
                    help="re-run even if result.json exists")

    # agent
    ap.add_argument("--agent", default="claude_code",
                    choices=["claude_code", "mock_perfect", "mock_lazy"])
    ap.add_argument("--reasoning-effort", default=None)

    # timing
    ap.add_argument("--timeout", type=_parse_duration, default="1h",
                    help="agent wall clock per task (e.g. 2h, 30m, 90s, 3600)")
    ap.add_argument("--verify-timeout", type=_parse_duration, default="2m",
                    help="verification timeout (e.g. 5m, 120s)")

    # resources
    ap.add_argument("--mem-limit", default=DEFAULT_MEM_LIMIT)
    ap.add_argument("--nano-cpus", type=int, default=DEFAULT_NANO_CPUS)
    ap.add_argument("--agent-image", default=DEFAULT_AGENT_IMAGE)
    ap.add_argument("--verifier-image", default="tamaringym/verifier:1.12.0")

    # API
    ap.add_argument("--api-key", default=DEFAULT_API_KEY)
    ap.add_argument("--api-base-url", default=DEFAULT_API_BASE)
    ap.add_argument("--credential-path", type=Path, default=None)

    # ablation
    ap.add_argument("--tool-config", default="full",
                    choices=["full", "no-tamarin", "black-box"])

    args = ap.parse_args()

    # auto-append timestamp to out-dir to isolate runs
    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = args.out_dir / f"{args.model.replace('/', '_')}_{ts}"
    args.out_dir = out_dir
    logger.info("output dir: %s", out_dir)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.agent == "claude_code" and args.model == "mock":
        args.agent = "mock_perfect"

    if args.agent == "claude_code" and not (args.api_key or args.credential_path):
        logger.error("claude_code requires --api-key or --credential-path")
        sys.exit(2)

    task_ids = load_task_ids(args)
    logger.info("running %d tasks, %d workers, model=%s",
                len(task_ids), args.concurrency, args.model)

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
        "claude_model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "tool_config": args.tool_config,
    }

    stagger = max(10, 5 * args.concurrency)
    results = []
    t0 = time.monotonic()
    with ProcessPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {}
        for i, tid in enumerate(task_ids):
            if global_terminate_flag:
                break
            futures[pool.submit(run_one_task, tid, args_dict)] = tid
            if i < args.concurrency * 3:
                time.sleep(random.uniform(0.5, min(stagger, 30) / 10))
        for fut in as_completed(futures):
            tid = futures[fut]
            try:
                res = fut.result()
            except KeyboardInterrupt:
                pool.shutdown(wait=False, cancel_futures=True)
                raise
            except Exception as e:
                res = {"task_id": tid, "error": str(e)}
            results.append(res)
            score = res.get("weighted_score")
            if res.get("skipped"):
                logger.info("[%d/%d] %s skipped", len(results), len(task_ids), tid)
            else:
                logger.info(
                    "[%d/%d] %s score=%.3f elapsed=%.0fs%s",
                    len(results), len(task_ids), tid,
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
        "mean_score": sum(scores) / len(scores) if scores else None,
        "wall_seconds": elapsed,
        "model": args.model,
        "concurrency": args.concurrency,
    }
    summary_path = args.out_dir / "summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2))
    logger.info("done in %.0fs: %s", elapsed, json.dumps(summary))


if __name__ == "__main__":
    main()
