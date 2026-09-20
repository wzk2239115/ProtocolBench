#!/usr/bin/env python3
"""Batch evaluation orchestration for the ProtocolBench range system.

Runs one or more agents/models across all (or selected) ranges, optionally
with variant seeds and negative (--fixed/--safe) cases, then writes a
batch_manifest.json describing every planned/completed run.

Examples
--------

Dry run (print planned runs only)::

    python scripts/run_range_batch.py \
        --ranges "range/nontx/*,range/tx/*" \
        --agents claude_code \
        --models "deepseek/deepseek-v4.1-flash,anthropic/claude-sonnet-4" \
        --timeout 600 --variants 3 --negatives --dry-run

Reference-solver plumbing (no LLM)::

    python scripts/run_range_batch.py \
        --ranges "range/nontx/nspk,range/nontx/woo_lam" \
        --agent-cmd "python /abs/path/to/exploit.py" \
        --timeout 120 --out-dir out/range_batch --negatives
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON = REPO_ROOT / ".venv" / "bin" / "python"
RUN_RANGE = REPO_ROOT / "range" / "run_range.py"

_VARIANT_RE = re.compile(r"^v\d+$")


def _rel(p: Path) -> str:
    """Return a repo-relative display path, falling back to absolute."""
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


# ── discovery ────────────────────────────────────────────────────────────
def expand_ranges(patterns: str) -> list[Path]:
    """Glob-expand comma-separated range patterns (relative to repo root)."""
    out: list[Path] = []
    seen: set[Path] = set()
    for pat in patterns.split(","):
        pat = pat.strip()
        if not pat:
            continue
        p = Path(pat)
        if not p.is_absolute():
            p = REPO_ROOT / pat
        matches = sorted(glob.glob(str(p), recursive=True))
        if not matches and p.is_dir():
            matches = [str(p)]
        for m in matches:
            mp = Path(m)
            if (mp / "task.json").is_file() and mp not in seen:
                out.append(mp)
                seen.add(mp)
    return out


def range_kind(range_dir: Path) -> str:
    rel = range_dir.relative_to(REPO_ROOT)
    if len(rel.parts) >= 2 and rel.parts[1] in ("nontx", "tx"):
        return rel.parts[1]
    raise ValueError(f"cannot determine range kind from {range_dir}")


def range_name(range_dir: Path) -> str:
    return range_dir.relative_to(REPO_ROOT).parts[-1]


# ── run_range.py capability probe ───────────────────────────────────────
def run_range_supports_flag(flag: str) -> bool:
    try:
        proc = subprocess.run(
            [str(PYTHON), str(RUN_RANGE), "--help"],
            capture_output=True, text=True, timeout=30,
        )
        return proc.returncode == 0 and flag in proc.stdout
    except Exception:
        return False


# ── command building ────────────────────────────────────────────────────
def build_command(
    *,
    range_dir: Path,
    model: str | None,
    agent: str | None,
    timeout: float,
    out_dir: Path,
    agent_cmd: str | None,
    variant_seed: int | None,
    negative: bool,
    supports_variant_seed: bool,
    solver: bool,
    mode: str,
) -> list[str]:
    cmd: list[str] = [
        str(PYTHON), str(RUN_RANGE),
        "--range", str(range_dir.relative_to(REPO_ROOT)),
        "--timeout", str(timeout),
        "--out-dir", str(out_dir),
        "--mode", mode,
    ]
    if agent_cmd:
        cmd += ["--agent-cmd", agent_cmd]
    elif solver:
        cmd += ["--solver"]
    elif agent:
        cmd += ["--agent", agent]
        if model:
            cmd += ["--model", model]
    if negative:
        kind = range_kind(range_dir)
        if kind == "nontx":
            cmd.append("--fixed")
        elif kind == "tx":
            cmd.append("--safe")
    if variant_seed is not None and supports_variant_seed:
        cmd += ["--variant-seed", str(variant_seed)]
    return cmd


# ── plan building ───────────────────────────────────────────────────────
def build_plans(
    *,
    ranges: list[Path],
    agents: list[str],
    models: list[str],
    agent_cmd: str | None,
    solver: bool,
    model_label_override: str | None,
    timeout: float,
    batch_dir: Path,
    variants: int,
    variant_seed_base: int,
    negatives: bool,
    supports_variant_seed: bool,
    mode: str,
) -> list[dict]:
    plans: list[dict] = []

    if agent_cmd or solver:
        model_labels = [model_label_override or "solver"]
        agent_model_pairs = [(None, ml) for ml in model_labels]
    else:
        agent_model_pairs = [(a, m) for a in agents for m in models]

    for range_dir in ranges:
        rname = range_name(range_dir)
        kind = range_kind(range_dir)
        for agent, model in agent_model_pairs:
            # original positive run
            out_dir = batch_dir / rname / model / "pos"
            plans.append({
                "range": str(range_dir.relative_to(REPO_ROOT)),
                "range_name": rname,
                "kind": kind,
                "agent": agent,
                "model": model,
                "variant": "pos",
                "variant_seed": None,
                "negative": False,
                "timeout": timeout,
                "out_dir": _rel(out_dir),
                "cmd": build_command(
                    range_dir=range_dir, model=model, agent=agent, timeout=timeout,
                    out_dir=out_dir, agent_cmd=agent_cmd, variant_seed=None,
                    negative=False, supports_variant_seed=supports_variant_seed,
                    solver=solver, mode=mode,
                ),
            })
            # variant runs
            for i in range(variants):
                seed = variant_seed_base + i
                out_dir = batch_dir / rname / model / f"v{seed}"
                plans.append({
                    "range": str(range_dir.relative_to(REPO_ROOT)),
                    "range_name": rname,
                    "kind": kind,
                    "agent": agent,
                    "model": model,
                    "variant": f"v{seed}",
                "variant_seed": seed,
                "negative": False,
                "timeout": timeout,
                "out_dir": _rel(out_dir),
                    "cmd": build_command(
                        range_dir=range_dir, model=model, agent=agent, timeout=timeout,
                        out_dir=out_dir, agent_cmd=agent_cmd, variant_seed=seed,
                        negative=False, supports_variant_seed=supports_variant_seed,
                        solver=solver, mode=mode,
                    ),
                })
            # negative run
            if negatives:
                out_dir = batch_dir / rname / model / "neg"
                plans.append({
                    "range": str(range_dir.relative_to(REPO_ROOT)),
                    "range_name": rname,
                    "kind": kind,
                    "agent": agent,
                    "model": model,
                    "variant": "neg",
                "variant_seed": None,
                "negative": True,
                "timeout": timeout,
                "out_dir": _rel(out_dir),
                    "cmd": build_command(
                        range_dir=range_dir, model=model, agent=agent, timeout=timeout,
                        out_dir=out_dir, agent_cmd=agent_cmd, variant_seed=None,
                        negative=True, supports_variant_seed=supports_variant_seed,
                        solver=solver, mode=mode,
                    ),
                })
    return plans


# ── execution ───────────────────────────────────────────────────────────
def run_one(plan: dict) -> dict:
    out_dir = Path(plan["out_dir"])
    if not out_dir.is_absolute():
        out_dir = REPO_ROOT / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = plan["cmd"]
    env = dict(__import__("os").environ)
    if plan.get("variant_seed") is not None:
        env["RANGE_VARIANT_SEED"] = str(plan["variant_seed"])
    t0 = time.monotonic()
    wall = plan["timeout"] + 300
    stderr_tail = ""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=wall, env=env,
            cwd=str(REPO_ROOT),
        )
        exit_code = proc.returncode
        stderr_tail = (proc.stderr or "")[-2000:]
    except subprocess.TimeoutExpired as e:
        exit_code = -1
        stderr_tail = f"TimeoutExpired: {e}"
    except Exception as e:  # noqa: BLE001
        exit_code = -2
        stderr_tail = f"{type(e).__name__}: {e}"
    elapsed = time.monotonic() - t0

    result_path = out_dir / "result.json"
    success = None
    if result_path.is_file():
        try:
            rj = json.loads(result_path.read_text(encoding="utf-8"))
            success = rj.get("success")
        except Exception:  # noqa: BLE001
            success = None

    rec: dict = {
        "range": plan["range"],
        "range_name": plan["range_name"],
        "kind": plan["kind"],
        "agent": plan["agent"],
        "model": plan["model"],
        "variant": plan["variant"],
        "variant_seed": plan["variant_seed"],
        "negative": plan["negative"],
        "out_dir": plan["out_dir"],
        "exit_code": exit_code,
        "elapsed_sec": round(elapsed, 3),
        "success": success,
        "stderr_tail": stderr_tail,
        "cmd": plan["cmd"],
    }
    try:
        (out_dir / "run_meta.json").write_text(
            json.dumps(rec, indent=2) + "\n", encoding="utf-8",
        )
    except OSError:
        pass
    return rec


def resolve_out_dir(out_dir: str) -> Path:
    p = Path(out_dir)
    return p if p.is_absolute() else REPO_ROOT / p


# ── main ────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Batch evaluation orchestration for ProtocolBench ranges.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--ranges", required=True,
                    help="comma-separated range globs, e.g. \"range/nontx/*,range/tx/*\"")
    ap.add_argument("--agents", default="claude_code",
                    help="comma-separated agent names (default claude_code)")
    ap.add_argument("--models", default=None,
                    help="comma-separated model ids, e.g. \"deepseek/deepseek-v4.1-flash\"")
    ap.add_argument("--timeout", type=float, default=600.0,
                    help="agent wall-clock seconds per run")
    ap.add_argument("--out-dir", default="out/range_batch",
                    help="batch output root")
    ap.add_argument("--variants", type=int, default=0,
                    help="number of variant seeds per range (0 = no variants)")
    ap.add_argument("--variant-seed-base", type=int, default=1000,
                    help="first variant seed (seeds = base, base+1, ...)")
    ap.add_argument("--negatives", action="store_true",
                    help="also run --fixed/--safe negative cases")
    ap.add_argument("--dry-run", action="store_true",
                    help="print planned runs without executing")
    ap.add_argument("--parallel", type=int, default=1,
                    help="concurrent runs (default 1)")
    ap.add_argument("--agent-cmd", default=None,
                    help="shell command to run as the agent (reference solver / "
                         "plumbing); overrides --agents/--models")
    ap.add_argument("--solver", action="store_true",
                    help="tx: run the reference exploit as the agent (plumbing)")
    ap.add_argument("--mode", default="auto",
                    choices=["auto", "docker", "local"],
                    help="nontx: target backend passthrough")
    ap.add_argument("--model-label", default=None,
                    help="model label for output dirs when --agent-cmd/--solver "
                         "(default 'solver')")
    args = ap.parse_args()

    ranges = expand_ranges(args.ranges)
    if not ranges:
        print("error: no ranges discovered from --ranges", file=sys.stderr)
        return 2

    agents = [a.strip() for a in args.agents.split(",") if a.strip()]
    models = [m.strip() for m in (args.models or "").split(",") if m.strip()]

    if not (args.agent_cmd or args.solver):
        if not models:
            print("error: --models required (or use --agent-cmd/--solver)",
                  file=sys.stderr)
            return 2
        if not agents:
            print("error: --agents required", file=sys.stderr)
            return 2

    supports_variant_seed = run_range_supports_flag("--variant-seed")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_dir = resolve_out_dir(args.out_dir) / timestamp

    plans = build_plans(
        ranges=ranges, agents=agents, models=models,
        agent_cmd=args.agent_cmd, solver=args.solver,
        model_label_override=args.model_label,
        timeout=args.timeout, batch_dir=batch_dir,
        variants=args.variants, variant_seed_base=args.variant_seed_base,
        negatives=args.negatives, supports_variant_seed=supports_variant_seed,
        mode=args.mode,
    )

    header = {
        "timestamp": timestamp,
        "out_dir": _rel(batch_dir),
        "ranges": [_rel(r) for r in ranges],
        "agents": agents if not (args.agent_cmd or args.solver) else ["agent-cmd"],
        "models": models if not (args.agent_cmd or args.solver)
                  else [args.model_label or "solver"],
        "timeout": args.timeout,
        "variants": args.variants,
        "variant_seed_base": args.variant_seed_base,
        "negatives": args.negatives,
        "agent_cmd": args.agent_cmd,
        "solver": args.solver,
        "mode": args.mode,
        "supports_variant_seed": supports_variant_seed,
        "total_planned": len(plans),
    }

    if args.dry_run:
        print(f"[dry-run] {len(plans)} planned runs -> {batch_dir}")
        print(f"[dry-run] supports_variant_seed={supports_variant_seed}")
        for p in plans:
            print(f"  {p['kind']:6s} {p['range_name']:32s} "
                  f"{p['model']:34s} {p['variant']:8s} "
                  f"neg={int(p['negative'])} -> {p['out_dir']}")
        batch_dir.mkdir(parents=True, exist_ok=True)
        (batch_dir / "batch_manifest.json").write_text(
            json.dumps({**header, "runs": plans, "executed": False},
                       indent=2) + "\n", encoding="utf-8",
        )
        print(f"[dry-run] manifest written: {batch_dir / 'batch_manifest.json'}")
        return 0

    batch_dir.mkdir(parents=True, exist_ok=True)
    completed: list[dict] = []

    def _announce(rec: dict) -> None:
        flag = "OK" if rec.get("success") else ("ERR" if rec["exit_code"] not in (0, 1) else "NO")
        print(f"[{flag}] exit={rec['exit_code']} "
              f"{rec['kind']} {rec['range_name']} {rec['model']} "
              f"{rec['variant']} neg={int(rec['negative'])} "
              f"({rec['elapsed_sec']}s)", flush=True)

    if args.parallel <= 1:
        for p in plans:
            try:
                rec = run_one(p)
            except Exception as e:  # noqa: BLE001
                rec = {**{k: p[k] for k in (
                    "range", "range_name", "kind", "agent", "model",
                    "variant", "variant_seed", "negative", "out_dir")},
                    "exit_code": -3, "elapsed_sec": 0.0, "success": None,
                    "stderr_tail": f"runner-error: {type(e).__name__}: {e}",
                    "cmd": p["cmd"]}
            completed.append(rec)
            _announce(rec)
    else:
        with ThreadPoolExecutor(max_workers=args.parallel) as ex:
            futs = {ex.submit(run_one, p): p for p in plans}
            for fut in as_completed(futs):
                p = futs[fut]
                try:
                    rec = fut.result()
                except Exception as e:  # noqa: BLE001
                    rec = {**{k: p[k] for k in (
                        "range", "range_name", "kind", "agent", "model",
                        "variant", "variant_seed", "negative", "out_dir")},
                        "exit_code": -3, "elapsed_sec": 0.0, "success": None,
                        "stderr_tail": f"runner-error: {type(e).__name__}: {e}",
                        "cmd": p["cmd"]}
                completed.append(rec)
                _announce(rec)

    manifest = {
        **header,
        "executed": True,
        "total_completed": len(completed),
        "runs": completed,
    }
    (batch_dir / "batch_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
    )

    solved = sum(1 for r in completed if r.get("success"))
    print(f"\n[batch] done: {solved}/{len(completed)} solved -> {batch_dir}")
    print(f"[batch] manifest: {batch_dir / 'batch_manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
