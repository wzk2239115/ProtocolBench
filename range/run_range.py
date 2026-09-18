#!/usr/bin/env python3
"""Unified agent runner for the ProtocolBench live exploit ranges.

For a given range, runs an agent against the live target and produces an
objective result.  The range controller starts the target, the agent tries to
exploit the protocol flaw and write ``/workspace/flag.txt``, and the controller
independently verifies the objective condition + flag.  This script normalizes
the controller's verdict into a unified ``result.json`` and collects the agent
trajectory + captured flag.

Examples
--------

Reference solver (plumbing, no LLM)::

    python range/run_range.py --range range/nontx/nspk \\
        --agent-cmd "python range/nontx/nspk/solution/exploit.py" \\
        --timeout 120 --out-dir out/range/nspk-pos

    python range/run_range.py --range range/tx/erc20_allowance_race \\
        --agent-cmd "bash range/tx/erc20_allowance_race/solution/exploit.sh" \\
        --timeout 120 --out-dir out/range/erc20-pos

Real LLM agent (containerized claude_code)::

    python range/run_range.py --range range/nontx/nspk \\
        --agent claude_code --model deepseek/deepseek-v4.1-flash \\
        --timeout 600 --out-dir out/range/nspk
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import io
import json
import shutil
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RANGE_ROOT = REPO_ROOT / "range"

sys.path.insert(0, str(RANGE_ROOT))
from common.agent import build_claude_code_command  # noqa: E402
from common.env import load_glm_env  # noqa: E402
from common.result import normalize_result  # noqa: E402


# ── range discovery ──────────────────────────────────────────────────────
def _load_task(range_dir: Path) -> dict:
    task_json = range_dir / "task.json"
    if not task_json.is_file():
        raise FileNotFoundError(f"no task.json in {range_dir}")
    return json.loads(task_json.read_text(encoding="utf-8"))


def _range_kind(range_dir: Path) -> str:
    """Return ``"nontx"`` or ``"tx"`` from the path structure."""
    rel = range_dir.relative_to(RANGE_ROOT)
    if len(rel.parts) >= 1 and rel.parts[0] in ("nontx", "tx"):
        return rel.parts[0]
    raise ValueError(f"cannot determine range kind from {range_dir}")


def _import_controller(range_dir: Path):
    """Import the range's ``controller`` module (adds task dir to sys.path)."""
    range_dir_str = str(range_dir)
    if range_dir_str not in sys.path:
        sys.path.insert(0, range_dir_str)
    return importlib.import_module("controller")


# ── per-range runners ────────────────────────────────────────────────────
def _run_nspk(
    controller,
    range_dir: Path,
    agent_cmd: str,
    timeout: float,
    out_dir: Path,
    fixed: bool,
    mode: str,
) -> dict:
    """Invoke the NSPK controller's ``main(argv)`` and read its result.json."""
    argv = [
        "--agent-cmd", agent_cmd,
        "--out-dir", str(out_dir),
        "--timeout", str(timeout),
        "--mode", mode,
    ]
    if fixed:
        argv.append("--fixed")
    # Suppress the controller's own stdout (it prints the raw result).
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        controller.main(argv)
    result_path = out_dir / "result.json"
    if result_path.is_file():
        return json.loads(result_path.read_text(encoding="utf-8"))
    return {"ok": False, "errors": ["controller did not write result.json"]}


def _run_tx(
    controller,
    range_dir: Path,
    agent_cmd: str,
    timeout: float,
    out_dir: Path,
    safe: bool,
    window: float,
) -> dict:
    """Invoke the TX controller's ``run_scenario()`` directly."""
    result = controller.run_scenario(
        safe=safe,
        agent_cmd=agent_cmd,
        window=window,
        agent_timeout=timeout,
        verbose=False,
    )
    # run_scenario() cleans up workspace/flag.txt in stop(); save the raw result.
    (out_dir / "controller_result.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    return result


# ── artifact collection ──────────────────────────────────────────────────
def _snapshot_workspace(workspace: Path) -> set[str]:
    """Return the set of top-level entry names in the workspace."""
    return {p.name for p in workspace.iterdir()} if workspace.is_dir() else set()


def _restore_workspace(workspace: Path, original: set[str]) -> None:
    """Remove files the agent created during the run (flag.txt, scripts, etc.).

    This keeps the workspace clean so no-plaintext / no-bypass tests stay green
    and the next run starts from a pristine state.
    """
    if not workspace.is_dir():
        return
    for item in workspace.iterdir():
        if item.name in original:
            continue
        try:
            if item.is_dir() and not item.is_symlink():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink(missing_ok=True)
        except OSError:
            pass
    # Always remove the flag (the controller may leave it behind on success).
    for name in ("flag.txt", "target.json"):
        (workspace / name).unlink(missing_ok=True)
def _collect_flag(
    range_dir: Path,
    out_dir: Path,
    controller_result: dict,
    range_kind: str,
) -> None:
    """Copy/reconstruct the captured flag into the out-dir."""
    flag_dest = out_dir / "flag.txt"
    if flag_dest.exists():
        flag_dest.unlink()

    # NSPK: workspace/flag.txt survives the run (controller doesn't delete it).
    ws_flag = range_dir / "workspace" / "flag.txt"
    if ws_flag.is_file():
        shutil.copy2(ws_flag, flag_dest)
        return

    # TX: controller deletes workspace/flag.txt in stop(); reconstruct from result.
    captured = controller_result.get("flag_captured")
    if captured:
        flag_dest.write_text(captured + "\n", encoding="utf-8")


def _collect_trajectory(out_dir: Path, logs_dir: Path) -> None:
    """Copy the agent trajectory + session JSONL into the out-dir."""
    traj_src = logs_dir / "trajectory.jsonl"
    if traj_src.is_file():
        traj_dest = out_dir / "trajectory.jsonl"
        if traj_dest != traj_src:
            shutil.copy2(traj_src, traj_dest)
    # Claude Code session JSONL files (CLAUDE_CONFIG_DIR = /logs).
    # They live under logs_dir/projects/<workspace>/<session>.jsonl.
    for session_file in logs_dir.rglob("*.jsonl"):
        if session_file.name == "trajectory.jsonl":
            continue
        dest = out_dir / "session" / session_file.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(session_file, dest)
        except (PermissionError, OSError):
            pass


# ── main ─────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Unified agent runner for ProtocolBench live exploit ranges.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--range", required=True, type=Path,
                    help="range directory, e.g. range/nontx/nspk")
    ap.add_argument("--agent", default=None,
                    choices=["claude_code"],
                    help="LLM agent to run inside a container")
    ap.add_argument("--model", default=None,
                    help="model id, e.g. deepseek/deepseek-v4.1-flash")
    ap.add_argument("--timeout", type=float, default=600.0,
                    help="agent wall-clock seconds")
    ap.add_argument("--out-dir", required=True, type=Path,
                    help="output directory for result.json + artifacts")
    ap.add_argument("--agent-cmd", default=None,
                    help="shell command to run as the agent (reference solver / "
                         "plumbing); overrides --agent")
    # Range-specific passthroughs.
    ap.add_argument("--fixed", action="store_true",
                    help="nontx: run Lowe's fixed protocol (negative test)")
    ap.add_argument("--safe", action="store_true",
                    help="tx: Alice uses the approve(0) safe pattern (negative test)")
    ap.add_argument("--solver", action="store_true",
                    help="tx: run the reference exploit as the agent")
    ap.add_argument("--mode", default="auto",
                    choices=["auto", "docker", "local"],
                    help="nontx: target backend")
    ap.add_argument("--window", type=float, default=8.0,
                    help="tx: seconds between the two approve txs")
    ap.add_argument("--agent-image", default=None,
                    help="override the agent docker image")
    args = ap.parse_args()

    # Resolve the range directory.
    range_dir = args.range
    if not range_dir.is_absolute():
        range_dir = (REPO_ROOT / args.range).resolve()
    if not range_dir.is_dir():
        print(f"error: range directory not found: {range_dir}", file=sys.stderr)
        return 2

    range_kind = _range_kind(range_dir)
    task = _load_task(range_dir)
    task_id = task["id"]

    out_dir = args.out_dir
    if not out_dir.is_absolute():
        out_dir = (REPO_ROOT / out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    workspace = range_dir / "workspace"
    logs_dir = out_dir / "agent_logs"

    # ── determine the agent command ────────────────────────────────────
    agent_label = "agent-cmd"
    model_label: str | None = None

    if args.agent_cmd:
        agent_cmd = args.agent_cmd
        agent_label = "agent-cmd"
    elif args.solver and range_kind == "tx":
        agent_cmd = f"bash {range_dir / 'solution' / 'exploit.sh'}"
        agent_label = "solver"
    elif args.agent == "claude_code":
        if not args.model:
            print("error: --agent claude_code requires --model", file=sys.stderr)
            return 2
        glm = load_glm_env()
        api_key = glm.get("GLM_API_KEY") or glm.get("API_KEY")
        api_base = glm.get("GLM_API_BASE")
        if not api_key or not api_base:
            print("error: GLM_API_KEY / GLM_API_BASE not found in .glm_env or env",
                  file=sys.stderr)
            return 2
        agent_image = args.agent_image or None
        cmd_kwargs = dict(
            range_kind=range_kind,
            workspace=workspace,
            logs_dir=logs_dir,
            api_key=api_key,
            api_base=api_base,
            model=args.model,
            timeout=int(args.timeout),
        )
        if agent_image:
            cmd_kwargs["agent_image"] = agent_image
        agent_cmd = build_claude_code_command(**cmd_kwargs)
        agent_label = "claude_code"
        model_label = args.model
    else:
        print("error: provide --agent-cmd, --solver, or --agent claude_code",
              file=sys.stderr)
        return 2

    # ── run the range ──────────────────────────────────────────────────
    controller = _import_controller(range_dir)

    print(f"[run_range] range={range_dir.relative_to(REPO_ROOT)} "
          f"task_id={task_id} agent={agent_label} "
          f"model={model_label or 'n/a'} timeout={args.timeout}s", flush=True)

    ws_snapshot = _snapshot_workspace(workspace)
    t0 = time.monotonic()
    try:
        if range_kind == "nontx":
            controller_result = _run_nspk(
                controller, range_dir, agent_cmd, args.timeout,
                out_dir, args.fixed, args.mode,
            )
        else:
            controller_result = _run_tx(
                controller, range_dir, agent_cmd, args.timeout,
                out_dir, args.safe, args.window,
            )
    except Exception as exc:  # noqa: BLE001
        elapsed = time.monotonic() - t0
        controller_result = {
            "ok": False,
            "success": False,
            "errors": [f"{type(exc).__name__}: {exc}"],
        }
        print(f"[run_range] controller error: {exc}", file=sys.stderr)
        _restore_workspace(workspace, ws_snapshot)
        normalized = normalize_result(
            range_path=str(range_dir.relative_to(REPO_ROOT)),
            task_id=task_id,
            agent=agent_label,
            model=model_label,
            controller_result=controller_result,
            elapsed_sec=elapsed,
        )
        (out_dir / "result.json").write_text(
            json.dumps(normalized, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(normalized, indent=2))
        return 1
    elapsed = time.monotonic() - t0

    # ── normalize + collect artifacts ──────────────────────────────────
    _collect_flag(range_dir, out_dir, controller_result, range_kind)
    if logs_dir.is_dir():
        _collect_trajectory(out_dir, logs_dir)
    # Restore the workspace to its pre-run state (remove agent-created files).
    _restore_workspace(workspace, ws_snapshot)

    normalized = normalize_result(
        range_path=str(range_dir.relative_to(REPO_ROOT)),
        task_id=task_id,
        agent=agent_label,
        model=model_label,
        controller_result=controller_result,
        elapsed_sec=elapsed,
    )
    (out_dir / "result.json").write_text(
        json.dumps(normalized, indent=2) + "\n", encoding="utf-8"
    )

    print(json.dumps(normalized, indent=2))
    return 0 if normalized["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
