#!/usr/bin/env python3
"""Turn collected Claude Code session JSONL into a readable trajectory.

The raw stream log is ~99.8% `system/thinking_tokens` counters and is useless
for analysis; the session JSONL under ``trajectory/projects/-workspace/*.jsonl``
is the clean record (assistant text, tool calls, tool results).  This script
renders it to Markdown (text + tool calls, results truncated) for inspection or
downstream scoring.

Usage:
    python3 scripts/extract_trajectory.py <run_dir | task_dir> [--out FILE] [--max-result 400]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

TRUNC = "\n…[truncated]"


def _text_of(content) -> str:
    if isinstance(content, str):
        return content
    parts = []
    for c in content or []:
        if not isinstance(c, dict):
            continue
        t = c.get("type")
        if t == "text":
            parts.append(c.get("text", ""))
        elif t == "thinking":
            continue  # reasoning omitted by default
        elif t == "tool_use":
            inp = c.get("input", {})
            try:
                inp_s = json.dumps(inp, ensure_ascii=False)
            except TypeError:
                inp_s = str(inp)
            parts.append(f"[tool_call {c.get('name')}] {inp_s}")
        elif t == "tool_result":
            parts.append(f"[tool_result] {_text_of(c.get('content'))}")
    return "\n".join(p for p in parts if p)


def render_session(path: pathlib.Path, max_result: int) -> str:
    out = [f"## session `{path.stem}`", ""]
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        typ = rec.get("type")
        if typ not in ("assistant", "user"):
            continue
        body = _text_of(rec.get("message", {}).get("content"))
        if not body:
            continue
        if max_result and len(body) > max_result:
            body = body[:max_result] + TRUNC
        who = "assistant" if typ == "assistant" else "user"
        out.append(f"### {who}")
        out.append(body)
        out.append("")
    return "\n".join(out)


def find_task_dirs(root: pathlib.Path) -> list[pathlib.Path]:
    if (root / "trajectory" / "projects").is_dir():
        return [root]
    return sorted(p for p in root.glob("L2_onchain_*") if (p / "trajectory" / "projects").is_dir())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=pathlib.Path)
    ap.add_argument("--out", type=pathlib.Path, default=None)
    ap.add_argument("--max-result", type=int, default=600)
    args = ap.parse_args()

    tasks = find_task_dirs(args.root)
    if not tasks:
        print(f"no trajectory/projects found under {args.root}", file=sys.stderr)
        return 1

    combined = []
    for t in tasks:
        proj = t / "trajectory" / "projects"
        sessions = sorted(proj.rglob("*.jsonl"))
        if not sessions:
            continue
        combined.append(f"\n# {t.name}\n")
        for s in sessions:
            combined.append(render_session(s, args.max_result))

    text = "\n".join(combined)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out} ({len(text)} chars, {len(tasks)} tasks)")
    else:
        base = tasks[0] / "trajectory" / "trajectory.md"
        base.write_text(text, encoding="utf-8")
        print(f"wrote {base} ({len(text)} chars, {len(tasks)} tasks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
