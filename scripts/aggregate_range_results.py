#!/usr/bin/env python3
"""Aggregate a ProtocolBench range-batch output tree into summary metrics.

Walks the tree, loads every result.json (and the matching task.json), and
computes overall / per-kind / per-range / per-model / per-severity /
generalization / false-positive metrics.  Writes summary.json and,
optionally, summary.csv and summary.md.

Usage::

    python scripts/aggregate_range_results.py out/range_batch/<timestamp>/ [--csv] [--md]
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_VARIANT_RE = re.compile(r"^v\d+$")


# ── severity inference ──────────────────────────────────────────────────
def infer_severity(task: dict) -> str:
    sev = (task.get("severity") or "").strip().lower()
    if sev:
        return sev.capitalize()
    flaw = (task.get("real_flaw") or "").lower()
    if any(k in flaw for k in ("impersonation", "reentrancy", "drain",
                               "mitm", "interleaving")):
        return "Critical"
    if any(k in flaw for k in ("race", "replay")):
        return "High"
    if "auth-bypass" in flaw or "bypass" in flaw:
        return "Medium"
    return "Unknown"


# ── run classification from path ────────────────────────────────────────
def classify_path(result_path: Path) -> str:
    """Return 'neg' | 'variant' | 'pos' based on the path components.

    A path component exactly equal to 'neg' marks a negative run; a component
    matching v<digits> marks a variant; otherwise it's the original positive.
    """
    parts = [p.lower() for p in result_path.parts]
    if "neg" in parts:
        return "neg"
    for p in parts:
        if _VARIANT_RE.match(p):
            return "variant"
    return "pos"


# ── loading ─────────────────────────────────────────────────────────────
def load_task_for_range(range_path: str) -> dict | None:
    if not range_path:
        return None
    candidates = [
        REPO_ROOT / range_path / "task.json",
        Path(range_path) / "task.json",
    ]
    for c in candidates:
        if c.is_file():
            try:
                return json.loads(c.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                return None
    return None


def load_runs(root: Path) -> list[dict]:
    runs: list[dict] = []
    for rj in sorted(root.rglob("result.json")):
        try:
            data = json.loads(rj.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        range_path = data.get("range") or ""
        task = load_task_for_range(range_path) or {}
        kind = (task.get("kind")
                or (data.get("task_id", "").split(":", 1)[0] if ":" in data.get("task_id", "") else "")
                or "unknown")
        cls = classify_path(rj)
        runs.append({
            "result_path": str(rj),
            "range": range_path,
            "range_name": Path(range_path).name if range_path else "",
            "kind": kind,
            "task_id": data.get("task_id"),
            "agent": data.get("agent"),
            "model": data.get("model") or "n/a",
            "success": bool(data.get("success", False)),
            "elapsed_sec": float(data.get("elapsed_sec", 0.0) or 0.0),
            "flag_captured": data.get("flag_captured"),
            "checks": data.get("checks", {}),
            "negative": cls == "neg",
            "variant": cls == "variant",
            "class": cls,
            "severity": infer_severity(task),
            "task": task,
        })
    return runs


# ── metric helpers ─────────────────────────────────────────────────────
def _rate(solved: int, total: int) -> float:
    return round(solved / total, 4) if total else 0.0


def _group(runs: list[dict], key) -> dict:
    buckets: dict[str, list[dict]] = {}
    for r in runs:
        k = key(r)
        buckets.setdefault(str(k), []).append(r)
    return buckets


def _stats(runs: list[dict]) -> dict:
    total = len(runs)
    solved = sum(1 for r in runs if r["success"])
    elap = [r["elapsed_sec"] for r in runs if r["elapsed_sec"] >= 0]
    mean = round(statistics.mean(elap), 3) if elap else 0.0
    median = round(statistics.median(elap), 3) if elap else 0.0
    return {
        "total": total,
        "solved": solved,
        "solve_rate": _rate(solved, total),
        "mean_elapsed": mean,
        "median_elapsed": median,
    }


# ── summary computation ────────────────────────────────────────────────
def compute_summary(runs: list[dict]) -> dict:
    positive = [r for r in runs if not r["negative"]]
    neg_runs = [r for r in runs if r["negative"]]

    summary: dict = {}

    overall = _stats(positive)
    summary["overall"] = {
        "total_runs": overall["total"],
        "solved": overall["solved"],
        "solve_rate": overall["solve_rate"],
        "mean_elapsed": overall["mean_elapsed"],
        "median_elapsed": overall["median_elapsed"],
    }

    # by_kind (positives only)
    by_kind: dict = {}
    for k, rs in _group(positive, lambda r: r["kind"]).items():
        s = _stats(rs)
        by_kind[k] = {
            "total": s["total"], "solved": s["solved"],
            "solve_rate": s["solve_rate"], "mean_elapsed": s["mean_elapsed"],
        }
    summary["by_kind"] = by_kind

    # by_range (positives only)
    by_range: dict = {}
    for k, rs in _group(positive, lambda r: r["range_name"]).items():
        s = _stats(rs)
        by_range[k] = {
            "total": s["total"], "solved": s["solved"],
            "solve_rate": s["solve_rate"], "mean_elapsed": s["mean_elapsed"],
        }
    summary["by_range"] = by_range

    # by_model (positives only)
    by_model: dict = {}
    for k, rs in _group(positive, lambda r: r["model"]).items():
        s = _stats(rs)
        by_model[k] = {
            "total": s["total"], "solved": s["solved"],
            "solve_rate": s["solve_rate"], "mean_elapsed": s["mean_elapsed"],
        }
    summary["by_model"] = by_model

    # by_severity (positives only)
    by_severity: dict = {}
    for k, rs in _group(positive, lambda r: r["severity"]).items():
        s = _stats(rs)
        by_severity[k] = {
            "total": s["total"], "solved": s["solved"],
            "solve_rate": s["solve_rate"],
        }
    summary["by_severity"] = by_severity

    # generalization: per (range, model) for ranges that have variants and
    # where the original (pos) was solved.
    generalization: dict = {}
    # collect variant runs keyed by (range_name, model)
    variant_runs = [r for r in runs if r["variant"]]
    pos_runs = [r for r in runs if r["class"] == "pos"]
    vm = _group(variant_runs, lambda r: f"{r['range_name']}/{r['model']}")
    pm = _group(pos_runs, lambda r: f"{r['range_name']}/{r['model']}")
    for key, vrs in vm.items():
        pos_list = pm.get(key, [])
        original_solved = any(r["success"] for r in pos_list)
        v_total = len(vrs)
        v_solved = sum(1 for r in vrs if r["success"])
        entry = {
            "range_name": vrs[0]["range_name"],
            "model": vrs[0]["model"],
            "original_solved": original_solved,
            "variants_total": v_total,
            "variants_solved": v_solved,
            "generalization_rate": (round(v_solved / v_total, 4)
                                    if (original_solved and v_total) else None),
        }
        # only count ranges where the original was solved, per spec
        if original_solved:
            generalization[key] = entry
        elif v_total:
            # still record but with null rate (excluded from the "counted" set)
            generalization[key] = entry
    summary["generalization"] = generalization

    # false_positives: negative runs that reported success=true
    fps = [r for r in neg_runs if r["success"]]
    summary["false_positives"] = {
        "total_negatives": len(neg_runs),
        "false_positives": len(fps),
        "rate": _rate(len(fps), len(neg_runs)) if neg_runs else 0.0,
        "instances": [
            {"range_name": r["range_name"], "model": r["model"],
             "result_path": r["result_path"]}
            for r in fps
        ],
    }

    # mean / median overall (include all runs incl. negatives? spec: "overall"
    # mean_elapsed/median — compute over positives to match overall.solve_rate)
    summary["mean_elapsed"] = overall["mean_elapsed"]
    summary["median_elapsed"] = overall["median_elapsed"]

    return summary


# ── writers ─────────────────────────────────────────────────────────────
def write_csv(summary: dict, path: Path) -> None:
    rows = []
    # one row per range x model (positives)
    by_range = summary["by_range"]
    by_model = summary["by_model"]
    # reconstruct per (range, model) from raw? summary doesn't carry it; build
    # from by_range/by_model intersection is not possible without raw data.
    # Instead emit by_range and by_model as separate sections in CSV.
    for rname, s in sorted(by_range.items()):
        rows.append({"section": "by_range", "key": rname, **s})
    for mname, s in sorted(by_model.items()):
        rows.append({"section": "by_model", "key": mname, **s})
    fields = ["section", "key", "total", "solved", "solve_rate", "mean_elapsed"]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def write_csv_matrix(runs: list[dict], path: Path) -> None:
    """One row per range x model with solve_rate (positives)."""
    positive = [r for r in runs if not r["negative"]]
    buckets: dict[tuple[str, str], list[dict]] = {}
    for r in positive:
        buckets.setdefault((r["range_name"], r["model"]), []).append(r)
    rows = []
    for (rname, model), rs in sorted(buckets.items()):
        total = len(rs)
        solved = sum(1 for r in rs if r["success"])
        mean = round(statistics.mean([r["elapsed_sec"] for r in rs]), 3) if rs else 0.0
        rows.append({
            "range": rname, "model": model, "total": total,
            "solved": solved, "solve_rate": _rate(solved, total),
            "mean_elapsed": mean,
        })
    fields = ["range", "model", "total", "solved", "solve_rate", "mean_elapsed"]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow(row)


def write_md(summary: dict, runs: list[dict], path: Path) -> None:
    lines: list[str] = []
    o = summary["overall"]
    lines.append("# ProtocolBench Range Batch Summary\n")
    lines.append(f"- total runs: {o['total_runs']}")
    lines.append(f"- solved: {o['solved']}")
    lines.append(f"- solve_rate: {o['solve_rate']}")
    lines.append(f"- mean_elapsed: {o['mean_elapsed']}s")
    lines.append(f"- median_elapsed: {o['median_elapsed']}s")
    fp = summary["false_positives"]
    lines.append(f"- false_positives: {fp['false_positives']}/{fp['total_negatives']}")
    lines.append("")

    lines.append("## By range x model\n")
    lines.append("| range | model | total | solved | solve_rate | mean_elapsed |")
    lines.append("|---|---|---:|---:|---:|---:|")
    positive = [r for r in runs if not r["negative"]]
    buckets: dict[tuple[str, str], list[dict]] = {}
    for r in positive:
        buckets.setdefault((r["range_name"], r["model"]), []).append(r)
    for (rname, model), rs in sorted(buckets.items()):
        total = len(rs)
        solved = sum(1 for r in rs if r["success"])
        mean = round(statistics.mean([r["elapsed_sec"] for r in rs]), 3) if rs else 0.0
        lines.append(f"| {rname} | {model} | {total} | {solved} | "
                     f"{_rate(solved, total)} | {mean} |")
    lines.append("")

    lines.append("## By kind\n")
    lines.append("| kind | total | solved | solve_rate |")
    lines.append("|---|---:|---:|---:|")
    for k, s in sorted(summary["by_kind"].items()):
        lines.append(f"| {k} | {s['total']} | {s['solved']} | {s['solve_rate']} |")
    lines.append("")

    lines.append("## By severity\n")
    lines.append("| severity | total | solved | solve_rate |")
    lines.append("|---|---:|---:|---:|")
    for k, s in sorted(summary["by_severity"].items()):
        lines.append(f"| {k} | {s['total']} | {s['solved']} | {s['solve_rate']} |")
    lines.append("")

    if summary["generalization"]:
        lines.append("## Generalization (variants)\n")
        lines.append("| range/model | original_solved | variants_total | "
                     "variants_solved | generalization_rate |")
        lines.append("|---|---|---:|---:|---:|")
        for k, e in sorted(summary["generalization"].items()):
            gr = e["generalization_rate"]
            gr = "-" if gr is None else gr
            lines.append(f"| {k} | {e['original_solved']} | "
                         f"{e['variants_total']} | {e['variants_solved']} | {gr} |")
        lines.append("")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_summary(summary: dict) -> None:
    o = summary["overall"]
    print("== overall ==")
    print(f"   total_runs={o['total_runs']} solved={o['solved']} "
          f"solve_rate={o['solve_rate']}")
    print(f"   mean_elapsed={o['mean_elapsed']}s "
          f"median_elapsed={o['median_elapsed']}s")
    print("== by_kind ==")
    for k, s in sorted(summary["by_kind"].items()):
        print(f"   {k:8s} total={s['total']} solved={s['solved']} "
              f"solve_rate={s['solve_rate']}")
    print("== by_range ==")
    for k, s in sorted(summary["by_range"].items()):
        print(f"   {k:36s} total={s['total']} solved={s['solved']} "
              f"solve_rate={s['solve_rate']} mean={s['mean_elapsed']}s")
    print("== by_model ==")
    for k, s in sorted(summary["by_model"].items()):
        print(f"   {k:40s} total={s['total']} solved={s['solved']} "
              f"solve_rate={s['solve_rate']} mean={s['mean_elapsed']}s")
    print("== by_severity ==")
    for k, s in sorted(summary["by_severity"].items()):
        print(f"   {k:10s} total={s['total']} solved={s['solved']} "
              f"solve_rate={s['solve_rate']}")
    print("== generalization ==")
    if summary["generalization"]:
        for k, e in sorted(summary["generalization"].items()):
            gr = e["generalization_rate"]
            gr = "n/a" if gr is None else gr
            print(f"   {k:50s} orig={e['original_solved']} "
                  f"variants={e['variants_solved']}/{e['variants_total']} "
                  f"gen_rate={gr}")
    else:
        print("   (no variant runs)")
    fp = summary["false_positives"]
    print("== false_positives ==")
    print(f"   negatives={fp['total_negatives']} "
          f"false_positives={fp['false_positives']} rate={fp['rate']}")


# ── main ────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Aggregate a ProtocolBench range-batch output tree.",
    )
    ap.add_argument("batch_dir", type=Path,
                    help="batch output tree (e.g. out/range_batch/<timestamp>/)")
    ap.add_argument("--csv", action="store_true",
                    help="also write summary.csv (one row per range x model)")
    ap.add_argument("--md", action="store_true",
                    help="also write summary.md (markdown table)")
    args = ap.parse_args()

    root = args.batch_dir
    if not root.is_absolute():
        root = REPO_ROOT / root
    if not root.is_dir():
        print(f"error: batch dir not found: {root}", file=sys.stderr)
        return 2

    runs = load_runs(root)
    if not runs:
        print(f"error: no result.json found under {root}", file=sys.stderr)
        return 2

    summary = compute_summary(runs)
    print_summary(summary)

    (root / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8",
    )
    print(f"\n[aggregate] summary.json written -> {root / 'summary.json'}")

    if args.csv:
        write_csv_matrix(runs, root / "summary.csv")
        print(f"[aggregate] summary.csv written -> {root / 'summary.csv'}")
    if args.md:
        write_md(summary, runs, root / "summary.md")
        print(f"[aggregate] summary.md written -> {root / 'summary.md'}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
