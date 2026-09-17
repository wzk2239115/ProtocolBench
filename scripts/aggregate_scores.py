#!/usr/bin/env python3
"""Aggregate agent-scorer results into a leaderboard/CSV.

Reads every ``scorer_result.json`` under ``--in`` (flat layout written by
``scripts/run_scorer.py``) and reports the authoritative attack score
(LLM-judged, not the deterministic regex gate):

    attack_rate   : fraction of scored tasks with attack_valid == true
    mean_score    : mean of scorer score in [0,1]
    reward_hacking: tasks flagged as reward hacking
    goal coverage : sum(goals_falsified)/sum(goals_total)

Usage:
    python3 scripts/aggregate_scores.py --in out/scores [--csv out/scores.csv]
"""
from __future__ import annotations

import argparse
import csv
import json
import pathlib
import statistics


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="root", type=pathlib.Path, required=True)
    ap.add_argument("--csv", type=pathlib.Path, default=None)
    args = ap.parse_args()

    rows = []
    for f in sorted(args.root.rglob("scorer_result.json")):
        try:
            d = json.loads(f.read_text())
        except Exception:
            continue
        goals = d.get("goals", [])
        rows.append({
            "task": d.get("task_id") or f.parent.name,
            "score": d.get("score"),
            "attack_valid": d.get("attack_valid"),
            "model_faithful": d.get("model_faithful"),
            "reward_hacking": d.get("reward_hacking"),
            "goals_total": d.get("goals_total", len(goals)),
            "goals_falsified": d.get("goals_falsified", sum(1 for g in goals if g.get("falsified"))),
            "goals_faithful_falsified": d.get("goals_faithful_falsified"),
        })

    if not rows:
        print(json.dumps({"scored": 0}))
        return 0

    scores = [r["score"] for r in rows if isinstance(r["score"], (int, float))]
    gt = sum(r["goals_total"] or 0 for r in rows)
    gf = sum(r["goals_falsified"] or 0 for r in rows)
    summary = {
        "scored": len(rows),
        "attack_valid": sum(1 for r in rows if r["attack_valid"]),
        "attack_rate": round(sum(1 for r in rows if r["attack_valid"]) / len(rows), 4),
        "mean_score": round(statistics.mean(scores), 4) if scores else None,
        "median_score": round(statistics.median(scores), 4) if scores else None,
        "model_faithful": sum(1 for r in rows if r["model_faithful"]),
        "reward_hacking": sum(1 for r in rows if r["reward_hacking"]),
        "goal_coverage": round(gf / gt, 4) if gt else None,
    }
    print(json.dumps(summary, indent=2))

    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        with args.csv.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(sorted(rows, key=lambda r: (r["score"] is None, -(r["score"] or 0))))
        print(f"wrote {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
