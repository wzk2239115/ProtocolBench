#!/usr/bin/env python3
"""Generate on-chain L2_form tasks from data/onchain/protocols.json.

For each catalog entry this writes

    data/tasks/L2_form/onchain_<slug>/
        spec.md                    # protocol identity + goals + threat model
        task.json                  # TaskMeta
        solution/ground_truth.json # verdict + per-goal truth (hidden)
        solution/reference.md      # real flaw / fix (hidden)

No Lean/Tamarin model is ever written into the agent workspace: the agent
chooses its own modeling strategy (see docs/tasks.md). Existing task dirs are
left untouched unless --force is passed, so hand-authored tasks are safe.

The task list data/task_ids/onchain.txt is rebuilt by scanning all
onchain_* task directories.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from tamaringym.task.metadata import GroundTruth, LemmaTruth, TaskMeta  # noqa: E402

CATALOG = REPO / "data" / "onchain" / "protocols.json"
TASKS_DIR = REPO / "data" / "tasks" / "L2_form"
TASK_LIST = REPO / "data" / "task_ids" / "onchain.txt"
SPEC_TEMPLATE = """# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: {goals_hint}.

---

## Protocol: {name}

**Category:** {category}

### Overview

{overview}

### Roles

{roles}

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
{goal_rows}

### Threat model

{threat_model}

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

{references}
"""


def goal_rows(goals: list[dict]) -> str:
    return "\n".join(
        f"| {i+1} | `{g['name']}` | {g['property']} |"
        for i, g in enumerate(goals)
    )


def roles_md(roles: list[str] | None) -> str:
    if not roles:
        return "See the overview."
    return "\n".join(f"- **{r}**" for r in roles)


def references_md(refs: list[str]) -> str:
    return "\n".join(f"- {r}" for r in refs)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="overwrite existing task dirs")
    ap.add_argument("--catalog", type=Path, action="append", default=None,
                    help="catalog JSON (repeatable); default: data/onchain/protocols*.json")
    args = ap.parse_args()

    catalogs = args.catalog or sorted((REPO / "data" / "onchain").glob("protocols*.json"))
    protocols = []
    for c in catalogs:
        protocols.extend(json.loads(Path(c).read_text(encoding="utf-8"))["protocols"])
    written, skipped = [], []
    for p in protocols:
        slug = "onchain_" + p["slug"]
        d = TASKS_DIR / slug
        if d.exists() and not args.force:
            skipped.append(slug)
            continue
        (d / "solution").mkdir(parents=True, exist_ok=True)

        goals = p["goals"]
        spec = SPEC_TEMPLATE.format(
            name=p["name"],
            category=p.get("category", "onchain"),
            overview=p["overview"].strip(),
            roles=roles_md(p.get("roles")),
            goal_rows=goal_rows(goals),
            goals_hint=", ".join(g["name"] for g in goals),
            threat_model=p["threat_model"].strip(),
            references=references_md(p.get("references", [])),
        )
        (d / "spec.md").write_text(spec, encoding="utf-8")

        meta = TaskMeta(
            task_id=f"L2:{slug}",
            level="L2_form",
            name=slug,
            protocol=p["name"],
            source_file=p.get("source", p["name"]),
            source_dataset="onchain",
            given_files=["spec.md"],
            lemma_names=[g["name"] for g in goals],
            uses_diff_terms=False,
            family="tamarin",
            description=p.get("description", p["overview"].strip()[:160]),
        )
        (d / "task.json").write_text(meta.model_dump_json(indent=2), encoding="utf-8")

        verdict = p["verdict"]
        per_goal = p.get("goal_verdicts") or {}
        gt = GroundTruth(
            protocol=p["name"],
            overall_verdict=verdict,
            lemmas=[
                LemmaTruth(
                    name=g["name"],
                    quantifier=g.get("quantifier", "all-traces"),
                    verdict=per_goal.get(
                        g["name"], "falsified" if verdict == "UNSAFE" else "verified"
                    ),
                )
                for g in goals
            ],
            validated=False,
        )
        (d / "solution" / "ground_truth.json").write_text(
            gt.model_dump_json(indent=2), encoding="utf-8"
        )

        flaw = p.get("flaw") or "No documented design flaw; the protocol is expected to meet its goals."
        refs = references_md(p.get("references", []))
        (d / "solution" / "reference.md").write_text(
            f"# Reference: {p['name']}\n\n**Verdict: {verdict}.**\n\n{flaw.strip()}\n\n"
            f"## References\n\n{refs}\n",
            encoding="utf-8",
        )
        written.append(slug)

    all_tasks = sorted(
        d.name for d in TASKS_DIR.iterdir()
        if d.is_dir() and d.name.startswith("onchain_") and (d / "task.json").is_file()
    )
    TASK_LIST.write_text("\n".join(f"L2:{n}" for n in all_tasks) + "\n", encoding="utf-8")

    print(json.dumps({
        "written": len(written),
        "skipped_existing": len(skipped),
        "total_onchain_tasks": len(all_tasks),
        "task_list": str(TASK_LIST.relative_to(REPO)),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
