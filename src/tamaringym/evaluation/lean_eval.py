"""Lean-based evaluator for L1/L2/L3 protocol analysis tasks.

Replaces TamarinScorer with a simple binary scoring:
  1. verdict_correct (0.5): agent's SAFE/UNSAFE matches ground truth → 0 or 1
  2. evidence_compiles (0.5): Lean model compiles (exit 0) → 0 or 1

The agent receives the protocol's theory.spthy (as reference) and models
it in Lean 4.  The verdict is compared against ground_truth.json.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import docker
from tamaringym.evaluation.agents.base import Agent
from tamaringym.evaluation.types import (
    AgentFnArguments,
    CheckResult,
    EvalConfig,
    EvalResult,
)
from tamaringym.task.metadata import (
    GroundTruth,
    TaskMeta,
    load_task_registry,
    task_dir_for,
)
from tamaringym.task.workspace import prepare_workspace
from tamaringym.utils import (
    docker_cp_dir_from_container_filtered,
    docker_cp_from_container,
    docker_cp_to_container,
    get_docker_client,
    save_json,
)

logger = logging.getLogger(__name__)

_REGISTRY: dict[str, dict[str, TaskMeta]] | None = None


def get_task_meta(task_id: str) -> TaskMeta:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = load_task_registry()
    level, _, name = task_id.partition(":")
    try:
        return _REGISTRY[level][name] if ":" in task_id else _REGISTRY[task_id][name]
    except KeyError:
        level_map = {"L1": "L1_verdict", "L2": "L2_form", "L3": "L3_repair"}
        return _REGISTRY[level_map.get(level, level)][name]


def load_ground_truth(meta: TaskMeta) -> GroundTruth:
    tdir = task_dir_for(meta.task_id)
    return GroundTruth.model_validate_json(
        (tdir / "solution" / "ground_truth.json").read_text()
    )


class LeanEvaluator:
    """Lean-based protocol analysis evaluator."""

    def __init__(self, config: EvalConfig) -> None:
        self.config = config
        self.meta = get_task_meta(config.task_id)
        self.ground_truth = load_ground_truth(self.meta)
        self.container = None

    def evaluate(self, agent: Agent) -> EvalResult:
        cfg = self.config
        cfg.out_dir.mkdir(parents=True, exist_ok=True)
        save_json(cfg, cfg.out_dir / "config.json", indent=2)

        workspace_dir = cfg.out_dir / "workspace"
        workspace_dir.mkdir(exist_ok=True)
        prompt = prepare_workspace(self.meta, workspace_dir)

        task_description = (
            cfg.task_description_template.format(task_description=prompt)
            if cfg.task_description_template
            else prompt
        )

        client = get_docker_client()
        tic = time.perf_counter()
        container = None
        try:
            container = self._start_container(client)
            container.exec_run(["mkdir", "-p", "/workspace", "/logs"])
            docker_cp_to_container(container.id, f"{workspace_dir}/.", "/workspace")
            logger.info("workspace copied into container")

            if not (cfg.api_key or cfg.credential_path):
                raise ValueError(
                    "no auth configured: api_key or credential_path required"
                )

            logger.info("running agent (task=%s)", cfg.task_id)
            try:
                agent.run(
                    AgentFnArguments(
                        task_description=task_description,
                        container_id=container.id,
                        runtime_dir_in_container=cfg.runtime_dir_in_container,
                        agent_timeout_seconds=cfg.agent_timeout_seconds,
                        out_dir=cfg.out_dir,
                        api_base_url=cfg.api_base_url,
                        api_key=(
                            cfg.api_key.get_secret_value() if cfg.api_key else None
                        ),
                        extra_kwargs=cfg.agent_extra_kwargs,
                        credential_path=cfg.credential_path,
                        disable_web_search=cfg.disable_web_search,
                    )
                )
            except Exception:
                logger.exception("agent run failed")
        finally:
            toc = time.perf_counter()

        outputs_dir = cfg.out_dir / "outputs"
        try:
            outputs_dir = self._collect_outputs(container, cfg.out_dir)
        except Exception:
            logger.exception("output collection failed")

        # Persist the agent trajectory: cc session jsonl + streamed log live
        # under /logs inside the container (CLAUDE_CONFIG_DIR=/logs) and are
        # otherwise destroyed with the container.
        self._collect_logs(container, cfg.out_dir)

        try:
            checks = self._score(outputs_dir)
        except Exception as e:
            logger.exception("scoring failed")
            checks = [CheckResult(name="error", score=0.0, details={"error": str(e)})]

        result = EvalResult(task_id=cfg.task_id, elapsed_time=toc - tic, checks=checks)
        save_json(result, cfg.out_dir / "result.json", indent=2)
        logger.info(
            "task %s done: weighted=%.3f checks=%s",
            cfg.task_id,
            result.weighted_score,
            [(c.name, round(c.score, 2)) for c in checks],
        )
        self._cleanup()
        return result

    def _start_container(self, client):
        import re

        cname = f"pb-lean-{self.config.task_id.replace(':','-')}-{uuid4().hex[:8]}"
        volumes = {
            str(self.config.runtime_dir.absolute()): {
                "bind": self.config.runtime_dir_in_container,
                "mode": "ro",
            },
        }
        run_kwargs = dict(
            image=self.config.agent_image,
            command=["tail", "-f", "/dev/null"],
            detach=True,
            name=cname,
            volumes=volumes,
            environment={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            mem_limit=self.config.container_mem_limit,
            nano_cpus=self.config.container_nano_cpus,
        )
        for attempt in range(3):
            try:
                self.container = client.containers.run(**run_kwargs)
                break
            except (docker.errors.APIError, OSError) as e:
                logger.warning("container attempt %d failed: %s", attempt + 1, e)
                run_kwargs["name"] = f"{cname}-{uuid4().hex[:8]}"
                time.sleep(5 * (attempt + 1))
        if self.container is None:
            raise RuntimeError("failed to start container")
        logger.info("container started: %s", self.container.name)
        return self.container

    def _collect_outputs(self, container, out_dir: Path) -> Path:
        outputs_dir = out_dir / "outputs"
        outputs_dir.mkdir(parents=True, exist_ok=True)
        for fname in ("final.lean", "verdict.json", "attack_report.md", "final.spthy", "final.vp"):
            try:
                docker_cp_from_container(
                    container.id,
                    f"/workspace/{fname}",
                    str(outputs_dir / fname),
                    check=False,
                )
            except Exception:
                pass
        return outputs_dir

    def _collect_logs(self, container, out_dir: Path) -> None:
        """Copy the clean agent trajectory out of the container.

        Only the Claude Code session JSONL under ``/logs/projects`` (full
        message/tool-call trajectory, resumable) and the small session config
        are kept. The raw streamed CLI log is written host-side as a filtered
        ``logs/trajectory.jsonl`` (see ``agents/claude_code.py``); the noisy
        in-container ``claude_code.log`` is neither produced nor copied.
        """
        if container is None:
            return
        dest = out_dir / "trajectory"
        dest.mkdir(parents=True, exist_ok=True)
        try:
            docker_cp_from_container(
                container.id, "/logs/projects", str(dest / "projects"), check=False
            )
            logger.info("collected session trajectory -> %s", dest / "projects")
        except Exception:
            logger.exception("failed to collect /logs/projects from container")
        try:
            docker_cp_from_container(
                container.id, "/logs/.claude.json", str(dest / ".claude.json"), check=False
            )
        except Exception:
            pass

    def _score(self, outputs_dir: Path) -> list[CheckResult]:
        """Attack-discovery scoring.

        Every on-chain task is an attack task: the agent must produce a Lean
        model that formalises the protocol, formalise each required goal, and
        machine-check its falsification (an attack witness).  We do not compare
        against a stored SAFE/UNSAFE label; the deterministic signal is:

          * attack_evidence (0.6): final.lean compiles, contains no
            sorry/admit/axiom/unsafe, and defines every required goal name.
          * verdict_unsafe  (0.2): verdict.json says UNSAFE and lists the
            falsified goals.
          * attack_report   (0.2): attack_report.md is present and substantive.

        Semantic acceptance (is the attack real / the target bug?) is a
        separate judge stage.
        """
        checks: list[CheckResult] = []
        required = list(getattr(self.meta, "lemma_names", []) or [])

        # 1. attack_evidence
        lean_file = outputs_dir / "final.lean"
        forbidden_patterns = {
            "sorry": re.compile(r"(?<![A-Za-z0-9_'])sorry(?![A-Za-z0-9_'])"),
            "admit": re.compile(r"(?<![A-Za-z0-9_'])admit(?![A-Za-z0-9_'])"),
            "axiom": re.compile(r"(?m)^\s*axiom\b"),
            "unsafe": re.compile(r"(?<![A-Za-z0-9_'])unsafe(?![A-Za-z0-9_'])"),
        }
        ev_detail: dict = {"has_lean_file": lean_file.is_file()}
        compile_ok = False
        forbidden_used: list[str] = []
        missing_goals: list[str] = list(required)
        if lean_file.is_file():
            try:
                src = lean_file.read_text(encoding="utf-8", errors="replace")
                forbidden_used = [
                    name for name, pat in forbidden_patterns.items() if pat.search(src)
                ]
                missing_goals = [
                    n for n in required
                    if not re.search(
                        r"\b(?:theorem|lemma|def)\s+" + re.escape(n) + r"\b", src
                    )
                ]
                if not forbidden_used:
                    r = subprocess.run(
                        [
                            "docker", "run", "--rm",
                            "-v", f"{lean_file.resolve()}:/model.lean:ro",
                            self.config.agent_image,
                            "lean", "/model.lean",
                        ],
                        capture_output=True, text=True,
                        timeout=self.config.verify_timeout_seconds or 120,
                    )
                    compile_ok = r.returncode == 0
                    ev_detail["exit_code"] = r.returncode
                    ev_detail["stderr_tail"] = r.stderr[-300:]
            except Exception as e:
                ev_detail["error"] = str(e)
        if forbidden_used:
            ev_detail["reward_hacking_tokens"] = forbidden_used
        if missing_goals and len(missing_goals) < len(required):
            ev_detail["missing_goals"] = missing_goals
        evidence_ok = (
            lean_file.is_file()
            and not forbidden_used
            and compile_ok
            and not missing_goals
        )
        checks.append(
            CheckResult(
                name="attack_evidence",
                score=1.0 if evidence_ok else 0.0,
                weight=0.6,
                details=ev_detail,
            )
        )

        # 2. verdict_unsafe
        verdict: dict = {}
        vp = outputs_dir / "verdict.json"
        if vp.is_file():
            try:
                verdict = json.loads(vp.read_text())
            except (OSError, json.JSONDecodeError):
                verdict = {}
        overall = str(verdict.get("overall", ""))
        attacks = verdict.get("attack_lemmas") or []
        verdict_ok = overall.upper().startswith("UNSAFE") and bool(attacks)
        checks.append(
            CheckResult(
                name="verdict_unsafe",
                score=1.0 if verdict_ok else 0.0,
                weight=0.2,
                details={"agent_verdict": overall, "attack_lemmas": attacks},
            )
        )

        # 3. attack_report
        rep = outputs_dir / "attack_report.md"
        report_ok = False
        report_detail: dict = {"has_report": rep.is_file()}
        if rep.is_file():
            body = rep.read_text(encoding="utf-8", errors="replace").strip()
            report_detail["chars"] = len(body)
            report_ok = len(body) >= 200
        checks.append(
            CheckResult(
                name="attack_report",
                score=1.0 if report_ok else 0.0,
                weight=0.2,
                details=report_detail,
            )
        )

        return checks

    def _cleanup(self):
        if self.container is None:
            return
        if not self.config.keep_container:
            try:
                self.container.remove(force=True)
            except Exception:
                pass
            finally:
                self.container = None

    def cleanup(self):
        self._cleanup()
