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

    def _score(self, outputs_dir: Path) -> list[CheckResult]:
        checks: list[CheckResult] = []

        # 1. verdict_correct: agent verdict matches ground truth → 0 or 1
        verdict = {}
        vp = outputs_dir / "verdict.json"
        if vp.is_file():
            try:
                verdict = json.loads(vp.read_text())
            except (OSError, json.JSONDecodeError):
                pass
        agent_overall = verdict.get("overall", "")
        gt_is_unsafe = any(
            not lt.verified for lt in self.ground_truth.lemmas
        )
        gt_overall = "UNSAFE" if gt_is_unsafe else "SAFE"
        verdict_correct = (
            agent_overall.upper().startswith("UNSAFE") == gt_is_unsafe
            and bool(agent_overall)
        )
        checks.append(
            CheckResult(
                name="verdict_correct",
                score=1.0 if verdict_correct else 0.0,
                weight=0.5,
                details={
                    "agent_verdict": agent_overall,
                    "ground_truth": gt_overall,
                },
            )
        )

        # 2. evidence_compiles: Lean model compiles → 0 or 1
        lean_file = outputs_dir / "final.lean"
        lean_ok = False
        lean_detail: dict = {"has_lean_file": lean_file.is_file()}
        if lean_file.is_file():
            try:
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
                lean_ok = r.returncode == 0
                lean_detail["exit_code"] = r.returncode
                lean_detail["stderr_tail"] = r.stderr[-300:]
            except Exception as e:
                lean_detail["error"] = str(e)
        checks.append(
            CheckResult(
                name="evidence_compiles",
                score=1.0 if lean_ok else 0.0,
                weight=0.5,
                details=lean_detail,
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
