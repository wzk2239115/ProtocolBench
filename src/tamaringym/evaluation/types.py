"""Core evaluation types (mirrors ExploitGym's shapes)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from tamaringym.utils import DATA_DIR

type JSONValue = Any


class EvalConfig(BaseModel):
    task_id: str  # "L1:NSPK3"
    out_dir: Path
    verifier_image: str = "tamaringym/verifier:1.12.0"
    agent_image: str = "protocolbench/agent:latest"
    runtime_dir: Path = DATA_DIR / "runtime"
    runtime_dir_in_container: str = "/data"
    workspace_dir_in_container: str = "/workspace"
    agent_timeout_seconds: int = 3600
    verify_timeout_seconds: int = 600
    agent_extra_kwargs: dict[str, JSONValue] = Field(default_factory=dict)
    api_base_url: str | None = None
    api_key: SecretStr | None = None
    allowed_models: list[str] | None = None
    credential_path: Path | None = None
    keep_container: bool = False
    save_workspace_after_eval: bool = True
    save_workspace_max_file_bytes: int | None = 10 * 1024 * 1024
    use_firewall: bool = False
    container_mem_limit: str | None = "8g"
    container_nano_cpus: int | None = 4_000_000_000
    container_memswap_limit: str | None = "8g"
    container_pids_limit: int | None = 4096
    task_description_template: str | None = None


class CheckResult(BaseModel):
    name: str
    score: float
    weight: float = 1.0
    details: dict[str, JSONValue] | None = None


class AgentFnArguments(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    task_description: str
    runtime_dir_in_container: str
    agent_timeout_seconds: int
    out_dir: Path
    container_id: str | None = None
    extra_kwargs: dict[str, JSONValue] = Field(default_factory=dict)
    api_base_url: str | None = None
    api_key: str | None = None
    credential_path: Path | None = None
    firewall_env: dict[str, str] | None = None
    disable_web_search: bool = True


class EvalResult(BaseModel):
    task_id: str
    elapsed_time: float = 0.0
    checks: list[CheckResult]
    error: str | None = None

    @property
    def weighted_score(self) -> float:
        total_w = sum(c.weight for c in self.checks)
        if total_w == 0:
            return 0.0
        return sum(c.score * c.weight for c in self.checks) / total_w
