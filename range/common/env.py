"""Load host secrets/config from ``.glm_env`` without hardcoding values.

The repo ``.glm_env`` file (gitignored) holds ``GLM_API_KEY``, ``GLM_API_BASE``,
``GLM_MODEL``, and optionally ``FLAG_SEED``.  Real process environment variables
take precedence over the file so CI/production can override.
"""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GLM_ENV_PATH = REPO_ROOT / ".glm_env"


def load_glm_env() -> dict[str, str]:
    """Return a dict of config values from ``.glm_env`` (env overrides file)."""
    values: dict[str, str] = {}
    if GLM_ENV_PATH.is_file():
        for raw in GLM_ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :]
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                values[key] = value
    # Real process env overrides file values.
    for key in list(values):
        env_val = os.environ.get(key)
        if env_val is not None:
            values[key] = env_val
    return values


def get_api_key() -> str | None:
    return load_glm_env().get("GLM_API_KEY") or load_glm_env().get("API_KEY")


def get_api_base() -> str | None:
    return load_glm_env().get("GLM_API_BASE")
