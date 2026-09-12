#!/usr/bin/env python3
"""Pre-run readiness checks + service startup (adapted from ExploitGym).

Checks: docker daemon, task data + validated ground truths, images, runtime.
Starts (or reuses): the LLM proxy and the firewall proxies. Prints export
lines for the per-deployment secrets (flag seed / token salt).

Usage::

    python scripts/setup/pre_run.py                 # check + start services
    python scripts/setup/pre_run.py --check-only    # checks only
    python scripts/setup/pre_run.py --no-proxy      # skip the LLM proxy
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from tamaringym.task.metadata import load_task_registry  # noqa: E402
from tamaringym.task.token import (  # noqa: E402
    FLAG_SEED_ENV_VAR,
    SALT_ENV_VAR,
    generate_secret,
)
from tamaringym.utils import DATA_DIR, get_docker_client  # noqa: E402

logger = logging.getLogger("pre_run")

STATE_DIR = REPO_ROOT / "logs"
SECRETS_FILE = STATE_DIR / "deployment_secrets.json"


def check_docker() -> bool:
    try:
        client = get_docker_client()
        client.ping()
        logger.info("docker: ok (server %s)", client.version()["Version"])
        return True
    except Exception as e:  # noqa: BLE001
        logger.error("docker daemon unreachable: %s", e)
        return False


def check_tasks() -> tuple[int, int, bool]:
    registry = load_task_registry()
    total = sum(len(v) for v in registry.values())
    if total == 0:
        logger.error(
            "no tasks found under %s — run scripts/convert_cfb.py", DATA_DIR / "tasks"
        )
        return 0, 0, False
    validated = 0
    for level_tasks in registry.values():
        for meta in level_tasks.values():
            gt_path = (
                DATA_DIR
                / "tasks"
                / meta.level
                / meta.name
                / "solution"
                / "ground_truth.json"
            )
            try:
                gt = json.loads(gt_path.read_text())
                if gt.get("validated"):
                    validated += 1
            except (OSError, json.JSONDecodeError):
                pass
    ok = validated == total
    logger.info(
        "tasks: %d total, %d validated%s",
        total,
        validated,
        ""
        if ok
        else f" — run scripts/validate_tasks.py to validate the remaining {total - validated}",
    )
    return total, validated, ok


def check_images(agent_image: str, verifier_image: str) -> bool:
    try:
        client = get_docker_client()
    except Exception:  # noqa: BLE001
        return False
    ok = True
    for name in (agent_image, verifier_image):
        try:
            client.images.get(name)
            logger.info("image %s: present", name)
        except Exception:  # noqa: BLE001
            logger.error("image %s missing — run scripts/setup/build_images.sh", name)
            ok = False
    return ok


def check_runtime() -> bool:
    claude = DATA_DIR / "runtime" / "node" / "bin" / "claude-code.sh"
    if claude.is_file():
        logger.info("runtime: claude-code CLI present at %s", claude)
        return True
    logger.warning(
        "runtime: %s missing — run scripts/setup/setup_runtime.sh "
        "(only needed for the claude_code agent)",
        claude,
    )
    return True  # not fatal: mock agents / codex don't need it


def load_or_create_secrets() -> dict:
    """Per-deployment secrets persisted under logs/ (gitignored)."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if SECRETS_FILE.is_file():
        return json.loads(SECRETS_FILE.read_text())
    secrets = {
        "token_salt": generate_secret("tg-salt"),
        "flag_seed": generate_secret("tg-seed"),
    }
    SECRETS_FILE.write_text(json.dumps(secrets, indent=2))
    os.chmod(SECRETS_FILE, 0o600)
    return secrets


def start_proxy(port: int) -> None:
    from tamaringym.llm_proxy import LLMProxyManager

    mgr = LLMProxyManager(port=port)
    mgr.start()
    print(f"# LLM proxy: {mgr.url}")
    print(f"export TAMARINGYM_PROXY_URL={mgr.url}")
    print(f"export TAMARINGYM_PROXY_MASTER_KEY={mgr.master_key}")


def start_firewall() -> None:
    from tamaringym.firewall import FirewallProxyManager

    run_proxy = FirewallProxyManager()
    run_proxy.start()
    print(
        f"# firewall run proxy: {run_proxy.proxy_url} network={run_proxy.network_name}"
    )
    install_proxy = FirewallProxyManager.for_install()
    install_proxy.start()
    print(
        f"# firewall install proxy: {install_proxy.proxy_url} network={install_proxy.network_name}"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check-only", action="store_true")
    ap.add_argument("--no-proxy", action="store_true")
    ap.add_argument("--no-firewall", action="store_true")
    ap.add_argument("--proxy-port", type=int, default=4000)
    ap.add_argument("--agent-image", default="protocolbench/agent:latest")
    ap.add_argument("--verifier-image", default="tamaringym/verifier:1.12.0")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    ok = True
    ok &= check_docker()
    _, _, tasks_ok = check_tasks()
    ok &= tasks_ok
    ok &= check_images(args.agent_image, args.verifier_image)
    check_runtime()

    if args.check_only:
        return 0 if ok else 1

    secrets = load_or_create_secrets()
    print("# ---- export these before running the batch runner ----")
    print(f"export {SALT_ENV_VAR}={secrets['token_salt']}")
    print(f"export {FLAG_SEED_ENV_VAR}={secrets['flag_seed']}")

    if not args.no_proxy:
        try:
            start_proxy(args.proxy_port)
        except Exception as e:  # noqa: BLE001
            logger.error("LLM proxy failed to start: %s", e)
    if not args.no_firewall:
        try:
            start_firewall()
        except Exception as e:  # noqa: BLE001
            logger.error("firewall failed to start: %s", e)

    return 0


if __name__ == "__main__":
    sys.exit(main())
