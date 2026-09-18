"""No-bypass checks: the flag must not exist in the agent-visible surface."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from woo_lam_testkit import TASK_DIR, WORKSPACE

IMAGE = os.environ.get("WOOLAM_IMAGE", "protocolbench/woo-lam-target:latest")


def _iter_files(base: Path):
    for path in base.rglob("*"):
        if path.is_file():
            yield path


def test_no_flag_plaintext_in_workspace_or_target_source(expected_flag):
    needle = expected_flag.encode()
    for base in (WORKSPACE, TASK_DIR / "target"):
        for path in _iter_files(base):
            assert needle not in path.read_bytes(), f"flag plaintext leaked into {path}"


def test_workspace_has_no_exploit_or_solution(expected_flag):
    names = {p.name for p in _iter_files(WORKSPACE)}
    assert "exploit.py" not in names
    assert "expected_flag.txt" not in names
    text = (WORKSPACE / "README.md").read_text(encoding="utf-8")
    assert expected_flag not in text


@pytest.mark.skipif(
    os.environ.get("WOOLAM_TEST_DOCKER") != "1" or shutil.which("docker") is None,
    reason="set WOOLAM_TEST_DOCKER=1 to build and inspect the image",
)
def test_no_flag_plaintext_in_target_image(expected_flag):
    subprocess.run(["bash", str(TASK_DIR / "build.sh")], check=True)
    script = (
        "if grep -r --binary-files=text -q " + f"'{expected_flag}'" + " /app; "
        "then echo FOUND; else echo CLEAN; fi"
    )
    proc = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "sh", IMAGE, "-c", script],
        capture_output=True, text=True, check=True,
    )
    assert "CLEAN" in proc.stdout, proc.stdout