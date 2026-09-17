"""Unique-named test helpers for the NSPK live range.

Kept out of ``conftest.py`` so tests never import a module named ``conftest``
(which could collide with other test suites in the repository).
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

TASK_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TASK_DIR))
sys.path.insert(0, str(TASK_DIR / "workspace"))

import controller  # noqa: E402
import nspk_lib  # noqa: E402,F401

PYTHON = sys.executable
SERVER = TASK_DIR / "target" / "server.py"
EXPLOIT = TASK_DIR / "solution" / "exploit.py"
WORKSPACE = TASK_DIR / "workspace"
SOLUTION = TASK_DIR / "solution"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Target:
    def __init__(self, proc: subprocess.Popen, ports: dict, events: Path) -> None:
        self.proc = proc
        self.ports = ports
        self.events = events
        self.host = "127.0.0.1"

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


@pytest.fixture(scope="session")
def expected_flag() -> str:
    return controller.derive_expected_flag(controller.load_flag_seed())


@pytest.fixture
def start_target(tmp_path):
    started: list[Target] = []

    def _start(fixed: bool = False, expected: str = "test-flag-value") -> Target:
        ports = {"dir": free_port(), "a": free_port(), "b": free_port()}
        events = tmp_path / f"events-{len(started)}.jsonl"
        env = dict(os.environ)
        env["EXPECTED_FLAG"] = expected
        cmd = [
            PYTHON, str(SERVER),
            "--dir-port", str(ports["dir"]),
            "--a-port", str(ports["a"]),
            "--b-port", str(ports["b"]),
            "--events-file", str(events),
        ]
        if fixed:
            cmd.append("--fixed")
        proc = subprocess.Popen(
            cmd, cwd=str(SERVER.parent), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        assert proc.stdout is not None
        line = proc.stdout.readline()
        assert '"ready": true' in line, f"server did not start: {line!r}"
        controller.wait_ready("127.0.0.1", ports["dir"], timeout=15)
        target = Target(proc, ports, events)
        started.append(target)
        return target

    yield _start
    for target in started:
        target.stop()


def run_exploit(target: Target, out: Path, timeout: float = 120.0) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["NSPK_HOST"] = target.host
    env["NSPK_DIR_PORT"] = str(target.ports["dir"])
    env["NSPK_A_PORT"] = str(target.ports["a"])
    env["NSPK_B_PORT"] = str(target.ports["b"])
    env["NSPK_FLAG_OUT"] = str(out)
    return subprocess.run(
        [PYTHON, str(EXPLOIT), "--out", str(out)],
        capture_output=True, text=True, timeout=timeout, env=env, cwd=str(TASK_DIR),
    )


def read_events(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out
