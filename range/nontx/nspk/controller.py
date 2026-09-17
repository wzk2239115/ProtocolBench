#!/usr/bin/env python3
"""Controller for the NSPK (1978) live exploit range.

Responsibilities
----------------
1. Derive ``expected_flag = HMAC_SHA256(FLAG_SEED, "nontx:nspk")``.
2. Start the target (Docker by default; a local subprocess fallback for tests),
   injecting the flag as ``EXPECTED_FLAG`` and recording server-side events to a
   host-only file.
3. Run an agent command with the target coordinates in its environment.
4. Independently verify success: the server-side ``flag_released`` event must
   exist **and** the captured flag must equal the derived flag.  Writes
   ``result.json``.

``FLAG_SEED`` is read from the environment, else from the repo ``.glm_env``
(``export FLAG_SEED=...``), else the documented dev default ``tg-dev-seed``.
The dev default is for tests only; production derives the seed from the host
secret.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

TASK_ID = "nontx:nspk"
TASK_DIR = Path(__file__).resolve().parent
REPO_ROOT = TASK_DIR.parents[2]
TARGET_DIR = TASK_DIR / "target"
WORKSPACE = TASK_DIR / "workspace"
SOLUTION = TASK_DIR / "solution"
DOCKER_IMAGE = os.environ.get("NSPK_IMAGE", "protocolbench/nspk-target:latest")
DEV_FLAG_SEED = "tg-dev-seed"
CONTAINER_PORTS = {"dir": 9100, "a": 9101, "b": 9102}


def load_flag_seed() -> str:
    seed = os.environ.get("FLAG_SEED")
    if seed:
        return seed
    glm_env = REPO_ROOT / ".glm_env"
    if glm_env.is_file():
        for line in glm_env.read_text(encoding="utf-8").splitlines():
            m = re.match(r"\s*(?:export\s+)?FLAG_SEED\s*=\s*(.+?)\s*$", line)
            if m:
                return m.group(1).strip().strip('"').strip("'")
    return DEV_FLAG_SEED


def derive_expected_flag(seed: str) -> str:
    return hmac.new(seed.encode(), TASK_ID.encode(), hashlib.sha256).hexdigest()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_ready(host: str, port: int, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0) as s:
                s.sendall(b'{"op":"pubkey","name":"A"}\n')
                data = s.recv(4096)
                if b'"ok": true' in data or b'"ok":true' in data:
                    return
        except OSError as exc:
            last = exc
        time.sleep(0.1)
    raise TimeoutError(f"target not ready on {host}:{port}: {last}")


class LocalTarget:
    mode = "local"

    def __init__(self, fixed: bool, events_file: Path) -> None:
        self.fixed = fixed
        self.events_file = events_file
        self.ports = {"dir": free_port(), "a": free_port(), "b": free_port()}
        self.proc: subprocess.Popen | None = None

    def start(self, flag: str) -> None:
        env = dict(os.environ)
        env["EXPECTED_FLAG"] = flag
        cmd = [
            sys.executable,
            str(TARGET_DIR / "server.py"),
            "--dir-port",
            str(self.ports["dir"]),
            "--a-port",
            str(self.ports["a"]),
            "--b-port",
            str(self.ports["b"]),
            "--events-file",
            str(self.events_file),
        ]
        if self.fixed:
            cmd.append("--fixed")
        self.proc = subprocess.Popen(
            cmd, cwd=str(TARGET_DIR), env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True,
        )
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        if '"ready": true' not in line and '"ready":true' not in line:
            raise RuntimeError(f"target failed to start: {line!r}")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class DockerTarget:
    mode = "docker"

    def __init__(self, fixed: bool, events_file: Path) -> None:
        self.fixed = fixed
        self.events_file = events_file
        self.name = f"nspk-target-{os.getpid()}"
        self.ports = {"dir": free_port(), "a": free_port(), "b": free_port()}
        self.started = False

    def ensure_image(self) -> None:
        if subprocess.run(
            ["docker", "image", "inspect", DOCKER_IMAGE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0:
            return
        subprocess.run(["bash", str(TASK_DIR / "build.sh")], check=True)

    def start(self, flag: str) -> None:
        self.ensure_image()
        events_dir = self.events_file.parent
        events_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(events_dir, 0o777)
        if self.events_file.exists():
            self.events_file.unlink()
        cmd = [
            "docker", "run", "--rm", "-d", "--name", self.name,
            "-e", f"EXPECTED_FLAG={flag}",
            "-p", f"127.0.0.1:{self.ports['dir']}:{CONTAINER_PORTS['dir']}",
            "-p", f"127.0.0.1:{self.ports['a']}:{CONTAINER_PORTS['a']}",
            "-p", f"127.0.0.1:{self.ports['b']}:{CONTAINER_PORTS['b']}",
            "-v", f"{events_dir}:/events",
            DOCKER_IMAGE,
            "--host", "0.0.0.0",
            "--events-file", f"/events/{self.events_file.name}",
        ]
        if self.fixed:
            cmd.append("--fixed")
        subprocess.run(cmd, check=True, capture_output=True)
        self.started = True

    def stop(self) -> None:
        if self.started:
            subprocess.run(
                ["docker", "rm", "-f", self.name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )


def pick_target(mode: str, fixed: bool, events_file: Path):
    docker_ok = shutil.which("docker") is not None
    if mode == "docker" or (mode == "auto" and docker_ok):
        return DockerTarget(fixed, events_file)
    return LocalTarget(fixed, events_file)


def read_events(path: Path) -> list[dict]:
    events = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def main() -> int:
    ap = argparse.ArgumentParser(description="NSPK live range controller")
    ap.add_argument("--mode", choices=["auto", "docker", "local"], default="auto")
    ap.add_argument("--fixed", action="store_true", help="run Lowe's fixed protocol")
    ap.add_argument("--agent-cmd", default=None,
                    help="command the agent runs (cwd=workspace)")
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--out-dir", default=str(TASK_DIR / "out"))
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    events_file = out_dir / "server-events" / "events.jsonl"
    events_file.parent.mkdir(parents=True, exist_ok=True)
    if events_file.exists():
        events_file.unlink()
    flag_path = WORKSPACE / "flag.txt"
    if flag_path.exists():
        flag_path.unlink()

    seed = load_flag_seed()
    expected = derive_expected_flag(seed)
    SOLUTION.mkdir(exist_ok=True)
    (SOLUTION / "expected_flag.txt").write_text(expected + "\n", encoding="utf-8")

    agent_cmd = args.agent_cmd
    if agent_cmd is None:
        agent_cmd = f'{sys.executable} "{SOLUTION / "exploit.py"}"'

    result: dict = {
        "task": TASK_ID,
        "mode": None,
        "fixed": args.fixed,
        "flag_seed_source": "dev-default" if seed == DEV_FLAG_SEED else "host",
        "expected_sha256": hashlib.sha256(expected.encode()).hexdigest(),
        "ok": False,
        "flag_released": False,
        "flag_captured": None,
        "flag_match": False,
        "agent_exit": None,
        "errors": [],
        "started_at": time.time(),
    }

    target = pick_target(args.mode, args.fixed, events_file)
    result["mode"] = target.mode
    try:
        target.start(expected)
        wait_ready(args.host, target.ports["dir"], timeout=args.timeout)
        result["ports"] = target.ports

        env = dict(os.environ)
        env.update({
            "NSPK_HOST": args.host,
            "NSPK_DIR_PORT": str(target.ports["dir"]),
            "NSPK_A_PORT": str(target.ports["a"]),
            "NSPK_B_PORT": str(target.ports["b"]),
            "NSPK_FLAG_OUT": "flag.txt",
        })
        proc = subprocess.run(
            agent_cmd, shell=True, cwd=str(WORKSPACE), env=env,
            capture_output=True, text=True, timeout=args.timeout,
        )
        result["agent_exit"] = proc.returncode
        (out_dir / "agent.stdout").write_text(proc.stdout, encoding="utf-8")
        (out_dir / "agent.stderr").write_text(proc.stderr, encoding="utf-8")

        events = read_events(events_file)
        result["flag_released"] = any(e.get("event") == "flag_released" for e in events)
        result["server_events"] = [e.get("event") for e in events]

        flag_path = WORKSPACE / "flag.txt"
        if flag_path.is_file():
            captured = flag_path.read_text(encoding="utf-8").strip()
            result["flag_captured"] = captured
            result["flag_match"] = hmac.compare_digest(captured, expected)

        result["ok"] = bool(result["flag_released"] and result["flag_match"])
        result["status"] = "EXPLOITED" if result["ok"] else "NOT_EXPLOITED"
    except subprocess.TimeoutExpired:
        result["errors"].append("agent command timed out")
    except Exception as exc:  # noqa: BLE001
        result["errors"].append(f"{type(exc).__name__}: {exc}")
    finally:
        target.stop()
        result["finished_at"] = time.time()
        (out_dir / "result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    raise SystemExit(main())
