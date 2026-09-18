"""Positive test: Denning-Sacco replay captures the controller-derived flag."""

from __future__ import annotations

import hashlib

from ns_sym_testkit import SOLUTION, read_events, run_exploit


def test_denning_sacco_replay_captures_flag(start_target, expected_flag, tmp_path):
    target = start_target(fixed=False, expected=expected_flag)
    out = tmp_path / "flag.txt"

    proc = run_exploit(target, out)
    assert proc.returncode == 0, f"exploit failed: {proc.stderr}\n{proc.stdout}"

    assert out.is_file(), "exploit did not write the flag"
    captured = out.read_text(encoding="utf-8").strip()
    assert captured == expected_flag, f"captured {captured!r} != {expected_flag!r}"

    events = read_events(target.events)
    releases = [e for e in events if e.get("event") == "flag_released"]
    assert releases, f"no server-side flag_released event: {events}"
    assert releases[0]["peer"] == "A"
    assert releases[0]["flag_sha256"] == hashlib.sha256(expected_flag.encode()).hexdigest()

    completes = [e for e in events if e.get("event") == "b_complete"]
    assert any(c.get("peer") == "A" and c.get("replay") for c in completes), events
    assert any(c.get("peer") == "A" and not c.get("replay") for c in completes), events

    SOLUTION.mkdir(exist_ok=True)
    (SOLUTION / "expected_flag.txt").write_text(expected_flag + "\n", encoding="utf-8")
