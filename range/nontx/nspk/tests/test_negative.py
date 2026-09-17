"""Negative test: Lowe's fix defeats the same MITM; no flag."""

from __future__ import annotations

import nspk_lib
from nspk_testkit import read_events, run_exploit


def test_fixed_protocol_defeats_mitm(start_target, expected_flag, tmp_path):
    target = start_target(fixed=True, expected=expected_flag)
    out = tmp_path / "flag.txt"

    proc = run_exploit(target, out)
    assert proc.returncode != 0, f"exploit unexpectedly succeeded: {proc.stdout}"

    if out.is_file():
        assert out.read_text(encoding="utf-8").strip() != expected_flag

    events = read_events(target.events)
    assert not any(e.get("event") == "flag_released" for e in events), events
    assert any(e.get("event") == "a_rejected" for e in events), events


def test_fixed_protocol_still_completes_an_honest_run(start_target, expected_flag):
    """The fix must not break honest operation, only the impersonation."""
    target = start_target(fixed=True, expected=expected_flag)

    a = nspk_lib.Conn(target.host, target.ports["a"])
    a.send({"op": "start", "peer": "B"})
    msg1 = a.recv()
    assert msg1.get("type") == "msg1"

    b = nspk_lib.Conn(target.host, target.ports["b"])
    b.send({"type": "msg1", "data": msg1["data"]})
    msg2 = b.recv()
    assert msg2.get("type") == "msg2"

    a.send({"type": "msg2", "data": msg2["data"]})
    msg3 = a.recv()
    assert msg3.get("type") == "msg3", msg3

    b.send({"type": "msg3", "data": msg3["data"]})
    done = b.recv()
    assert done.get("type") == "done"
    assert done.get("peer") == "A"

    # A benign relay never learns the session nonce, so the flag stays denied.
    b.send({"type": "flag", "peer": "A", "nonce": "00" * 16})
    assert b.recv().get("type") == "error"

    events = read_events(target.events)
    assert any(e.get("event") == "b_complete" and e.get("peer") == "A" for e in events)
    assert not any(e.get("event") == "flag_released" for e in events)
