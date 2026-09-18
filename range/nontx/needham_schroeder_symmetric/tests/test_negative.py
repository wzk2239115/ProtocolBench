"""Negative test: Denning-Sacco's fix defeats the replay; no flag."""

from __future__ import annotations

import ns_sym_lib
from ns_sym_testkit import NONCE_BITS, NONCE_MOD, read_events, run_exploit


def _nonce_hex(n: int) -> str:
    return format(n % NONCE_MOD, "032x")


def test_fixed_protocol_defeats_replay(start_target, expected_flag, tmp_path):
    target = start_target(fixed=True, expected=expected_flag)
    out = tmp_path / "flag.txt"

    proc = run_exploit(target, out)
    assert proc.returncode != 0, f"exploit unexpectedly succeeded: {proc.stdout}"

    if out.is_file():
        assert out.read_text(encoding="utf-8").strip() != expected_flag

    events = read_events(target.events)
    assert not any(e.get("event") == "flag_released" for e in events), events
    assert any(e.get("event") == "b_rejected" for e in events), events


def test_fixed_protocol_still_completes_an_honest_run(start_target, expected_flag):
    """The fix must not break honest operation, only the replay."""
    target = start_target(fixed=True, expected=expected_flag)

    a = ns_sym_lib.Conn(target.host, target.ports["a"])
    a.send({"op": "start", "peer": "B"})
    ticket_msg = a.recv()
    assert ticket_msg.get("type") == "ticket", ticket_msg

    b = ns_sym_lib.Conn(target.host, target.ports["b"])
    b.send({"type": "ticket", "data": ticket_msg["data"]})
    chal = b.recv()
    assert chal.get("type") == "challenge", chal

    a.send({"type": "challenge", "data": chal["data"]})
    resp = a.recv()
    assert resp.get("type") == "response", resp

    b.send({"type": "response", "data": resp["data"]})
    done = b.recv()
    assert done.get("type") == "done", done
    assert done.get("peer") == "A"

    # A benign relay never learns the session key, so the flag stays denied.
    b.send({"type": "flag", "peer": "A", "key": "00" * 32})
    assert b.recv().get("type") == "error"

    events = read_events(target.events)
    assert any(e.get("event") == "b_complete" and e.get("peer") == "A" for e in events)
    assert not any(e.get("event") == "flag_released" for e in events)
