"""Negative test: the responder-binding fix defeats the interleaving attack; no flag."""

from __future__ import annotations

import woo_lam_lib
from woo_lam_testkit import read_events, run_exploit


def test_fixed_protocol_defeats_attack(start_target, expected_flag, tmp_path):
    target = start_target(fixed=True, expected=expected_flag)
    out = tmp_path / "flag.txt"

    proc = run_exploit(target, out)
    assert proc.returncode != 0, f"exploit unexpectedly succeeded: {proc.stdout}"

    if out.is_file():
        assert out.read_text(encoding="utf-8").strip() != expected_flag

    events = read_events(target.events)
    assert not any(e.get("event") == "flag_released" for e in events), events
    assert any(
        e.get("event") in ("s_rejected", "a_rejected") for e in events
    ), events


def test_fixed_protocol_still_completes_an_honest_run(start_target, expected_flag):
    """The fix must not break honest operation, only the impersonation."""
    target = start_target(fixed=True, expected=expected_flag)

    # Honest A initiates with B.
    a = woo_lam_lib.Conn(target.host, target.ports["a"])
    a.send({"op": "start", "peer": "B"})
    wl1 = a.recv()
    assert wl1.get("type") == "wl1"
    assert wl1.get("a") == "A"
    # In fixed mode A sends its own nonce NA; B must echo it in WL2.
    a_na = wl1.get("na", "")

    b = woo_lam_lib.Conn(target.host, target.ports["b"])
    b.send({"type": "wl1", "a": "A", "na": a_na})
    wl2 = b.recv()
    assert wl2.get("type") == "wl2"
    nb = wl2["nb"]

    a.send({"type": "wl2", "nb": nb, "na": a_na})
    wl3 = a.recv()
    assert wl3.get("type") == "wl3", wl3

    b.send({"type": "wl3", "data": wl3["data"]})
    done = b.recv()
    assert done.get("type") == "done"
    assert done.get("peer") == "A"

    # An eavesdropper that only saw the nonce still cannot claim without the
    # completed run; presenting a wrong nonce is denied.
    b.send({"type": "flag", "peer": "A", "nonce": "00" * 16})
    assert b.recv().get("type") == "error"

    events = read_events(target.events)
    assert any(e.get("event") == "b_complete" and e.get("peer") == "A" for e in events)
    assert not any(e.get("event") == "flag_released" for e in events)