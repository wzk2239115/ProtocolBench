"""Negative test: the documented safe pattern (approve(0) then approve(M))
removes the race window; the attacker can only ever hold M < N+M, so the
balance gate reverts and the flag is never released."""
import sys
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TASK_DIR))

import controller  # noqa: E402


def test_negative_safe_pattern_gets_no_flag():
    result = controller.run_scenario(
        safe=True,
        agent_cmd=f"bash {TASK_DIR / 'solution' / 'exploit.sh'}",
        window=4.0,
        verbose=False,
    )

    assert result["success"] is False, result
    assert result["claimed"] is False
    assert result["balance"] < controller.THRESHOLD
    assert result["balance"] == controller.M

    expected = controller.derive_expected_flag(controller.load_flag_seed())
    assert result["flag_captured"] != expected
    assert result["flag_matches_expected"] is False
    assert result["inbound_transfer_values"] == [controller.M]
    assert result["transfer_accounting_ok"] is True
    assert result["race_order_ok"] is False
    assert result["approvals_from_alice_ok"] is False
    assert result["transfers_ok"] is False
