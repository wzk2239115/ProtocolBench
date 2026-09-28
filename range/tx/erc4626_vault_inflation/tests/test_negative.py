"""Negative test: the documented fix (SafeVault with OZ `_decimalsOffset()`
virtual shares + dead shares) makes the donation inflation unprofitable. The
virtual shares capture the attacker's donation, the victim still receives a
fair, non-zero amount of shares, and the attacker's asset balance never
reaches the profit threshold, so the flag is never released."""
import sys
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TASK_DIR))

import controller  # noqa: E402


def test_negative_safe_vault_blocks_inflation():
    result = controller.run_scenario(
        safe=True,
        agent_cmd=f"bash {TASK_DIR / 'solution' / 'exploit.sh'}",
        window=10.0,
        agent_timeout=180,
        verbose=False,
    )

    assert result["safe_mode"] is True
    assert result["success"] is False, result
    assert result["claimed"] is False

    # the attacker cannot reach the profit threshold with the guarded vault
    assert result["balance"] < controller.PROFIT_THRESHOLD
    assert result["asset_balance_of_attacker"] < controller.PROFIT_THRESHOLD

    # the fix works: the victim's deposit does NOT mint 0 shares (no inflation)
    assert result["victim_zero_shares"] is False
    assert result["victim_deposit_shares"] != 0

    expected = controller.derive_expected_flag(controller.load_flag_seed())
    assert result["flag_matches_expected"] is False
    assert result["flag_captured"] != expected
