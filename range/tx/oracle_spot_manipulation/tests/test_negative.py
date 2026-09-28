"""Negative test: the documented fix (LendingPoolSafe with a price band /
deviation check) rejects the large spot-price move needed to over-borrow, so
the manipulation fails, the attacker never reaches the profit threshold, and
the flag is never released."""
import sys
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TASK_DIR))

import controller  # noqa: E402


def test_negative_safe_pool_blocks_manipulation():
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

    # the attacker cannot reach the profit threshold with the guarded pool
    assert result["balance"] < controller.PROFIT_THRESHOLD
    assert result["asset_balance_of_attacker"] < controller.PROFIT_THRESHOLD

    expected = controller.derive_expected_flag(controller.load_flag_seed())
    assert result["flag_matches_expected"] is False
    assert result["flag_captured"] != expected
