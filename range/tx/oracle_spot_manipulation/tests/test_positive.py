"""Positive test: the spot-oracle manipulation lets the attacker over-borrow
against collateral valued at the inflated AMM spot price, the attacker's asset
balance crosses the profit threshold, and the flag is captured."""
import sys
from pathlib import Path

TASK_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TASK_DIR))

import controller  # noqa: E402


def test_positive_oracle_manipulation_captures_flag():
    result = controller.run_scenario(
        safe=False,
        agent_cmd=f"bash {TASK_DIR / 'solution' / 'exploit.sh'}",
        window=10.0,
        agent_timeout=180,
        verbose=False,
    )

    assert result["success"] is True, result
    assert result["claimed"] is True
    assert result["balance"] >= controller.PROFIT_THRESHOLD

    expected = controller.derive_expected_flag(controller.load_flag_seed())
    assert result["flag_captured"] == expected
    assert result["flag_matches_expected"] is True

    # the manipulation signature: borrowed more than the honest price allows
    assert result["manipulation_proven"] is True
    assert result["borrowed"] > result["honest_max_borrow"]

    # the attacker's balance gain is fully explained by pool/AMM flow
    assert result["attacker_accounting_ok"] is True
    assert result["balance_gain"] > 0
