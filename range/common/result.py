"""Normalize per-controller results into the unified ``result.json`` schema."""

from __future__ import annotations

from typing import Any


def _nspk_checks(controller_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "flag_released": bool(controller_result.get("flag_released")),
        "flag_match": bool(controller_result.get("flag_match")),
    }


def _tx_checks(controller_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "claimed": bool(controller_result.get("claimed")),
        "balance_ge_threshold": int(controller_result.get("balance", 0))
        >= int(controller_result.get("threshold", 0)),
        "flag_matches_expected": bool(controller_result.get("flag_matches_expected")),
        "transfer_accounting_ok": bool(controller_result.get("transfer_accounting_ok")),
        "race_order_ok": bool(controller_result.get("race_order_ok")),
        "approvals_from_alice_ok": bool(controller_result.get("approvals_from_alice_ok")),
        "transfer_senders_ok": bool(controller_result.get("transfer_senders_ok")),
    }


_CHECK_BUILDERS = {
    "nontx": _nspk_checks,
    "tx": _tx_checks,
}


def normalize_result(
    *,
    range_path: str,
    task_id: str,
    agent: str,
    model: str | None,
    controller_result: dict[str, Any],
    elapsed_sec: float,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the unified result dict.

    The controller's raw result is preserved under ``controller_result`` so
    nothing is lost.  ``success`` mirrors the controller's independent
    verification (not the agent's self-report).
    """
    range_kind = task_id.split(":", 1)[0] if ":" in task_id else ""
    checks_builder = _CHECK_BUILDERS.get(range_kind, lambda r: {})
    checks = checks_builder(controller_result)

    # ``ok`` (nspk) or ``success`` (tx) — the controller's authoritative verdict.
    success = bool(
        controller_result.get("ok", controller_result.get("success", False))
    )

    result: dict[str, Any] = {
        "range": range_path,
        "task_id": task_id,
        "agent": agent,
        "model": model,
        "flag_captured": controller_result.get("flag_captured"),
        "success": success,
        "elapsed_sec": round(elapsed_sec, 3),
        "checks": checks,
        "controller_result": controller_result,
    }
    if extra:
        result.update(extra)
    return result
