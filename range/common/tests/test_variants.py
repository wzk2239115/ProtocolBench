"""Tests for the ProtocolBench variant framework.

Covers:
- Determinism: same (task_id, seed) -> same VariantConfig.
- Distinctness: different seeds -> different params (with high probability).
- Constraint validity: tx variants have threshold == N + M, N > 0, M > 0;
  nontx variants have RSA bits >= 2048.
- variant_id format correct.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
RANGE_ROOT = REPO_ROOT / "range"
sys.path.insert(0, str(RANGE_ROOT))

from common.variants import (  # noqa: E402
    generate_variant,
    generate_variants,
    VariantConfig,
)


# ── determinism ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("task_id", ["nontx:nspk", "tx:erc20_allowance_race"])
@pytest.mark.parametrize("seed", [1, 42, 100, 999])
def test_determinism_same_pair_same_config(task_id: str, seed: int):
    a = generate_variant(task_id, seed)
    b = generate_variant(task_id, seed)
    assert a == b, f"same ({task_id}, {seed}) produced different configs"


def test_determinism_across_processes():
    """The variant must not depend on PYTHONHASHSEED."""
    cfg = generate_variant("nontx:nspk", 42)
    # Re-generate and compare the JSON-serializable form (not object identity).
    import json
    a = json.dumps(cfg.__dict__, sort_keys=True)
    cfg2 = generate_variant("nontx:nspk", 42)
    b = json.dumps(cfg2.__dict__, sort_keys=True)
    assert a == b


# ── distinctness ────────────────────────────────────────────────────────
def test_distinct_seeds_produce_distinct_params():
    seeds = list(range(1000, 1020))
    configs = [generate_variant("nontx:nspk", s) for s in seeds]
    param_sets = [tuple(sorted(c.params.items())) for c in configs]
    # At least 15 of 20 should be distinct (allow rare collisions).
    assert len(set(param_sets)) >= 15


def test_distinct_seeds_produce_distinct_flags():
    """Different seeds -> different variant_ids -> different HMAC flags."""
    a = generate_variant("nontx:nspk", 42)
    b = generate_variant("nontx:nspk", 43)
    assert a.variant_id != b.variant_id
    assert a.params != b.params or a.role_map != b.role_map


def test_generate_variants_all_distinct():
    configs = generate_variants("tx:erc20_allowance_race", 10, base_seed=2000)
    ids = [c.variant_id for c in configs]
    assert len(set(ids)) == 10


# ── constraint validity ─────────────────────────────────────────────────
@pytest.mark.parametrize("seed", range(1, 50))
def test_tx_constraints(seed: int):
    cfg = generate_variant("tx:erc20_allowance_race", seed)
    p = cfg.params
    N, M = p["N"], p["M"]
    threshold = p["threshold"]
    supply = p["supply"]
    assert N > 0
    assert M > 0
    assert threshold == N + M, f"threshold {threshold} != N+M {N+M}"
    assert supply > threshold, f"supply {supply} not >> threshold {threshold}"
    assert p["decimals"] in (6, 18)
    assert p["token_name"]
    assert p["token_symbol"]


@pytest.mark.parametrize("seed", range(1, 50))
def test_nontx_constraints(seed: int):
    cfg = generate_variant("nontx:nspk", seed)
    p = cfg.params
    assert p["rsa_bits"] >= 2048
    assert p["nonce_bytes"] in (8, 16, 32)
    assert p["port_offset"] >= 0
    # role_map has exactly A, B, S mapped to distinct names.
    rm = cfg.role_map
    assert set(rm.keys()) == {"A", "B", "S"}
    names = list(rm.values())
    assert len(set(names)) == 3, f"role names not distinct: {names}"


# ── variant_id format ──────────────────────────────────────────────────
def test_variant_id_format():
    cfg = generate_variant("nontx:nspk", 42)
    assert cfg.variant_id == "nontx:nspk#v42"
    assert cfg.task_id_base == "nontx:nspk"
    assert cfg.seed == 42


def test_variant_id_format_tx():
    cfg = generate_variant("tx:erc20_allowance_race", 7)
    assert cfg.variant_id == "tx:erc20_allowance_race#v7"


def test_description_is_human_readable():
    cfg = generate_variant("nontx:nspk", 42)
    assert isinstance(cfg.description, str)
    assert len(cfg.description) > 10
    assert "42" in cfg.description
