"""Deterministic variant configuration for ProtocolBench.

Variants implement the "防退化：攻击手法发现 ≠ POC/EXP" design: they prevent
agents from reproducing memorized exploits by changing deployment parameters
and presentation while leaving the real protocol flaw intact.

Each variant is fully determined by ``(task_id, seed)``: the same pair always
yields the same :class:`VariantConfig`, so a benchmark run is reproducible and
two different seeds produce two different flags / deployment surfaces.

Variant rules
-------------
nontx variants (e.g. ``nontx:nspk``):
  - ``role_map``: ``A`` / ``B`` / ``S`` -> three distinct random names from a
    pool (presentation only; the target still uses ``A`` / ``B`` internally,
    so the agent must map the presented naming onto the wire protocol).
  - ``nonce_bytes``: 8 / 16 / 32.
  - ``rsa_bits``: 2048 / 3072 (kept ``>= 2048`` for security).
  - ``port_offset``: small deterministic offset.

tx variants (e.g. ``tx:erc20_allowance_race``):
  - ``token_name`` / ``token_symbol`` from pools.
  - ``N``, ``M``, ``threshold = N + M`` (both ``> 0``), ``supply`` (``>>
    threshold``), ``decimals``.
  - Contract / function names are unchanged (they are standard); only
    parameter values change so any hardcoded POC amounts fail.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field


# ── stable task-id hashing ──────────────────────────────────────────────
# Python's built-in ``hash()`` is randomized per process (PYTHONHASHSEED),
# which would break cross-process determinism.  Use a truncated SHA-256
# instead so ``random.Random(seed + _task_hash(task_id))`` is reproducible.
def _task_hash(task_id: str) -> int:
    digest = hashlib.sha256(task_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


@dataclass
class VariantConfig:
    seed: int
    variant_id: str
    task_id_base: str
    params: dict
    role_map: dict
    description: str


# ── nontx variant pools ─────────────────────────────────────────────────
ROLE_NAME_POOL = [
    "Init", "Resp", "Dir", "Node", "Peer", "Agent", "Server", "Client",
    "Alice", "Bob", "Carol", "Dave", "Eve", "Mallory", "Trent", "Peggy",
    "Victor", "Wendy", "Zara", "Sam", "Oscar", "Ivan", "Pat", "Quinn",
]
NONCE_BYTES_CHOICES = [8, 16, 32]
RSA_BITS_CHOICES = [2048, 3072]

# ── tx variant pools ─────────────────────────────────────────────────────
TOKEN_NAME_POOL = [
    "RaceToken", "AlphaToken", "BetaCoin", "GammaToken", "DeltaToken",
    "EpsilonCoin", "ZetaToken", "EtaCoin", "ThetaToken", "IotaToken",
    "KappaCoin", "LambdaToken", "MuToken", "NuCoin", "XiToken",
    "OmicronToken", "PiCoin", "RhoToken", "SigmaCoin", "TauToken",
]
TOKEN_SYMBOL_POOL = [
    "RACE", "ALPH", "BETA", "GAMM", "DELT", "EPSI", "ZETA", "ETAC",
    "THET", "IOTA", "KAPP", "LAMB", "MUTK", "NUTK", "XITK", "OMIC",
    "PITK", "RHOX", "SIGM", "TAUT",
]
DECIMALS_CHOICES = [6, 18]


def _generate_nontx_variant(
    rng: random.Random, task_id: str, seed: int
) -> VariantConfig:
    names = rng.sample(ROLE_NAME_POOL, 3)
    role_map = {"A": names[0], "B": names[1], "S": names[2]}
    nonce_bytes = rng.choice(NONCE_BYTES_CHOICES)
    rsa_bits = rng.choice(RSA_BITS_CHOICES)
    port_offset = rng.randint(0, 1000)
    params = {
        "nonce_bytes": nonce_bytes,
        "rsa_bits": rsa_bits,
        "port_offset": port_offset,
    }
    description = (
        f"nontx variant {seed}: roles A/B/S -> "
        f"{names[0]}/{names[1]}/{names[2]}, "
        f"nonce_bytes={nonce_bytes}, rsa_bits={rsa_bits}, "
        f"port_offset={port_offset}"
    )
    return VariantConfig(
        seed=seed,
        variant_id=f"{task_id}#v{seed}",
        task_id_base=task_id,
        params=params,
        role_map=role_map,
        description=description,
    )


def _generate_tx_variant(
    rng: random.Random, task_id: str, seed: int
) -> VariantConfig:
    token_name = rng.choice(TOKEN_NAME_POOL)
    token_symbol = rng.choice(TOKEN_SYMBOL_POOL)
    decimals = rng.choice(DECIMALS_CHOICES)
    unit = 10 ** decimals
    n_tokens = rng.randint(50, 500)
    m_tokens = rng.randint(10, 200)
    N = n_tokens * unit
    M = m_tokens * unit
    threshold = N + M
    supply_mult = rng.randint(10, 1000)
    supply = threshold * supply_mult
    params = {
        "token_name": token_name,
        "token_symbol": token_symbol,
        "decimals": decimals,
        "N": N,
        "M": M,
        "threshold": threshold,
        "supply": supply,
    }
    description = (
        f"tx variant {seed}: token={token_name}({token_symbol}) "
        f"decimals={decimals} N={n_tokens} M={m_tokens} "
        f"threshold={n_tokens + m_tokens} supply_mult={supply_mult}"
    )
    return VariantConfig(
        seed=seed,
        variant_id=f"{task_id}#v{seed}",
        task_id_base=task_id,
        params=params,
        role_map={},
        description=description,
    )


def generate_variant(task_id: str, seed: int) -> VariantConfig:
    """Deterministically generate a variant config from ``task_id`` + ``seed``."""
    rng = random.Random(seed + _task_hash(task_id))
    kind = task_id.split(":", 1)[0] if ":" in task_id else ""
    if kind == "nontx":
        return _generate_nontx_variant(rng, task_id, seed)
    if kind == "tx":
        return _generate_tx_variant(rng, task_id, seed)
    return VariantConfig(
        seed=seed,
        variant_id=f"{task_id}#v{seed}",
        task_id_base=task_id,
        params={},
        role_map={},
        description=f"variant {seed} of {task_id}",
    )


def generate_variants(
    task_id: str, n: int, base_seed: int = 1000
) -> list[VariantConfig]:
    """Generate ``n`` distinct variants with seeds ``base_seed .. base_seed+n-1``."""
    return [generate_variant(task_id, base_seed + i) for i in range(n)]
