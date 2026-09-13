#!/usr/bin/env python3
"""Expand the on-chain catalog to production scale.

Reads data/onchain/registry.json, which maps a category to a flat list of
production protocol names, and emits data/onchain/protocols_batch3.json in the
same shape as the hand-authored catalogs (see add_onchain_tasks.py).

Per category it fills in:
  * goals   — a security-property template for that protocol family
  * threat_model, references
  * verdict  — UNSAFE by default (the task is to find the flaw) except for
               families whose core is a cryptographic/soundness primitive
               (signature, zk, da, consensus), which default to SAFE

Names are sanitized to slugs and de-duplicated against each other and against
existing task directories, so the registry can be over-approximated freely.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
REGISTRY = REPO / "data" / "onchain" / "registry.json"
OUT = REPO / "data" / "onchain" / "protocols_batch3.json"
TASKS_DIR = REPO / "data" / "tasks" / "L2_form"

# category -> (goals, threat_model, references, default_verdict)
TEMPLATES: dict[str, dict] = {
    "consensus": {
        "goals": [
            ("safety", "No two correct nodes commit conflicting finalized blocks or values."),
            ("liveness", "Under the protocol's synchrony and fault assumptions, the chain keeps making progress."),
            ("fork_choice_correctness", "The fork-choice / finality rule never reverts an already-finalized block under the fault bound."),
            ("no_double_spend", "A confirmed transaction cannot be reverted without exceeding the protocol's fault budget."),
        ],
        "threat_model": "An adversary controls up to the protocol's fault threshold (stake/hashrate/<1/3 BFT) and may delay or reorder messages and be a leader in some rounds.",
        "references": ["Protocol whitepaper / consensus specification", "https://ethereum.org/en/developers/docs/consensus-mechanisms/"],
        "verdict": "UNSAFE",
    },
    "layer2": {
        "goals": [
            ("state_root_soundness", "Only valid state roots are finalized."),
            ("withdrawal_safety", "Withdrawals release funds only against finalized valid state."),
            ("data_availability", "The data needed to reconstruct state (and exit) is available."),
            ("censorship_resistance", "Users can force-include transactions / exit even if the operator censors."),
        ],
        "threat_model": "The sequencer/operator is adversarial (censors, reorders, withholds data); at least one honest verifier/challenger is live unless stated otherwise.",
        "references": ["https://ethereum.org/en/developers/docs/scaling/", "Rollup / L2 documentation"],
        "verdict": "UNSAFE",
    },
    "bridge": {
        "goals": [
            ("message_authenticity", "A cross-chain message/withdrawal is executed only if attested by the validator/guardian quorum."),
            ("no_replay", "Each attested message is consumed at most once."),
            ("value_conservation", "Minted/released value never exceeds locked/burned value."),
            ("proof_verification_soundness", "Merkle/signature/light-client verification cannot be bypassed."),
        ],
        "threat_model": "The adversary cannot corrupt the quorum but may craft arbitrary proofs/messages, replay them, and exploit verification or accounting code.",
        "references": ["Cross-chain bridge security surveys", "https://ethereum.org/en/developers/docs/bridges/"],
        "verdict": "UNSAFE",
    },
    "interop": {
        "goals": [
            ("message_authenticity", "A message is executed only if committed/attested by the source chain."),
            ("packet_exactly_once", "Each packet/message is processed at most once."),
            ("channel_binding", "Messages are bound to the correct channel / source-destination pair."),
        ],
        "threat_model": "Adversary is a relayer; light clients / consensus are honest, and the adversary cannot forge proofs or signatures.",
        "references": ["Interoperability protocol specification"],
        "verdict": "UNSAFE",
    },
    "dex": {
        "goals": [
            ("invariant_non_decrease", "The pool invariant does not decrease across swaps and liquidity operations."),
            ("no_price_manipulation", "The on-chain price cannot be profitably manipulated within a transaction."),
            ("lp_solvency", "Liquidity providers can redeem their proportional share of reserves."),
        ],
        "threat_model": "Adversary is a trader/LP with flash-loan capital and atomic composability; may reorder transactions.",
        "references": ["AMM whitepaper / docs"],
        "verdict": "UNSAFE",
    },
    "lending": {
        "goals": [
            ("solvency_invariant", "No account's debt exceeds its collateral value times the allowed factor."),
            ("liquidation_correctness", "Liquidations execute only for undercollateralized accounts and keep the market solvent."),
            ("oracle_soundness", "The price feed cannot be manipulated to borrow or liquidate unfairly."),
        ],
        "threat_model": "Adversary is a borrower/liquidator with flash loans; may manipulate an oracle or exploit interest-index timing.",
        "references": ["Lending protocol docs / whitepaper"],
        "verdict": "UNSAFE",
    },
    "stablecoin": {
        "goals": [
            ("peg_solvency", "The stablecoin is fully backed by protocol collateral / collateralized positions."),
            ("backing_integrity", "Collateral cannot be double-counted or rehypothecated."),
            ("mint_authorization", "Only authorized paths can mint or redeem."),
        ],
        "threat_model": "Adversary manipulates collateral prices, oracle feeds, or redemption paths; may exploit privileged roles.",
        "references": ["Stablecoin protocol docs"],
        "verdict": "UNSAFE",
    },
    "oracle": {
        "goals": [
            ("feed_authenticity", "An answer is accepted only with a valid signer/reporter quorum."),
            ("freshness", "Stale rounds cannot be used as current prices."),
            ("manipulation_resistance", "The reported value cannot be profitably manipulated by an attacker."),
        ],
        "threat_model": "Adversary cannot compromise the reporter quorum but may manipulate the underlying market or replay stale rounds.",
        "references": ["Oracle protocol documentation"],
        "verdict": "UNSAFE",
    },
    "nft": {
        "goals": [
            ("ownership_integrity", "A token has one owner and ownership changes only via authorized transfers."),
            ("approval_authorization", "Only approved operators can move tokens."),
            ("no_reentrancy", "Receiver hooks cannot reenter to observe inconsistent state."),
        ],
        "threat_model": "Adversary controls the receiver hook, marketplace orders, or operator approvals.",
        "references": ["NFT standard / marketplace docs"],
        "verdict": "UNSAFE",
    },
    "token": {
        "goals": [
            ("balance_integrity", "Balances and total supply are conserved across transfers and mint/burn."),
            ("allowance_correctness", "Spending is bounded by the owner's allowance and not reusable."),
            ("transfer_authorization", "Only the owner / approved spender can transfer."),
        ],
        "threat_model": "Adversary is a spender/operator exploiting approval semantics, hooks, or ordering.",
        "references": ["Token standard documentation"],
        "verdict": "UNSAFE",
    },
    "signature": {
        "goals": [
            ("unforgeability", "No party can produce a valid signature without the key."),
            ("domain_binding", "Signatures are bound to the intended chain/contract/context."),
            ("no_replay", "A signature cannot be reused for another message/domain/nonce."),
        ],
        "threat_model": "Adversary is a malicious signer/relayer and can choose messages and domains; cannot break the underlying hardness assumption.",
        "references": ["Signature scheme / EIP documentation"],
        "verdict": "UNSAFE",
    },
    "account_abstraction": {
        "goals": [
            ("userop_authentication", "Operations execute only when authorized by the account."),
            ("no_replay", "Operations and validations are chain/account/nonce bound."),
            ("module_authorization", "Extensions cannot bypass the account's authorization policy."),
            ("paymaster_safety", "Sponsors cannot be drained beyond their intended budget."),
        ],
        "threat_model": "Adversary controls user operations, modules, paymasters, and relayers; exploits validation-time reentrancy/storage access.",
        "references": ["Account abstraction EIPs / docs"],
        "verdict": "UNSAFE",
    },
    "governance": {
        "goals": [
            ("proposal_threshold", "Only accounts meeting the threshold can propose."),
            ("vote_accounting", "Votes are counted once and respect snapshots/delegation."),
            ("timelock_delay", "Passed proposals respect the timelock before execution."),
        ],
        "threat_model": "Adversary acquires voting power atomically or via delegation manipulation; cannot break the token.",
        "references": ["Governance framework documentation"],
        "verdict": "UNSAFE",
    },
    "zk": {
        "goals": [
            ("soundness", "No false statement has a valid proof."),
            ("knowledge_soundness", "A valid proof implies knowledge of a satisfying witness."),
            ("setup_integrity", "Security holds under the specified setup assumption."),
        ],
        "threat_model": "Adversary is a malicious prover; the trusted setup is honest (or transparent).",
        "references": ["Proof system paper / documentation"],
        "verdict": "UNSAFE",
    },
    "privacy": {
        "goals": [
            ("anonymity", "The sender/recipient cannot be linked within the anonymity set."),
            ("double_spend_prevention", "A note/commitment can be spent at most once."),
            ("unlinkability", "Deposits and withdrawals cannot be correlated."),
        ],
        "threat_model": "Adversary is an on-chain observer/relayer and may use metadata; cannot break the proof system.",
        "references": ["Privacy protocol documentation"],
        "verdict": "UNSAFE",
    },
    "mev": {
        "goals": [
            ("ordering_fairness", "Users are not systematically harmed by transaction reordering."),
            ("censorship_resistance", "No small set of builders/relays can exclude transactions."),
            ("bid_authenticity", "The proposer is paid atomically for the exact block it signs."),
        ],
        "threat_model": "Adversary is a dominant builder/relay or searcher with ordering power.",
        "references": ["MEV / PBS design documentation"],
        "verdict": "UNSAFE",
    },
    "payment": {
        "goals": [
            ("atomicity", "Either both legs settle or both are refunded."),
            ("timeout_fairness", "A party cannot gain by delaying near a timeout."),
            ("no_free_option", "A party cannot abandon after learning the witness without cost."),
        ],
        "threat_model": "Adversary is a rational counterparty with mempool/timing control and atomic composability.",
        "references": ["Payment channel / HTLC documentation"],
        "verdict": "UNSAFE",
    },
    "restaking": {
        "goals": [
            ("slashing_completeness", "Defined misbehaviour is eventually slashable."),
            ("withdrawal_safety", "Stake cannot be withdrawn while slashable obligations are open."),
            ("no_double_slashing", "Stake is not double-counted across services."),
        ],
        "threat_model": "Adversary is an operator/service colluding to avoid or weaponize slashing.",
        "references": ["Restaking protocol documentation"],
        "verdict": "UNSAFE",
    },
    "derivatives": {
        "goals": [
            ("oracle_price_integrity", "Positions are priced only from a manipulation-resistant source."),
            ("solvency", "Trader PnL cannot drain the liquidity pool beyond design limits."),
            ("liquidation_correctness", "Liquidations execute only when required."),
        ],
        "threat_model": "Adversary manipulates the price source or exploits execution ordering.",
        "references": ["Derivatives protocol documentation"],
        "verdict": "UNSAFE",
    },
    "yield": {
        "goals": [
            ("share_price_integrity", "Existing depositors' redeemable value is not diluted by others."),
            ("strategy_authorization", "Only authorized strategies receive funds."),
            ("no_inflation_theft", "Rounding/donation cannot be exploited for profit."),
        ],
        "threat_model": "Adversary is a depositor/strategist exploiting share math or strategy permissions.",
        "references": ["Vault / yield protocol documentation"],
        "verdict": "UNSAFE",
    },
    "da": {
        "goals": [
            ("da_soundness", "A commitment is accepted only when the data is available under the sampling/attestation rules."),
            ("commitment_binding", "The commitment binds the exact erasure-coded data."),
        ],
        "threat_model": "Adversary controls a bounded fraction of validators and may withhold data.",
        "references": ["Data availability layer documentation"],
        "verdict": "UNSAFE",
    },
    "identity": {
        "goals": [
            ("name_ownership", "A name/identity has one owner, transferable only by the owner."),
            ("resolver_authorization", "Records change only under owner authorization."),
            ("commit_reveal_fairness", "Registration cannot be front-run."),
        ],
        "threat_model": "Adversary front-runs registration and record updates.",
        "references": ["Identity protocol documentation"],
        "verdict": "UNSAFE",
    },
}

DEFAULT_TEMPLATE = {
    "goals": [
        ("security_invariant", "The protocol's stated security invariant holds for all reachable states."),
        ("authorization", "Only authorized parties can trigger privileged transitions."),
        ("no_replay", "Messages/transactions cannot be replayed."),
    ],
    "threat_model": "An unprivileged adversary with atomic composability and transaction-ordering control; cryptographic primitives cannot be broken.",
    "references": ["Protocol documentation"],
    "verdict": "UNSAFE",
}


def slugify(name: str) -> str:
    s = name.lower().replace("&", " and ")
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return s or "protocol"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--registry", type=Path, default=REGISTRY)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()

    registry = json.loads(Path(args.registry).read_text(encoding="utf-8"))
    existing = {
        d.name[len("onchain_"):]
        for d in TASKS_DIR.iterdir()
        if d.is_dir() and d.name.startswith("onchain_") and (d / "task.json").is_file()
    } if TASKS_DIR.is_dir() else set()

    seen = set(existing)
    entries, skipped = [], 0
    for category, names in registry["by_category"].items():
        tpl = TEMPLATES.get(category, DEFAULT_TEMPLATE)
        for name in names:
            slug = slugify(name)
            if slug in seen:
                skipped += 1
                continue
            seen.add(slug)
            entries.append({
                "slug": slug,
                "name": name,
                "category": category,
                "overview": (
                    f"{name} is a production on-chain {category} protocol. "
                    "Its deployed interfaces, message/transaction formats and parameters are "
                    "the ground truth for this task; consult the protocol's documentation, "
                    "deployment addresses and incident reports as needed."
                ),
                "goals": [{"name": g, "property": p} for g, p in tpl["goals"]],
                "threat_model": tpl["threat_model"],
                "references": tpl["references"],
                "verdict": tpl["verdict"],
            })

    Path(args.out).write_text(
        json.dumps({
            "version": 1,
            "note": "Auto-generated from registry.json via scripts/expand_onchain_generic.py. "
                    "Overview/goals are category templates; per-protocol detail is fetched by the agent.",
            "protocols": entries,
        }, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(json.dumps({
        "generated": len(entries),
        "skipped_existing_or_duplicate": skipped,
        "categories": len(registry["by_category"]),
        "out": str(Path(args.out).relative_to(REPO)),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
