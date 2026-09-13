# Task design

Three levels, all derived from the CrypFormBench spthy corpus (58 distinct
protocol theories; 5 with no provable goals were excluded, leaving 55).

## L1_verdict — property formulation & verdict (55 tasks)

**Given**: the complete theory with all security lemmas stripped
(`theory.spthy`) + `goals.md` (lemma names, quantifiers, NL description).

**Do**: formulate each goal as a Tamarin lemma (name and quantifier are
binding; helper/source lemmas allowed), drive `--prove` to termination,
deliver `final.spthy` + `verdict.json` (+ `attack_report.md` when UNSAFE).

**Why**: tests the core agentic skill — knowing *what* to verify and
driving an interactive prover — without free-form modeling noise. The agent
does not know whether the protocol is safe; 46 of the 55 are SAFE, 9 hide
attacks.

## L2_form — modeling from a natural-language spec (10 tasks)

**Given**: `spec.md` only (CrypFormBench's NL protocol descriptions).

**Do**: build the full theory from scratch, verify, discover the attack.

**Selection**: the 10 attack-bearing protocols of the corpus (NSPK3,
CCITT-X509-R, dh_alternative, ...) — every ground truth is UNSAFE, so the
level measures attack discovery through honest modeling.

## L3_repair — theory repair & attack discovery (10 tasks)

**Given**: `broken.spthy` (CrypFormBench's `errorcode` variants: syntax /
wellformedness / modeling errors) + `error_hint.txt`.

**Do**: repair the theory, verify, and determine the verdict.

**Selection**: NSPK3 and RYY_PFS use the *falsely-passing* variants
(the broken model masks a real attack — the agent must both repair and
discover); the rest are error variants with mixed verdicts.

## On-chain protocols (L2_form, spec-only, attack tasks)

> **1,259 tasks**, all framed as *find the attack* (ground truth `UNSAFE`).

Real, production-deployed on-chain transaction protocols. The agent gets only
`spec.md` (protocol identity + security goals + threat model + references) and
is free to choose its method and modeling strategy — **no Lean (or Tamarin)
model is provided**. The agent decides whether to formalise first or to reason
about the flaw directly, and must back its verdict with machine-checkable
evidence. Networked research tools are enabled, so the agent fetches the
detailed specs/RFCs and public incident analyses itself.

The catalog is `data/onchain/protocols.json`; regenerate/update tasks with:

```bash
PYTHONPATH=src .venv/bin/python scripts/add_onchain_tasks.py [--force]
```

Each entry becomes `data/tasks/L2_form/onchain_<slug>/` with `spec.md`,
`task.json`, and hidden `solution/{ground_truth.json,reference.md}`. The task
list `data/task_ids/onchain.txt` is rebuilt by scanning the directories, so
hand-authored on-chain tasks are preserved.

Current coverage (add more entries to the catalog to extend):

| Category | Protocols |
|----------|-----------|
| Tokens / standards | ERC-20 allowance race, ERC-2612 permit, ERC-2771 meta-tx, ERC-4337, ERC-777, ERC-1155, ERC-4626, ERC-1967, WETH, Merkle airdrop |
| DEX / AMM | Uniswap V2/V3, Curve StableSwap, Balancer, sandwich |
| Lending / stablecoin | Compound, Aave, MakerDAO, Liquity, Euler, Cream |
| Oracles | Chainlink feeds, Uniswap V2 TWAP |
| Bridges / interop | Nomad, Wormhole, Ronin, Poly Network, Multichain, Harmony Horizon, BNB bridge, THORChain, IBC, XCMP, LayerZero |
| Payment / channels | HTLC atomic swap, Lightning channel, replacement cycling, Raiden, submarine swap, adaptor-signature swap |
| Consensus | Nakamoto PoW, Casper FFG, Tendermint, HotStuff, Algorand BA*, Ouroboros Praos, Avalanche, Stellar SCP |
| Signatures / multisig | ECDSA malleability, Schnorr rogue key, BLS threshold, Gnosis Safe, Parity multisig |
| Governance | Governor Bravo, ERC-1967 upgradeable proxy |
| Rollups / ZK | Optimistic rollup, ZK rollup, Groth16, PLONK |
| MEV / ordering | Flashbots/PBS, sandwich |
| Cross-chain replay | pre-EIP-155 signed transactions |
| Bridge (example) | Nomad lock-and-mint |

## Ground truth

`solution/ground_truth.json` per task, produced by
`scripts/validate_tasks.py` (real Tamarin 1.12.0 runs in the verifier
image): overall verdict, per-lemma verdicts + proof steps, and per falsified
lemma the **protocol-rule event sequences** of every attack trace
(`--output-json`). Ground truth never enters the agent workspace.

Special cases handled:

- diff-term theories (`probEnc`, `issue193`, ...) run with `--diff`; their
  goal is the default observational-equivalence check.
- Theories whose lemmas live inside (nested!) block comments or `#ifdef`
  regions have no provable goals — excluded at conversion time.
- `falsified - no trace found` (negated exists-trace) counts as falsified.

## Anti-cheat

The objective checks are the primary defense (structure + clean-container
re-run). The prompt-level ground rules forbid altering given rules and
weakening goals; `check_given_rules_unchanged` (normalized SHA-256 per
block), `check_lemma_coverage`, `check_lemma_fact_references` and
`check_no_trivial_lemmas` enforce them mechanically.

Networked research tools (`WebSearch`/`WebFetch`, plus `Bash`-driven HTTP)
are **enabled by default**: agents batch-run real deployed protocols and are
expected to fetch specs/RFCs and public analyses themselves, so no protocol
material is bundled beyond the task's own `spec.md`. The container has outbound
network access, but Claude Code's `WebFetch`/`WebSearch` may be unavailable
through third-party model endpoints, so the prompt tells the agent to use
`Bash` + `curl`/`urllib` instead. Pass `--disable-web-search` (run_protocol.py)
for a no-network ablation.

For the **Lean/on-chain attack track** the deterministic checks are:

| check | weight | requires |
|-------|--------|----------|
| `attack_evidence` | 0.6 | `final.lean` compiles, contains no `sorry`/`admit`/`axiom`/`unsafe`, and defines **every** required goal name (`task.json:lemma_names`) as a `theorem`/`def` |
| `verdict_unsafe` | 0.2 | `verdict.json` says `UNSAFE` and lists `attack_lemmas` |
| `attack_report` | 0.2 | `attack_report.md` present and substantive (>= 200 chars) |

There is no stored SAFE/UNSAFE label to match: a task scores by producing
machine-checkable attack evidence. Semantic acceptance (is the attack real, is
it the target flaw, are the witnesses sound?) is a separate judge stage.

**Trajectories** are collected per task: `trajectory/projects/-workspace/*.jsonl`
(the native Claude Code session, resumable) plus `trajectory/claude_code.log`.

## Difficulty axes (future)

- Information provided: with/without `goals.md` lemma names, with/without
  the NL spec (L1 → L2 continuum).
- Tooling: allow/disallow `--auto-sources`, oracles.
- Budget: per-task timeout (Tamarin non-termination is a real constraint).
