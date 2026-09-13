# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: claim_exactly_once, claim_binding, no_proof_forgery.

---

## Protocol: Merkle-Proof Token Airdrop

**Category:** token

### Overview

An airdrop distributor commits to a Merkle root of (index, account, amount) leaves; each account claims by submitting a proof; claims are marked per index.

### Roles

- **Distributor**
- **Claimer**
- **Merkle tree**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `claim_exactly_once` | Each leaf can be claimed at most once. |
| 2 | `claim_binding` | The claimed account/amount match the committed leaf. |
| 3 | `no_proof_forgery` | No account can claim without a valid Merkle proof. |

### Threat model

Adversary submits arbitrary proofs/indices; cannot forge Merkle proofs.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Uniswap/MerkleDistributor reference
