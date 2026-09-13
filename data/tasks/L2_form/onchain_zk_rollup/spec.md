# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: validity_proof_soundness, no_forged_proof.

---

## Protocol: ZK Rollup (validity proofs)

**Category:** rollup

### Overview

A ZK rollup posts a validity proof (SNARK/STARK) with each state transition; L1 verifies the proof before accepting the new root, so no challenge window is needed.

### Roles

- **Prover/sequencer**
- **Verifier contract**
- **L1 bridge**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `validity_proof_soundness` | A state root is accepted only if a valid proof of the transition verifies. |
| 2 | `no_forged_proof` | An attacker cannot produce a proof for an invalid transition. |

### Threat model

Adversary cannot break the proof system's soundness; may censor or delay data availability.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://ethereum.org/en/developers/docs/scaling/zk-rollups/
- zkSync/StarkNet docs
