# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: validity_soundness, state_commitment_binding.

---

## Protocol: Starknet (STARK validity rollup)

**Category:** layer2

### Overview

A zk rollup using STARK proofs of a Cairo-based state transition, verified on L1, with a sequencer and provers.

### Roles

- **Sequencer**
- **Prover**
- **L1 verifier**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `validity_soundness` | A state update is accepted only with a valid STARK. |
| 2 | `state_commitment_binding` | The proof binds the exact new state root and consumed messages. |

### Threat model

Adversary cannot break STARK soundness; sequencer may censor.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.starknet.io/
- StarkNet/Cairo documentation
