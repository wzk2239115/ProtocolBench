# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: blob_availability, commitment_binding.

---

## Protocol: EigenDA (restaked data availability)

**Category:** da

### Overview

EigenDA uses restaked operators with erasure coding and KZG commitments, where operators attest to storing blobs and can be slashed.

### Roles

- **Operators**
- **Disperser**
- **EigenLayer restakers**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `blob_availability` | Committed blobs are retrievable or the responsible operators are slashed. |
| 2 | `commitment_binding` | KZG commitments bind the erasure-coded data. |

### Threat model

Adversary controls <1/3 restaked stake and may withhold blobs.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.eigenlayer.xyz/eigenda/
- EigenDA whitepaper
