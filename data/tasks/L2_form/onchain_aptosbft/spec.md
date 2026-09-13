# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: safety, liveness.

---

## Protocol: AptosBFT

**Category:** consensus

### Overview

AptosBFT is a chained BFT consensus (HotStuff-like) with a leader reputation/pipeline and a round-based quorum certificate.

### Roles

- **Validators**
- **Leader**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `safety` | No two correct validators commit conflicting blocks. |
| 2 | `liveness` | After GST a correct leader commits. |

### Threat model

Adversary controls <1/3 of voting power.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://aptos.dev/
- AptosBFT paper
