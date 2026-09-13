# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: publisher_quorum, staleness_detection, confidence_bounds.

---

## Protocol: Pyth Network Price Oracle

**Category:** oracle

### Overview

Pyth aggregates first-party publisher price feeds off-chain and posts them on-chain with signed updates (price, confidence, publish time); consumers pay to update and read.

### Roles

- **Publishers**
- **Pyth program**
- **Consumer**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `publisher_quorum` | A price is accepted only with enough publisher signatures and stake. |
| 2 | `staleness_detection` | Consumers can reject stale updates. |
| 3 | `confidence_bounds` | Consumers can account for the reported confidence interval. |

### Threat model

Adversary cannot compromise a publisher quorum; may exploit stale prices or confidence handling in consumers.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.pyth.network/
