# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: batch_validity, forced_batch_liveness, emergency_state_consistency.

---

## Protocol: Polygon zkEVM

**Category:** layer2

### Overview

A zkEVM rollup with a verification contract, a trusted sequencer, and forced-batch/emergency mechanisms.

### Roles

- **Sequencer**
- **Aggregator**
- **L1 verifier**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `batch_validity` | Invalid batches cannot be verified. |
| 2 | `forced_batch_liveness` | A user's forced batch is eventually processed. |
| 3 | `emergency_state_consistency` | Emergency state transitions cannot steal funds. |

### Threat model

Adversary controls/withholds the sequencer; cannot break the proof system.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.polygon.technology/zkEVM/
