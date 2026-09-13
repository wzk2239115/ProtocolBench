# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: safety, liveness.

---

## Protocol: Algorand BA*

**Category:** consensus

### Overview

Algorand uses cryptographic sortition to select committees per step and a BA* protocol with graded consensus and a binary agreement, giving probabilistic finality with negligible fork probability.

### Roles

- **Users/validators**
- **Committee members**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `safety` | The probability that two blocks are finalized at the same height is negligible. |
| 2 | `liveness` | Under partial synchrony and honest majority of money, blocks finalize. |

### Threat model

Adversary controls a bounded fraction of stake/money; can corrupt selected committee members adaptively.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://algorand.com/
- Chen & Micali, Algorand (2019)
