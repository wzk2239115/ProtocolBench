# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: output_root_soundness, withdrawal_safety, censorship_resistance.

---

## Protocol: OP Stack Optimistic Rollup

**Category:** layer2

### Overview

Optimistic rollup with a single-round interactive fault proof (cannon) over an L2 output root, plus a dispute game with a challenger bond.

### Roles

- **Sequencer**
- **Proposer**
- **Challenger**
- **L1 bridge**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `output_root_soundness` | A challenged invalid output root is rejected. |
| 2 | `withdrawal_safety` | Withdrawals cannot release against an invalid root. |
| 3 | `censorship_resistance` | Users can force-include deposits via L1. |

### Threat model

Adversary is the sequencer and may censor; challenger must be live.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.optimism.io/
- OP Stack specifications
