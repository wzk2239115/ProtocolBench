# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: anonymity, double_spend_prevention, unlinkability.

---

## Protocol: Secret Network

**Category:** privacy

### Overview

Secret Network is a production on-chain privacy protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `anonymity` | The sender/recipient cannot be linked within the anonymity set. |
| 2 | `double_spend_prevention` | A note/commitment can be spent at most once. |
| 3 | `unlinkability` | Deposits and withdrawals cannot be correlated. |

### Threat model

Adversary is an on-chain observer/relayer and may use metadata; cannot break the proof system.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Privacy protocol documentation
