# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: atomicity, timeout_fairness, no_free_option.

---

## Protocol: Eclair

**Category:** payment

### Overview

Eclair is a production on-chain payment protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `atomicity` | Either both legs settle or both are refunded. |
| 2 | `timeout_fairness` | A party cannot gain by delaying near a timeout. |
| 3 | `no_free_option` | A party cannot abandon after learning the witness without cost. |

### Threat model

Adversary is a rational counterparty with mempool/timing control and atomic composability.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Payment channel / HTLC documentation
