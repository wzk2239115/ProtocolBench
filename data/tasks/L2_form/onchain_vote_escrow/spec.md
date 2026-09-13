# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: proposal_threshold, vote_accounting, timelock_delay.

---

## Protocol: Vote Escrow

**Category:** governance

### Overview

Vote Escrow is a production on-chain governance protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `proposal_threshold` | Only accounts meeting the threshold can propose. |
| 2 | `vote_accounting` | Votes are counted once and respect snapshots/delegation. |
| 3 | `timelock_delay` | Passed proposals respect the timelock before execution. |

### Threat model

Adversary acquires voting power atomically or via delegation manipulation; cannot break the token.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Governance framework documentation
