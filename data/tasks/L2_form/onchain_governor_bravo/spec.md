# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: proposal_threshold, vote_accounting, timelock_delay.

---

## Protocol: Compound Governor Bravo

**Category:** governance

### Overview

On-chain governance: holders delegate votes; a proposal requires a proposer threshold, then a voting period with quorum, then a timelock. Votes are checkpointed per block.

### Roles

- **Token holders**
- **Delegates**
- **Timelock**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `proposal_threshold` | Only accounts meeting the proposal threshold can propose. |
| 2 | `vote_accounting` | A delegator's votes are counted once per proposal and follow delegation checkpoints. |
| 3 | `timelock_delay` | Passed proposals cannot execute before the timelock. |

### Threat model

Adversary may acquire votes atomically (flash loans) or via delegation manipulation.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.compound.finance/v2/governance/
- Compound Governor Bravo
