# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: safety, locking_correctness, liveness.

---

## Protocol: Tendermint / CometBFT Consensus

**Category:** consensus

### Overview

Tendermint is a BFT consensus with proposer/prevote/precommit rounds; a block is committed when >2/3 of validators precommit. Locking prevents conflicting commits across rounds.

### Roles

- **Validators**
- **Proposers**
- **Full nodes**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `safety` | Two correct validators never commit conflicting blocks at the same height. |
| 2 | `locking_correctness` | A validator only unlocks on a valid polka for a higher round. |
| 3 | `liveness` | With <1/3 Byzantine and partial synchrony, the chain makes progress. |

### Threat model

Adversary controls <1/3 of voting power and can delay messages.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.tendermint.com/
- Buchman, Tendermint (2016)
