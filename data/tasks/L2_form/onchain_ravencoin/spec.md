# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: safety, liveness, fork_choice_correctness, no_double_spend.

---

## Protocol: Ravencoin

**Category:** consensus

### Overview

Ravencoin is a production on-chain consensus protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `safety` | No two correct nodes commit conflicting finalized blocks or values. |
| 2 | `liveness` | Under the protocol's synchrony and fault assumptions, the chain keeps making progress. |
| 3 | `fork_choice_correctness` | The fork-choice / finality rule never reverts an already-finalized block under the fault bound. |
| 4 | `no_double_spend` | A confirmed transaction cannot be reverted without exceeding the protocol's fault budget. |

### Threat model

An adversary controls up to the protocol's fault threshold (stake/hashrate/<1/3 BFT) and may delay or reorder messages and be a leader in some rounds.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Protocol whitepaper / consensus specification
- https://ethereum.org/en/developers/docs/consensus-mechanisms/
