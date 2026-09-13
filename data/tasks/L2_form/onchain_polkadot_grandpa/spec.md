# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: safety, liveness.

---

## Protocol: Polkadot GRANDPA Finality

**Category:** consensus

### Overview

GRANDPA finalizes chains (not blocks) by having validators vote on the best chain containing a set of blocks, with a supermajority and a multi-round protocol.

### Roles

- **Validators**
- **Voters**
- **Relay chain**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `safety` | Two finalized chains never conflict. |
| 2 | `liveness` | Finality progresses with >2/3 honest validators. |

### Threat model

Adversary controls <1/3 of stake (and performs the accountable-fault attribution otherwise).

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://wiki.polkadot.network/docs/learn-consensus
- GRANDPA (2019)
