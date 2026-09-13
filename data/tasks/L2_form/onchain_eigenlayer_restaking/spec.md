# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: slashing_completeness, withdrawal_safety, no_double_slashing.

---

## Protocol: EigenLayer Restaking

**Category:** defi

### Overview

EigenLayer lets ETH stakers opt into additional services (AVSs) with slashing conditions, re-using stake for economic security.

### Roles

- **Restaker**
- **Operator**
- **AVS**
- **EigenLayer core**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `slashing_completeness` | Misbehaviour defined by an AVS is slashable. |
| 2 | `withdrawal_safety` | Stake cannot be withdrawn while slashable obligations are open. |
| 3 | `no_double_slashing` | A stake cannot be slashed beyond its size across AVSs. |

### Threat model

Adversary is an operator/AVS colluding to avoid slashing or to slash unfairly.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.eigenlayer.xyz/
- EigenLayer whitepaper
