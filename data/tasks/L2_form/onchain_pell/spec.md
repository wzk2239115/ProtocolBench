# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: slashing_completeness, withdrawal_safety, no_double_slashing.

---

## Protocol: Pell

**Category:** restaking

### Overview

Pell is a production on-chain restaking protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `slashing_completeness` | Defined misbehaviour is eventually slashable. |
| 2 | `withdrawal_safety` | Stake cannot be withdrawn while slashable obligations are open. |
| 3 | `no_double_slashing` | Stake is not double-counted across services. |

### Threat model

Adversary is an operator/service colluding to avoid or weaponize slashing.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Restaking protocol documentation
