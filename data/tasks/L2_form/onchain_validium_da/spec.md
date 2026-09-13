# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: validity_soundness, data_availability.

---

## Protocol: Validium (off-chain data availability)

**Category:** layer2

### Overview

A validity proof system where transaction data is kept off-chain (by a committee/DA layer) while only the state root and proof go on-chain.

### Roles

- **Operator**
- **DA committee**
- **L1 verifier**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `validity_soundness` | State updates are valid. |
| 2 | `data_availability` | All state data is retrievable so users can exit. |

### Threat model

Adversary controls the operator/DA committee and may withhold data.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- StarkEx Validium documentation
- https://ethereum.org/en/developers/docs/scaling/validium/
