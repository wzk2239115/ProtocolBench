# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: keeper_signature_binding, arbitrary_call_prevention.

---

## Protocol: Poly Network Bridge (keeper signatures)

**Category:** bridge

### Overview

Poly Network's cross-chain manager verifies a keeper signature over a cross-chain transaction header before releasing funds; the header includes the target chain and method.

### Roles

- **Keepers**
- **EthCrossChainManager**
- **User**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `keeper_signature_binding` | A cross-chain call is executed only if the keeper signature covers the exact (chain, method, args). |
| 2 | `arbitrary_call_prevention` | The manager never executes an attacker-chosen method on an attacker-chosen contract without a valid keeper signature. |

### Threat model

Adversary submits crafted cross-chain headers; cannot forge the keeper key.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Poly Network 2021 incident (~US$611M)
