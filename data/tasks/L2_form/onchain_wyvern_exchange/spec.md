# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: order_binding, no_reentrancy.

---

## Protocol: Wyvern Exchange

**Category:** nft

### Overview

Wyvern (early OpenSea) matches signed sell/offer orders with a delegate/registry pattern using CALL/DELEGATECALL target specifications.

### Roles

- **Maker**
- **Taker**
- **Wyvern contract**
- **Proxy registry**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `order_binding` | The executed transfer matches the signed order's target and calldata. |
| 2 | `no_reentrancy` | Matching cannot be reentered to double-fill an order. |

### Threat model

Adversary supplies crafted targets/calldata and reentrancy.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Wyvern Protocol v3 documentation
