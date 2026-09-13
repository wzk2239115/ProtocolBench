# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: order_authorization, consideration_satisfaction, order_expiry.

---

## Protocol: OpenSea Seaport

**Category:** nft

### Overview

Seaport is a marketplace protocol where orders are signed structs (offers/considerations) matched on-chain; fulfillments specify how to transfer items, and an order hash is the offer identifier.

### Roles

- **Offerer**
- **Fulfiller**
- **Seaport contract**
- **Zone**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `order_authorization` | Only orders signed by the offerer are fulfilled as specified. |
| 2 | `consideration_satisfaction` | All consideration items are paid before the offer is transferred. |
| 3 | `order_expiry` | Expired or cancelled orders cannot be fulfilled. |

### Threat model

Adversary crafts orders, tips, and fulfillment components; cannot forge signatures.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://github.com/ProjectOpenSea/seaport
- Seaport documentation
