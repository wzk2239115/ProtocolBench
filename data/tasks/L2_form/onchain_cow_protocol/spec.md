# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: uniform_clearing_price, user_limit_respected, solver_bond_safety.

---

## Protocol: CoW Protocol (batch auctions)

**Category:** mev

### Overview

CoW Protocol batches user orders and settles them with a uniform clearing price via solvers; orders are signed intents and the CoW settlement contract enforces interactions.

### Roles

- **User**
- **Solver**
- **Settlement contract**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `uniform_clearing_price` | All matched orders in a batch clear at the same price per token pair. |
| 2 | `user_limit_respected` | No order settles worse than its signed limit price. |
| 3 | `solver_bond_safety` | A malicious solver cannot steal user funds beyond its bond. |

### Threat model

Adversary is a solver choosing interactions and batch composition.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.cow.fi/
- CoW Protocol documentation
