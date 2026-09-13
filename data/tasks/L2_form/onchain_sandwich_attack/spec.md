# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: no_sandwich_profit, slippage_protection.

---

## Protocol: AMM Sandwich Attack

**Category:** mev

### Overview

A DEX trade is sandwiched when an adversary places a buy before and a sell after a victim's swap in the same block, profiting from the price impact and slippage the victim tolerates.

### Roles

- **Victim trader**
- **Sandwicher (searcher)**
- **Block builder**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `no_sandwich_profit` | No ordering of a victim's swap with adversarial swaps yields the adversary a guaranteed profit at the victim's expense. |
| 2 | `slippage_protection` | The victim's min-output bound limits the adversary's extraction. |

### Threat model

Adversary controls transaction ordering (or pays a builder) and can craft atomic swaps around a pending victim transaction.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- MEV literature
- https://ethereum.org/en/developers/docs/mev/
