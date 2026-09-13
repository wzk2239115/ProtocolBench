# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: oracle_price_integrity, pool_solvency, liquidation_correctness.

---

## Protocol: GMX Perpetual Exchange

**Category:** defi

### Overview

GMX is a pooled-liquidity perpetual DEX: traders open leveraged positions against a GLP/GM pool, pricing comes from an oracle, and liquidators/keepers close positions.

### Roles

- **Trader**
- **Liquidity provider**
- **Keeper**
- **Price oracle**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `oracle_price_integrity` | Positions are priced only from a manipulation-resistant oracle. |
| 2 | `pool_solvency` | Trader PnL cannot drain the LP pool beyond design limits. |
| 3 | `liquidation_correctness` | Liquidations execute only when the position is undercollateralized. |

### Threat model

Adversary manipulates the price feed or exploits keeper/execution ordering.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.gmx.io/
- GMX contracts
