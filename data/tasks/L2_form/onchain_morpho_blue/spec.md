# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: market_solvency, oracle_soundness, no_bad_debt.

---

## Protocol: Morpho Blue

**Category:** lending

### Overview

Morpho Blue is a minimal immutable lending primitive: each market is a single (collateral, loan, oracle, IRM, LLTV) tuple; positions are matched peer-to-peer with a fallback to the underlying protocol.

### Roles

- **Supplier**
- **Borrower**
- **Liquidator**
- **Curator**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `market_solvency` | Positions cannot exceed the market's LLTV. |
| 2 | `oracle_soundness` | The market oracle cannot be manipulated to liquidate or borrow unfairly. |
| 3 | `no_bad_debt` | Liquidations keep markets solvent. |

### Threat model

Adversary manipulates a market's oracle or exploits isolated-market parameter choices.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.morpho.org/
- Morpho Blue whitepaper
