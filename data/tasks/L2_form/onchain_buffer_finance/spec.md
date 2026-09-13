# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: oracle_price_integrity, solvency, liquidation_correctness.

---

## Protocol: Buffer Finance

**Category:** derivatives

### Overview

Buffer Finance is a production on-chain derivatives protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `oracle_price_integrity` | Positions are priced only from a manipulation-resistant source. |
| 2 | `solvency` | Trader PnL cannot drain the liquidity pool beyond design limits. |
| 3 | `liquidation_correctness` | Liquidations execute only when required. |

### Threat model

Adversary manipulates the price source or exploits execution ordering.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Derivatives protocol documentation
