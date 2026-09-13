# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: health_factor_soundness, flashloan_repayment.

---

## Protocol: Aave Lending Pool

**Category:** lending

### Overview

Aave is a pooled lending protocol with variable/stable rates, aTokens, debt tokens, health-factor gating, and flash loans; aToken transfers can trigger receiver hooks via `onERC1155`-style callbacks in some configurations.

### Roles

- **Supplier**
- **Borrower**
- **Liquidator**
- **Flash-loan user**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `health_factor_soundness` | Borrowing/withdrawals are rejected when the health factor would fall below 1. |
| 2 | `flashloan_repayment` | A flash loan transaction reverts unless principal plus fee is repaid. |

### Threat model

Adversary uses flash loans and composability; cannot break the accounting.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.aave.com/
- Aave V2/V3 technical papers
