# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: solvency_invariant, interest_accrual_correctness.

---

## Protocol: Compound Lending Market

**Category:** lending

### Overview

Compound is an algorithmic money market: cTokens represent supplied assets, borrowing accrues interest, and liquidations repay debt in exchange for collateral at a discount. An interest-rate model and a comptroller gate actions.

### Roles

- **Supplier**
- **Borrower**
- **Liquidator**
- **Comptroller**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `solvency_invariant` | Accounts cannot borrow beyond their collateral factor. |
| 2 | `interest_accrual_correctness` | Borrow/supply indices accrue correctly and are not manipulable within a block. |

### Threat model

Adversary is a user exploiting oracle/price or interest-index timing; cannot break the accounting arithmetic.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.compound.finance/
- Compound cToken whitepaper
