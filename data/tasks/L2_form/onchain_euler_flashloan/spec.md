# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: health_score_soundness, reserve_accounting.

---

## Protocol: Euler Finance (donate / health check)

**Category:** lending

### Overview

Euler is a permissionless lending protocol; users supply/borrow, and a health score based on collateral and debt gates actions. It supports flash loans and a donateToReserves function.

### Roles

- **Supplier**
- **Borrower**
- **Liquidator**
- **Flash-loan user**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `health_score_soundness` | No action sequence leaves an account with debt exceeding its collateral value. |
| 2 | `reserve_accounting` | donateToReserves changes accounting only as intended and cannot be used to manipulate the health score. |

### Threat model

Adversary is an unprivileged user with flash-loan capital and atomic composition.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.euler.finance/
- Euler Finance 2023 exploit analyses
