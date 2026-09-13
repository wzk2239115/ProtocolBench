# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: pt_redemption_integrity, yt_yield_accounting, amm_solvency.

---

## Protocol: Pendle Yield Tokenization

**Category:** defi

### Overview

Pendle splits a yield-bearing asset into a principal token (PT) and a yield token (YT); PT redeems 1:1 at maturity, YT captures yield, and an AMM trades them.

### Roles

- **PT/YT trader**
- **LP**
- **Protocol**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `pt_redemption_integrity` | PT redeems exactly its principal at maturity. |
| 2 | `yt_yield_accounting` | YT claims exactly the yield accrued over its holding period. |
| 3 | `amm_solvency` | The PT/YT AMM remains solvent at maturity. |

### Threat model

Adversary manipulates the AMM or exploits yield-accounting indexing across time.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.pendle.finance/
