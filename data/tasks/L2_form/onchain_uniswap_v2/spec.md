# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: constant_product_invariant, lp_solvency.

---

## Protocol: Uniswap V2 AMM

**Category:** dex

### Overview

Constant-product AMM: each pair holds reserves (x, y) and enforces x*y = k; swaps add to one reserve and remove from the other with a 0.3% fee; mint/burn provide liquidity. A cumulative price accumulator supports TWAP.

### Roles

- **Trader**
- **Liquidity provider**
- **Pair contract**
- **Router**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `constant_product_invariant` | After every swap, reserveX * reserveY does not decrease. |
| 2 | `lp_solvency` | Liquidity providers can redeem a share of reserves proportional to their pool tokens. |

### Threat model

Adversary is a trader/liquidity provider with atomic composability (flash loans); cannot break the invariant arithmetic.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.uniswap.org/contracts/v2/overview
- https://uniswap.org/whitepaper.pdf
