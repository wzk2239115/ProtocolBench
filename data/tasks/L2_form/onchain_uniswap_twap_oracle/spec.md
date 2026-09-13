# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: twap_manipulation_resistance, accumulator_overflow_safety.

---

## Protocol: Uniswap V2 TWAP Oracle

**Category:** oracle

### Overview

Uniswap V2 pairs expose cumulative price accumulators (price0CumulativeLast, price1CumulativeLast); a consumer samples them over a window to obtain a time-weighted average price, resistant to single-block manipulation only if the window is long.

### Roles

- **Pool**
- **Oracle consumer**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `twap_manipulation_resistance` | The TWAP over the chosen window cannot be profitably manipulated within a single block. |
| 2 | `accumulator_overflow_safety` | Cumulative price accounting cannot overflow/underflow to forge a price. |

### Threat model

Adversary is a trader holding capital across the entire TWAP window (multi-block), or exploiting a short window.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.uniswap.org/contracts/v2/guides/smart-contract-integration/building-an-oracle
