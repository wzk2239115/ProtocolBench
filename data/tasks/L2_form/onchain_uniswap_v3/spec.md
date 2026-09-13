# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: range_liquidity_solvency, swap_price_correctness.

---

## Protocol: Uniswap V3 Concentrated Liquidity

**Category:** dex

### Overview

V3 lets LPs concentrate liquidity in price ranges using ticks and positions; swaps cross initialized ticks and apply concentrated liquidity, with a price-dependent fee.

### Roles

- **Trader**
- **Liquidity provider**
- **Pool contract**
- **NFT position manager**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `range_liquidity_solvency` | Liquidity in a range is correctly added/removed at tick boundaries. |
| 2 | `swap_price_correctness` | The pool price changes only according to reserve changes and fee growth. |

### Threat model

Adversary is a trader/LP exploiting tick crossing and fee accounting.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.uniswap.org/contracts/v3/overview
- https://uniswap.org/whitepaper-v3.pdf
