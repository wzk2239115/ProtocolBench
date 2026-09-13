# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: invariant_non_decrease, virtual_price_monotonicity.

---

## Protocol: Curve StableSwap

**Category:** dex

### Overview

Curve's StableSwap invariant is a hybrid between constant-sum and constant-product tuned for stablecoins; pools expose get_virtual_price used as an oracle by external protocols.

### Roles

- **Trader**
- **LP**
- **Pool**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `invariant_non_decrease` | The StableSwap invariant D never decreases across swaps. |
| 2 | `virtual_price_monotonicity` | get_virtual_price is non-decreasing and manipulation-resistant within a transaction. |

### Threat model

Adversary is a trader with flash loans interacting with pools and external protocols that read get_virtual_price.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://curve.fi/files/stableswap-paper.pdf
- https://docs.curve.fi/
