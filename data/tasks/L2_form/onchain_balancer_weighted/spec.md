# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: weighted_invariant_non_decrease, no_rounding_extraction.

---

## Protocol: Balancer Weighted Pools

**Category:** dex

### Overview

Balancer generalizes constant-product to weighted geometric-mean pools: invariant = product(balance_i ^ weight_i); swaps and joins/exits compute exact amounts with a fee.

### Roles

- **Trader**
- **LP**
- **Vault/Pool**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `weighted_invariant_non_decrease` | The weighted invariant does not decrease across swaps and liquidity ops. |
| 2 | `no_rounding_extraction` | Rounding in swap/exit math cannot be exploited for profit by dust transactions. |

### Threat model

Adversary is a trader exploiting rounding and rate-provider (e.g. yield-bearing) token accounting.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.balancer.fi/
- https://balancer.fi/whitepaper.pdf
