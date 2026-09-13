# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: debt_share_correctness, atomic_swap_fairness, oracle_freshness.

---

## Protocol: Synthetix Synths and Atomic Swaps

**Category:** defi

### Overview

Synthetix issues synthetic assets backed by staked SNX; a debt pool tracks global debt and a shared debt distribution, and atomic swaps let users exchange synths at oracle prices.

### Roles

- **SNX staker (debt pool)**
- **Synth trader**
- **Oracle**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `debt_share_correctness` | A staker's debt share reflects only protocol-wide debt changes, not another staker's trades. |
| 2 | `atomic_swap_fairness` | Atomic swaps are priced such that the debt pool is not drained by MEV. |
| 3 | `oracle_freshness` | Stale prices cannot be used to trade profitably. |

### Threat model

Adversary races oracle updates with atomic swaps and front-runs the debt pool.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.synthetix.io/
- Synthetix litepaper
