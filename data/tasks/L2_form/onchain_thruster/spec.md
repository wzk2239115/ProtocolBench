# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: invariant_non_decrease, no_price_manipulation, lp_solvency.

---

## Protocol: Thruster

**Category:** dex

### Overview

Thruster is a production on-chain dex protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `invariant_non_decrease` | The pool invariant does not decrease across swaps and liquidity operations. |
| 2 | `no_price_manipulation` | The on-chain price cannot be profitably manipulated within a transaction. |
| 3 | `lp_solvency` | Liquidity providers can redeem their proportional share of reserves. |

### Threat model

Adversary is a trader/LP with flash-loan capital and atomic composability; may reorder transactions.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- AMM whitepaper / docs
