# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: invariant_preservation, hook_authorization, no_reentrancy.

---

## Protocol: Uniswap V4 Hooks

**Category:** dex

### Overview

V4 uses a singleton pool manager with hooks that run before/after pool actions (initialize, swap, liquidity, donate), letting custom logic alter behavior.

### Roles

- **Pool creator**
- **Hook contract**
- **Liquidity provider**
- **Trader**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `invariant_preservation` | Hooks cannot break the core constant-product accounting. |
| 2 | `hook_authorization` | Only the pool's registered hook can run and only for its pool. |
| 3 | `no_reentrancy` | Hooks cannot reenter the pool manager to corrupt state. |

### Threat model

Adversary deploys a malicious hook or exploits a vulnerable hook's reentrancy/flash accounting.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.uniswap.org/contracts/v4/overview
- Uniswap V4 whitepaper
