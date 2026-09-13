# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: balance_integrity, operator_authorization, allowance_correctness.

---

## Protocol: ERC-6909 Minimal Multi-Token

**Category:** token

### Overview

ERC-6909 is a minimal multi-token interface with per-id balances and operator approvals, separate from ERC-1155.

### Roles

- **Holder**
- **Operator**
- **Contract**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `balance_integrity` | Per-id balances are conserved across transfers. |
| 2 | `operator_authorization` | Only approved operators can move tokens. |
| 3 | `allowance_correctness` | Per-id allowances are enforced and not shared across ids. |

### Threat model

Adversary exploits per-id allowance/operator confusion.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-6909
