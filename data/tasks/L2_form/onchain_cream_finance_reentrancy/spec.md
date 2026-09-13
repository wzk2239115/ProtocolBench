# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: collateral_value_consistency, no_reentrancy_on_borrow.

---

## Protocol: Cream Finance (ERC-777 reentrancy)

**Category:** lending

### Overview

Cream is a Compound fork lending market accepting many ERC-20s, including ERC-777 tokens with transfer hooks, as collateral.

### Roles

- **Supplier**
- **Borrower**
- **Liquidator**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `collateral_value_consistency` | An account's collateral value reflects only settled token balances. |
| 2 | `no_reentrancy_on_borrow` | Borrowing cannot be reentered while the account's balances are mid-update. |

### Threat model

Adversary supplies an ERC-777 token and reenters during the token hook.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Cream Finance 2021 exploit post-mortems
- https://eips.ethereum.org/EIPS/eip-777
