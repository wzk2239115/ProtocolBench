# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: owner_control, account_uniqueness, no_cross_account_control.

---

## Protocol: ERC-6551 Token-Bound Accounts

**Category:** nft

### Overview

ERC-6551 gives every NFT a deterministic smart-contract account controlled by the NFT's owner; the account can hold assets and execute calls.

### Roles

- **NFT owner**
- **Token-bound account**
- **Registry**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `owner_control` | Only the current NFT owner can execute from the account. |
| 2 | `account_uniqueness` | The account address is deterministically bound to the NFT. |
| 3 | `no_cross_account_control` | Control of one account cannot affect another. |

### Threat model

Adversary transfers/approves the NFT and probes account ownership checks.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-6551
