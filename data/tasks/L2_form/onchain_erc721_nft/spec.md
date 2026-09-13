# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: ownership_uniqueness, no_unauthorized_transfer, no_reentrancy.

---

## Protocol: ERC-721 Non-Fungible Token

**Category:** nft

### Overview

ERC-721 tracks unique token ownership and approves operators via setApprovalForAll; safeTransferFrom calls onERC721Received on contract recipients.

### Roles

- **Owner**
- **Approved operator**
- **Recipient**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `ownership_uniqueness` | A token has exactly one owner and transfers update it atomically. |
| 2 | `no_unauthorized_transfer` | Only the owner or an approved operator can transfer. |
| 3 | `no_reentrancy` | The receiver hook cannot reenter to observe inconsistent ownership. |

### Threat model

Adversary controls the receiver hook / operator approvals.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-721
