# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: ownership_integrity, approval_authorization, no_reentrancy.

---

## Protocol: ERC-6900

**Category:** nft

### Overview

ERC-6900 is a production on-chain nft protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `ownership_integrity` | A token has one owner and ownership changes only via authorized transfers. |
| 2 | `approval_authorization` | Only approved operators can move tokens. |
| 3 | `no_reentrancy` | Receiver hooks cannot reenter to observe inconsistent state. |

### Threat model

Adversary controls the receiver hook, marketplace orders, or operator approvals.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- NFT standard / marketplace docs
