# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: ownership_correctness, no_transfer_bypass.

---

## Protocol: ERC-721A (batch minting)

**Category:** nft

### Overview

ERC-721A reduces gas for sequential batch mints by tracking an ownership slot's begin timestamp; ownerOf derives ownership from the packed slot.

### Roles

- **Owner**
- **Minter**
- **Operator**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `ownership_correctness` | ownerOf is correct for all tokens including batch-minted ones. |
| 2 | `no_transfer_bypass` | Batch minting does not let an attacker claim another user's token. |

### Threat model

Adversary mints/transfers and probes slot-packing edge cases (e.g. minting to a contract, transfer of a first-owned token).

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://www.erc721a.org/
- ERC-721A reference implementation
