# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: ownership_integrity, bid_escrow_safety.

---

## Protocol: CryptoPunks

**Category:** nft

### Overview

CryptoPunks predates ERC-721: a custom market contract tracks ownership and bids, with raw transfer and offer/bid functions.

### Roles

- **Owner**
- **Bidder**
- **Market contract**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `ownership_integrity` | Ownership only changes via a valid transfer/sale. |
| 2 | `bid_escrow_safety` | Escrowed bids can only be withdrawn by the bidder or applied to an accepted sale. |

### Threat model

Adversary interacts with bid/accept methods and the fallback function.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- CryptoPunks market contract
