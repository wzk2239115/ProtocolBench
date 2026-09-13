# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: royalty_enforcement, no_royalty_bypass.

---

## Protocol: ERC-2981 NFT Royalties

**Category:** nft

### Overview

ERC-2981 exposes royaltyInfo(tokenId, salePrice) returning a receiver and amount; marketplaces are expected to honor it, but it is advisory only.

### Roles

- **Creator**
- **Marketplace**
- **Buyer**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `royalty_enforcement` | A compliant sale pays the specified royalty to the receiver. |
| 2 | `no_royalty_bypass` | Sellers cannot avoid royalties by routing through a marketplace. |

### Threat model

Adversary is the seller/marketplace choosing whether to honor royaltyInfo.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-2981
