# Reference: AMM Sandwich Attack

**Verdict: UNSAFE.**

Inherent to transparent AMMs with public mempools: an adversary can front-run/back-run to extract the victim's slippage. Mitigations are commitment schemes, batch auctions, or sealed-bid mempools; without them the sandwich is always available.

## References

- MEV literature
- https://ethereum.org/en/developers/docs/mev/
