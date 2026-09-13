# Reference: Merkle-Proof Token Airdrop

**Verdict: UNSAFE.**

Distributors that key the claimed flag on the account (instead of the unique leaf index) or that omit the index from the proof let a single eligibility set be claimed multiple times / by front-runners; second preimage/duplicate-leaf constructions also allow double claims.

## References

- Uniswap/MerkleDistributor reference
