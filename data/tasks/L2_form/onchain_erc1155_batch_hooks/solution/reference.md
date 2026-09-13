# Reference: ERC-1155 Multi-Token with Receiver Hooks

**Verdict: UNSAFE.**

The receiver hook runs arbitrary code before the caller's state settles (same class as ERC-777/ERC-721 hooks); naive marketplace/lending integrations that check balances after the hook can be reentered.

## References

- https://eips.ethereum.org/EIPS/eip-1155
