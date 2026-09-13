# Reference: ERC-6551 Token-Bound Accounts

**Verdict: UNSAFE.**

Account control follows the NFT, so an NFT transfer or a compromised operator approval hands over the entire bound account and all its assets; implementations that cache the owner or use ERC-721 enumerable/approval edge cases have allowed unintended control.

## References

- https://eips.ethereum.org/EIPS/eip-6551
