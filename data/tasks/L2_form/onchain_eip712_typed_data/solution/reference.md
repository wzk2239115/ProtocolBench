# Reference: EIP-712 Typed Structured Data Hashing

**Verdict: UNSAFE.**

The scheme is only as safe as its use: domains that omit chainId/verifyingContract are cross-domain replayable; nested structs without type hashes, or ambiguous field ordering, enable signature-confusion attacks; wallets often display insufficient detail, enabling blind-signing theft.

## References

- https://eips.ethereum.org/EIPS/eip-712
