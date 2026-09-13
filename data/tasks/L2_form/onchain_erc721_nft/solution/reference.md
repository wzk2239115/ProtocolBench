# Reference: ERC-721 Non-Fungible Token

**Verdict: UNSAFE.**

The onERC721Received hook enables reentrancy in naive marketplace/lending integrations (same class as ERC-777); unset/never-expiring operator approvals and approval phishing remain a major real-world loss vector.

## References

- https://eips.ethereum.org/EIPS/eip-721
