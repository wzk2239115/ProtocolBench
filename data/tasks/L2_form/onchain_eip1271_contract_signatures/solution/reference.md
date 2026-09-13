# Reference: EIP-1271 Contract Signatures

**Verdict: UNSAFE.**

The standard is stateful and can be reentered: a malicious contract signer can return the magic value while reentering the verifier, and verifiers that ignore the returned magic value or verify outside the intended domain accept invalid signatures. Real NFT/marketplace exploits abused ERC-1271 verification.

## References

- https://eips.ethereum.org/EIPS/eip-1271
