# Reference: ERC-3156 Flash Loans

**Verdict: UNSAFE.**

Flash loans are a feature, but receivers that do not verify msg.sender against the expected lender (or that use transfer instead of safeTransfer) can be reentered by a malicious 'lender' or have their allowance drained; the pattern has been the primitive in many DeFi drains.

## References

- https://eips.ethereum.org/EIPS/eip-3156
