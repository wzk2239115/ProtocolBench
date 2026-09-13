# Reference: ERC-2771 Meta-Transactions (trusted forwarder)

**Verdict: UNSAFE.**

Replay: if the signed request does not bind a per-contract/per-chain nonce or domain separator, a relayer can replay it to the same contract or a sibling deployment. Spoofing: contracts that trust a user-supplied forwarder (or that read the last 20 bytes of calldata without pinning the trusted forwarder) let anyone forge _msgSender().

## References

- https://eips.ethereum.org/EIPS/eip-2771
- https://eips.ethereum.org/EIPS/eip-712
