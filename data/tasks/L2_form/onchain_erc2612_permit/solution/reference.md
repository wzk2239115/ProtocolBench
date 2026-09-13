# Reference: ERC-2612 Permit (gasless approvals)

**Verdict: UNSAFE.**

Permit verification is only as strong as the EIP-712 domain separator. Deployed tokens that hardcode or omit chainId (or cache the separator across a fork) let a permit signed on one chain be replayed on the forked chain; tokens that omit the nonce allow unlimited replay. A related griefing issue: anyone can front-run a permit and consume it.

## References

- https://eips.ethereum.org/EIPS/eip-2612
- https://eips.ethereum.org/EIPS/eip-712
