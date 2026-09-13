# Reference: ERC-777 Tokens and Receiver Hooks

**Verdict: UNSAFE.**

The recipient hook executes arbitrary code during the transfer; integrations that update their own state after the token call (e.g. DEX pools, lending markets) are reentrancy-exploitable. This class caused the imBTC/Uniswap and several DeFi drains.

## References

- https://eips.ethereum.org/EIPS/eip-777
- https://eips.ethereum.org/EIPS/eip-1820
