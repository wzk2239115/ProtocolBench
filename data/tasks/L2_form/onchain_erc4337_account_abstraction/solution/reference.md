# Reference: ERC-4337 Account Abstraction

**Verdict: UNSAFE.**

Validation runs user code and has historically violated storage isolation (an account reading another entity's storage) and allowed reentrancy into validation; paymasters can be griefed or drained, and aggregator/paymaster validation semantics were revised repeatedly. Implementations that do not enforce the ERC-7562 reputation/storage rules are exploitable.

## References

- https://eips.ethereum.org/EIPS/eip-4337
- https://docs.erc4337.io/
