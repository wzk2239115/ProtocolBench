# Reference: Cream Finance (ERC-777 reentrancy)

**Verdict: UNSAFE.**

The October 2021 exploit (~US$130M) reentered Cream through the ERC-777 token hook during a borrow/repay path, inflating collateral accounting and draining markets.

## References

- Cream Finance 2021 exploit post-mortems
- https://eips.ethereum.org/EIPS/eip-777
