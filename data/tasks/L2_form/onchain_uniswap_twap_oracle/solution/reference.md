# Reference: Uniswap V2 TWAP Oracle

**Verdict: UNSAFE.**

TWAPs are only as strong as the window: short-window TWAPs can be manipulated across a few blocks with a large capital position, and the cumulative accumulator assumes the pool price is not otherwise broken. Several DeFi protocols were drained via flash-loan/short-window TWAP manipulation.

## References

- https://docs.uniswap.org/contracts/v2/guides/smart-contract-integration/building-an-oracle
