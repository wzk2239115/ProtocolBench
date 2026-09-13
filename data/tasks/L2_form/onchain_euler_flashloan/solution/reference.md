# Reference: Euler Finance (donate / health check)

**Verdict: UNSAFE.**

The March 2023 exploit (~US$197M) combined a flash loan, self-liquidation, and donateToReserves: the donate path failed to update the account's health check, so a deliberately undercollateralized position could be created and then not liquidated, letting the attacker mint a huge debt and extract it.

## References

- https://docs.euler.finance/
- Euler Finance 2023 exploit analyses
