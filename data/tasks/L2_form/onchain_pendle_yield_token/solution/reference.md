# Reference: Pendle Yield Tokenization

**Verdict: UNSAFE.**

Yield accounting with index normalisation and maturity transitions is subtle: rounding/index-seeding and flash manipulation of PT/YT AMM prices near maturity have been exploited, and malicious/rebasing yield-bearing collateral can break the PT:YT invariant.

## References

- https://docs.pendle.finance/
