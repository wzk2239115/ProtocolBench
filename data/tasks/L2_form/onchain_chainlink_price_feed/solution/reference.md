# Reference: Chainlink Price Feed

**Verdict: UNSAFE.**

The aggregation design is sound; outages are liveness/latency issues. The real risk is consumer misuse (ignoring staleness/round checks, using a feed with too few decimals), which is an integration bug.

## References

- https://docs.chain.link/data-feeds
- Chainlink whitepaper
