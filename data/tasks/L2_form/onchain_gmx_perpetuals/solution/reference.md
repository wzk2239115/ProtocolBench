# Reference: GMX Perpetual Exchange

**Verdict: UNSAFE.**

The design relies on a fast, manipulation-resistant oracle; price manipulation (including through low-liquidity venues and oracle latency) has repeatedly drained perp DEXes, and keeper/execution ordering can be exploited for unfair fills.

## References

- https://docs.gmx.io/
- GMX contracts
