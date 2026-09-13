# Reference: Arbitrum Rollup (multi-round fraud proof)

**Verdict: UNSAFE.**

Safety rests on a live honest challenger within multi-round, multi-day timeouts; censorship of the challenger or an unavailable validator lets a wrong assertion confirm, and forced-inclusion depends on L1 liveness.

## References

- https://docs.arbitrum.io/
- Arbitrum Nitro whitepaper
