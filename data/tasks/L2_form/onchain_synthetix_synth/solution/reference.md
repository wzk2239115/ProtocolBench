# Reference: Synthetix Synths and Atomic Swaps

**Verdict: UNSAFE.**

Atomic swaps plus an oracle that updates on a schedule enable front-running/sandwiching of price updates against the shared debt pool (documented atomic-swap/front-running attacks); stale or lagged oracle prices let traders extract value from stakers.

## References

- https://docs.synthetix.io/
- Synthetix litepaper
