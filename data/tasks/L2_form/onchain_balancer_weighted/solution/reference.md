# Reference: Balancer Weighted Pools

**Verdict: UNSAFE.**

Rounding and rate manipulation: a 2023 Balancer incident (and several forks) exploited incorrect rounding in pool math combined with a manipulated rate provider, allowing an attacker to drain value. Composable pools with linear/rate providers are especially sensitive.

## References

- https://docs.balancer.fi/
- https://balancer.fi/whitepaper.pdf
