# Reference: Uniswap V4 Hooks

**Verdict: UNSAFE.**

V4 moves a large amount of security into user-deployed hooks: a malicious/buggy hook can reenter the pool manager, mis-handle donate/fee accounting, or break the unlocked-state invariant. The attack surface is the hooks, not the core math.

## References

- https://docs.uniswap.org/contracts/v4/overview
- Uniswap V4 whitepaper
