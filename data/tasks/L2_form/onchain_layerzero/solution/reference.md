# Reference: LayerZero (ultra-light nodes)

**Verdict: UNSAFE.**

Security is entirely delegated to the chosen oracle/relayer pair; applications can (and do) configure both to the same party or to a single EOA, collapsing the two-of-two check to one. Library/config changes without proper access control enable forged messages.

## References

- https://docs.layerzero.network/
- LayerZero whitepaper
