# Reference: Wrapped Ether (WETH)

**Verdict: UNSAFE.**

No documented design flaw: accounting is 1:1 and withdraw burns before sending (the canonical implementation sends after burning).

## References

- https://weth.io/
- WETH9 reference implementation
