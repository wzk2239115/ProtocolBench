# Reference: CoW Protocol (batch auctions)

**Verdict: UNSAFE.**

Solver-controlled arbitrary interactions and partially fillable/limit order semantics are a large surface: a malicious/buggy solver can craft interactions that violate the intended uniform-price outcome or drain allowances (mitigated by bonds/simulation), and order-signing interface attacks have caused real losses.

## References

- https://docs.cow.fi/
- CoW Protocol documentation
