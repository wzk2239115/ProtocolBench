# Reference: Curve StableSwap

**Verdict: UNSAFE.**

Read-only reentrancy: integrations read get_virtual_price mid-transaction while a pool's state is inconsistent (e.g. inside remove_liquidity callbacks), enabling under-collateralized borrowing/draining. Several 2022-2023 Curve-ecosystem incidents exploited this; the 2023 Vyper compiler bug made some pools vulnerable to direct reentrancy.

## References

- https://curve.fi/files/stableswap-paper.pdf
- https://docs.curve.fi/
