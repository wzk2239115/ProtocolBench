# Reference: Aave V3 E-Mode and Isolation Mode

**Verdict: UNSAFE.**

E-mode applies high LTV assuming assets stay correlated; if the correlation breaks (a depeg or an oracle that lags one asset), positions become undercollateralized and bad debt accrues. Isolation-mode and debt-ceiling parameters are governance-controlled and can be mis-set.

## References

- https://docs.aave.com/developers/
- Aave V3 whitepaper
