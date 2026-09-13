# Reference: Validium (off-chain data availability)

**Verdict: UNSAFE.**

Validity does not imply data availability: if the committee withholds data, users cannot reconstruct state or exit with correct balances, so funds can be frozen/stolen even though every proof verifies.

## References

- StarkEx Validium documentation
- https://ethereum.org/en/developers/docs/scaling/validium/
