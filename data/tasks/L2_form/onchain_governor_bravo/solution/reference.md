# Reference: Compound Governor Bravo

**Verdict: UNSAFE.**

If voting power is read from the current balance rather than a snapshot, an attacker can flash-loan governance tokens, pass a proposal, and return the loan within one transaction. Even with snapshots, delegation can be griefed and the proposer threshold can be manipulated. Real DAOs have been exploited via flash-loan/borrowed voting power.

## References

- https://docs.compound.finance/v2/governance/
- Compound Governor Bravo
