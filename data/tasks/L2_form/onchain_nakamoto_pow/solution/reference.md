# Reference: Nakamoto Consensus (Proof of Work)

**Verdict: UNSAFE.**

The protocol is only secure below a hash-power threshold: a >50% adversary double-spends, and selfish mining is profitable for smaller fractions when the attacker's hashrate share is high enough (Eyal-Sirer). Rational deviation and stale-block withholding break the honest-majority assumption.

## References

- https://bitcoin.org/bitcoin.pdf
- Eyal & Sirer, Majority is not Enough (2014)
