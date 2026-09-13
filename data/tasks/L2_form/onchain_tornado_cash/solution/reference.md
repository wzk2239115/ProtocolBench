# Reference: Tornado Cash Mixer

**Verdict: UNSAFE.**

The cryptography is sound, but anonymity is easily broken by metadata (address reuse, relayer choice, gas/amount timing) and the verifier historically accepted non-canonical proofs (the 2021 tornado.cash bug where the nullifier check could be bypassed for one pool via a malformed proof). Also compliance/sanctions are external.

## References

- https://tornado.cash/
- Tornado Cash docs
