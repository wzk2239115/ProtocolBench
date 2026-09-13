# Reference: Schnorr Multisig (rogue-key / MuSig)

**Verdict: UNSAFE.**

Rogue-key attack: in naive key aggregation (sum of public keys) the last signer can choose pk' = pk_target - sum(other pks) so the aggregate key is the target's, and it alone can sign. MuSig prevents it by hashing each public key with the session context.

## References

- https://eprint.iacr.org/2018/068
- MuSig2 (2020/1261)
