# Reference: ECDSA Signature Malleability

**Verdict: UNSAFE.**

Malleability: without a canonical low-s rule and with txids computed over signatures, an attacker can alter a pending transaction's txid, breaking unconfirmed-spend chains (this enabled the Mt. Gox withdrawal bug and motivated SegWit).

## References

- https://en.bitcoin.it/wiki/Transaction_malleability
- BIP-62/BIP-141 (SegWit)
