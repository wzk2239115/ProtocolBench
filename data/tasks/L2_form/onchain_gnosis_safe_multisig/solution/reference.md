# Reference: Gnosis Safe (smart-contract multisig)

**Verdict: UNSAFE.**

The core threshold + nonce design is sound. (Risk concentrates in modules/guards, which extend trust; the base Safe enforces distinct-signer threshold and monotonic nonce.)

## References

- https://docs.safe.global/
- Safe contract audits
