# Reference: secp256r1 / Passkey Smart Accounts

**Verdict: UNSAFE.**

Passkey assertions are not chain/account bound by default, so accounts must wrap them in a replay-safe hash; naive P-256 verifiers accept non-canonical/malleable inputs or fail to hash the challenge correctly, enabling replay across accounts or signature forgery.

## References

- WebAuthn
- RIP-7212 (P-256 precompile)
- ERC-4337 passkey accounts
