# Reference: Poly Network Bridge (keeper signatures)

**Verdict: UNSAFE.**

The August 2021 exploit forged cross-chain headers: the manager's verification allowed an attacker to specify the target method/arguments, and a keeper key was used to sign a malicious header chain, letting the attacker redirect the arbitrary call to their own method and eventually withdraw funds.

## References

- Poly Network 2021 incident (~US$611M)
