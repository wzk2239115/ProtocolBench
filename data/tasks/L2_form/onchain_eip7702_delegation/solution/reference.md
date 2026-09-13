# Reference: EIP-7702 Set-Code Delegation

**Verdict: UNSAFE.**

The design expands the attack surface: signed delegation authorizations can be front-run/replayed across chains if not domain-separated, delegate contracts can execute in the EOA's context (drain via arbitrary calls), and clearing/re-delegating semantics are subtle; the standard had to add nonce/chain binding.

## References

- https://eips.ethereum.org/EIPS/eip-7702
