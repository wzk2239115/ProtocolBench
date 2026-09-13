# Reference: EIP-3074 AUTH/AUTHCALL

**Verdict: UNSAFE.**

AUTH grants the invoker full control of the EOA for the transaction (including arbitrary calls), so any authorization to a malicious/buggy invoker drains the account; replay protection must be in the invoker, and the spec was ultimately superseded by EIP-7702 partly for these reasons.

## References

- https://eips.ethereum.org/EIPS/eip-3074
