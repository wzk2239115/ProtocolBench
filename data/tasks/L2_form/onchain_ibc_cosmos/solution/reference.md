# Reference: Cosmos IBC

**Verdict: UNSAFE.**

No protocol-level soundness flaw: packet commitment + ordered/unordered channels + timeouts give exactly-once delivery, assuming the light-client security (validator quorum) holds.

## References

- https://ibc.cosmos.network/
- IBC specification
