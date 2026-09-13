# Reference: The DAO (reentrancy)

**Verdict: UNSAFE.**

Classic reentrancy: splitDAO sent ETH via call before zeroing the attacker's token balance, so the reentrant fallback could recursively withdraw until the DAO was drained (~US$60M), leading to the ETH/ETC hard fork.

## References

- https://en.wikipedia.org/wiki/The_DAO
- 2016 DAO exploit post-mortems
