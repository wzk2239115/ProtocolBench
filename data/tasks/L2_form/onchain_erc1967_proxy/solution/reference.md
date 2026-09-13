# Reference: ERC-1967 Upgradeable Proxy

**Verdict: UNSAFE.**

UUPS/transparent proxies are exploitable when the implementation's initializer is left callable (uninitialized logic contract taken over), when the upgrade function lacks access control, or when storage layouts collide. Real upgrades have been hijacked by front-running `initialize`.

## References

- https://eips.ethereum.org/EIPS/eip-1967
- OpenZeppelin upgrades docs
