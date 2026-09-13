# Reference: Wormhole Token Bridge

**Verdict: UNSAFE.**

The February 2022 exploit forged a VAA by abusing a deprecated instruction: the attacker supplied a spoofed sysvar/instruction account so the signature verification returned success without real guardian signatures, then minted 120k wrapped ETH. Verification was not bound to the genuine instructions sysvar.

## References

- Wormhole 2022 incident (~US$326M)
- https://docs.wormhole.com/
