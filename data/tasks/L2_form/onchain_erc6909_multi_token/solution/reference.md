# Reference: ERC-6909 Minimal Multi-Token

**Verdict: UNSAFE.**

Multi-token operators and per-id allowances are easy to confuse: implementations that share an approval across ids, or that fail to decrement infinite allowances correctly, let an operator drain unintended ids. Interface- confusion with ERC-1155/ERC-20 is a recurring integration risk.

## References

- https://eips.ethereum.org/EIPS/eip-6909
