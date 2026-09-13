# Reference: Wyvern Exchange

**Verdict: UNSAFE.**

The generic CALL/DELEGATECALL order execution model was the root of the 2022 OpenSea copycat bug that let attackers steal NFTs via unvalidated calldata/initialization across fork contracts; order matching also lacked robust reentrancy/double-fill protection.

## References

- Wyvern Protocol v3 documentation
