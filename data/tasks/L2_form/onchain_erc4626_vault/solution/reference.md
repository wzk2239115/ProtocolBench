# Reference: ERC-4626 Tokenized Vault (share inflation)

**Verdict: UNSAFE.**

First-depositor / donation inflation: an attacker deposits 1 wei, donates a large amount to inflate totalAssets, then subsequent depositors get 0 shares due to integer rounding; the attacker redeems and captures their assets. Requires rounding-safe share accounting (virtual shares/assets or minimum initial deposit).

## References

- https://eips.ethereum.org/EIPS/eip-4626
- https://docs.openzeppelin.com/contracts/4.x/erc4626
