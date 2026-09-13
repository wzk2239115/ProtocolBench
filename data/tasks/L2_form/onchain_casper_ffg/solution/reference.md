# Reference: Casper FFG (Ethereum finality)

**Verdict: UNSAFE.**

The original Casper FFG slashing conditions were revised because naive formulations admitted surround/equivocation cases not caught by the first rule set; LMD-GHOST and FFG interactions required additional slashing conditions. Systems implementing only the initial two conditions can be finalized-conflicting without accountability.

## References

- Buterin & Griffith, Casper the Friendly Finality Gadget (2017)
- Ethereum consensus specs
