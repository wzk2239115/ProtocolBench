# Reference: Ethereum Gasper (LMD-GHOST + FFG)

**Verdict: UNSAFE.**

LMD-GHOST has known balancing/reorg attacks in the presence of network delays and adversarial timing (documented by Neu, Tas, Gasser, Zhang et al.), and validator inactivity leaks penalize liveness; safety needs <1/3 but chain quality/MEV reorgs are exploitable below that.

## References

- https://ethereum.org/en/developers/docs/consensus-mechanisms/pos/
- Gasper (2018)
