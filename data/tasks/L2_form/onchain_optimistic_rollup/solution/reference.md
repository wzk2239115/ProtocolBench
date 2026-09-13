# Reference: Optimistic Rollup (fraud proofs)

**Verdict: UNSAFE.**

Safety depends on a live honest challenger within the challenge window: if the challenger is censored, offline, or the window is too short relative to L1 censorship, a fraudulent root finalizes and withdrawals release invalid funds. Sequencer censorship and delayed data availability are known attack surfaces (hence forced-inclusion and multi-challenger designs).

## References

- https://ethereum.org/en/developers/docs/scaling/optimistic-rollups/
- Arbitrum/Optimism docs
