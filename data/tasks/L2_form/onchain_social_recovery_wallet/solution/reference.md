# Reference: Social Recovery Wallet

**Verdict: UNSAFE.**

If the owner is unavailable (key lost) exactly when recovery is intended, the delay window is the only defense; a guardian quorum can steal the wallet during that window, and a compromised guardian combined with owner inactivity (or a missed veto) completes theft. Implementations have also lacked a proper guardian-set update quorum.

## References

- Argent/Gnosis social recovery designs
