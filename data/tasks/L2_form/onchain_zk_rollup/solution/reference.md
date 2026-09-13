# Reference: ZK Rollup (validity proofs)

**Verdict: UNSAFE.**

Correctness reduces to the proof system's soundness and the verifier contract; with a sound SNARK/STARK, invalid transitions cannot be finalized (data-availability/liveness are separate concerns).

## References

- https://ethereum.org/en/developers/docs/scaling/zk-rollups/
- zkSync/StarkNet docs
