# Reference: Polygon zkEVM

**Verdict: UNSAFE.**

The trusted sequencer plus emergency-state mechanism concentrates power: a malicious/compromised sequencer or admin can delay forced batches or trigger an emergency transition that changes state, and forced-batch liveness can be blocked by gas griefing.

## References

- https://docs.polygon.technology/zkEVM/
