# Reference: Solana Tower BFT / Proof of History

**Verdict: UNSAFE.**

Throughput and leader scheduling create liveness/censorship risks (the network has repeatedly halted under load), and the locked-vote tower with long lockups gives liveness and reorg concerns; PoH is an ordering aid, not a consensus-safety proof.

## References

- https://docs.solana.com/
- Tower BFT / PoH design
