# Reference: HTLC Atomic Cross-Chain Swap

**Verdict: UNSAFE.**

HTLCs give no fairness guarantee under adversarial timing: the receiver holds a free option to claim near the timeout, griefing the sender; if fee spikes or chain congestion delay the claim, the counterparty leg can expire, and on Lightning the same preimage can be used in replacement-cycling. Atomicity (both-or-neither) holds only under optimistic liveness assumptions.

## References

- https://en.bitcoin.it/wiki/Hash_Time_Locked_Contracts
- Cross-chain atomic swap literature
