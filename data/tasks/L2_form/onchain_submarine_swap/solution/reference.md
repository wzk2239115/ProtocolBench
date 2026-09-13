# Reference: Submarine Swap

**Verdict: UNSAFE.**

The provider (who knows the invoice preimage) can delay releasing the on-chain leg until the last moment or exploit fee/mempool conditions to force a timeout mismatch, extracting value or griefing the user; the trust model is asymmetric in favour of the provider.

## References

- Submarine swap literature
- Lightning HTLC design
