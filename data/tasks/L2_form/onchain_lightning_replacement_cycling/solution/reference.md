# Reference: Lightning Replacement Cycling

**Verdict: UNSAFE.**

Replacement cycling (Riard, 2023): an attacker repeatedly replaces the victim's preimage-revealing transaction in mempools, evicting the honest claim so the HTLC times out; combined with the preimage being exposed, this can steal funds or force channel exhaustion. The commitment design did not account for adversarial RBF mempool interactions.

## References

- Antoine Riard, replacement cycling disclosure (2023)
- https://github.com/lightning/bolts/pull/1081
