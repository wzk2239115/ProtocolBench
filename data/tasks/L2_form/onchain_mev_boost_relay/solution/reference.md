# Reference: MEV-Boost Relay

**Verdict: UNSAFE.**

The relay is a trusted central party: a malicious relay can withhold payloads (causing missed slots), leak builder intents for unbundling, or equivocate; relay outages have caused mass missed proposals. This is a real centralization/availability flaw.

## References

- https://docs.flashbots.net/flashbots-mev-boost/
- MEV-Boost design
