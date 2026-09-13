# Reference: Flashbots / PBS (block builder market)

**Verdict: UNSAFE.**

PBS concentrates power in a few builders and relays (and the relay is a trusted party): a dominant builder can censor and reorder transactions, and relay/builder bugs or equivocation can break payment/authenticity. It is a real centralization/censorship attack surface, not a cryptographic break.

## References

- https://docs.flashbots.net/
- MEV-Boost/relay designs
