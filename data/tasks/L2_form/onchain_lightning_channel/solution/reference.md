# Reference: Lightning Network Payment Channel

**Verdict: UNSAFE.**

The Poon-Dryja revocation mechanism is sound for balance enforcement (an old state is penalizable). Known attacks are liveness/jamming or require implementation bugs, not a break of the channel state machine.

## References

- https://github.com/lightning/bolts
- Lightning Network whitepaper (Poon-Dryja)
