# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: payload_availability, bid_integrity, equivocation_prevention.

---

## Protocol: MEV-Boost Relay

**Category:** mev

### Overview

A relay receives builder bids and payloads, validates them, and passes the winning header to the proposer; the relay is a trusted party between builders and proposers.

### Roles

- **Builder**
- **Relay**
- **Proposer**
- **Validator client**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `payload_availability` | The proposer can obtain the full payload after signing the header. |
| 2 | `bid_integrity` | The relay does not leak the payload before the proposal or alter bids. |
| 3 | `equivocation_prevention` | The relay cannot serve conflicting views to proposers. |

### Threat model

Adversary is a malicious relay or a network attacker; relays are permissioned-ish and few.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.flashbots.net/flashbots-mev-boost/
- MEV-Boost design
