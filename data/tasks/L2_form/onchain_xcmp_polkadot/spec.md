# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: message_binding, no_replay_or_forge.

---

## Protocol: Polkadot XCMP

**Category:** interop

### Overview

XCMP moves cross-consensus messages between parachains; the relay chain's message queue ensures ordering and delivery, with HRMP for older deployments. Messages are bound to a channel between two parachains.

### Roles

- **Parachain A**
- **Parachain B**
- **Relay-chain message queue**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `message_binding` | A message is delivered only to its addressed channel and in order. |
| 2 | `no_replay_or_forge` | Messages cannot be injected by a party other than the source parachain. |

### Threat model

Adversary is a parachain; the relay chain and other validators are honest.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://wiki.polkadot.network/docs/learn-cross-consensus
- XCMP design
