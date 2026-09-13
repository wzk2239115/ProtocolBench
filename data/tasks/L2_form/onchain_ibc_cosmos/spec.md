# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: packet_authenticity, packet_exactly_once, light_client_soundness.

---

## Protocol: Cosmos IBC

**Category:** interop

### Overview

IBC is a generic, permissioned-channel protocol between light clients: packet commitments and acknowledgements are proven against the counterparty's consensus state using Merkle proofs; clients track consensus and timeouts.

### Roles

- **Chain A**
- **Chain B**
- **Relayer**
- **Light client**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `packet_authenticity` | A packet is delivered only if committed on the source chain. |
| 2 | `packet_exactly_once` | Each packet is processed at most once (sequence numbers + timeouts). |
| 3 | `light_client_soundness` | The consensus state accepting proofs is itself validated. |

### Threat model

Adversary is a relayer; light clients and consensus are honest. Cannot forge Merkle proofs.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://ibc.cosmos.network/
- IBC specification
