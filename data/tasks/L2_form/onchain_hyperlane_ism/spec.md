# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: message_authenticity, packet_exactly_once, channel_binding.

---

## Protocol: Hyperlane ISM

**Category:** interop

### Overview

Hyperlane ISM is a production on-chain interop protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `message_authenticity` | A message is executed only if committed/attested by the source chain. |
| 2 | `packet_exactly_once` | Each packet/message is processed at most once. |
| 3 | `channel_binding` | Messages are bound to the correct channel / source-destination pair. |

### Threat model

Adversary is a relayer; light clients / consensus are honest, and the adversary cannot forge proofs or signatures.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Interoperability protocol specification
