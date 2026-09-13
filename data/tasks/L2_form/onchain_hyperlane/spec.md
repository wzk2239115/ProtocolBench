# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: ism_verification, ism_authorization, message_uniqueness.

---

## Protocol: Hyperlane Interchain Messaging

**Category:** interop

### Overview

Hyperlane is permissionless: any chain can be connected by deploying Mailbox/ISM contracts; security is provided by a configurable Interchain Security Module (ISM) per application.

### Roles

- **Mailbox**
- **ISM**
- **Relayer**
- **Application**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `ism_verification` | A message is delivered only if the app's ISM validates it. |
| 2 | `ism_authorization` | The ISM cannot be replaced without authorization. |
| 3 | `message_uniqueness` | Messages are consumed at most once. |

### Threat model

Adversary is a relayer or can change/trick a weak ISM configuration.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.hyperlane.xyz/
