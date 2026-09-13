# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: unforgeability, domain_binding, no_replay.

---

## Protocol: Proxy Signature

**Category:** signature

### Overview

Proxy Signature is a production on-chain signature protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `unforgeability` | No party can produce a valid signature without the key. |
| 2 | `domain_binding` | Signatures are bound to the intended chain/contract/context. |
| 3 | `no_replay` | A signature cannot be reused for another message/domain/nonce. |

### Threat model

Adversary is a malicious signer/relayer and can choose messages and domains; cannot break the underlying hardness assumption.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Signature scheme / EIP documentation
