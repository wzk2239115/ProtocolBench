# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: authorization_binding, no_replay.

---

## Protocol: EIP-3074 AUTH/AUTHCALL

**Category:** account_abstraction

### Overview

EIP-3074 adds AUTH and AUTHCALL opcodes letting a sponsor (invoker) act on behalf of an EOA after an ECDSA authorization; the invoker gets full control within the call.

### Roles

- **EOA**
- **Invoker contract**
- **Sponsor**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `authorization_binding` | The invoker can only act within the authorized scope. |
| 2 | `no_replay` | Authorizations are bound to chain/invoker/nonce. |

### Threat model

Adversary is a malicious invoker that gets temporary control of the EOA.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-3074
