# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: delegation_authorization, no_replay, storage_isolation.

---

## Protocol: EIP-7702 Set-Code Delegation

**Category:** account_abstraction

### Overview

EIP-7702 lets an EOA set code (a delegation indicator) to a contract, temporarily giving the EOA smart-account behavior while retaining its key.

### Roles

- **EOA**
- **Delegate contract**
- **Relayer**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `delegation_authorization` | Only the EOA's key can authorize or clear a delegation. |
| 2 | `no_replay` | Delegation authorizations are chain- and nonce-bound and cannot be replayed. |
| 3 | `storage_isolation` | Delegated code cannot corrupt the EOA's storage/behavior unexpectedly. |

### Threat model

Adversary is a relayer or a malicious delegate contract; can replay signed authorizations.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-7702
