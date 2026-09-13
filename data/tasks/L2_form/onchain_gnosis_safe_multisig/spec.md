# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: threshold_approval, nonce_no_replay, no_signature_reuse.

---

## Protocol: Gnosis Safe (smart-contract multisig)

**Category:** governance

### Overview

Safe is an account contract executing transactions approved by an owner threshold; it stores owner set, threshold, nonce, and module/guard hooks, and verifies EIP-712 or EIP-1271 signatures.

### Roles

- **Owners**
- **Safe contract**
- **Modules/Guards**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `threshold_approval` | A transaction executes only with at least `threshold` distinct owner signatures over its hash. |
| 2 | `nonce_no_replay` | Each executed transaction increments the nonce and cannot be replayed. |
| 3 | `no_signature_reuse` | An owner signature cannot be counted twice or reused for a different transaction. |

### Threat model

Adversary cannot compromise the threshold; may submit arbitrary transactions/signatures.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.safe.global/
- Safe contract audits
