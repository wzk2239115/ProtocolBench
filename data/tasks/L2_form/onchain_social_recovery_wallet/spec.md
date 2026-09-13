# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: recovery_authorization, owner_veto, guardian_set_integrity.

---

## Protocol: Social Recovery Wallet

**Category:** account_abstraction

### Overview

A smart wallet where guardians can replace a lost signer key after a delay; the owner can cancel a pending recovery.

### Roles

- **Owner**
- **Guardians**
- **Wallet contract**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `recovery_authorization` | Only a quorum of current guardians can initiate recovery. |
| 2 | `owner_veto` | The legitimate owner can cancel an in-progress recovery before it executes. |
| 3 | `guardian_set_integrity` | A compromised guardian cannot shrink or replace the guardian set unilaterally. |

### Threat model

Adversary compromises a minority of guardians and tries to recover the wallet.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Argent/Gnosis social recovery designs
