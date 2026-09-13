# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: execution_soundness, image_journal_binding, no_forged_receipt.

---

## Protocol: RISC Zero zkVM

**Category:** zk

### Overview

A general-purpose zkVM that proves execution of RISC-V programs and issues a receipt bound to an image id and journal (public outputs).

### Roles

- **Prover**
- **Verifier/dApp**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `execution_soundness` | A receipt is accepted only for a faithful execution of the claimed program image. |
| 2 | `image_journal_binding` | The receipt binds the exact image id and public journal. |
| 3 | `no_forged_receipt` | An attacker cannot forge a receipt without executing the program. |

### Threat model

Adversary is a malicious prover/dApp reusing receipts across contexts.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://dev.risczero.com/
- RISC Zero docs
