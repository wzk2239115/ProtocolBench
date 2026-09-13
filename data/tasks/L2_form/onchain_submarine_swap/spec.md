# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: swap_atomicity, provider_solvency.

---

## Protocol: Submarine Swap

**Category:** payment

### Overview

A submarine swap exchanges on-chain coins for off-chain Lightning balance using an HTLC: the Lightning sender pays an invoice whose preimage releases an on-chain HTLC to the on-chain counterparty, with a timeout.

### Roles

- **On-chain party**
- **Lightning party**
- **Swap provider**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `swap_atomicity` | The on-chain and Lightning legs cannot settle unequally. |
| 2 | `provider_solvency` | The provider cannot take on-chain funds without completing the Lightning payment. |

### Threat model

Adversary is a malicious swap provider exploiting timeout/preimage ordering and mempool conditions.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Submarine swap literature
- Lightning HTLC design
