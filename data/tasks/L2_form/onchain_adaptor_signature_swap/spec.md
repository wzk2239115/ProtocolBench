# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: witness_binding, swap_atomicity.

---

## Protocol: Scriptless Atomic Swap (adaptor signatures)

**Category:** payment

### Overview

Adaptor signatures (e.g. Schnorr) hide the secret key inside a signature: settling one leg reveals the witness that settles the other, without HTLC scripts and timeouts.

### Roles

- **Alice**
- **Bob**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `witness_binding` | Settling one leg reveals exactly the witness needed for the other. |
| 2 | `swap_atomicity` | Neither party can settle only one leg. |

### Threat model

Adversary is a rational counterparty; cannot break the signature scheme's security.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://github.com/ElementsProject/scriptless-scripts
- Adaptor signature literature
