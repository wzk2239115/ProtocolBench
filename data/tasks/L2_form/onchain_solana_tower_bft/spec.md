# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: safety, liveness, poh_ordering_integrity.

---

## Protocol: Solana Tower BFT / Proof of History

**Category:** consensus

### Overview

Solana orders transactions with Proof of History (a verifiable delay of hashes) and finalizes with Tower BFT, where validators lock a vote tower and vote for increasingly many slots.

### Roles

- **Leaders**
- **Validators**
- **RPC nodes**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `safety` | Two conflicting slots cannot both be finalized under the stake bound. |
| 2 | `liveness` | With enough honest stake and a healthy leader schedule, progress continues. |
| 3 | `poh_ordering_integrity` | PoH provides a reliable ordering/cryptographic clock. |

### Threat model

Adversary controls a minority of stake and can spam/congest; PoH leaders can censor.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.solana.com/
- Tower BFT / PoH design
