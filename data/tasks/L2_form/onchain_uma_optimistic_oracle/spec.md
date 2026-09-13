# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: assertion_correctness, dispute_liveness, dvm_soundness.

---

## Protocol: UMA Optimistic Oracle

**Category:** oracle

### Overview

UMA lets a proposer assert an outcome with a bond; anyone can dispute within a liveness window, escalating to a token-holder vote (DVM) if disputed.

### Roles

- **Proposer**
- **Disputer**
- **DVM voters**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `assertion_correctness` | Only true assertions finalize. |
| 2 | `dispute_liveness` | An honest disputer can challenge within the window. |
| 3 | `dvm_soundness` | The DVM cannot be economically captured to finalize a false assertion. |

### Threat model

Adversary is a dishonest proposer/disputer with capital and governance tokens; may grief or capture votes.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.uma.xyz/
- UMA optimistic oracle
