# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: range_soundness, zero_knowledge, binding.

---

## Protocol: Bulletproofs Range Proofs

**Category:** zk

### Overview

Bulletproofs are short non-interactive zero-knowledge range proofs without a trusted setup, used in Confidential Transactions to prove a value is in [0, 2^n).

### Roles

- **Prover**
- **Verifier**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `range_soundness` | No prover can prove a value outside the range. |
| 2 | `zero_knowledge` | The proof reveals nothing beyond the range statement. |
| 3 | `binding` | Commitments/transcripts bind the proven value. |

### Threat model

Adversary is a malicious prover; no toxic waste exists.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Bunz et al., Bulletproofs (2018)
