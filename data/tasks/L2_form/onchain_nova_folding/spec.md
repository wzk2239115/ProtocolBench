# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: ivc_validity, folding_soundness.

---

## Protocol: Nova (folding scheme IVC)

**Category:** zk

### Overview

Nova is an incrementally verifiable computation scheme based on a relaxed R1CS folding scheme and a cycle of elliptic curves; it avoids per-step SNARKs.

### Roles

- **Prover**
- **Verifier**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `ivc_validity` | A final proof attests to the correctness of the entire computation chain. |
| 2 | `folding_soundness` | Each fold preserves the satisfiability relation. |

### Threat model

Adversary is a malicious prover.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Kothapalli, Setty, Tzialla, Nova (CRYPTO 2022)
