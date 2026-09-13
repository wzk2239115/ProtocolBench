# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: soundness, commitment_binding, transcript_binding.

---

## Protocol: Halo2 / Recursive Proofs

**Category:** zk

### Overview

Halo2 uses an inner-product polynomial commitment with no trusted setup and supports recursive proof composition, used in Zcash Orchard and zkEVMs.

### Roles

- **Prover**
- **Verifier**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `soundness` | A false statement has no valid proof. |
| 2 | `commitment_binding` | The commitment scheme binds the polynomial. |
| 3 | `transcript_binding` | Fiat-Shamir challenges are uniquely determined. |

### Threat model

Adversary is a malicious prover; no setup trust required.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://zcash.github.io/halo2/
- Halo2 documentation
