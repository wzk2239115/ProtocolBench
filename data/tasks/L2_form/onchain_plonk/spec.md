# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: soundness, public_input_binding, transcript_binding.

---

## Protocol: PLONK Universal SNARK

**Category:** zk

### Overview

PLONK is a universal, updatable-setup SNARK using a polynomial commitment scheme; circuits are expressed as permutations over a fixed domain, with public inputs bound in the transcript.

### Roles

- **Prover**
- **Verifier**
- **Universal setup**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `soundness` | No false statement has a valid proof (Fiat-Shamir is sound). |
| 2 | `public_input_binding` | The proof binds the exact public inputs. |
| 3 | `transcript_binding` | Fiat-Shamir challenges are uniquely derived, preventing grinding. |

### Threat model

Adversary is a malicious prover; the universal setup is honest.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Gabizon, Williamson, Ciobotaru, PLONK (2019)
