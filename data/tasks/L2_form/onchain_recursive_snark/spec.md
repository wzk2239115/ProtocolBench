# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: composition_soundness, domain_binding.

---

## Protocol: Recursive SNARK / proof aggregation

**Category:** zk

### Overview

Recursive SNARKs verify a proof inside another proof, enabling aggregation and incrementally verifiable computation across many steps.

### Roles

- **Prover**
- **Verifier**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `composition_soundness` | The outer proof is sound if the inner verifier is correctly embedded. |
| 2 | `domain_binding` | Each recursion level binds the correct verification key/domain. |

### Threat model

Adversary is a malicious prover exploiting a missing binding in the recursive verifier.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Recursive SNARK literature
- Halo/Nova/Pickles
