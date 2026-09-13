# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: da_soundness, namespace_binding.

---

## Protocol: Celestia Data Availability

**Category:** da

### Overview

Celestia separates data availability from execution using data-availability sampling and namespaced Merkle trees; rollups post data as blobs and light clients sample.

### Roles

- **Rollup**
- **Celestia validators**
- **Light clients**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `da_soundness` | A block is accepted only if its data is available under sampling. |
| 2 | `namespace_binding` | Data is bound to the correct rollup namespace. |

### Threat model

Adversary controls a minority of validators and may attempt unavailable-data attacks; light clients sample.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://celestia.org/
- Celestia specification
