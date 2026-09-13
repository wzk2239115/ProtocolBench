# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: kzg_binding, proof_soundness.

---

## Protocol: EIP-4844 Proto-Danksharding (blobs)

**Category:** layer2

### Overview

Blob-carrying transactions add a KZG commitment to blobs whose data is pruned after ~18 days; rollups use blobs for cheap data availability.

### Roles

- **Rollup**
- **Beacon nodes**
- **L1**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `kzg_binding` | A blob's versioned hash binds the exact blob data. |
| 2 | `proof_soundness` | Point-evaluation proofs verify against the commitment. |

### Threat model

Adversary cannot break KZG; may exploit pruning windows or mempool data withholding.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-4844
