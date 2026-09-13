# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: chain_quality, storage_proof_binding.

---

## Protocol: Filecoin Expected Consensus

**Category:** consensus

### Overview

Filecoin uses storage-based leader election (ElectionProof) weighted by quality-adjusted power, a tipset structure, and a longest-chain rule over tipsets.

### Roles

- **Storage miners**
- **Full nodes**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `chain_quality` | Adversarial mining power cannot outpace honest chain growth. |
| 2 | `storage_proof_binding` | Power derives from valid PoRep/PoSt proofs. |

### Threat model

Adversary with a minority of storage power and rational miners.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://spec.filecoin.io/
