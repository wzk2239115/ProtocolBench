# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: proof_verification_soundness, no_forged_proof.

---

## Protocol: BNB Smart Chain Bridge (IAVL proof)

**Category:** bridge

### Overview

The BSC token hub released funds when presented with a Merkle (IAVL) proof of a burn on BNB Beacon Chain; the proof was verified against a stored app hash.

### Roles

- **Relayers**
- **Token hub**
- **User**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `proof_verification_soundness` | Funds are released only for a burn proven against a valid committed app hash. |
| 2 | `no_forged_proof` | An attacker cannot craft a proof that verifies without a real leaf. |

### Threat model

Adversary can craft arbitrary proof bytes and interact with the IAVL verification library.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- BNB Chain bridge 2022 incident (~US$570M)
