# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: soundness, knowledge_soundness, setup_integrity.

---

## Protocol: Groth16 zk-SNARK

**Category:** zk

### Overview

Groth16 is a pairing-based zk-SNARK with a circuit-specific trusted setup producing a proving key and a verification key; proofs are three group elements and verification is a constant-size pairing check.

### Roles

- **Prover**
- **Verifier**
- **Trusted setup (ceremony)**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `soundness` | A prover cannot produce a proof for a false statement. |
| 2 | `knowledge_soundness` | A valid proof implies knowledge of a satisfying witness. |
| 3 | `setup_integrity` | Security holds if at least one ceremony participant was honest. |

### Threat model

Adversary is a malicious prover with full control of proof generation; the toxic waste is unknown to at least one honest participant.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Groth, On the Size of Pairing-based NIZKs (2016)
- Zcash ceremony
