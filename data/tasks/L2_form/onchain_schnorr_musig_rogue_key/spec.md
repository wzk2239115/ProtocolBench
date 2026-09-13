# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: unforgeability, key_aggregation_binding.

---

## Protocol: Schnorr Multisig (rogue-key / MuSig)

**Category:** signature

### Overview

Naive Schnorr multisig aggregates public keys as the sum of participants' keys and asks for the sum signature. MuSig hardens this with per-session key coefficients.

### Roles

- **Signers**
- **Verifier/aggregator**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `unforgeability` | A coalition of n-1 signers cannot produce a signature valid for the aggregated key of n honest signers. |
| 2 | `key_aggregation_binding` | Each participant's contribution to the aggregate key is bound to the session. |

### Threat model

Adversary is a malicious participant that chooses its public key after seeing the others (rogue-key attack).

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eprint.iacr.org/2018/068
- MuSig2 (2020/1261)
