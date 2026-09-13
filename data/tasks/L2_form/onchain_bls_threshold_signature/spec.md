# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: threshold_unforgeability, unique_signature.

---

## Protocol: BLS Threshold Signatures

**Category:** signature

### Overview

BLS signatures are unique and aggregatable; a t-of-n threshold is implemented with a Shamir sharing of the secret key, where t shares produce one signature verifiable against the group public key.

### Roles

- **Signers**
- **Aggregator**
- **Verifier**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `threshold_unforgeability` | Fewer than t signers cannot produce a valid signature. |
| 2 | `unique_signature` | There is a single valid signature per (key, message), preventing malleability. |

### Threat model

Adversary corrupts up to t-1 signers and may choose messages adaptively.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Boneh-Lynn-Shacham (2001)
- Threshold BLS constructions
