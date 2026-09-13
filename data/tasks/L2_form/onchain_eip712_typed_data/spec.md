# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: domain_separation, struct_binding, no_replay.

---

## Protocol: EIP-712 Typed Structured Data Hashing

**Category:** signature

### Overview

EIP-712 defines a hashing/signing scheme for structured data with a domain separator (name, version, chainId, verifyingContract) and type hashes.

### Roles

- **Signer**
- **Verifier contract**
- **Relayer**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `domain_separation` | A signature is valid only for the exact domain (chain + contract). |
| 2 | `struct_binding` | The signature binds the exact field values and type. |
| 3 | `no_replay` | Signatures cannot be replayed across domains or nonces. |

### Threat model

Adversary replays signatures across chains/contracts or trick users into signing ambiguous payloads.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-712
