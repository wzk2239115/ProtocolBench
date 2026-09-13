# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: vaa_guardian_quorum, no_signature_spoof.

---

## Protocol: Wormhole Token Bridge

**Category:** bridge

### Overview

Wormhole moves tokens via guardian-signed VAAs: the core contract verifies a quorum of guardian signatures over a message, and the token bridge mints wrapped tokens from a VAA. On Solana the signature set was verified by the system program's secp256k1 instruction.

### Roles

- **Guardians**
- **Core contract**
- **Token bridge**
- **User/relayer**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `vaa_guardian_quorum` | A VAA is executed only if signed by the current guardian set quorum. |
| 2 | `no_signature_spoof` | An attacker cannot supply arbitrary bytes that pass signature verification. |

### Threat model

Adversary cannot compromise the guardian keys; it may exploit the verification code path.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Wormhole 2022 incident (~US$326M)
- https://docs.wormhole.com/
