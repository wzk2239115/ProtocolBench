# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: permit_signature_binding, permit_no_replay, permit_nonce_monotonicity.

---

## Protocol: ERC-2612 Permit (gasless approvals)

**Category:** token

### Overview

ERC-2612 adds an EIP-712 signature-based approval to ERC-20: a spender submits permit(owner, spender, value, deadline, v, r, s) and the token contract sets allowance[owner][spender] if the signature is valid and deadline has not passed. The signed struct is bound to a domain separator. Goal is to replace the separate approve transaction.

### Roles

- **Owner (signer of the permit)**
- **Spender (submits the permit)**
- **Token contract (verifies the EIP-712 signature and records the nonce)**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `permit_signature_binding` | A permit is accepted only for the exact (owner, spender, value, nonce, deadline) signed by the owner. |
| 2 | `permit_no_replay` | A permit signature cannot be reused to grant an allowance twice, on the same chain or on any other chain/contract. |
| 3 | `permit_nonce_monotonicity` | Each accepted permit increments the owner's nonce by exactly one. |

### Threat model

Adversary can read all signed permits from the mempool/chain and submit arbitrary permits; cannot forge the owner's signature. Chains may fork and share genesis state.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-2612
- https://eips.ethereum.org/EIPS/eip-712
