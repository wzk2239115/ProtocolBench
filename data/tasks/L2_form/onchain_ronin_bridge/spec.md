# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: withdrawal_quorum, key_independence.

---

## Protocol: Ronin Bridge (threshold validators)

**Category:** bridge

### Overview

The Ronin bridge used a 5-of-9 validator multisig to approve cross-chain withdrawals; validators included Axie-related nodes and one third-party (Axie DAO) node whose access was not revoked.

### Roles

- **Validators**
- **Bridge contract**
- **User**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `withdrawal_quorum` | A withdrawal is released only with 5 valid, independent validator approvals. |
| 2 | `key_independence` | No small coalition can obtain the threshold via a single point of compromise. |

### Threat model

Adversary may social-engineer/compromise validator keys and abuse special delegations; cannot break ECDSA.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Ronin bridge 2022 incident (~US$624M)
