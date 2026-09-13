# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: withdrawal_multisig, signer_compromise_resistance.

---

## Protocol: Harmony Horizon Bridge

**Category:** bridge

### Overview

Horizon used a 2-of-5 multisig of EOA keys to approve cross-chain withdrawals of assets between Harmony and Ethereum/BSC.

### Roles

- **Multisig signers**
- **Bridge contract**
- **User**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `withdrawal_multisig` | A withdrawal requires 2 valid signer approvals. |
| 2 | `signer_compromise_resistance` | No single compromise yields the threshold. |

### Threat model

Adversary compromises signer EOAs (e.g. via malware/social engineering).

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Harmony Horizon 2022 incident (~US$100M)
