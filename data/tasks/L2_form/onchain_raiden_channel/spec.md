# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: settlement_at_agreed_balance, lock_uniqueness.

---

## Protocol: Raiden Network

**Category:** payment

### Overview

Raiden is an Ethereum payment-channel network using balance proofs, a monitoring service, and a one-time-use lock (secret) for transfers; channels are settled on-chain after an unlock/settle window.

### Roles

- **Channel parties**
- **Monitoring service**
- **Path-finding service**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `settlement_at_agreed_balance` | Settlement reflects the latest balance proof with the highest nonce. |
| 2 | `lock_uniqueness` | A transfer secret unlocks at most its intended amount once. |

### Threat model

Adversary is a counterparty that withholds or replays balance proofs; the monitoring service may be unavailable.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://raiden.network/
- Raiden specification
