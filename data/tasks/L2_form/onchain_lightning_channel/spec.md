# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: close_at_agreed_balance, revoked_state_penalty, no_htlc_theft.

---

## Protocol: Lightning Network Payment Channel

**Category:** payment

### Overview

A 2-of-2 funding transaction opens a channel; commitment transactions encode the current balance split with revocation secrets. Revoking an old state lets the wronged party penalize the counterparty; HTLCs are added for routed payments.

### Roles

- **Channel parties**
- **Routing nodes**
- **Watchtowers**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `close_at_agreed_balance` | A channel can only close at the latest agreed balance split. |
| 2 | `revoked_state_penalty` | Broadcasting a revoked commitment lets the counterparty take all funds. |
| 3 | `no_htlc_theft` | HTLC outputs can be claimed only by the rightful party after preimage/timeout. |

### Threat model

Adversary is a channel counterparty that broadcasts old states, withholds preimages, or griefs HTLCs; watchtowers may be offline.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://github.com/lightning/bolts
- Lightning Network whitepaper (Poon-Dryja)
