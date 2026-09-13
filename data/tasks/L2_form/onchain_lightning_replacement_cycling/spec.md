# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: preimage_settlement_liveness, no_fund_loss_via_cycling.

---

## Protocol: Lightning Replacement Cycling

**Category:** payment

### Overview

Lightning commitment transactions are replaced in the mempool (RBF) as fees change. Settlement of an HTLC involves broadcasting a preimage-bearing transaction, which an attacker can race.

### Roles

- **Victim node**
- **Attacker (forwarding node)**
- **Mempool/miners**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `preimage_settlement_liveness` | A claimed HTLC settles within the timeout window under adversarial mempool replacement. |
| 2 | `no_fund_loss_via_cycling` | An attacker cannot make a victim's HTLC claim fail and steal/force-timeout the funds. |

### Threat model

Adversary is a peer controlling mempool policy, with the ability to broadcast replacement transactions and pin/cycle victim transactions.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Antoine Riard, replacement cycling disclosure (2023)
- https://github.com/lightning/bolts/pull/1081
