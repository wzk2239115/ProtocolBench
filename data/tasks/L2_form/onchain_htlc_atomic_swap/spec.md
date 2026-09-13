# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: atomicity, no_free_option, timeout_fairness.

---

## Protocol: HTLC Atomic Cross-Chain Swap

**Category:** payment

### Overview

Two parties swap assets across chains using Hash-Time-Locked Contracts: the swap secret's hash locks funds; the receiver claims on one chain revealing the preimage and uses it to claim on the other; both legs have timeouts with a safety margin.

### Roles

- **Initiator (Alice)**
- **Participant (Bob)**
- **Both chains**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `atomicity` | Either both legs settle or both are refunded; no party loses assets. |
| 2 | `no_free_option` | Neither party can gain by delaying or by abandoning after learning the preimage. |
| 3 | `timeout_fairness` | If one leg is claimed, the counterparty has time to claim their leg. |

### Threat model

Adversary is a rational, possibly timing-manipulating counterparty and a congestion-causing network adversary.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://en.bitcoin.it/wiki/Hash_Time_Locked_Contracts
- Cross-chain atomic swap literature
