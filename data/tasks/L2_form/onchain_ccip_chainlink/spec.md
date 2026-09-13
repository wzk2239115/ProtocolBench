# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: message_authenticity, lane_and_rate_limit, no_router_confusion.

---

## Protocol: Chainlink CCIP

**Category:** interop

### Overview

CCIP uses a decentralized oracle network (Committing + Executing DONs) plus optional risk management to move messages and tokens; an on-chain Router enforces lane config and rate limits.

### Roles

- **Committing DON**
- **Executing DON**
- **Risk Management Network**
- **Router**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `message_authenticity` | Execution happens only for messages attested by the oracle network. |
| 2 | `lane_and_rate_limit` | Per-lane rate limits and token pools are enforced. |
| 3 | `no_router_confusion` | Messages cannot be redirected to the wrong receiver. |

### Threat model

Adversary cannot corrupt the DON; exploits misconfigured lanes/receivers and rate-limit accounting.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.chain.link/ccip
