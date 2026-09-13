# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: bid_authenticity, builder_neutrality, payment_guarantee.

---

## Protocol: Flashbots / PBS (block builder market)

**Category:** mev

### Overview

Proposer-Builder Separation: builders assemble blocks and bid in a sealed-bid auction; the proposer signs the highest bid header. Relays mediate to prevent stealing. MEV-Boost is the software used by most validators.

### Roles

- **Builders**
- **Relays**
- **Proposers/validators**
- **Searchers**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `bid_authenticity` | The proposer can only sign a header for which a matching body is available (no unbundling). |
| 2 | `builder_neutrality` | The market does not let one builder or relay censor/suppress transactions. |
| 3 | `payment_guarantee` | The proposer is paid the winning bid atomically. |

### Threat model

Adversary is a dominant builder or relay maximizing MEV and censoring transactions.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.flashbots.net/
- MEV-Boost/relay designs
