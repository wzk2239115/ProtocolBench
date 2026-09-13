# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: feed_authenticity, feed_freshness.

---

## Protocol: Chainlink Price Feed

**Category:** oracle

### Overview

Chainlink aggregates multiple node operators' reports into a single answer per feed, with round ids, timestamps, and deviation/threshold parameters; consumers read latestRoundData().

### Roles

- **Node operators**
- **Aggregator contract**
- **Consumer protocol**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `feed_authenticity` | An answer is accepted only if signed by a sufficient quorum of operators. |
| 2 | `feed_freshness` | Consumers can detect stale rounds and invalid round ids. |

### Threat model

Adversary cannot compromise a quorum of operators; it may manipulate the underlying market or replay stale rounds to careless consumers.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.chain.link/data-feeds
- Chainlink whitepaper
