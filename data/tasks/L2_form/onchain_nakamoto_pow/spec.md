# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: common_prefix, no_double_spend, selfish_mining_resistance.

---

## Protocol: Nakamoto Consensus (Proof of Work)

**Category:** consensus

### Overview

Nodes extend the heaviest (most-work) chain; the longest-chain rule plus proof-of-work gives eventual consistency. Transactions have probabilistic finality after k confirmations.

### Roles

- **Miners**
- **Full nodes**
- **Light clients**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `common_prefix` | Honest chains diverge only in the last k blocks with probability decreasing in k. |
| 2 | `no_double_spend` | A confirmed transaction cannot be reverted without controlling a majority of hash power. |
| 3 | `selfish_mining_resistance` | Deviating by withholding blocks is not more profitable than honest mining. |

### Threat model

Adversary controls a fraction of hash power and network timing; rational miners maximize revenue.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://bitcoin.org/bitcoin.pdf
- Eyal & Sirer, Majority is not Enough (2014)
