# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: ordering_fairness, censorship_resistance, bid_authenticity.

---

## Protocol: Angstrom

**Category:** mev

### Overview

Angstrom is a production on-chain mev protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `ordering_fairness` | Users are not systematically harmed by transaction reordering. |
| 2 | `censorship_resistance` | No small set of builders/relays can exclude transactions. |
| 3 | `bid_authenticity` | The proposer is paid atomically for the exact block it signs. |

### Threat model

Adversary is a dominant builder/relay or searcher with ordering power.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- MEV / PBS design documentation
