# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: feed_authenticity, freshness, manipulation_resistance.

---

## Protocol: Winklink

**Category:** oracle

### Overview

Winklink is a production on-chain oracle protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `feed_authenticity` | An answer is accepted only with a valid signer/reporter quorum. |
| 2 | `freshness` | Stale rounds cannot be used as current prices. |
| 3 | `manipulation_resistance` | The reported value cannot be profitably manipulated by an attacker. |

### Threat model

Adversary cannot compromise the reporter quorum but may manipulate the underlying market or replay stale rounds.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Oracle protocol documentation
