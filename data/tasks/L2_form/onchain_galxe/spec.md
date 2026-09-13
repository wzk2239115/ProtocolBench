# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: name_ownership, resolver_authorization, commit_reveal_fairness.

---

## Protocol: Galxe

**Category:** identity

### Overview

Galxe is a production on-chain identity protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `name_ownership` | A name/identity has one owner, transferable only by the owner. |
| 2 | `resolver_authorization` | Records change only under owner authorization. |
| 3 | `commit_reveal_fairness` | Registration cannot be front-run. |

### Threat model

Adversary front-runs registration and record updates.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Identity protocol documentation
