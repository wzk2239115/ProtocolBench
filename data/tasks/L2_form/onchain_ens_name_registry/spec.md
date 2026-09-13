# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: name_ownership_uniqueness, commit_reveal_fairness, resolver_authorization.

---

## Protocol: ENS Name Registry

**Category:** identity

### Overview

ENS assigns names via a registrar that commits/reveals to prevent front-running; a registry maps names to owners/resolvers, and a resolver records addresses.

### Roles

- **Registrant**
- **Registry**
- **Resolver**
- **Controller**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `name_ownership_uniqueness` | A name has one owner, transferable only by the owner. |
| 2 | `commit_reveal_fairness` | An observer cannot front-run a registration by copying the reveal. |
| 3 | `resolver_authorization` | Records can be changed only by the name owner/authorized controller. |

### Threat model

Adversary front-runs registration and resolver updates.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.ens.domains/
- ENS registry/registrar
