# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: module_authorization, threshold_not_bypassed, guard_completeness.

---

## Protocol: Gnosis Safe Modules and Guards

**Category:** account_abstraction

### Overview

Safe modules can execute transactions from a Safe without the normal owner threshold; guards can veto transactions. Modules extend Safe with automation.

### Roles

- **Owners**
- **Module**
- **Guard**
- **Safe**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `module_authorization` | Only enabled modules can execute, and only within their intended scope. |
| 2 | `threshold_not_bypassed` | A module cannot bypass the owner threshold for arbitrary transfers. |
| 3 | `guard_completeness` | A guard can veto every state-changing path. |

### Threat model

Adversary compromises or lures the Safe into enabling a malicious module.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.safe.global/advanced/smart-account-modules
- Safe modules/guards
