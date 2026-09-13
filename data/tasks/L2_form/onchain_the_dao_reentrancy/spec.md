# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: withdraw_exactly_once, balance_consistency.

---

## Protocol: The DAO (reentrancy)

**Category:** defi

### Overview

The DAO held ETH and let token holders withdraw their share via splitDAO, which computed the reward and sent ETH to the caller before updating the internal token balance.

### Roles

- **Token holder**
- **DAO contract**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `withdraw_exactly_once` | A holder can withdraw at most the balance corresponding to their tokens. |
| 2 | `balance_consistency` | The internal balance is debited before any external value transfer. |

### Threat model

Adversary is a token holder that is a contract with a payable fallback, able to reenter.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://en.wikipedia.org/wiki/The_DAO
- 2016 DAO exploit post-mortems
