# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: withdrawal_once, anonymity_set, deposit_withdraw_consistency.

---

## Protocol: Tornado Cash Mixer

**Category:** privacy

### Overview

A fixed-denomination mixer: users deposit into a Merkle tree and later withdraw to a fresh address using a zk-SNARK proving membership of a note, with a nullifier preventing double withdrawal.

### Roles

- **Depositor**
- **Withdrawer**
- **Relayer**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `withdrawal_once` | A note can be withdrawn at most once (nullifier binding). |
| 2 | `anonymity_set` | The withdrawer is unlinkable to the depositor within the anonymity set. |
| 3 | `deposit_withdraw_consistency` | Only notes inserted into the tree can be withdrawn. |

### Threat model

Adversary is an observer/relayer; may exploit note leakage, relayer front-running, or metadata.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://tornado.cash/
- Tornado Cash docs
