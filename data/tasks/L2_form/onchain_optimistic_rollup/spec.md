# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: state_root_soundness, fraud_proof_soundness, withdrawal_safety.

---

## Protocol: Optimistic Rollup (fraud proofs)

**Category:** rollup

### Overview

An optimistic rollup posts L2 state roots to L1 and assumes validity; withdrawals are delayed by a challenge window during which anyone can submit a fraud proof. A sequencer orders transactions.

### Roles

- **Sequencer**
- **Verifier/challenger**
- **L1 bridge**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `state_root_soundness` | Only valid state roots are finalized after the challenge window. |
| 2 | `fraud_proof_soundness` | A fraudulent root can always be proven wrong by an honest challenger within the window. |
| 3 | `withdrawal_safety` | Withdrawals cannot finalize against an unchallenged fraudulent root. |

### Threat model

Adversary controls the sequencer and may censor/speed up; at least one honest challenger must be live within the window.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://ethereum.org/en/developers/docs/scaling/optimistic-rollups/
- Arbitrum/Optimism docs
