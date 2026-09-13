# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: message_authenticity, no_replay, value_conservation, proof_verification_soundness.

---

## Protocol: Arbitrum Outbox

**Category:** bridge

### Overview

Arbitrum Outbox is a production on-chain bridge protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `message_authenticity` | A cross-chain message/withdrawal is executed only if attested by the validator/guardian quorum. |
| 2 | `no_replay` | Each attested message is consumed at most once. |
| 3 | `value_conservation` | Minted/released value never exceeds locked/burned value. |
| 4 | `proof_verification_soundness` | Merkle/signature/light-client verification cannot be bypassed. |

### Threat model

The adversary cannot corrupt the quorum but may craft arbitrary proofs/messages, replay them, and exploit verification or accounting code.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Cross-chain bridge security surveys
- https://ethereum.org/en/developers/docs/bridges/
