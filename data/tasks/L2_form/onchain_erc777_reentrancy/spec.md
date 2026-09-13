# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: transfer_atomicity, no_reentrancy.

---

## Protocol: ERC-777 Tokens and Receiver Hooks

**Category:** token

### Overview

ERC-777 defines send() which calls tokensReceived on the recipient if it is a registered contract, and ERC-1820 registry lookups. This hook executes attacker code mid-transfer.

### Roles

- **Sender**
- **Recipient (may be an attacker contract with a hooks)**
- **ERC-1820 registry**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `transfer_atomicity` | A transfer either completes fully or has no effect; balances and total supply stay consistent. |
| 2 | `no_reentrancy` | The recipient hook cannot reenter the token or an integrating protocol to observe an inconsistent state. |

### Threat model

Adversary is the recipient of a transfer and controls the tokensReceived hook, which runs before the sender's state update in naive integrations.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-777
- https://eips.ethereum.org/EIPS/eip-1820
