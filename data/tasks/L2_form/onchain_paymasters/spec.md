# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: userop_authentication, no_replay, module_authorization, paymaster_safety.

---

## Protocol: Paymasters

**Category:** account_abstraction

### Overview

Paymasters is a production on-chain account_abstraction protocol. Its deployed interfaces, message/transaction formats and parameters are the ground truth for this task; consult the protocol's documentation, deployment addresses and incident reports as needed.

### Roles

See the overview.

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `userop_authentication` | Operations execute only when authorized by the account. |
| 2 | `no_replay` | Operations and validations are chain/account/nonce bound. |
| 3 | `module_authorization` | Extensions cannot bypass the account's authorization policy. |
| 4 | `paymaster_safety` | Sponsors cannot be drained beyond their intended budget. |

### Threat model

Adversary controls user operations, modules, paymasters, and relayers; exploits validation-time reentrancy/storage access.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Account abstraction EIPs / docs
