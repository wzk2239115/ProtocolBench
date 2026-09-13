# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: userop_authentication, paymaster_safety, validation_storage_isolation.

---

## Protocol: ERC-4337 Account Abstraction

**Category:** token

### Overview

ERC-4337 introduces UserOperations processed by an EntryPoint contract: validation calls the account's validateUserOp (and optionally a paymaster's validatePaymasterUserOp), then execution runs the call. Bundlers package UserOps; the EntryPoint enforces nonce and prefunding.

### Roles

- **User (account owner)**
- **Bundler**
- **EntryPoint**
- **Account contract**
- **Paymaster (optional gas sponsor)**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `userop_authentication` | A UserOperation is executed only if the account's validation function approves it. |
| 2 | `paymaster_safety` | A paymaster cannot be drained: it pays only for UserOps it validated and within its stake/allowance. |
| 3 | `validation_storage_isolation` | During validation, one entity cannot read or write storage of another entity. |

### Threat model

Adversary controls UserOps, accounts, paymasters and bundling; cannot break ECDSA. It may exploit reentrancy and cross-entity storage access during validation.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-4337
- https://docs.erc4337.io/
