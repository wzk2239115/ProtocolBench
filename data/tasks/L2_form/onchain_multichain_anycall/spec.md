# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: message_uniqueness, mpc_authorization.

---

## Protocol: Multichain anyCall (router)

**Category:** bridge

### Overview

Multichain (formerly Anyswap) uses an MPC network to validate cross-chain messages; anyCall lets a contract on chain A invoke a function on chain B after MPC attestation.

### Roles

- **MPC nodes**
- **anyCall contract**
- **User**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `message_uniqueness` | Each attested cross-chain call is executed at most once. |
| 2 | `mpc_authorization` | Only messages signed by the MPC threshold are executed. |

### Threat model

Adversary cannot corrupt the MPC threshold; may exploit reentrancy/processing order or the token router.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Multichain 2023 incident (~US$126M)
