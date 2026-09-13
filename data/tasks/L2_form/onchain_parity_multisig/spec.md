# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: owner_initialization_once, access_control, library_protection.

---

## Protocol: Parity Multisig Wallet (2017)

**Category:** governance

### Overview

The Parity multisig used a library contract containing the wallet logic plus a tiny proxy per wallet; wallets were created by delegatecall to the library's initWallet, which configured owners and the required threshold.

### Roles

- **Owners**
- **Wallet proxy**
- **WalletLibrary**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `owner_initialization_once` | A wallet's owners can be initialized exactly once by the legitimate creator. |
| 2 | `access_control` | Only owners can execute/kill the wallet. |
| 3 | `library_protection` | The shared library cannot be hijacked to control wallets. |

### Threat model

Adversary can call anyone-permissioned functions on the library and proxies.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- Parity multisig incidents (July and November 2017)
