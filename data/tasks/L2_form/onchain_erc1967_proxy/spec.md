# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: implementation_authorization, storage_isolation, initializer_once.

---

## Protocol: ERC-1967 Upgradeable Proxy

**Category:** token

### Overview

Upgradeable contracts use a proxy storing the implementation address in a standardized slot and delegatecall to it; an admin (or logic contract via UUPS) upgrades the implementation. Initializers replace constructors.

### Roles

- **Admin/upgrader**
- **Proxy**
- **Implementation**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `implementation_authorization` | Only the authorized admin/upgrader can change the implementation. |
| 2 | `storage_isolation` | Proxy and implementation storage never collide. |
| 3 | `initializer_once` | The initializer can be called at most once. |

### Threat model

Adversary can call any externally reachable function; the admin key is uncompromised.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-1967
- OpenZeppelin upgrades docs
