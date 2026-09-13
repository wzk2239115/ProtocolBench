# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: sender_authentication, meta_tx_no_replay, forwarder_trust.

---

## Protocol: ERC-2771 Meta-Transactions (trusted forwarder)

**Category:** token

### Overview

ERC-2771 lets a relayer pay gas: a user signs a request (from, to, data, nonce) off-chain; the trusted forwarder appends the original sender to calldata and calls the target contract, which reads the sender via _msgSender(). The forwarder is trusted by the target.

### Roles

- **User (signs the meta-transaction)**
- **Relayer (submits it)**
- **Trusted forwarder**
- **Target contract (executes using _msgSender())**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `sender_authentication` | Only requests signed by the claimed sender are executed as that sender. |
| 2 | `meta_tx_no_replay` | A signed meta-transaction is executed at most once per target contract and chain. |
| 3 | `forwarder_trust` | The appended sender field cannot be forged by an untrusted caller. |

### Threat model

Adversary is a relayer that observes signed requests and can submit any request; cannot forge signatures. The forwarder contract is honest.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://eips.ethereum.org/EIPS/eip-2771
- https://eips.ethereum.org/EIPS/eip-712
