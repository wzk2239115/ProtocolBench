# Protocol modeling task

Model the protocol described below and analyze it. You may use any method
(Lean 4, Tamarin, Verifpal, or a combination of them). Deliverables follow the
task README: `verdict.json`, an attack report when a goal fails, and
machine-checkable evidence in your chosen tool.

**No model is provided.** You decide the strategy: formalize the whole protocol
first, or reason about the likely flaw and then prove it. The security goals you
must formulate should cover, at minimum: oracle_relayer_consistency, config_soundness.

---

## Protocol: LayerZero (ultra-light nodes)

**Category:** interop

### Overview

LayerZero uses an oracle (e.g. Chainlink) and a relayer that must be distinct-but-independent: the endpoint verifies a message only if the block header from the oracle and the proof from the relayer agree. Security is configurable per application.

### Roles

- **User**
- **Endpoint**
- **Oracle**
- **Relayer**
- **Application**

### Security goals (formulate each as a theorem/lemma)

| # | Goal name | Property |
|---|-----------|----------|
| 1 | `oracle_relayer_consistency` | A message is accepted only if both the oracle header and the relayer proof match. |
| 2 | `config_soundness` | The library configuration cannot be replaced by an unauthorized party. |

### Threat model

Adversary may control or collude with the chosen oracle/relayer pair, or exploit an application misconfiguration.

### What to decide

Whether the goals hold for the deployed protocol as described. If a goal
fails, produce a concrete sequence of on-chain transactions/messages (an
attack trace) and the resulting violation. If you can, back it with a
machine-checked proof in your chosen tool.

### References

- https://docs.layerzero.network/
- LayerZero whitepaper
