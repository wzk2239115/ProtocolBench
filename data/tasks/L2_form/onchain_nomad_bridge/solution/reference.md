# Reference: Nomad bridge (2022)

**Verdict: UNSAFE.** Deployed Nomad token bridge; ~US$190M drained on
2022-08-01.

## Root cause

The remote `Replica` contract's `process(message, proof, root)` accepts any
`root` for which `acceptableRoot[root] == true`. During the initialisation, the
mapping was set with the zero root accepted (`acceptableRoot[0] = true`) as a
bootstrap value. The Merkle verification therefore treats the zero root as a
valid, confirmed tree, and a message can be crafted whose (trivial) proof
verifies against the all-zero root.

## Attack

1. Read a legitimate transaction that had already been processed (to learn the
   message encoding and the `process` call format).
2. Craft an arbitrary `Message` for the adversary's own recipient/amount.
3. Submit `process(craftedMessage, proof, 0)` where `0` is the zero root
   (or the pre-initialised committed root). The `acceptableRoot(0)` check
   passes.
4. The MsgHash is marked processed and the mint executes — the adversary
   receives tokens on the remote chain that were never locked on the home
   chain, violating `only_confirmed_messages` and `value_conservation`.

Replays of the same pattern (other callers reusing the same `proof`/root) made
the drain permissionless; the same `(message_id, destination_chain)` could be
processed repeatedly in the first wave because the processed map was
`trySet` upstream and lagged.

## Fix

- Do not pre-authorise any root; require a validator quorum for every root.
- Track processed messages per `(message_id, destination_chain)` and reject
  duplicates atomically.
- Treat an absent/zero root as unacceptable.
