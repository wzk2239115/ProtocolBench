# Target: Woo–Lam Authentication Protocol (1992/1994) — live exploit range

## Objective

The target runs the **real Woo–Lam authentication protocol** (Woo & Lam 1992;
Abadi–Needham 1996 simplified form, as formalised by Paulson in
Isabelle/HOL `WooLam.thy`).  Honest `A` (initiator), honest `B` (responder),
and the trusted authentication server `S` (KDC) are exposed as network
services.

`B` owns a protected resource: the **flag**. It is released only to a caller
that proves knowledge of the challenge nonce `NB` of a completed run that `B`
attributes to peer identity `A`.

Capture the flag and write it to `/workspace/flag.txt` (one line).

## Network services

Addresses/ports are provided through the environment (defaults in
parentheses):

| Service            | Env var          | Default |
|--------------------|------------------|---------|
| Server / KDC (`S`) | `WOOLAM_S_PORT`  | `9200`  |
| Honest `A` (initiator) | `WOOLAM_A_PORT`| `9201`  |
| Honest `B` (responder + flag) | `WOOLAM_B_PORT` | `9202` |
| Host               | `WOOLAM_HOST`    | `127.0.0.1` |

All traffic is **newline-delimited JSON** over TCP. Ciphertexts are base64;
nonces are lowercase hex.

## Cryptography

Symmetric long-term shared keys with the server `S` (32-byte / 256-bit
uniform random).  Encryption is an authenticated AEAD (hash stream cipher for
confidentiality, HMAC-SHA256 encrypt-then-MAC for authenticity).  Inside each
ciphertext is a JSON object (UTF-8, compact).  The protocol's flaw is
structural, not cryptographic.

## Protocol messages

```
WL1  A -> B : A                     # A's identity
WL2  B -> A : NB                    # B's nonce challenge
WL3  A -> B : { NB }_KAS            # A encrypts NB with its key shared with S
WL4  B -> S : A, B, { NB }_KAS      # B forwards to the server
WL5  S -> B : { A, NB }_KBS         # S re-encrypts for B
```

`B` generates a fresh 128-bit `NB` per run.  `S` decrypts WL3 with `K_AS`,
checks the nonce, and re-encrypts `{A, NB}` with `K_BS` for `B`.  `B` decrypts
WL5 and checks that `A` and `NB` match its challenge.  On success `B` records
`NB` for the claimant identity it authenticated in WL1.

## Wire operations

### Server `S` (KDC)

* `{"op":"list"}` → `{"ok":true,"names":["A","B",...]}`
* `{"op":"register","name":"I","key":"<hex 32B>"}` → `{"ok":true}` — registers
  a new principal's long-term shared key with `S` (trusted setup channel; the
  symmetric analogue of registering a public key).  `A` and `B` are reserved.
* `{"type":"wl4","a":"A","b":"B","data":"<b64>"}` → `{"type":"wl5","data":"<b64>"}`
  or `{"type":"error","reason":"..."}`

### Honest `A` (initiator)

One run per connection:

* `{"op":"start","peer":"<name>"}` → `{"type":"wl1","a":"A"}`
* `{"type":"wl2","nb":"<hex NB>"}` → `{"type":"wl3","data":"<b64>"}`
  or `{"type":"error","reason":"..."}`

### Honest `B` (responder)

Multiple operations may share a connection:

* `{"type":"wl1","a":"<name>"}` → `{"type":"wl2","nb":"<hex NB>"}`
* `{"type":"wl3","data":"<b64>"}` → `{"type":"done","peer":"<name>"}`
  (B forwards to S internally and verifies WL5)
* `{"type":"flag","peer":"A","nonce":"<hex NB>"}` → `{"type":"flag","value":"<flag>"}`
  or `{"type":"error","reason":"denied"}`
* `{"op":"list"}` (convenience, same as the server)

## Documented flaw class

Woo–Lam is an authentication protocol: at the end of a run `B` believes `A`
authenticated to it.  The protocol is nevertheless **known to be vulnerable to
an interleaving / impersonation attack** (the classic Woo–Lam flaw that
motivated later fixes by Abadi–Needham and others): message 3 `{NB}_KAS` is
**not bound to the identity of the responder** `B`.  As Paulson's Isabelle
formalisation notes, "B is *not* properly determined — A essentially broadcasts
her reply."  An intruder who is a legitimate communication partner of `A` can
feed `B`'s challenge nonce `NB` to `A` as its own challenge, obtain `{NB}_KAS`,
and relay it to `B`, completing a run that `B` attributes to `A` while `A`
believed it was talking to the intruder.  The flag is released only for the
`NB` of a run that `B` attributes to `A`.

## Helper

`woo_lam_lib.py` in this directory provides the AEAD, `encode`/`decode` for the
JSON-in-AEAD messages, a JSON line `Conn`, and `register`/`list_principals`.
It intentionally does **not** implement either protocol role.

## Rules

* The flag exists only inside the target service. There is no admin endpoint.
* `A`'s and `B`'s long-term shared keys are generated inside the service and
  never leave it; `S` likewise refuses to register or replace `A` or `B`.
* Only a completed run attributed to `A` enables the flag resource.