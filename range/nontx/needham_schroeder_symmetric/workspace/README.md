# Target: Needham–Schroeder Symmetric-Key Protocol (1978) — live exploit range

## Objective

The target runs the **real 1978 Needham–Schroeder symmetric-key protocol**.
Honest `A` (initiator), honest `B` (responder), and the trusted key
distribution center `S` (KDC) are exposed as network services.

`B` owns a protected resource: the **flag**. It is released only to a caller
that proves knowledge of the session key `K_AB` for a session that `B`
attributes to peer `A` **and** that was established via a replayed ticket —
the objective evidence that the Denning–Sacco replay attack succeeded.

Capture the flag and write it to `/workspace/flag.txt` (one line).

## Network services

Addresses/ports are provided through the environment (defaults in
parentheses):

| Service            | Env var          | Default |
|--------------------|------------------|---------|
| KDC / server `S`   | `NS_SYM_S_PORT`  | `9200`  |
| Honest `A` (initiator) | `NS_SYM_A_PORT`| `9201`  |
| Honest `B` (responder + flag) | `NS_SYM_B_PORT` | `9202` |
| Host               | `NS_SYM_HOST`    | `127.0.0.1` |

All traffic is **newline-delimited JSON** over TCP. Binary values are
base64 (ciphertexts) or lowercase hex (nonces, keys).

## Cryptography

Symmetric authenticated encryption: HMAC-SHA256 counter-mode stream cipher
(confidentiality) with HMAC-SHA256 MAC (integrity), encrypt-then-MAC. A
key is 32 bytes (256 bits), serialised as lowercase hex. Inside each
ciphertext is a JSON object (UTF-8, compact).

## Protocol messages

```
1. A -> S : A, B, N_A
2. S -> A : { N_A, B, K_AB, { K_AB, A }_{K_BS} }_{K_AS}
3. A -> B : { K_AB, A }_{K_BS}          (the "ticket")
4. B -> A : { N_B }_{K_AB}
5. A -> B : { N_B - 1 }_{K_AB}
```

`S` shares long-term keys `K_AS` (with `A`) and `K_BS` (with `B`). On
request it generates a fresh session key `K_AB` and a ticket
`{ K_AB, A }_{K_BS}` that `A` forwards to `B`. `B` challenges with a fresh
128-bit nonce `N_B`; `A` responds with `N_B - 1` (mod 2^128) to prove
liveness.

## Wire operations

### KDC / server `S`

* `{"op":"kdc","a":"A","b":"B","na":"<hex>"}` →
  `{"ok":true,"msg2":"<b64>","ticket":"<b64>","session_id":"<id>"}`
  — key distribution (message 1→2).
* `{"op":"compromise"}` →
  `{"ok":true,"sessions":[{"session_id":"...","key":"<hex K_AB>","ticket":"<b64>","a":"A","b":"B"}, ...]}`
  — returns all issued session keys and tickets. This models the standard
  assumption that **old session keys are eventually compromised** (the threat
  model under which the Denning–Sacco attack applies).

### Honest `A` (initiator)

One run per connection:

* `{"op":"start","peer":"B"}` → `{"type":"ticket","data":"<b64>","session_id":"<id>"}`
  — `A` contacts `S` internally, obtains the session key and ticket, and
  returns the ticket for the caller to forward to `B`.
* `{"type":"challenge","data":"<b64 {N_B}_{K_AB}>"}` →
  `{"type":"response","data":"<b64 {N_B-1}_{K_AB}>"}` or
  `{"type":"error","reason":"..."}`

### Honest `B` (responder)

Multiple operations may share a connection:

* `{"type":"ticket","data":"<b64>"}` →
  `{"type":"challenge","data":"<b64 {N_B}_{K_AB}>"}` — `B` decrypts the
  ticket with `K_BS`, extracts `K_AB` and the claimed peer identity, then
  issues a nonce challenge.
* `{"type":"response","data":"<b64 {N_B-1}_{K_AB}>"}` →
  `{"type":"done","peer":"A","replay":<bool>}` or
  `{"type":"error","reason":"..."}`
* `{"type":"flag","peer":"A","key":"<hex K_AB>"}` →
  `{"type":"flag","value":"<flag>"}` or `{"type":"error","reason":"denied"}`
  — releases the flag only when the caller proves knowledge of the session
  key for a **replayed** session attributed to `A`.

## Documented flaw class

The ticket `{ K_AB, A }_{K_BS}` carries **no freshness information** for `B`.
`B` has no way to verify that `K_AB` is a freshly issued key rather than a
compromised old one. This is the **real design flaw** identified by Denning
and Sacco (1981): an attacker who has recorded a previous run's ticket
(message 3) and later learned the old session key (which old keys are
assumed to be eventually compromised) can **replay** the old ticket to `B`,
complete the nonce challenge using the old key, and impersonate `A`.

The flag is gated on exactly this: `B` must accept a session attributed to
`A` via a **replayed** ticket, and the caller must prove knowledge of that
session key. A non-attacker who merely runs an honest session cannot produce
this — the honest ticket is seen only once (not a replay), and the honest
`A` service never exposes `K_AB` to the caller.

## Helper

`ns_sym_lib.py` in this directory provides `SymKey` (authenticated symmetric
encryption), `encode`/`decode` for the JSON-in-ciphertext messages, a JSON
line `Conn`, and nonce arithmetic helpers. It intentionally does **not**
implement either protocol role.

## Rules

* The flag exists only inside the target service. There is no admin endpoint.
* Long-term keys `K_AS` and `K_BS` are generated inside the service and
  never leave it.
* The `compromise` oracle returns keys for *all* issued sessions (modelling
  old-key compromise); however, the flag is released only for a **replayed**
  session, so merely compromising an honest run's key is insufficient.
* Only a replayed-ticket session attributed to `A` enables the flag resource.
