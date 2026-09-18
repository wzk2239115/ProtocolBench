#!/usr/bin/env python3
"""Live target: the REAL Woo-Lam authentication protocol (1992/1994).

Honest roles
------------
* ``A`` (initiator) on ``--a-port``: on request, runs one Woo-Lam initiator
  session — sends its identity, receives a nonce challenge, and encrypts the
  challenge with its long-term shared key ``K_AS``.
* ``B`` (responder) on ``--b-port``: runs the Woo-Lam responder role, forwards
  the claimant's encrypted nonce to the server, and verifies the server's
  response.  ``B`` owns the flag resource.
* ``S`` (authentication server / KDC) on ``--s-port``: holds the long-term
  shared keys, decrypts ``B``'s forwarded message, and re-encrypts the result
  for ``B``.

Message flow (verbatim from Woo & Lam 1992, Abadi-Needham 1996 simplified
form, as formalised by Paulson in Isabelle/HOL ``WooLam.thy``)::

    WL1  A -> B : A
    WL2  B -> A : NB
    WL3  A -> B : { NB }_KAS          # flaw: B's identity is NOT bound
    WL4  B -> S : A, B, { NB }_KAS
    WL5  S -> B : { A, NB }_KBS

``B`` stores the challenge nonce ``NB`` under the claimant identity it
authenticated.  The flag resource owned by ``B`` is released only to a caller
that presents the ``NB`` bound to peer identity ``A`` (the honest A<->B
authentication).  In the real protocol the binding in message 3 is the design
flaw: ``{NB}_KAS`` does not name the responder, so an intruder who is a
legitimate communication partner of ``A`` can obtain ``{NB}_KAS`` for ``B``'s
challenge ``NB`` (by feeding it to ``A`` as its own challenge) and relay it to
``B``, completing a run that ``B`` attributes to ``A`` (the classic Woo-Lam
interleaving/impersonation attack).

With ``--fixed`` the server implements the published fix (bind the responder
identity in WL3: ``{B, NB}_KAS``; S checks it and includes it in WL5).  The
vulnerable path is untouched otherwise.

The flag value is read from ``EXPECTED_FLAG`` (host-derived) and never written
to disk or logs.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import signal
import socket
import socketserver
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sym_mini import AEAD, random_key  # noqa: E402

NONCE_LEN = 16
RESERVED = {"A", "B"}


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


class State:
    def __init__(self, fixed: bool, events_file: str | None) -> None:
        self.fixed = fixed
        self.events_file = events_file
        self.lock = threading.Lock()
        self.keys: dict[str, bytes] = {}
        self.sessions: dict[str, bytes] = {}
        self.flag = os.environ.get("EXPECTED_FLAG", "")
        self.s_host = "127.0.0.1"
        self.s_port = 9200
        if not self.flag:
            raise SystemExit("EXPECTED_FLAG is required (host-derived secret)")

    def event(self, **fields: object) -> None:
        if not self.events_file:
            return
        line = json.dumps(fields, sort_keys=True)
        with self.lock:
            with open(self.events_file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    def encrypt_json(self, key: bytes, obj: dict) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
        return b64e(AEAD(key).encrypt(raw))

    def decrypt_json(self, key: bytes, blob: str) -> dict:
        raw = AEAD(key).decrypt(b64d(blob))
        obj = json.loads(raw.decode())
        if not isinstance(obj, dict):
            raise ValueError("message is not a JSON object")
        return obj


STATE: State


def _read_json(rfile) -> dict | None:
    line = rfile.readline()
    if not line:
        return None
    obj = json.loads(line.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("expected JSON object")
    return obj


def _send_json(wfile, obj: dict) -> None:
    wfile.write((json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8"))
    wfile.flush()


class ServerHandler(socketserver.StreamRequestHandler):
    """S (authentication server / KDC): key registry + WL4->WL5."""

    def handle(self) -> None:
        while True:
            try:
                req = _read_json(self.rfile)
            except (ValueError, json.JSONDecodeError):
                _send_json(self.wfile, {"ok": False, "error": "bad json"})
                return
            if req is None:
                return

            op = req.get("op")
            if op == "list":
                with STATE.lock:
                    _send_json(self.wfile, {"ok": True, "names": sorted(STATE.keys)})
                continue

            if op == "register":
                name = req.get("name", "")
                key_hex = req.get("key", "")
                if not isinstance(name, str) or not name or len(name) > 64:
                    _send_json(self.wfile, {"ok": False, "error": "invalid name"})
                    continue
                if name in RESERVED:
                    _send_json(self.wfile, {"ok": False, "error": "reserved"})
                    continue
                with STATE.lock:
                    if name in STATE.keys:
                        _send_json(self.wfile, {"ok": False, "error": "name taken"})
                        continue
                    try:
                        key = bytes.fromhex(key_hex)
                    except (ValueError, TypeError):
                        _send_json(self.wfile, {"ok": False, "error": "bad key"})
                        continue
                    if len(key) != 32:
                        _send_json(self.wfile, {"ok": False, "error": "bad key len"})
                        continue
                    STATE.keys[name] = key
                _send_json(self.wfile, {"ok": True, "name": name})
                continue

            if req.get("type") == "wl4":
                claim = req.get("a", "")
                resp = req.get("b", "")
                data = req.get("data", "")
                with STATE.lock:
                    claim_key = STATE.keys.get(claim)
                    resp_key = STATE.keys.get(resp)
                if claim_key is None or resp_key is None:
                    _send_json(self.wfile, {"type": "error", "reason": "unknown principal"})
                    continue
                try:
                    inner = STATE.decrypt_json(claim_key, data)
                except Exception:
                    _send_json(self.wfile, {"type": "error", "reason": "cannot decrypt wl3"})
                    continue
                nb_hex = inner.get("nb")
                if not isinstance(nb_hex, str):
                    _send_json(self.wfile, {"type": "error", "reason": "malformed wl3"})
                    continue
                if STATE.fixed:
                    bound_resp = inner.get("b")
                    if bound_resp != resp:
                        STATE.event(
                            event="s_rejected", claim=claim, resp=resp,
                            reason="responder binding mismatch",
                        )
                        _send_json(self.wfile, {"type": "error", "reason": "binding mismatch"})
                        continue
                    msg5 = {"a": claim, "b": resp, "nb": nb_hex}
                else:
                    msg5 = {"a": claim, "nb": nb_hex}
                _send_json(self.wfile, {"type": "wl5", "data": STATE.encrypt_json(resp_key, msg5)})
                continue

            _send_json(self.wfile, {"ok": False, "error": "unknown op"})


class AHandler(socketserver.StreamRequestHandler):
    """A (initiator): WL1 (identity) then WL3 (encrypt challenge with K_AS)."""

    def handle(self) -> None:
        try:
            req = _read_json(self.rfile)
        except (ValueError, json.JSONDecodeError):
            _send_json(self.wfile, {"type": "error", "reason": "bad json"})
            return
        if not req or req.get("op") != "start":
            _send_json(self.wfile, {"type": "error", "reason": "expected start"})
            return
        peer = req.get("peer", "")
        if not isinstance(peer, str) or not peer:
            _send_json(self.wfile, {"type": "error", "reason": "bad peer"})
            return
        _send_json(self.wfile, {"type": "wl1", "a": "A"})

        try:
            reply = _read_json(self.rfile)
        except (ValueError, json.JSONDecodeError):
            _send_json(self.wfile, {"type": "error", "reason": "bad json"})
            return
        if not reply or reply.get("type") != "wl2":
            _send_json(self.wfile, {"type": "error", "reason": "expected wl2"})
            return
        nb_hex = reply.get("nb")
        if not isinstance(nb_hex, str):
            _send_json(self.wfile, {"type": "error", "reason": "missing nonce"})
            return
        try:
            nb = bytes.fromhex(nb_hex)
        except ValueError:
            _send_json(self.wfile, {"type": "error", "reason": "bad nonce"})
            return
        with STATE.lock:
            a_key = STATE.keys.get("A")
        if a_key is None:
            _send_json(self.wfile, {"type": "error", "reason": "no key"})
            return
        payload: dict = {"nb": nb_hex}
        if STATE.fixed:
            payload["b"] = peer
        _send_json(self.wfile, {"type": "wl3", "data": STATE.encrypt_json(a_key, payload)})
        STATE.event(event="a_complete", peer=peer)


class BHandler(socketserver.StreamRequestHandler):
    """B (responder + flag): WL1->WL2, WL3->(forward to S)->done, flag gate."""

    def handle(self) -> None:
        claimant: str | None = None
        nb: bytes | None = None
        while True:
            try:
                req = _read_json(self.rfile)
            except (ValueError, json.JSONDecodeError):
                _send_json(self.wfile, {"type": "error", "reason": "bad json"})
                return
            if req is None:
                return

            if req.get("op") == "list":
                with STATE.lock:
                    _send_json(self.wfile, {"ok": True, "names": sorted(STATE.keys)})
                continue

            if req.get("type") == "flag":
                peer = req.get("peer", "")
                nonce = req.get("nonce", "")
                with STATE.lock:
                    expected = STATE.sessions.get(peer)
                if (
                    peer == "A"
                    and expected is not None
                    and isinstance(nonce, str)
                    and hmac.compare_digest(expected.hex(), nonce)
                ):
                    STATE.event(
                        event="flag_released",
                        peer="A",
                        nonce=nonce,
                        flag_sha256=hashlib.sha256(STATE.flag.encode()).hexdigest(),
                    )
                    _send_json(self.wfile, {"type": "flag", "value": STATE.flag})
                else:
                    STATE.event(event="flag_denied", peer=str(peer))
                    _send_json(self.wfile, {"type": "error", "reason": "denied"})
                continue

            if req.get("type") == "wl1":
                claimant = req.get("a", "")
                if not isinstance(claimant, str) or not claimant:
                    _send_json(self.wfile, {"type": "error", "reason": "bad claimant"})
                    continue
                nb = secrets.token_bytes(NONCE_LEN)
                _send_json(self.wfile, {"type": "wl2", "nb": nb.hex()})
                continue

            if req.get("type") == "wl3":
                if claimant is None or nb is None:
                    _send_json(self.wfile, {"type": "error", "reason": "no pending wl1"})
                    continue
                data = req.get("data", "")
                if not isinstance(data, str):
                    _send_json(self.wfile, {"type": "error", "reason": "bad data"})
                    continue
                wl5 = self._forward_to_server(claimant, "B", data)
                if wl5 is None:
                    _send_json(self.wfile, {"type": "error", "reason": "server rejected"})
                    continue
                try:
                    with STATE.lock:
                        b_key = STATE.keys.get("B")
                    if b_key is None:
                        _send_json(self.wfile, {"type": "error", "reason": "no key"})
                        continue
                    inner = STATE.decrypt_json(b_key, wl5)
                except Exception:
                    _send_json(self.wfile, {"type": "error", "reason": "cannot decrypt wl5"})
                    continue
                if inner.get("a") != claimant or inner.get("nb") != nb.hex():
                    _send_json(self.wfile, {"type": "error", "reason": "wl5 mismatch"})
                    continue
                if STATE.fixed and inner.get("b") != "B":
                    _send_json(self.wfile, {"type": "error", "reason": "wl5 responder mismatch"})
                    continue
                with STATE.lock:
                    STATE.sessions[claimant] = nb
                STATE.event(
                    event="b_complete",
                    peer=claimant,
                    nonce_sha256=hashlib.sha256(nb).hexdigest(),
                )
                _send_json(self.wfile, {"type": "done", "peer": claimant})
                continue

            _send_json(self.wfile, {"type": "error", "reason": "unknown op"})

    def _forward_to_server(self, claim: str, resp: str, data: str) -> str | None:
        try:
            with socket.create_connection((STATE.s_host, STATE.s_port), timeout=10.0) as sock:
                rfile = sock.makefile("rb")
                wfile = sock.makefile("wb")
                _send_json(wfile, {"type": "wl4", "a": claim, "b": resp, "data": data})
                reply = _read_json(rfile)
                if reply and reply.get("type") == "wl5":
                    return reply.get("data", "")
        except OSError:
            pass
        return None


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve(host: str, port: int, handler) -> Server:
    srv = Server((host, port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main() -> int:
    parser = argparse.ArgumentParser(description="Woo-Lam live target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--s-port", type=int, default=9200)
    parser.add_argument("--a-port", type=int, default=9201)
    parser.add_argument("--b-port", type=int, default=9202)
    parser.add_argument("--events-file", default=None)
    parser.add_argument("--fixed", action="store_true", help="apply the responder-binding fix")
    args = parser.parse_args()

    global STATE
    STATE = State(fixed=args.fixed, events_file=args.events_file)
    STATE.s_host = args.host
    STATE.s_port = args.s_port
    STATE.keys["A"] = random_key()
    STATE.keys["B"] = random_key()

    servers = [
        _serve(args.host, args.s_port, ServerHandler),
        _serve(args.host, args.a_port, AHandler),
        _serve(args.host, args.b_port, BHandler),
    ]

    def shutdown(*_a: object) -> None:
        for srv in servers:
            srv.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    mode = "FIXED (responder binding)" if args.fixed else "VULNERABLE (Woo-Lam 1992)"
    print(
        json.dumps(
            {
                "ready": True,
                "mode": mode,
                "host": args.host,
                "s_port": args.s_port,
                "a_port": args.a_port,
                "b_port": args.b_port,
            }
        ),
        flush=True,
    )
    while True:
        signal.pause()


if __name__ == "__main__":
    raise SystemExit(main())