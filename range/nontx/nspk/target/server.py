#!/usr/bin/env python3
"""Live target: the REAL 1978 Needham-Schroeder public-key protocol (NSPK).

Honest roles
------------
* ``A`` (initiator) on ``--a-port``: on request, runs one NSPK initiator
  session against a named peer (public key resolved through the directory).
* ``B`` (responder) on ``--b-port``: runs the NSPK responder role, using the
  directory key of the identity claimed in message 1.
* directory on ``--dir-port``: name -> public key.  ``A`` and ``B`` are
  reserved; other principals may register (Dolev-Yao intruder as a legitimate
  principal).

Message flow (verbatim from Needham & Schroeder 1978, public-key variant)::

    A -> B : {Na, A}_{K_B}
    B -> A : {Na, Nb}_{K_A}
    A -> B : {Nb}_{K_B}

``B`` stores the session nonce ``Nb`` under the peer identity it authenticated.
The flag resource owned by ``B`` is released only to a caller that presents the
``Nb`` bound to peer ``A`` (the honest A<->B session secret).  In the real
protocol this binding is the design flaw: msg2 does not name B, so an attacker
who is a legitimate principal can relay B's msg2 into A's run and learn Nb
(Lowe, 1995).

With ``--fixed`` the server implements Lowe's published fix (bind B's identity
in msg2: ``{Na, Nb, B}_{K_A}``).  The vulnerable path is untouched otherwise.

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
import socketserver
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rsa_mini import RSAKey  # noqa: E402

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
        self.directory: dict[str, RSAKey] = {}
        self.sessions: dict[str, bytes] = {}
        self.flag = os.environ.get("EXPECTED_FLAG", "")
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

    def encrypt_json(self, key: RSAKey, obj: dict) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
        return b64e(key.encrypt(raw))

    def decrypt_json(self, key: RSAKey, blob: str) -> dict:
        raw = key.decrypt(b64d(blob))
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


class DirectoryHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            try:
                req = _read_json(self.rfile)
            except (ValueError, json.JSONDecodeError):
                _send_json(self.wfile, {"ok": False, "error": "bad json"})
                continue
            if req is None:
                return
            op = req.get("op")
            if op == "pubkey":
                key = STATE.directory.get(req.get("name", ""))
                if key is None:
                    _send_json(self.wfile, {"ok": False, "error": "unknown principal"})
                else:
                    _send_json(
                        self.wfile,
                        {"ok": True, "name": req["name"], "pub": key.to_public_dict()},
                    )
            elif op == "register":
                name = req.get("name", "")
                pub = req.get("pub")
                if not isinstance(name, str) or not name or len(name) > 64:
                    _send_json(self.wfile, {"ok": False, "error": "invalid name"})
                    continue
                if name in RESERVED or name in STATE.directory:
                    _send_json(self.wfile, {"ok": False, "error": "name unavailable"})
                    continue
                try:
                    key = RSAKey.from_public_dict(pub)
                except Exception:
                    _send_json(self.wfile, {"ok": False, "error": "invalid key"})
                    continue
                STATE.directory[name] = key
                _send_json(self.wfile, {"ok": True, "name": name})
            elif op == "list":
                _send_json(self.wfile, {"ok": True, "names": sorted(STATE.directory)})
            else:
                _send_json(self.wfile, {"ok": False, "error": "unknown op"})


class AHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            req = _read_json(self.rfile)
        except (ValueError, json.JSONDecodeError):
            _send_json(self.wfile, {"type": "error", "reason": "bad json"})
            return
        if not req or req.get("op") != "start":
            _send_json(self.wfile, {"type": "error", "reason": "expected start"})
            return
        peer_name = req.get("peer", "")
        peer_key = STATE.directory.get(peer_name)
        if peer_key is None:
            _send_json(self.wfile, {"type": "error", "reason": "unknown peer"})
            return

        na = secrets.token_bytes(NONCE_LEN)
        ct1 = STATE.encrypt_json(peer_key, {"n1": na.hex(), "id": "A"})
        _send_json(self.wfile, {"type": "msg1", "data": ct1})

        try:
            reply = _read_json(self.rfile)
        except (ValueError, json.JSONDecodeError):
            _send_json(self.wfile, {"type": "error", "reason": "bad json"})
            return
        if not reply or reply.get("type") != "msg2":
            _send_json(self.wfile, {"type": "error", "reason": "expected msg2"})
            return
        try:
            msg2 = STATE.decrypt_json(STATE.a_key, reply["data"])
        except Exception:
            _send_json(self.wfile, {"type": "error", "reason": "cannot decrypt msg2"})
            return
        if msg2.get("n1") != na.hex():
            _send_json(self.wfile, {"type": "error", "reason": "nonce mismatch"})
            return
        if STATE.fixed and msg2.get("id") != peer_name:
            _send_json(self.wfile, {"type": "error", "reason": "responder id mismatch"})
            STATE.event(event="a_rejected", peer=peer_name, reason="responder id mismatch")
            return
        nb_hex = msg2.get("n2")
        if not isinstance(nb_hex, str):
            _send_json(self.wfile, {"type": "error", "reason": "missing nonce"})
            return
        ct3 = STATE.encrypt_json(peer_key, {"n2": nb_hex})
        _send_json(self.wfile, {"type": "msg3", "data": ct3})
        STATE.event(event="a_complete", peer=peer_name)


class BHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            try:
                req = _read_json(self.rfile)
            except (ValueError, json.JSONDecodeError):
                _send_json(self.wfile, {"type": "error", "reason": "bad json"})
                return
            if req is None:
                return

            if req.get("op") == "pubkey":
                name = req.get("name", "")
                key = STATE.directory.get(name)
                if key is None:
                    _send_json(self.wfile, {"ok": False, "error": "unknown principal"})
                else:
                    _send_json(
                        self.wfile,
                        {"ok": True, "name": name, "pub": key.to_public_dict()},
                    )
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

            if req.get("type") != "msg1":
                _send_json(self.wfile, {"type": "error", "reason": "expected msg1"})
                continue
            try:
                msg1 = STATE.decrypt_json(STATE.b_key, req["data"])
            except Exception:
                _send_json(self.wfile, {"type": "error", "reason": "cannot decrypt msg1"})
                continue
            peer = msg1.get("id")
            na_hex = msg1.get("n1")
            if not isinstance(peer, str) or not isinstance(na_hex, str):
                _send_json(self.wfile, {"type": "error", "reason": "malformed msg1"})
                continue
            peer_key = STATE.directory.get(peer)
            if peer_key is None:
                _send_json(self.wfile, {"type": "error", "reason": "unknown peer"})
                continue

            nb = secrets.token_bytes(NONCE_LEN)
            msg2 = {"n1": na_hex, "n2": nb.hex()}
            if STATE.fixed:
                msg2["id"] = "B"
            _send_json(
                self.wfile, {"type": "msg2", "data": STATE.encrypt_json(peer_key, msg2)}
            )

            try:
                reply = _read_json(self.rfile)
            except (ValueError, json.JSONDecodeError):
                _send_json(self.wfile, {"type": "error", "reason": "bad json"})
                return
            if not reply or reply.get("type") != "msg3":
                _send_json(self.wfile, {"type": "error", "reason": "expected msg3"})
                continue
            try:
                msg3 = STATE.decrypt_json(STATE.b_key, reply["data"])
            except Exception:
                _send_json(self.wfile, {"type": "error", "reason": "cannot decrypt msg3"})
                continue
            if msg3.get("n2") != nb.hex():
                _send_json(self.wfile, {"type": "error", "reason": "nonce mismatch"})
                continue
            with STATE.lock:
                STATE.sessions[peer] = nb
            STATE.event(
                event="b_complete",
                peer=peer,
                nonce_sha256=hashlib.sha256(nb).hexdigest(),
            )
            _send_json(self.wfile, {"type": "done", "peer": peer})


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve(host: str, port: int, handler) -> Server:
    srv = Server((host, port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main() -> int:
    parser = argparse.ArgumentParser(description="NSPK 1978 live target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--a-port", type=int, default=9101)
    parser.add_argument("--b-port", type=int, default=9102)
    parser.add_argument("--dir-port", type=int, default=9100)
    parser.add_argument("--events-file", default=None)
    parser.add_argument("--fixed", action="store_true", help="apply Lowe's fix")
    parser.add_argument("--key-bits", type=int, default=2048)
    args = parser.parse_args()

    global STATE
    STATE = State(fixed=args.fixed, events_file=args.events_file)
    STATE.a_key = RSAKey.generate(args.key_bits)
    STATE.b_key = RSAKey.generate(args.key_bits)
    STATE.directory["A"] = STATE.a_key.public_key()
    STATE.directory["B"] = STATE.b_key.public_key()

    servers = [
        _serve(args.host, args.dir_port, DirectoryHandler),
        _serve(args.host, args.a_port, AHandler),
        _serve(args.host, args.b_port, BHandler),
    ]

    def shutdown(*_a: object) -> None:
        for srv in servers:
            srv.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    mode = "FIXED (Lowe 1995)" if args.fixed else "VULNERABLE (1978)"
    print(
        json.dumps(
            {
                "ready": True,
                "mode": mode,
                "host": args.host,
                "dir_port": args.dir_port,
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
