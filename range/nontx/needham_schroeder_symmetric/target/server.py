#!/usr/bin/env python3
"""Live target: the REAL 1978 Needham-Schroeder symmetric-key protocol.

Honest roles
------------
* ``S`` (KDC) on ``--s-port``: key distribution center.  Shares long-term
  symmetric keys ``K_AS`` and ``K_BS`` with ``A`` and ``B``.  Issues fresh
  session keys and tickets.  Also exposes a ``compromise`` oracle modelling
  the standard assumption that *old* session keys are eventually compromised
  (this is the threat model under which Denning-Sacco's replay attack applies).
* ``A`` (initiator) on ``--a-port``: runs the NS symmetric-key initiator role
  against a named peer.  Contacts ``S`` (in-process) to obtain a session key
  and ticket, then interacts with the agent (the network) to forward the
  ticket to ``B`` and complete the nonce challenge-response.
* ``B`` (responder + flag) on ``--b-port``: runs the NS symmetric-key responder
  role.  Accepts tickets, challenges with a fresh nonce ``N_B``, verifies the
  ``N_B - 1`` response.  Releases the flag only for a session established via a
  *replayed* ticket (the Denning-Sacco attack) when the caller proves knowledge
  of that session key.

Message flow (Needham & Schroeder 1978, symmetric-key variant)::

    A -> S : A, B, N_A
    S -> A : { N_A, B, K_AB, { K_AB, A }_{K_BS} }_{K_AS}
    A -> B : { K_AB, A }_{K_BS}
    B -> A : { N_B }_{K_AB}
    A -> B : { N_B - 1 }_{K_AB}

The ticket ``{ K_AB, A }_{K_BS}`` carries **no freshness** for ``B``.  An
attacker who records a ticket and later learns the (now-old) session key can
replay the ticket to ``B`` and impersonate ``A`` (Denning & Sacco, 1981).

With ``--fixed`` the server adds a timestamp ``T`` to the ticket
(``{ K_AB, A, T }_{K_BS}``) and ``B`` rejects stale tickets — the
Denning-Sacco published fix.

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
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sym_mini import SymKey  # noqa: E402

NONCE_BITS = 128
NONCE_MOD = 1 << NONCE_BITS
RESERVED = {"A", "B"}


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def gen_nonce_int() -> int:
    return secrets.randbits(NONCE_BITS)


def nonce_hex(n: int) -> str:
    return format(n % NONCE_MOD, "032x")


def nonce_from_hex(text: str) -> int:
    return int(text, 16) % NONCE_MOD


class State:
    def __init__(self, fixed: bool, events_file: str | None,
                 freshness_window: float) -> None:
        self.fixed = fixed
        self.events_file = events_file
        self.freshness_window = freshness_window
        self.lock = threading.Lock()
        self.k_as = SymKey.generate()
        self.k_bs = SymKey.generate()
        self.issued: list[dict] = []
        self.b_sessions: dict[str, dict] = {}
        self.b_seen_tickets: dict[str, int] = {}
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

    def encrypt_json(self, key: SymKey, obj: dict) -> str:
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
        return b64e(key.encrypt(raw))

    def decrypt_json(self, key: SymKey, blob: str) -> dict:
        raw = key.decrypt(b64d(blob))
        obj = json.loads(raw.decode())
        if not isinstance(obj, dict):
            raise ValueError("message is not a JSON object")
        return obj

    def kdc(self, a: str, b: str, na_hex: str) -> tuple[str, str, str]:
        """Issue a fresh session key and ticket (messages 1->2)."""
        kab = SymKey.generate()
        session_id = secrets.token_hex(16)
        ts = time.time()
        ticket_payload: dict = {"kab": kab.to_hex(), "a": a}
        if self.fixed:
            ticket_payload["ts"] = ts
        ticket = self.encrypt_json(self.k_bs, ticket_payload)
        msg2 = self.encrypt_json(
            self.k_as,
            {"na": na_hex, "b": b, "kab": kab.to_hex(), "ticket": ticket},
        )
        with self.lock:
            self.issued.append(
                {
                    "session_id": session_id,
                    "a": a,
                    "b": b,
                    "kab": kab.to_hex(),
                    "ticket": ticket,
                    "ts": ts,
                }
            )
        self.event(event="kdc_issued", a=a, b=b, session_id=session_id)
        return msg2, ticket, session_id

    def compromise(self) -> list[dict]:
        """Return all issued session keys + tickets (old-key compromise model)."""
        with self.lock:
            return [
                {
                    "session_id": s["session_id"],
                    "key": s["kab"],
                    "ticket": s["ticket"],
                    "a": s["a"],
                    "b": s["b"],
                }
                for s in self.issued
            ]


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


class SHandler(socketserver.StreamRequestHandler):
    """KDC: key distribution + compromise oracle (old-key assumption)."""

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
            if op == "kdc":
                a = req.get("a", "")
                b = req.get("b", "")
                na_hex = req.get("na", "")
                if not isinstance(na_hex, str) or not na_hex:
                    _send_json(self.wfile, {"ok": False, "error": "missing nonce"})
                    continue
                msg2, ticket, sid = STATE.kdc(a, b, na_hex)
                _send_json(
                    self.wfile,
                    {"ok": True, "msg2": msg2, "ticket": ticket, "session_id": sid},
                )
            elif op == "compromise":
                sessions = STATE.compromise()
                _send_json(self.wfile, {"ok": True, "sessions": sessions})
            else:
                _send_json(self.wfile, {"ok": False, "error": "unknown op"})


class AHandler(socketserver.StreamRequestHandler):
    """Initiator A: obtains a ticket from S, then runs challenge-response."""

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
        if peer not in RESERVED:
            _send_json(self.wfile, {"type": "error", "reason": "unknown peer"})
            return

        na = gen_nonce_int()
        na_hex = nonce_hex(na)
        msg2_blob, ticket, sid = STATE.kdc("A", peer, na_hex)
        try:
            msg2 = STATE.decrypt_json(STATE.k_as, msg2_blob)
        except Exception:
            _send_json(self.wfile, {"type": "error", "reason": "cannot decrypt msg2"})
            return
        if msg2.get("na") != na_hex or msg2.get("b") != peer:
            _send_json(self.wfile, {"type": "error", "reason": "kdc mismatch"})
            return
        kab_hex = msg2.get("kab")
        if not isinstance(kab_hex, str):
            _send_json(self.wfile, {"type": "error", "reason": "missing session key"})
            return
        kab = SymKey.from_hex(kab_hex)
        _send_json(self.wfile, {"type": "ticket", "data": ticket, "session_id": sid})

        try:
            reply = _read_json(self.rfile)
        except (ValueError, json.JSONDecodeError):
            _send_json(self.wfile, {"type": "error", "reason": "bad json"})
            return
        if not reply or reply.get("type") != "challenge":
            _send_json(self.wfile, {"type": "error", "reason": "expected challenge"})
            return
        try:
            chal = STATE.decrypt_json(kab, reply["data"])
        except Exception:
            _send_json(self.wfile, {"type": "error", "reason": "cannot decrypt challenge"})
            return
        nb_hex = chal.get("nb")
        if not isinstance(nb_hex, str):
            _send_json(self.wfile, {"type": "error", "reason": "malformed challenge"})
            return
        nb = nonce_from_hex(nb_hex)
        resp_payload = {"nb": nonce_hex((nb - 1) % NONCE_MOD)}
        _send_json(self.wfile, {"type": "response", "data": STATE.encrypt_json(kab, resp_payload)})
        STATE.event(event="a_complete", peer=peer, session_id=sid)


class BHandler(socketserver.StreamRequestHandler):
    """Responder B: accepts tickets, challenges, verifies, holds the flag."""

    def handle(self) -> None:
        while True:
            try:
                req = _read_json(self.rfile)
            except (ValueError, json.JSONDecodeError):
                _send_json(self.wfile, {"type": "error", "reason": "bad json"})
                return
            if req is None:
                return

            if req.get("type") == "flag":
                peer = req.get("peer", "")
                key_hex = req.get("key", "")
                with STATE.lock:
                    sess = STATE.b_sessions.get(peer)
                ok = (
                    peer == "A"
                    and sess is not None
                    and sess.get("complete")
                    and sess.get("replay")
                    and isinstance(key_hex, str)
                    and hmac.compare_digest(sess["kab"], key_hex)
                )
                if ok:
                    STATE.event(
                        event="flag_released",
                        peer="A",
                        key_sha256=hashlib.sha256(key_hex.encode()).hexdigest(),
                        flag_sha256=hashlib.sha256(STATE.flag.encode()).hexdigest(),
                    )
                    _send_json(self.wfile, {"type": "flag", "value": STATE.flag})
                else:
                    STATE.event(event="flag_denied", peer=str(peer))
                    _send_json(self.wfile, {"type": "error", "reason": "denied"})
                continue

            if req.get("type") != "ticket":
                _send_json(self.wfile, {"type": "error", "reason": "expected ticket"})
                continue

            try:
                ticket = STATE.decrypt_json(STATE.k_bs, req["data"])
            except Exception:
                _send_json(self.wfile, {"type": "error", "reason": "cannot decrypt ticket"})
                continue
            kab_hex = ticket.get("kab")
            peer = ticket.get("a")
            if not isinstance(kab_hex, str) or not isinstance(peer, str):
                _send_json(self.wfile, {"type": "error", "reason": "malformed ticket"})
                continue

            if STATE.fixed:
                ts = ticket.get("ts")
                if not isinstance(ts, (int, float)):
                    _send_json(self.wfile, {"type": "error", "reason": "stale ticket"})
                    STATE.event(event="b_rejected", peer=peer, reason="no timestamp")
                    continue
                if time.time() - ts > STATE.freshness_window:
                    _send_json(self.wfile, {"type": "error", "reason": "stale ticket"})
                    STATE.event(event="b_rejected", peer=peer, reason="stale ticket")
                    continue

            ticket_hash = hashlib.sha256(req["data"].encode()).hexdigest()
            with STATE.lock:
                seen_count = STATE.b_seen_tickets.get(ticket_hash, 0)
                is_replay = seen_count > 0
                STATE.b_seen_tickets[ticket_hash] = seen_count + 1

            if STATE.fixed and is_replay:
                _send_json(self.wfile, {"type": "error", "reason": "replayed ticket rejected"})
                STATE.event(event="b_rejected", peer=peer, reason="replay in fixed mode")
                continue

            nb = gen_nonce_int()
            nb_hex = nonce_hex(nb)
            with STATE.lock:
                STATE.b_sessions[peer] = {
                    "kab": kab_hex,
                    "nb": nb,
                    "replay": is_replay,
                    "complete": False,
                }
            chal = STATE.encrypt_json(SymKey.from_hex(kab_hex), {"nb": nb_hex})
            _send_json(self.wfile, {"type": "challenge", "data": chal})

            try:
                reply = _read_json(self.rfile)
            except (ValueError, json.JSONDecodeError):
                _send_json(self.wfile, {"type": "error", "reason": "bad json"})
                return
            if not reply or reply.get("type") != "response":
                _send_json(self.wfile, {"type": "error", "reason": "expected response"})
                continue
            try:
                resp = STATE.decrypt_json(SymKey.from_hex(kab_hex), reply["data"])
            except Exception:
                _send_json(self.wfile, {"type": "error", "reason": "cannot decrypt response"})
                continue
            expected = (nb - 1) % NONCE_MOD
            if nonce_from_hex(resp.get("nb", "0")) != expected:
                _send_json(self.wfile, {"type": "error", "reason": "nonce mismatch"})
                continue
            with STATE.lock:
                STATE.b_sessions[peer]["complete"] = True
            STATE.event(
                event="b_complete",
                peer=peer,
                replay=is_replay,
                key_sha256=hashlib.sha256(kab_hex.encode()).hexdigest(),
            )
            _send_json(self.wfile, {"type": "done", "peer": peer, "replay": is_replay})


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve(host: str, port: int, handler) -> Server:
    srv = Server((host, port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main() -> int:
    parser = argparse.ArgumentParser(description="NS symmetric-key 1978 live target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--s-port", type=int, default=9200)
    parser.add_argument("--a-port", type=int, default=9201)
    parser.add_argument("--b-port", type=int, default=9202)
    parser.add_argument("--events-file", default=None)
    parser.add_argument("--fixed", action="store_true", help="apply Denning-Sacco fix")
    parser.add_argument("--freshness-window", type=float, default=0.5,
                        help="max ticket age (s) in fixed mode")
    args = parser.parse_args()

    global STATE
    STATE = State(
        fixed=args.fixed,
        events_file=args.events_file,
        freshness_window=args.freshness_window,
    )

    servers = [
        _serve(args.host, args.s_port, SHandler),
        _serve(args.host, args.a_port, AHandler),
        _serve(args.host, args.b_port, BHandler),
    ]

    def shutdown(*_a: object) -> None:
        for srv in servers:
            srv.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    mode = "FIXED (Denning-Sacco 1981)" if args.fixed else "VULNERABLE (1978)"
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
