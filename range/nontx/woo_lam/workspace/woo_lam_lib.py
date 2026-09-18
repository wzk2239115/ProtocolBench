"""Woo-Lam client helper (crypto + wire framing).

Self-contained: a dependency-free symmetric AEAD (hash stream cipher +
HMAC-SHA256, encrypt-then-MAC) with no third-party dependencies, plus a tiny
newline-delimited-JSON socket client.

This module only provides primitives (the AEAD, key generation, a JSON-line
socket helper, and principal registration with the server S).  It does **not**
implement either honest role.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket

DEFAULT_HOST = os.environ.get("WOOLAM_HOST", "127.0.0.1")
DEFAULT_S_PORT = int(os.environ.get("WOOLAM_S_PORT", "9200"))
DEFAULT_A_PORT = int(os.environ.get("WOOLAM_A_PORT", "9201"))
DEFAULT_B_PORT = int(os.environ.get("WOOLAM_B_PORT", "9202"))

_NONCE_LEN = 16
_TAG_LEN = 32


def _derive(key: bytes, label: bytes) -> bytes:
    return hashlib.sha256(key + label).digest()


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(enc_key + nonce + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def random_key() -> bytes:
    return os.urandom(32)


class AEAD:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("shared key must be 32 bytes")
        self.enc_key = _derive(key, b"\x01enc")
        self.mac_key = _derive(key, b"\x02mac")

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = os.urandom(_NONCE_LEN)
        ct = _xor(plaintext, _keystream(self.enc_key, nonce, len(plaintext)))
        tag = hmac.new(self.mac_key, nonce + aad + ct, hashlib.sha256).digest()
        return nonce + ct + tag

    def decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        if len(blob) < _NONCE_LEN + _TAG_LEN:
            raise ValueError("ciphertext too short")
        nonce = blob[:_NONCE_LEN]
        tag = blob[-_TAG_LEN:]
        ct = blob[_NONCE_LEN:-_TAG_LEN]
        expected = hmac.new(self.mac_key, nonce + aad + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("authentication tag mismatch")
        return _xor(ct, _keystream(self.enc_key, nonce, len(ct)))


def encode(key: bytes, obj: dict) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(AEAD(key).encrypt(raw)).decode()


def decode(key: bytes, blob: str) -> dict:
    return json.loads(AEAD(key).decrypt(base64.b64decode(blob)).decode())


class Conn:
    def __init__(self, host: str, port: int, timeout: float = 30.0) -> None:
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.rfile = self.sock.makefile("rb")
        self.wfile = self.sock.makefile("wb")

    def send(self, obj: dict) -> None:
        self.wfile.write((json.dumps(obj) + "\n").encode())
        self.wfile.flush()

    def recv(self) -> dict:
        line = self.rfile.readline()
        if not line:
            raise RuntimeError("connection closed")
        return json.loads(line.decode())

    def close(self) -> None:
        for stream in (self.rfile, self.wfile, self.sock):
            try:
                stream.close()
            except OSError:
                pass


def register(
    name: str, key: bytes, host: str = DEFAULT_HOST, port: int = DEFAULT_S_PORT
) -> None:
    conn = Conn(host, port)
    try:
        conn.send({"op": "register", "name": name, "key": key.hex()})
        reply = conn.recv()
        if not reply.get("ok"):
            raise RuntimeError(f"register failed: {reply}")
    finally:
        conn.close()


def list_principals(host: str = DEFAULT_HOST, port: int = DEFAULT_S_PORT) -> list[str]:
    conn = Conn(host, port)
    try:
        conn.send({"op": "list"})
        reply = conn.recv()
        if not reply.get("ok"):
            raise RuntimeError(f"list failed: {reply}")
        return reply.get("names", [])
    finally:
        conn.close()


__all__ = [
    "AEAD",
    "Conn",
    "encode",
    "decode",
    "random_key",
    "register",
    "list_principals",
    "DEFAULT_HOST",
    "DEFAULT_S_PORT",
    "DEFAULT_A_PORT",
    "DEFAULT_B_PORT",
]