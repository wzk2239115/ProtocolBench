"""NS symmetric-key client helper (crypto + wire framing).

Self-contained: real authenticated symmetric encryption (HMAC-SHA256
counter-mode stream cipher + HMAC-SHA256 MAC, encrypt-then-MAC) with no
third-party dependencies, plus a tiny newline-delimited-JSON socket client.

This module only provides primitives (key generation, encode/decode, key
lookup).  It does not implement either honest role.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket

_HLEN = hashlib.sha256().digest_size
_KEYLEN = 32
_IVLEN = 16

DEFAULT_HOST = os.environ.get("NS_SYM_HOST", "127.0.0.1")
DEFAULT_S_PORT = int(os.environ.get("NS_SYM_S_PORT", "9200"))
DEFAULT_A_PORT = int(os.environ.get("NS_SYM_A_PORT", "9201"))
DEFAULT_B_PORT = int(os.environ.get("NS_SYM_B_PORT", "9202"))


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _keystream(key: bytes, iv: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += _hmac(key, iv + counter.to_bytes(4, "big"))
        counter += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class SymKey:
    """A 256-bit symmetric key."""

    def __init__(self, raw: bytes) -> None:
        if len(raw) != _KEYLEN:
            raise ValueError(f"key must be {_KEYLEN} bytes")
        self.raw = raw

    @classmethod
    def generate(cls) -> "SymKey":
        return cls(os.urandom(_KEYLEN))

    @classmethod
    def from_hex(cls, text: str) -> "SymKey":
        return cls(bytes.fromhex(text))

    def to_hex(self) -> str:
        return self.raw.hex()

    def encrypt(self, message: bytes) -> bytes:
        iv = os.urandom(_IVLEN)
        ks = _keystream(self.raw, iv, len(message))
        ct = _xor(message, ks)
        tag = _hmac(self.raw, iv + ct)
        return iv + ct + tag

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) < _IVLEN + _HLEN:
            raise ValueError("ciphertext too short")
        iv = ciphertext[:_IVLEN]
        ct = ciphertext[_IVLEN:-_HLEN]
        tag = ciphertext[-_HLEN:]
        expected = _hmac(self.raw, iv + ct)
        if not hmac.compare_digest(tag, expected):
            raise ValueError("authentication tag mismatch")
        ks = _keystream(self.raw, iv, len(ct))
        return _xor(ct, ks)


def encode(key: SymKey, obj: dict) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(key.encrypt(raw)).decode()


def decode(key: SymKey, blob: str) -> dict:
    return json.loads(key.decrypt(base64.b64decode(blob)).decode())


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


__all__ = [
    "SymKey",
    "Conn",
    "encode",
    "decode",
    "DEFAULT_HOST",
    "DEFAULT_S_PORT",
    "DEFAULT_A_PORT",
    "DEFAULT_B_PORT",
]
