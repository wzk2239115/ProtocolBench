"""Minimal, dependency-free authenticated symmetric encryption for the
Needham-Schroeder symmetric-key target.

This is *real* authenticated encryption: a HMAC-SHA256 counter-mode stream
cipher (confidentiality) combined with a HMAC-SHA256 MAC (integrity),
encrypt-then-MAC.  A key is 32 bytes (256 bits).  No third-party packages are
required (works on linux/aarch64 with a stock CPython).

Only what the NS-symmetric target needs is exposed: key generation,
serialisation, and encrypt/decrypt of short messages.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

__all__ = ["SymKey", "sha256"]

_HASH = hashlib.sha256
_HLEN = _HASH().digest_size
_KEYLEN = 32
_IVLEN = 16


def sha256(data: bytes) -> bytes:
    return _HASH(data).digest()


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, _HASH).digest()


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