"""Minimal, dependency-free symmetric AEAD for the Woo-Lam target.

Construction: a hash stream cipher (SHA-256 in counter mode) for
confidentiality, HMAC-SHA256 (encrypt-then-MAC) for authenticity.  This is a
legitimate AEAD built purely from standard primitives; the Woo-Lam design flaw
is structural (lack of responder-identity binding in message 3), not
cryptographic, so the exact symmetric primitive is immaterial to the attack.

Long-term "shared keys" with the server S are 32-byte (256-bit) uniform random
values, generated in-process.  A principal registers its shared key with S via
the trusted setup channel (the symmetric analogue of registering a public key
in the NSPK directory); the names ``A`` and ``B`` are reserved.
"""

from __future__ import annotations

import hashlib
import hmac
import os

__all__ = ["AEAD", "sha256", "random_key"]

_NONCE_LEN = 16
_TAG_LEN = 32
_HASH = hashlib.sha256


def sha256(data: bytes) -> bytes:
    return _HASH(data).digest()


def random_key() -> bytes:
    return os.urandom(32)


def _derive(key: bytes, label: bytes) -> bytes:
    return _HASH(key + label).digest()


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += _HASH(enc_key + nonce + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class AEAD:
    """Encrypt-then-MAC AEAD keyed by a 32-byte shared key."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("shared key must be 32 bytes")
        self.enc_key = _derive(key, b"\x01enc")
        self.mac_key = _derive(key, b"\x02mac")

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = os.urandom(_NONCE_LEN)
        ct = _xor(plaintext, _keystream(self.enc_key, nonce, len(plaintext)))
        tag = hmac.new(self.mac_key, nonce + aad + ct, _HASH).digest()
        return nonce + ct + tag

    def decrypt(self, blob: bytes, aad: bytes = b"") -> bytes:
        if len(blob) < _NONCE_LEN + _TAG_LEN:
            raise ValueError("ciphertext too short")
        nonce = blob[:_NONCE_LEN]
        tag = blob[-_TAG_LEN:]
        ct = blob[_NONCE_LEN:-_TAG_LEN]
        expected = hmac.new(self.mac_key, nonce + aad + ct, _HASH).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("authentication tag mismatch")
        return _xor(ct, _keystream(self.enc_key, nonce, len(ct)))