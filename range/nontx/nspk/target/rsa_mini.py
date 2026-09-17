"""Minimal, dependency-free RSA-OAEP (SHA-256) for the NSPK target.

This is *real* RSA: 2048-bit modulus, e = 65537, OAEP padding with SHA-256 /
MGF1.  It is intentionally small so the target image needs no third-party
packages (works on linux/aarch64 with a stock CPython).

Only what NSPK needs is exposed: key generation, public-key serialisation,
and encrypt/decrypt of short messages.
"""

from __future__ import annotations

import hashlib
import math
import os
import secrets

__all__ = ["RSAKey", "sha256"]

_HASH = hashlib.sha256
_HLEN = _HASH().digest_size
_E = 65537


def sha256(data: bytes) -> bytes:
    return _HASH(data).digest()


def _mgf1(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += _HASH(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _oaep_encode(message: bytes, k: int, label: bytes = b"") -> bytes:
    if len(message) > k - 2 * _HLEN - 2:
        raise ValueError("message too long for OAEP")
    lhash = _HASH(label).digest()
    ps = b"\x00" * (k - len(message) - 2 * _HLEN - 2)
    db = lhash + ps + b"\x01" + message
    seed = os.urandom(_HLEN)
    masked_db = _xor(db, _mgf1(seed, k - _HLEN - 1))
    masked_seed = _xor(seed, _mgf1(masked_db, _HLEN))
    return b"\x00" + masked_seed + masked_db


def _oaep_decode(em: bytes, k: int, label: bytes = b"") -> bytes:
    if len(em) != k or em[0] != 0:
        raise ValueError("decryption error")
    masked_seed = em[1 : 1 + _HLEN]
    masked_db = em[1 + _HLEN :]
    seed = _xor(masked_seed, _mgf1(masked_db, _HLEN))
    db = _xor(masked_db, _mgf1(seed, k - _HLEN - 1))
    lhash = _HASH(label).digest()
    if not secrets.compare_digest(db[: _HLEN], lhash):
        raise ValueError("decryption error")
    idx = db.find(b"\x01", _HLEN)
    if idx < 0:
        raise ValueError("decryption error")
    return db[idx + 1 :]


class RSAKey:
    """An RSA key pair (or public key when ``d is None``)."""

    def __init__(self, n: int, e: int, d: int | None = None) -> None:
        self.n = n
        self.e = e
        self.d = d

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @classmethod
    def generate(cls, bits: int = 2048, e: int = _E) -> "RSAKey":
        half = bits // 2
        while True:
            p = _gen_prime(half)
            q = _gen_prime(half)
            if p == q:
                continue
            n = p * q
            if n.bit_length() != bits:
                continue
            lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
            if math.gcd(e, lam) != 1:
                continue
            d = pow(e, -1, lam)
            return cls(n, e, d)

    @classmethod
    def from_public_numbers(cls, n: int, e: int) -> "RSAKey":
        return cls(n, e, None)

    def public_key(self) -> "RSAKey":
        return RSAKey(self.n, self.e, None)

    def to_public_dict(self) -> dict:
        return {"n": format(self.n, "x"), "e": self.e}

    @classmethod
    def from_public_dict(cls, data: dict) -> "RSAKey":
        n = int(data["n"], 16) if isinstance(data["n"], str) else int(data["n"])
        e = int(data["e"])
        return cls(n, e, None)

    def encrypt(self, message: bytes) -> bytes:
        k = self.size_bytes
        em = _oaep_encode(message, k)
        m = int.from_bytes(em, "big")
        if m >= self.n:
            raise ValueError("message representative out of range")
        c = pow(m, self.e, self.n)
        return c.to_bytes(k, "big")

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.d is None:
            raise ValueError("private key required")
        k = self.size_bytes
        if len(ciphertext) != k:
            raise ValueError("ciphertext length mismatch")
        m = pow(int.from_bytes(ciphertext, "big"), self.d, self.n)
        em = m.to_bytes(k, "big")
        return _oaep_decode(em, k)
