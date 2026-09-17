"""NSPK client helper (crypto + wire framing).

Self-contained: real RSA-OAEP (SHA-256, 2048-bit) with no third-party
dependencies, plus a tiny newline-delimited-JSON socket client.

This module only provides primitives (key generation, encode/decode, key
lookup/registration).  It does not implement either honest role.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import secrets
import socket

_E = 65537
_HLEN = hashlib.sha256().digest_size

DEFAULT_HOST = os.environ.get("NSPK_HOST", "127.0.0.1")
DEFAULT_DIR_PORT = int(os.environ.get("NSPK_DIR_PORT", "9100"))
DEFAULT_A_PORT = int(os.environ.get("NSPK_A_PORT", "9101"))
DEFAULT_B_PORT = int(os.environ.get("NSPK_B_PORT", "9102"))


def _mgf1(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _is_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
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
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(c):
            return c


class RSAKey:
    def __init__(self, n: int, e: int = _E, d: int | None = None) -> None:
        self.n, self.e, self.d = n, e, d

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @classmethod
    def generate(cls, bits: int = 2048) -> "RSAKey":
        half = bits // 2
        while True:
            p, q = _gen_prime(half), _gen_prime(half)
            if p == q:
                continue
            n = p * q
            if n.bit_length() != bits:
                continue
            lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
            if math.gcd(_E, lam) != 1:
                continue
            return cls(n, _E, pow(_E, -1, lam))

    @classmethod
    def from_public_dict(cls, data: dict) -> "RSAKey":
        n = int(data["n"], 16) if isinstance(data["n"], str) else int(data["n"])
        return cls(n, int(data["e"]), None)

    def to_public_dict(self) -> dict:
        return {"n": format(self.n, "x"), "e": self.e}

    def encrypt(self, msg: bytes) -> bytes:
        k = self.size_bytes
        if len(msg) > k - 2 * _HLEN - 2:
            raise ValueError("message too long")
        db = hashlib.sha256(b"").digest() + b"\x00" * (k - len(msg) - 2 * _HLEN - 2)
        db += b"\x01" + msg
        seed = os.urandom(_HLEN)
        masked_db = _xor(db, _mgf1(seed, k - _HLEN - 1))
        masked_seed = _xor(seed, _mgf1(masked_db, _HLEN))
        em = b"\x00" + masked_seed + masked_db
        return pow(int.from_bytes(em, "big"), self.e, self.n).to_bytes(k, "big")

    def decrypt(self, ct: bytes) -> bytes:
        if self.d is None:
            raise ValueError("private key required")
        k = self.size_bytes
        em = pow(int.from_bytes(ct, "big"), self.d, self.n).to_bytes(k, "big")
        masked_seed, masked_db = em[1 : 1 + _HLEN], em[1 + _HLEN :]
        seed = _xor(masked_seed, _mgf1(masked_db, _HLEN))
        db = _xor(masked_db, _mgf1(seed, k - _HLEN - 1))
        if not secrets.compare_digest(db[:_HLEN], hashlib.sha256(b"").digest()):
            raise ValueError("decryption error")
        idx = db.find(b"\x01", _HLEN)
        if idx < 0:
            raise ValueError("decryption error")
        return db[idx + 1 :]


def encode(key: RSAKey, obj: dict) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(key.encrypt(raw)).decode()


def decode(key: RSAKey, blob: str) -> dict:
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


def get_pubkey(name: str, host: str = DEFAULT_HOST, port: int = DEFAULT_DIR_PORT) -> RSAKey:
    conn = Conn(host, port)
    try:
        conn.send({"op": "pubkey", "name": name})
        reply = conn.recv()
        if not reply.get("ok"):
            raise RuntimeError(f"pubkey lookup failed: {reply}")
        return RSAKey.from_public_dict(reply["pub"])
    finally:
        conn.close()


def register(
    name: str, key: RSAKey, host: str = DEFAULT_HOST, port: int = DEFAULT_DIR_PORT
) -> None:
    conn = Conn(host, port)
    try:
        conn.send({"op": "register", "name": name, "pub": key.to_public_dict()})
        reply = conn.recv()
        if not reply.get("ok"):
            raise RuntimeError(f"register failed: {reply}")
    finally:
        conn.close()


__all__ = [
    "RSAKey",
    "Conn",
    "encode",
    "decode",
    "get_pubkey",
    "register",
    "DEFAULT_HOST",
    "DEFAULT_DIR_PORT",
    "DEFAULT_A_PORT",
    "DEFAULT_B_PORT",
]
