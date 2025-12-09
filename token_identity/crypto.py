from __future__ import annotations

import base64
import hashlib
import os
from typing import Tuple

from ecdsa import SigningKey, VerifyingKey, NIST256p, SECP256k1, BadSignatureError
from ecdsa.util import sigencode_string, sigdecode_string


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def gen_secp256k1_keypair(seed: bytes | None = None) -> Tuple[SigningKey, VerifyingKey]:
    """Generate a secp256k1 keypair. If seed is provided, derive a deterministic key."""
    if seed is None:
        sk = SigningKey.generate(curve=SECP256k1)
    else:
        # Derive private key from seed deterministically via sha256
        digest = sha256(seed)
        # Ensure within curve order; SigningKey.from_string expects 32 bytes
        sk = SigningKey.from_string(digest, curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk, vk


def jwk_from_verifying_key(vk: VerifyingKey) -> dict:
    """Construct a JsonWebKey2020 public JWK for secp256k1 from a VerifyingKey.

    x and y are base64url-encoded big-endian 32-byte coordinates.
    """
    # ecdsa lib uses uncompressed point by default: 0x04 | X(32) | Y(32)
    uncompressed = vk.to_string("uncompressed")
    # Strip 0x04 prefix
    x = uncompressed[1:33]
    y = uncompressed[33:65]
    return {
        "kty": "EC",
        "crv": "secp256k1",
        "x": b64url_encode(x),
        "y": b64url_encode(y),
    }


def sign_det_secp256k1(sk: SigningKey, message: bytes) -> bytes:
    """Deterministically sign message; returns 64-byte (r||s) raw signature."""
    return sk.sign_deterministic(message, hashfunc=hashlib.sha256, sigencode=sigencode_string)


def verify_sig_secp256k1(vk: VerifyingKey, message: bytes, signature: bytes) -> bool:
    try:
        return vk.verify(signature, message, hashfunc=hashlib.sha256, sigdecode=sigdecode_string)
    except BadSignatureError:
        return False

