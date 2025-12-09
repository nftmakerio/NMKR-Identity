from __future__ import annotations

import base64
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def encrypt_with_passphrase(passphrase: str, plaintext: bytes) -> str:
    salt = os.urandom(16)
    key = _derive_key(passphrase, salt)
    token = Fernet(key).encrypt(plaintext)
    return base64.urlsafe_b64encode(salt + token).decode()


def decrypt_with_passphrase(passphrase: str, payload: str) -> bytes:
    data = base64.urlsafe_b64decode(payload)
    salt, token = data[:16], data[16:]
    key = _derive_key(passphrase, salt)
    return Fernet(key).decrypt(token)

