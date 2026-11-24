"""Envelope encryption for screenshots.

Development uses a master key derived from a configured secret. Production swaps the
adapter for AWS KMS/age while keeping the same envelope shape: a per-object data key
wraps the pixels, and the master key wraps the data key.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_ID = "local:v1"


@dataclass(frozen=True, slots=True)
class Envelope:
    ciphertext: bytes
    wrapped_key: str
    key_id: str


def _master_key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def encrypt(plaintext: bytes, *, secret: str) -> Envelope:
    data_key = os.urandom(32)
    data_nonce = os.urandom(12)
    payload = data_nonce + AESGCM(data_key).encrypt(data_nonce, plaintext, None)

    wrap_nonce = os.urandom(12)
    wrapped = wrap_nonce + AESGCM(_master_key(secret)).encrypt(wrap_nonce, data_key, None)
    return Envelope(
        ciphertext=payload,
        wrapped_key=base64.b64encode(wrapped).decode("ascii"),
        key_id=KEY_ID,
    )


def decrypt(ciphertext: bytes, wrapped_key: str, *, secret: str, key_id: str) -> bytes:
    if key_id != KEY_ID:
        raise ValueError("unknown encryption key")
    wrapped = base64.b64decode(wrapped_key)
    if len(wrapped) < 13:
        raise ValueError("malformed wrapped key")
    wrap_nonce, wrapped_payload = wrapped[:12], wrapped[12:]
    data_key = AESGCM(_master_key(secret)).decrypt(wrap_nonce, wrapped_payload, None)
    if len(ciphertext) < 13:
        raise ValueError("malformed ciphertext")
    data_nonce, payload = ciphertext[:12], ciphertext[12:]
    return AESGCM(data_key).decrypt(data_nonce, payload, None)
