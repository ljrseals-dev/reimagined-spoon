"""Ed25519 signer for ledger entries (signs the 32-byte entry hash)."""
from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class Ed25519Signer:
    def __init__(self, private_key: Ed25519PrivateKey, key_id: str):
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("key_id must be a non-empty str")
        self._key = private_key
        self.key_id = key_id

    @classmethod
    def generate(cls, key_id: str) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.generate(), key_id)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    @property
    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
