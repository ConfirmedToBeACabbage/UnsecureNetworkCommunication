# crypto_box.py
# ------------------------------------------------------------
# This file is the "crypto wrapper" that uses KeyManager.
#
# It encrypts messages using the current active DEK, and it tags the
# ciphertext with the key_id so we know which DEK to use later.
#
# This is what enables key rotation:
# - new messages use the new key_id
# - old messages still decrypt using their old key_id
# ------------------------------------------------------------

import os
import json
import base64
from typing import Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from key_manager import KeyManager, Capability


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


class CryptoBox:
    def __init__(self, km: KeyManager):
        self.km = km

    def encrypt_message(self, ring: Dict[str, Any], cap: Capability, plaintext: str) -> str:
        # Pull the ACTIVE key used for new encryption operations
        key_id, dek = self.km.get_active_dek(ring, cap)

        aes = AESGCM(dek)
        nonce = os.urandom(12)

        # Associated data binds the ciphertext to a "message format version"
        ct = aes.encrypt(nonce, plaintext.encode("utf-8"), associated_data=b"MSG_V1")

        # Store key_id so decrypt can look up correct key after rotation
        msg = {
            "version": 1,
            "key_id": key_id,
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ct),
        }
        return json.dumps(msg)

    def decrypt_message(self, ring: Dict[str, Any], cap: Capability, msg_json: str) -> str:
        msg = json.loads(msg_json)

        key_id = msg["key_id"]
        nonce = _b64d(msg["nonce"])
        ct = _b64d(msg["ciphertext"])

        # Fetch the correct key for this message (old or new)
        dek = self.km.get_dek_by_id(ring, cap, key_id)

        aes = AESGCM(dek)
        pt = aes.decrypt(nonce, ct, associated_data=b"MSG_V1")
        return pt.decode("utf-8")
