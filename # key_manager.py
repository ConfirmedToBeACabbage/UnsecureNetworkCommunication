# key_manager.py
# ------------------------------------------------------------
# Lab 2 Key Management Layer
#
# What this does:
# 1) Secure Key Storage:
#    - Stores the symmetric "data encryption key" (DEK) in an encrypted form
#    - The DEK is wrapped (encrypted) by a "master key" derived from a password
#    - The keyring file is encrypted at rest (AES-GCM)
#
# 2) Key Access Control (RBAC simulation):
#    - Only authorized roles can request keys
#    - Unauthorized access attempts fail and get logged
#
# 3) Key Rotation:
#    - Creates a new active DEK for encrypting new messages
#    - Keeps older DEKs only for decrypting older messages
#
# 4) Key Usage Logging:
#    - Logs all key access attempts and whether they were allowed or denied
#
# 5) Key Destruction:
#    - Deletes old keys (simulates retirement)
#    - After destruction, old ciphertext becomes permanently unreadable
# ------------------------------------------------------------

import os
import json
import base64
import time
from dataclasses import dataclass
from typing import Dict, Any

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------
# Base64 helpers for JSON
# ---------------------------
# JSON can’t store raw bytes, so we base64 encode bytes to strings.
def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


# ---------------------------
# Master key derivation (KDF)
# ---------------------------
# We never store a master key on disk.
# We derive it from a password + salt using Scrypt (slow/memory-hard).
def derive_master_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,     # 32 bytes = 256-bit master key for AES-256-GCM
        n=2**14,       # cost factor
        r=8,
        p=1
    )
    return kdf.derive(password.encode("utf-8"))


# ---------------------------
# Capability token (RBAC simulation)
# ---------------------------
# In a real system, your app might run under a service account or IAM role.
# Here we simulate it with a simple role string.
@dataclass(frozen=True)
class Capability:
    role: str


class KeyManager:
    """
    Manages an encrypted keyring file containing wrapped DEKs.
    Provides RBAC checks, rotation, logging, and key destruction.
    """

    def __init__(self, keyring_path: str = "keyring.enc", log_path: str = "key_usage.log"):
        self.keyring_path = keyring_path
        self.log_path = log_path

        # Only this role can use keys (authorized part of your program)
        self.allowed_roles = {"crypto_service"}

    # ---------------------------
    # Audit logging
    # ---------------------------
    def _log(self, key_id: str, operation: str, success: bool, reason: str = "") -> None:
        """
        Records every key usage attempt (allowed or denied).
        Required for Lab 2: "Key Usage Logging".
        """
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = (
            f"{ts} key_id={key_id} op={operation} "
            f"result={'ALLOW' if success else 'DENY'} reason={reason}\n"
        )
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)

    # ---------------------------
    # Access control
    # ---------------------------
    def _require_auth(self, cap: Capability, key_id: str, operation: str) -> None:
        """
        Enforces role-based access control simulation:
        only allowed roles can use keys.
        """
        if cap.role not in self.allowed_roles:
            self._log(key_id, operation, False, f"unauthorized_role:{cap.role}")
            raise PermissionError(f"Access denied for role: {cap.role}")

        self._log(key_id, operation, True, "authorized")

    # ---------------------------
    # Encrypt/decrypt the keyring file
    # ---------------------------
    # The entire keyring JSON is encrypted at rest using the derived master key.
    def _encrypt_keyring(self, master_key: bytes, plaintext_json: bytes) -> bytes:
        aes = AESGCM(master_key)
        nonce = os.urandom(12)  # GCM nonce is typically 12 bytes
        ct = aes.encrypt(nonce, plaintext_json, associated_data=b"KEYRING_V1")
        return nonce + ct

    def _decrypt_keyring(self, master_key: bytes, blob: bytes) -> bytes:
        aes = AESGCM(master_key)
        nonce, ct = blob[:12], blob[12:]
        return aes.decrypt(nonce, ct, associated_data=b"KEYRING_V1")

    # ---------------------------
    # Create a new keyring
    # ---------------------------
    def init_keyring_with_header(self, password: str) -> None:
        """
        Creates a new encrypted keyring file with one active DEK.

        File format:
          b"KR1" + salt(16 bytes) + AESGCM(master_key, keyring_json)

        Salt is stored in cleartext header so we can derive master key during load.
        The DEKs are never stored in plaintext (they are wrapped).
        """
        if os.path.exists(self.keyring_path):
            raise FileExistsError("keyring already exists")

        # Generate salt + derive master key
        salt = os.urandom(16)
        master_key = derive_master_key(password, salt)

        # Generate initial DEK (Data Encryption Key) used for actual message encryption
        dek = os.urandom(32)  # 256-bit AES key
        key_id = f"k{int(time.time())}"

        wrapped = self.wrap_dek(master_key, dek)

        ring = {
            "version": 1,
            "salt": _b64e(salt),           # also saved in JSON for readability; header is source of truth
            "active_key_id": key_id,       # which key encrypts new messages
            "keys": {
                key_id: {
                    "wrapped_dek": wrapped,
                    "status": "active",
                    "created_at": time.time(),
                    "retired_at": None,
                }
            },
        }

        plaintext = json.dumps(ring, indent=2).encode("utf-8")
        enc_payload = self._encrypt_keyring(master_key, plaintext)

        with open(self.keyring_path, "wb") as f:
            f.write(b"KR1" + salt + enc_payload)

    # ---------------------------
    # Load the keyring
    # ---------------------------
    def load_keyring(self, password: str) -> Dict[str, Any]:
        """
        Loads and decrypts keyring using password-derived master key.
        If someone steals keyring.enc without the password, they cannot unwrap the keys.
        """
        if not os.path.exists(self.keyring_path):
            raise FileNotFoundError("keyring not found; run init_keyring_with_header first")

        blob = open(self.keyring_path, "rb").read()

        if not blob.startswith(b"KR1"):
            raise ValueError("Invalid keyring header (expected KR1).")

        salt = blob[3:19]        # 16 bytes
        enc_payload = blob[19:]  # remaining data

        master_key = derive_master_key(password, salt)
        plaintext = self._decrypt_keyring(master_key, enc_payload)

        ring = json.loads(plaintext.decode("utf-8"))

        # Store master key in memory ONLY (not written to disk).
        # This is needed so we can unwrap DEKs later.
        ring["_master_key"] = master_key
        return ring

    # ---------------------------
    # Save updated keyring
    # ---------------------------
    def save_keyring(self, ring: Dict[str, Any]) -> None:
        """
        Saves keyring changes (rotation/destruction/status updates) back to disk.
        Required for rotation/destruction to persist across restarts.
        """
        master_key = ring.get("_master_key")
        if not master_key:
            raise ValueError("ring missing _master_key; load_keyring() first")

        ring_copy = dict(ring)
        ring_copy.pop("_master_key", None)

        # Salt must match the header
        salt = _b64d(ring_copy["salt"])

        plaintext = json.dumps(ring_copy, indent=2).encode("utf-8")
        enc_payload = self._encrypt_keyring(master_key, plaintext)

        with open(self.keyring_path, "wb") as f:
            f.write(b"KR1" + salt + enc_payload)

    # ---------------------------
    # Wrap/unwrap a DEK
    # ---------------------------
    # "Wrapping" = encrypting a DEK using master key for storage.
    # This is a common pattern: master key protects many DEKs.
    def wrap_dek(self, master_key: bytes, dek: bytes) -> str:
        aes = AESGCM(master_key)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, dek, associated_data=b"DEK_WRAP_V1")
        return _b64e(nonce + ct)

    def unwrap_dek(self, master_key: bytes, wrapped: str) -> bytes:
        blob = _b64d(wrapped)
        nonce, ct = blob[:12], blob[12:]
        aes = AESGCM(master_key)
        return aes.decrypt(nonce, ct, associated_data=b"DEK_WRAP_V1")

    # ---------------------------
    # Key retrieval for crypto operations
    # ---------------------------
    def get_active_dek(self, ring: Dict[str, Any], cap: Capability) -> tuple[str, bytes]:
        """
        Returns (key_id, dek) for encrypting new messages.
        Enforces RBAC and logs usage.
        """
        key_id = ring["active_key_id"]
        self._require_auth(cap, key_id, "get_active_key")

        wrapped = ring["keys"][key_id]["wrapped_dek"]
        dek = self.unwrap_dek(ring["_master_key"], wrapped)
        return key_id, dek

    def get_dek_by_id(self, ring: Dict[str, Any], cap: Capability, key_id: str) -> bytes:
        """
        Returns DEK for decrypting messages created under a specific key_id.
        This is how old messages still decrypt after rotation.
        """
        self._require_auth(cap, key_id, "get_key_by_id")

        if key_id not in ring["keys"]:
            raise KeyError(f"key not found: {key_id}")

        wrapped = ring["keys"][key_id]["wrapped_dek"]
        return self.unwrap_dek(ring["_master_key"], wrapped)

    # ---------------------------
    # Key rotation
    # ---------------------------
    def rotate_key(self, ring: Dict[str, Any], cap: Capability) -> str:
        """
        Creates a new active DEK for encrypting NEW messages.
        Old key becomes "retired" and is kept for decrypting OLD messages.
        """
        active = ring["active_key_id"]
        self._require_auth(cap, active, "rotate_key")

        # Retire old key
        ring["keys"][active]["status"] = "retired"
        ring["keys"][active]["retired_at"] = time.time()

        # Create new active key
        new_dek = os.urandom(32)
        new_id = f"k{int(time.time())}"
        ring["keys"][new_id] = {
            "wrapped_dek": self.wrap_dek(ring["_master_key"], new_dek),
            "status": "active",
            "created_at": time.time(),
            "retired_at": None,
        }
        ring["active_key_id"] = new_id
        return new_id

    # ---------------------------
    # Key destruction
    # ---------------------------
    def destroy_key(self, ring: Dict[str, Any], cap: Capability, key_id: str) -> None:
        """
        Deletes an old key from the keyring. After this, any ciphertext
        encrypted with that key becomes permanently unreadable.

        We refuse to destroy the active key to prevent breaking new messages.
        """
        self._require_auth(cap, key_id, "destroy_key")

        if key_id == ring["active_key_id"]:
            raise ValueError("refuse to destroy active key (rotate first)")

        if key_id not in ring["keys"]:
            raise KeyError(f"key not found: {key_id}")

        del ring["keys"][key_id]
