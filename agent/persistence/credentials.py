"""
Secure Credential Vault using cryptography Fernet encryption.
Protects LLM API keys on disk with a locally derived, protected machine key.
"""
import os
import base64
import hashlib
from typing import Optional
from cryptography.fernet import Fernet

KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".agent_vault.key")


def _get_or_create_key() -> bytes:
    """Derive or generate a persistent local encryption key with restricted access."""
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, "rb") as f:
                return f.read().strip()
        except Exception:
            pass

    # Generate new random 32-byte key
    key = Fernet.generate_key()
    try:
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        # On POSIX set 0600 permissions if available
        if hasattr(os, "chmod"):
            try:
                os.chmod(KEY_FILE, 0o600)
            except Exception:
                pass
    except Exception as e:
        # Fallback to hash of machine identifiers
        seed = f"{os.environ.get('COMPUTERNAME', '')}-{os.environ.get('USERNAME', 'agent')}-agent-key"
        key = base64.urlsafe_b64encode(hashlib.sha256(seed.encode()).digest())
    return key


class CredentialVault:
    def __init__(self):
        self._key = _get_or_create_key()
        self._cipher = Fernet(self._key)

    def encrypt(self, plain_text: str) -> str:
        if not plain_text:
            return ""
        encrypted = self._cipher.encrypt(plain_text.encode("utf-8"))
        return encrypted.decode("utf-8")

    def decrypt(self, encrypted_text: str) -> Optional[str]:
        if not encrypted_text:
            return None
        try:
            decrypted = self._cipher.decrypt(encrypted_text.encode("utf-8"))
            return decrypted.decode("utf-8")
        except Exception:
            return None


vault = CredentialVault()
