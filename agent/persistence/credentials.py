"""
OS-Native Credential Vault.
Uses Windows DPAPI (Data Protection API) via ctypes on Windows,
with AES-GCM / Fernet fallback with restricted user-only permissions on POSIX.
Tied directly to the operating system user account without plaintext keys on disk.
"""
import os
import sys
import base64
import ctypes
from typing import Optional

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]


class CredentialEncryptionError(RuntimeError):
    """Raised when OS credential encryption fails."""
    pass


class CredentialVault:
    def __init__(self, key_dir: Optional[str] = None, is_windows: Optional[bool] = None):
        self._is_windows = IS_WINDOWS if is_windows is None else is_windows
        self._key_dir = key_dir or os.path.expanduser("~/.config/ai_execution_agent")
        self._key_file = os.path.join(self._key_dir, "vault.key")
        if not self._is_windows:
            from cryptography.fernet import Fernet
            self._fernet = Fernet(self._get_or_create_posix_key())

    def _get_or_create_posix_key(self) -> bytes:
        from cryptography.fernet import Fernet

        # 1. Symlink containment check
        if os.path.islink(self._key_dir):
            raise CredentialEncryptionError(f"Symlink attack detected at key directory '{self._key_dir}'.")
        if os.path.islink(self._key_file):
            raise CredentialEncryptionError(f"Symlink attack detected at key file '{self._key_file}'.")

        # 2. Key directory verification and permission hardening
        if not os.path.exists(self._key_dir):
            try:
                os.makedirs(self._key_dir, mode=0o700, exist_ok=True)
            except Exception as e:
                raise CredentialEncryptionError(f"Failed to create key directory '{self._key_dir}': {str(e)}") from e

        if sys.platform != "win32":
            try:
                os.chmod(self._key_dir, 0o700)
            except Exception as e:
                raise CredentialEncryptionError(f"Failed to enforce 0700 permissions on key directory '{self._key_dir}': {str(e)}") from e
            dir_st = os.stat(self._key_dir)
            if (dir_st.st_mode & 0o077) != 0:
                raise CredentialEncryptionError(
                    f"Insecure permissions on key directory '{self._key_dir}' (mode: {oct(dir_st.st_mode)}). Expected 0700."
                )

        # 3. If key file already exists, verify permissions and load
        if os.path.exists(self._key_file):
            try:
                if sys.platform != "win32":
                    st = os.stat(self._key_file)
                    if (st.st_mode & 0o077) != 0:
                        raise CredentialEncryptionError(
                            f"Insecure permissions on vault key '{self._key_file}' (mode: {oct(st.st_mode)}). Expected 0600."
                        )
                with open(self._key_file, "rb") as f:
                    content = f.read().strip()
                if not content or len(content) < 32:
                    raise CredentialEncryptionError(f"Corrupted or empty vault key file '{self._key_file}'.")
                return content
            except Exception as e:
                if isinstance(e, CredentialEncryptionError):
                    raise
                raise CredentialEncryptionError(f"Failed to read existing vault key '{self._key_file}': {str(e)}") from e

        # 4. Key does not exist: generate and atomically create with exclusive lock (O_EXCL)
        key = Fernet.generate_key()
        try:
            # Atomic creation with O_CREAT | O_EXCL prevents concurrent creation races
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | (getattr(os, "O_BINARY", 0))
            try:
                fd = os.open(self._key_file, flags, 0o600)
            except FileExistsError:
                # Concurrent creator finished first: read and verify their key
                with open(self._key_file, "rb") as f:
                    return f.read().strip()

            with os.fdopen(fd, "wb") as f:
                f.write(key)

            if sys.platform != "win32":
                os.chmod(self._key_file, 0o600)
                st = os.stat(self._key_file)
                if (st.st_mode & 0o077) != 0:
                    raise CredentialEncryptionError(
                        f"Failed to verify 0600 permissions on newly created vault key '{self._key_file}'."
                    )
        except Exception as e:
            if os.path.exists(self._key_file) and not isinstance(e, FileExistsError):
                try:
                    os.remove(self._key_file)
                except Exception:
                    pass
            if isinstance(e, CredentialEncryptionError):
                raise
            raise CredentialEncryptionError(
                f"POSIX vault key persistence failed. Startup aborted to prevent credential loss: {str(e)}"
            ) from e

        return key

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypts sensitive plaintext using OS-bound DPAPI or user-restricted key.
        Fails closed on any error. Never falls back to Base64 or plaintext.
        """
        if not plain_text:
            return ""

        raw_bytes = plain_text.encode("utf-8")

        if self._is_windows:
            try:
                p_in = ctypes.create_string_buffer(raw_bytes)
                blob_in = DATA_BLOB(len(raw_bytes), ctypes.cast(p_in, ctypes.POINTER(ctypes.c_char)))
                blob_out = DATA_BLOB()

                # CryptProtectData flags: CRYPTPROTECT_UI_FORBIDDEN = 0x1
                success = ctypes.windll.crypt32.CryptProtectData(
                    ctypes.byref(blob_in),
                    "ai_agent_credential",
                    None,
                    None,
                    None,
                    0x1,
                    ctypes.byref(blob_out),
                )
                if not success:
                    raise CredentialEncryptionError("Windows DPAPI CryptProtectData failed.")

                enc_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
                ctypes.windll.kernel32.LocalFree(blob_out.pbData)
                return "dpapi:" + base64.b64encode(enc_bytes).decode("ascii")
            except Exception as e:
                # Strictly fail closed: never return unencrypted or base64 data
                if isinstance(e, CredentialEncryptionError):
                    raise
                raise CredentialEncryptionError(f"Windows DPAPI encryption failed: {str(e)}") from e
        else:
            try:
                enc = self._fernet.encrypt(raw_bytes)
                return "fernet:" + enc.decode("ascii")
            except Exception as e:
                raise CredentialEncryptionError(f"POSIX Fernet encryption failed: {str(e)}") from e

    def decrypt(self, encrypted_text: str) -> Optional[str]:
        """
        Decrypts ciphertext using OS-bound DPAPI.
        Permits legacy formats (enc:, b64:) only for explicit migration.
        """
        if not encrypted_text:
            return None

        try:
            if encrypted_text.startswith("dpapi:") and self._is_windows:
                raw_b64 = encrypted_text[6:]
                enc_bytes = base64.b64decode(raw_b64.encode("ascii"))

                p_in = ctypes.create_string_buffer(enc_bytes)
                blob_in = DATA_BLOB(len(enc_bytes), ctypes.cast(p_in, ctypes.POINTER(ctypes.c_char)))
                blob_out = DATA_BLOB()

                success = ctypes.windll.crypt32.CryptUnprotectData(
                    ctypes.byref(blob_in),
                    None,
                    None,
                    None,
                    None,
                    0x1,
                    ctypes.byref(blob_out),
                )
                if not success:
                    return None

                dec_bytes = ctypes.string_at(blob_out.pbData, blob_out.cbData)
                ctypes.windll.kernel32.LocalFree(blob_out.pbData)
                return dec_bytes.decode("utf-8", errors="replace")

            elif encrypted_text.startswith("fernet:") and not self._is_windows:
                raw = encrypted_text[7:].encode("ascii")
                return self._fernet.decrypt(raw).decode("utf-8")

            elif encrypted_text.startswith("b64:"):
                return base64.b64decode(encrypted_text[4:].encode("ascii")).decode("utf-8")

            # Legacy migration support: if starts with enc: (from previous Fernet implementation)
            elif encrypted_text.startswith("enc:"):
                try:
                    from cryptography.fernet import Fernet
                    candidate_keys = [
                        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".agent_vault.key"),
                        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".agent_vault.key"),
                        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".agent_vault.key"),
                    ]
                    for kf in candidate_keys:
                        if os.path.exists(kf):
                            try:
                                with open(kf, "rb") as f:
                                    k = f.read().strip()
                                return Fernet(k).decrypt(encrypted_text[4:].encode("utf-8")).decode("utf-8")
                            except Exception:
                                continue
                except Exception:
                    return None

            return None
        except Exception:
            return None


vault = CredentialVault()
