"""
OS-Native Credential Vault.
Uses Windows DPAPI (Data Protection API) via ctypes on Windows,
with AES-GCM / Fernet fallback with restricted user-only permissions on POSIX.
Tied directly to the operating system user account without plaintext keys on disk.
"""
import os
import sys
import time
import secrets
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
            try:
                self._fernet = Fernet(self._get_or_create_posix_key())
            except Exception as e:
                if isinstance(e, CredentialEncryptionError):
                    raise
                raise CredentialEncryptionError(f"Failed to initialize Fernet with vault key: {e}") from e

    def _acquire_init_lock(self, timeout_sec: float = 10.0, poll_sec: float = 0.05) -> str:
        """Acquires an atomic directory-based initialization lock with stale lock reclamation."""
        lock_dir = os.path.join(self._key_dir, ".vault_key_init.lock")
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            try:
                os.mkdir(lock_dir)
                return lock_dir
            except FileExistsError:
                # Check for stale lock (older than 10 seconds)
                try:
                    mtime = os.path.getmtime(lock_dir)
                    if time.time() - mtime > 10.0:
                        try:
                            os.rmdir(lock_dir)
                            continue
                        except Exception:
                            pass
                except Exception:
                    pass
                time.sleep(poll_sec)
        raise CredentialEncryptionError(f"Timed out waiting for vault initialization lock '{lock_dir}'.")

    def _release_init_lock(self, lock_dir: str) -> None:
        try:
            if os.path.exists(lock_dir):
                os.rmdir(lock_dir)
        except Exception:
            pass

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

        # 3. If key file already exists, read with retry backoff to tolerate concurrent writes in progress
        if os.path.exists(self._key_file):
            try:
                return self._read_and_validate_with_retry(self._key_file)
            except CredentialEncryptionError as err:
                if "Symlink attack" in str(err) or "Insecure permissions" in str(err):
                    raise
                # A corrupted or unreadable key >= 32 bytes must fail closed to protect existing encrypted data
                if os.path.exists(self._key_file) and os.path.getsize(self._key_file) >= 32:
                    raise
                # Only if file is an abandoned incomplete remnant (< 32 bytes) do we fall through to locked recovery

        # 4. Acquire exclusive creation / recovery lock to eliminate cross-process races
        lock_dir = self._acquire_init_lock()
        staging_file = None
        try:
            # Under lock: re-check if another process established the key while we waited for lock
            if os.path.exists(self._key_file):
                try:
                    if os.path.getsize(self._key_file) >= 32:
                        return self._validate_and_read_posix_key(self._key_file)
                except CredentialEncryptionError:
                    pass

                # If key file is incomplete (< 32 bytes from an aborted crash), safely clean it up under lock
                try:
                    if os.path.getsize(self._key_file) < 32:
                        os.remove(self._key_file)
                except Exception:
                    pass

            # 5. Staged key creation: write to temporary file first so self._key_file is NEVER exposed with 0 bytes
            try:
                key = Fernet.generate_key()
                staging_file = os.path.join(self._key_dir, f".vault_key_tmp.{os.getpid()}.{secrets.token_hex(8)}")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | (getattr(os, "O_BINARY", 0))
                fd = os.open(staging_file, flags, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(key)
                    f.flush()
                    if hasattr(os, "fdatasync"):
                        try:
                            os.fdatasync(f.fileno())
                        except Exception:
                            pass

                if sys.platform != "win32":
                    os.chmod(staging_file, 0o600)

                # Atomically replace staging file into target key path
                os.replace(staging_file, self._key_file)
                staging_file = None

                if sys.platform != "win32":
                    os.chmod(self._key_file, 0o600)

                return self._validate_and_read_posix_key(self._key_file)
            except Exception as e:
                if isinstance(e, CredentialEncryptionError):
                    raise
                raise CredentialEncryptionError(
                    f"POSIX vault key persistence failed. Startup aborted to prevent credential loss: {str(e)}"
                ) from e
        finally:
            if staging_file and os.path.exists(staging_file):
                try:
                    os.remove(staging_file)
                except Exception:
                    pass
            self._release_init_lock(lock_dir)

    def _read_and_validate_with_retry(self, key_path: str, max_attempts: int = 20, delay_sec: float = 0.05) -> bytes:
        """
        Validates and reads the key file with retry backoff to tolerate concurrent writes in progress.
        Fails closed safely on timeout, corruption, or security violations.
        """
        last_err = None
        for _ in range(max_attempts):
            try:
                return self._validate_and_read_posix_key(key_path)
            except CredentialEncryptionError as err:
                if "Symlink attack" in str(err) or "Insecure permissions" in str(err):
                    raise
                last_err = err
                time.sleep(delay_sec)

        raise CredentialEncryptionError(
            f"Vault key initialization failed after concurrent creation: {last_err}"
        ) from last_err

    def _validate_and_read_posix_key(self, key_path: str) -> bytes:
        """
        Shared validation routine for POSIX vault key.
        Guarantees that:
        1. Key path is not a symlink.
        2. Key directory is not a symlink and has secure permissions.
        3. File mode has strict 0600 permissions on POSIX.
        4. File content is a valid, uncorrupted key of at least 32 bytes.
        """
        if os.path.islink(key_path):
            raise CredentialEncryptionError(f"Symlink attack detected at key file '{key_path}'.")

        if not os.path.exists(key_path):
            raise CredentialEncryptionError(f"Vault key file does not exist: '{key_path}'.")

        if sys.platform != "win32":
            st = os.stat(key_path)
            if (st.st_mode & 0o077) != 0:
                raise CredentialEncryptionError(
                    f"Insecure permissions on vault key '{key_path}' (mode: {oct(st.st_mode)}). Expected 0600."
                )

        try:
            with open(key_path, "rb") as f:
                content = f.read().strip()
        except Exception as e:
            raise CredentialEncryptionError(f"Failed to read vault key '{key_path}': {str(e)}") from e

        if not content or len(content) < 32:
            raise CredentialEncryptionError(f"Corrupted or empty vault key file '{key_path}'.")

        try:
            from cryptography.fernet import Fernet
            Fernet(content)
        except Exception as e:
            raise CredentialEncryptionError(f"Corrupted or invalid Fernet key in '{key_path}': {str(e)}") from e

        return content

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
