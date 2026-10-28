"""
Provenance and cryptographic trust boundary for verification execution records.
Guarantees that test execution records cannot be forged, fabricated, or tampered with.
Uses deterministic canonical JSON serialization with HMAC-SHA256 signatures.
Provides an OS-backed persistent secret lifecycle with strict permissions,
atomic concurrency, Windows ACL lockdown, explicit ephemeral mode, and key rotation.
"""
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

_SECRET_LOCK = threading.RLock()
_CACHED_SECRETS: Dict[str, bytes] = {}
_IS_EPHEMERAL_MAP: Dict[str, bool] = {}
_ACTIVE_CONFIG_DIR: Optional[str] = None
_CURRENT_ENV_SECRET: Optional[str] = None
_CACHED_SECRET: Optional[bytes] = None
_IS_EPHEMERAL: bool = False


class VerificationSecretError(RuntimeError):
    """Base exception for verification secret lifecycle errors."""
    pass


class VerificationSecretStorageError(VerificationSecretError):
    """Raised when persistent verification secret cannot be securely accessed or created."""
    pass


class VerificationSecretTamperedError(VerificationSecretError):
    """Raised when an existing verification key file is corrupted, truncated, or tampered with."""
    pass


def _get_canonical_config_key(config_dir: Optional[str] = None) -> str:
    path = config_dir or os.path.expanduser("~/.config/ai_execution_agent")
    return os.path.realpath(os.path.abspath(path))


def is_ephemeral_mode(config_dir: Optional[str] = None) -> bool:
    """Returns True if the runtime is currently using an ephemeral in-memory signing secret."""
    with _SECRET_LOCK:
        global _IS_EPHEMERAL, _ACTIVE_CONFIG_DIR
        target_dir = config_dir if config_dir is not None else _ACTIVE_CONFIG_DIR
        if target_dir:
            canonical_key = _get_canonical_config_key(target_dir)
            return _IS_EPHEMERAL_MAP.get(canonical_key, False)
        return _IS_EPHEMERAL


def get_secret_storage_path(config_dir: Optional[str] = None) -> str:
    """Returns the absolute file path for the persistent verification key."""
    base_dir = config_dir or os.path.expanduser("~/.config/ai_execution_agent")
    return os.path.join(base_dir, "verification.key")


def _lock_down_key_file(filepath: str) -> None:
    """
    Enforces strict user-only permissions:
    - On Windows: 
        1. Resets ACLs (icacls /reset) to eradicate any pre-existing explicit hostile or permissive ACEs.
        2. Strips inheritance and grants (R,W) exclusively to the active USERNAME (icacls /inheritance:r /grant:r).
        3. Audits the resulting ACL: strictly verifies that no unauthorized or permissive principals
           (e.g. Everyone, Users, BUILTIN\\Users, Authenticated Users, Guests, ANONYMOUS) possess access,
           and that the active user is granted access. Fails closed on any unexpected ACE.
    - On POSIX: Uses chmod 0o600 (owner read/write only).
    Fails closed if permissions cannot be enforced or verified.
    """
    if sys.platform == "win32":
        import subprocess
        username = os.environ.get("USERNAME")
        if not username:
            raise VerificationSecretStorageError(
                "Security Failure: Unable to determine active USERNAME for Windows key ACL lockdown."
            )

        # 1. Reset explicit permissions to eliminate hostile pre-existing ACEs
        reset_res = subprocess.run(
            ["icacls", filepath, "/reset"],
            capture_output=True,
            text=True,
            check=False,
        )
        if reset_res.returncode != 0:
            raise VerificationSecretStorageError(
                f"Security Failure: icacls /reset failed to reset key ACLs: {reset_res.stderr.strip()}"
            )

        # 2. Strip inherited permissions and grant exclusive (R,W) to active user
        grant_res = subprocess.run(
            ["icacls", filepath, "/inheritance:r", "/grant:r", f"{username}:(R,W)"],
            capture_output=True,
            text=True,
            check=False,
        )
        if grant_res.returncode != 0:
            raise VerificationSecretStorageError(
                f"Security Failure: icacls failed to lock down key ACLs: {grant_res.stderr.strip()}"
            )

        # 3. Audit resulting ACL to confirm no hostile or permissive ACEs remain
        audit_res = subprocess.run(
            ["icacls", filepath],
            capture_output=True,
            text=True,
            check=False,
        )
        if audit_res.returncode != 0:
            raise VerificationSecretStorageError(
                f"Security Failure: icacls failed to audit resulting key ACLs: {audit_res.stderr.strip()}"
            )

        # Remove the file path from audit string so that directory names like "C:\Users" don't trigger false positives
        acl_output = audit_res.stdout.lower()
        acl_entries = acl_output.replace(filepath.lower(), "")
        forbidden_principals = [
            "everyone",
            "builtin\\users",
            "authenticated users",
            "guests",
            "builtin\\guests",
            "anonymous",
        ]
        for principal in forbidden_principals:
            if principal in acl_entries:
                raise VerificationSecretStorageError(
                    f"Security Failure: Key file '{filepath}' retains unauthorized or permissive ACL for '{principal}': {audit_res.stdout.strip()}"
                )

        if username.lower() not in acl_entries:
            raise VerificationSecretStorageError(
                f"Security Failure: Key file '{filepath}' active user '{username}' missing from audited ACL: {audit_res.stdout.strip()}"
            )
    elif hasattr(os, "chmod"):
        try:
            os.chmod(filepath, 0o600)
        except Exception as e:
            raise VerificationSecretStorageError(
                f"Security Failure: Failed to set 0o600 permissions on key file: {e}"
            ) from e


def _validate_and_read_key(key_file: str) -> bytes:
    """Validates symlink absence, file size, permissions, and reads 32 bytes."""
    if os.path.islink(key_file):
        raise VerificationSecretStorageError(f"Symlink attack detected at key file: {key_file}")
    if not os.path.exists(key_file):
        raise VerificationSecretStorageError(f"Key file does not exist: {key_file}")

    file_size = os.path.getsize(key_file)
    if file_size != 32:
        raise VerificationSecretTamperedError(
            f"Verification key file '{key_file}' is corrupted or invalid size: {file_size} bytes (expected exactly 32 bytes)."
        )

    _lock_down_key_file(key_file)

    with open(key_file, "rb") as f:
        content = f.read()

    if len(content) != 32:
        raise VerificationSecretTamperedError(f"Failed to read 32 bytes from key file '{key_file}'.")

    return content


def get_verification_secret(
    config_dir: Optional[str] = None,
    allow_ephemeral: bool = False,
) -> bytes:
    """
    Retrieves or initializes the 256-bit cryptographic verification secret.

    Secret Lifecycle & Trust Boundary:
    1. Environment Variable: If 'AGENT_VERIFICATION_SECRET' is defined, its value is derived
       (SHA-256 digested if raw string, or parsed if 64-char hex) and used.
    2. Persistent Storage: Otherwise, loads or atomically generates a 32-byte secret persisted at
       '~/.config/ai_execution_agent/verification.key'.
       - On POSIX, directory is secured to 0o700, and file is secured to 0o600.
       - On Windows, ACLs are locked down to current USERNAME with inheritance stripped.
       - Symlinks are rejected to prevent symlink hijack attacks.
       - Atomic creation (O_CREAT | O_EXCL) prevents concurrency race conditions.
    3. Fail-Closed by Default: If disk persistence is unavailable, this function FAILS CLOSED
       (raises VerificationSecretStorageError) to prevent silent fallback to temporary keys.
    4. Explicit Ephemeral Mode: Temporary keys are only allowed if allow_ephemeral=True or
       AGENT_ALLOW_EPHEMERAL_SECRET=1, and all records produced in that mode are explicitly
       labeled with ephemeral=True.
    5. Config Directory Scoping: Secrets are scoped and cached per canonical config directory.
    """
    with _SECRET_LOCK:
        global _CACHED_SECRET, _IS_EPHEMERAL, _ACTIVE_CONFIG_DIR, _CURRENT_ENV_SECRET
        current_env = os.environ.get("AGENT_VERIFICATION_SECRET")
        if current_env != _CURRENT_ENV_SECRET:
            _CACHED_SECRETS.clear()
            _IS_EPHEMERAL_MAP.clear()
            _CACHED_SECRET = None
            _IS_EPHEMERAL = False
            _CURRENT_ENV_SECRET = current_env

        target_dir = config_dir if config_dir is not None else _ACTIVE_CONFIG_DIR
        canonical_key = _get_canonical_config_key(target_dir)
        if config_dir is not None:
            _ACTIVE_CONFIG_DIR = config_dir

        # 1. Check environment variable override
        env_secret = os.environ.get("AGENT_VERIFICATION_SECRET")
        if env_secret:
            if len(env_secret) == 64:
                try:
                    secret = bytes.fromhex(env_secret)
                    _CACHED_SECRETS[canonical_key] = secret
                    _IS_EPHEMERAL_MAP[canonical_key] = False
                    _CACHED_SECRET = secret
                    _IS_EPHEMERAL = False
                    return secret
                except ValueError:
                    pass
            secret = hashlib.sha256(env_secret.encode("utf-8")).digest()
            _CACHED_SECRETS[canonical_key] = secret
            _IS_EPHEMERAL_MAP[canonical_key] = False
            _CACHED_SECRET = secret
            _IS_EPHEMERAL = False
            return secret

        # 2. Check cached secret for this canonical configuration directory
        if canonical_key in _CACHED_SECRETS:
            secret = _CACHED_SECRETS[canonical_key]
            _CACHED_SECRET = secret
            _IS_EPHEMERAL = _IS_EPHEMERAL_MAP.get(canonical_key, False)
            return secret

        # 3. Check persistent key file
        key_file = get_secret_storage_path(target_dir)
        key_dir = os.path.dirname(key_file)

        try:
            if os.path.islink(key_dir):
                raise VerificationSecretStorageError(f"Symlink detected at key directory: {key_dir}")

            if os.path.exists(key_file):
                secret = _validate_and_read_key(key_file)
                _CACHED_SECRETS[canonical_key] = secret
                _IS_EPHEMERAL_MAP[canonical_key] = False
                _CACHED_SECRET = secret
                _IS_EPHEMERAL = False
                return secret

            # Atomic key creation under concurrency
            os.makedirs(key_dir, mode=0o700, exist_ok=True)
            new_secret = secrets.token_bytes(32)

            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
            try:
                fd = os.open(key_file, flags, 0o600)
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(new_secret)
                        f.flush()
                        os.fsync(f.fileno())
                except Exception as write_err:
                    if os.path.exists(key_file):
                        try:
                            os.remove(key_file)
                        except Exception:
                            pass
                    raise VerificationSecretStorageError(
                        f"Failed to write verification secret to '{key_file}': {write_err}"
                    ) from write_err

                # Validate that the file was written completely and matches exactly 32 bytes
                if not os.path.exists(key_file) or os.path.getsize(key_file) != 32:
                    if os.path.exists(key_file):
                        try:
                            os.remove(key_file)
                        except Exception:
                            pass
                    raise VerificationSecretStorageError(
                        f"Verification key file '{key_file}' creation verification failed (invalid size)."
                    )

                with open(key_file, "rb") as f:
                    persisted = f.read()
                if persisted != new_secret:
                    if os.path.exists(key_file):
                        try:
                            os.remove(key_file)
                        except Exception:
                            pass
                    raise VerificationSecretStorageError(
                        f"Persisted verification key at '{key_file}' does not match written secret."
                    )

                _lock_down_key_file(key_file)
                _CACHED_SECRETS[canonical_key] = new_secret
                _IS_EPHEMERAL_MAP[canonical_key] = False
                _CACHED_SECRET = new_secret
                _IS_EPHEMERAL = False
                return new_secret

            except FileExistsError:
                # Another process won the race and created it; read the established key with retry backoff
                for attempt in range(10):
                    time.sleep(0.02)
                    try:
                        secret = _validate_and_read_key(key_file)
                        _CACHED_SECRETS[canonical_key] = secret
                        _IS_EPHEMERAL_MAP[canonical_key] = False
                        _CACHED_SECRET = secret
                        _IS_EPHEMERAL = False
                        return secret
                    except (VerificationSecretTamperedError, OSError):
                        if attempt == 9:
                            raise

        except Exception as e:
            # Check if explicit ephemeral mode is permitted
            if allow_ephemeral or os.environ.get("AGENT_ALLOW_EPHEMERAL_SECRET") == "1":
                ephemeral_secret = secrets.token_bytes(32)
                _CACHED_SECRETS[canonical_key] = ephemeral_secret
                _IS_EPHEMERAL_MAP[canonical_key] = True
                _CACHED_SECRET = ephemeral_secret
                _IS_EPHEMERAL = True
                return ephemeral_secret

            # Fail closed: never silently generate temporary key
            if isinstance(e, VerificationSecretError):
                raise
            raise VerificationSecretStorageError(
                f"Failed to securely access or create persistent verification key at '{key_file}': {str(e)}"
            ) from e

        # Fallback safety guard
        if allow_ephemeral or os.environ.get("AGENT_ALLOW_EPHEMERAL_SECRET") == "1":
            ephemeral_secret = secrets.token_bytes(32)
            _CACHED_SECRETS[canonical_key] = ephemeral_secret
            _IS_EPHEMERAL_MAP[canonical_key] = True
            _CACHED_SECRET = ephemeral_secret
            _IS_EPHEMERAL = True
            return ephemeral_secret

        raise VerificationSecretStorageError(f"Persistent verification key unavailable at '{key_file}'.")


def rotate_verification_secret(config_dir: Optional[str] = None) -> bytes:
    """
    Atomically rotates the persistent verification secret.
    Invalidates in-memory cached secrets for this configuration directory and writes a new 32-byte secret.
    All historical records signed with the retired key will no longer verify (enforcing revocation).

    Recovery Guarantee:
    If replacement or post-replacement permission lockdown fails, the rotation atomically rolls back
    to the prior secret on disk and raises VerificationSecretStorageError. If rollback is physically
    impossible, the key file is evicted so the system fails closed rather than accepting an
    insecurely locked-down key.
    """
    with _SECRET_LOCK:
        global _CACHED_SECRET, _IS_EPHEMERAL, _ACTIVE_CONFIG_DIR
        target_dir = config_dir if config_dir is not None else _ACTIVE_CONFIG_DIR
        canonical_key = _get_canonical_config_key(target_dir)
        key_file = get_secret_storage_path(target_dir)
        key_dir = os.path.dirname(key_file)
        os.makedirs(key_dir, mode=0o700, exist_ok=True)

        # Snapshot prior established secret for atomic rollback if post-replacement steps fail
        prior_secret: Optional[bytes] = None
        if os.path.exists(key_file) and not os.path.islink(key_file):
            try:
                with open(key_file, "rb") as f:
                    content = f.read()
                    if len(content) == 32:
                        prior_secret = content
            except Exception:
                prior_secret = None

        new_secret = secrets.token_bytes(32)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=key_dir, prefix=".vkey_rot_")
        replaced = False
        try:
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(new_secret)
                f.flush()
                os.fsync(f.fileno())
            _lock_down_key_file(tmp_path)
            os.replace(tmp_path, key_file)
            replaced = True
            _lock_down_key_file(key_file)
        except Exception as rot_err:
            if replaced:
                # Post-replacement failure (e.g. lockdown failed): rollback to prior_secret
                if prior_secret is not None:
                    try:
                        rb_fd, rb_tmp = tempfile.mkstemp(dir=key_dir, prefix=".vkey_rb_")
                        with os.fdopen(rb_fd, "wb") as f:
                            f.write(prior_secret)
                            f.flush()
                            os.fsync(f.fileno())
                        _lock_down_key_file(rb_tmp)
                        os.replace(rb_tmp, key_file)
                        _lock_down_key_file(key_file)
                    except Exception as rb_err:
                        # If rollback also fails, remove key_file and purge in-memory cache to fail closed
                        if os.path.exists(key_file):
                            try:
                                os.remove(key_file)
                            except Exception:
                                pass
                        _CACHED_SECRETS.pop(canonical_key, None)
                        _IS_EPHEMERAL_MAP.pop(canonical_key, None)
                        if _ACTIVE_CONFIG_DIR == target_dir:
                            _CACHED_SECRET = None
                            _IS_EPHEMERAL = False
                        raise VerificationSecretStorageError(
                            f"Catastrophic secret rotation failure at '{key_file}': replacement succeeded but "
                            f"lockdown failed ({rot_err}) and rollback failed ({rb_err}). Key evicted to fail closed."
                        ) from rot_err
                else:
                    if os.path.exists(key_file):
                        try:
                            os.remove(key_file)
                        except Exception:
                            pass
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            raise VerificationSecretStorageError(
                f"Failed to rotate verification secret at '{key_file}': {rot_err}"
            ) from rot_err
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

        _CACHED_SECRETS[canonical_key] = new_secret
        _IS_EPHEMERAL_MAP[canonical_key] = False
        _CACHED_SECRET = new_secret
        _IS_EPHEMERAL = False
        _ACTIVE_CONFIG_DIR = target_dir
        return new_secret


def set_verification_secret(
    secret: Optional[bytes],
    is_ephemeral: bool = False,
    config_dir: Optional[str] = None,
) -> None:
    """Sets or clears the cached in-memory verification secret (for testing or lifecycle isolation)."""
    with _SECRET_LOCK:
        global _CACHED_SECRET, _IS_EPHEMERAL, _ACTIVE_CONFIG_DIR
        target_dir = config_dir if config_dir is not None else _ACTIVE_CONFIG_DIR
        canonical_key = _get_canonical_config_key(target_dir)
        if secret is None:
            reset_verification_secret(config_dir)
        else:
            _CACHED_SECRETS[canonical_key] = secret
            _IS_EPHEMERAL_MAP[canonical_key] = is_ephemeral
            _CACHED_SECRET = secret
            _IS_EPHEMERAL = is_ephemeral
            if config_dir is not None:
                _ACTIVE_CONFIG_DIR = config_dir


def reset_verification_secret(config_dir: Optional[str] = None) -> None:
    """Resets the cached verification secret to force re-evaluation from environment or persistent file."""
    with _SECRET_LOCK:
        global _CACHED_SECRET, _IS_EPHEMERAL, _ACTIVE_CONFIG_DIR, _CURRENT_ENV_SECRET
        if config_dir is not None:
            canonical_key = _get_canonical_config_key(config_dir)
            _CACHED_SECRETS.pop(canonical_key, None)
            _IS_EPHEMERAL_MAP.pop(canonical_key, None)
            if _ACTIVE_CONFIG_DIR == config_dir:
                _ACTIVE_CONFIG_DIR = None
                _CACHED_SECRET = None
                _IS_EPHEMERAL = False
        else:
            _CACHED_SECRETS.clear()
            _IS_EPHEMERAL_MAP.clear()
            _ACTIVE_CONFIG_DIR = None
            _CACHED_SECRET = None
            _IS_EPHEMERAL = False
            _CURRENT_ENV_SECRET = None


class TrustedExecutionRecord(BaseModel):
    run_id: str
    runner: str
    command: str
    exit_code: int
    total: int
    passed: int
    failed: int
    skipped: int = 0
    ephemeral: bool = False
    passed_nodes: List[str]
    failed_nodes: List[str] = Field(default_factory=list)
    skipped_nodes: List[str] = Field(default_factory=list)
    timestamp: float = Field(default_factory=time.time)
    signature: str = ""


def _canonical_record_payload(
    run_id: str,
    runner: str,
    command: str,
    exit_code: int,
    total: int,
    passed: int,
    failed: int,
    skipped: int,
    ephemeral: bool,
    passed_nodes: List[str],
    failed_nodes: List[str],
    skipped_nodes: List[str],
    timestamp: float,
) -> bytes:
    """
    Produces deterministic canonical JSON serialization of all security-relevant fields.
    Uses alphabetically sorted keys, compact separators (',', ':'), standardized types,
    and sorted deduplicated node lists to eliminate delimiter collisions and formatting ambiguities.
    """
    canonical_dict = {
        "command": command.strip(),
        "ephemeral": bool(ephemeral),
        "exit_code": int(exit_code),
        "failed": int(failed),
        "failed_nodes": sorted(set(n.strip().lower() for n in (failed_nodes or []))),
        "passed": int(passed),
        "passed_nodes": sorted(set(n.strip().lower() for n in (passed_nodes or []))),
        "run_id": run_id.strip(),
        "runner": runner.strip().lower(),
        "skipped": int(skipped),
        "skipped_nodes": sorted(set(n.strip().lower() for n in (skipped_nodes or []))),
        "timestamp": round(float(timestamp), 3),
        "total": int(total),
    }
    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _compute_record_digest(
    run_id: str,
    runner: str,
    command: str,
    exit_code: int,
    total: int,
    passed: int,
    failed: int,
    skipped: int,
    ephemeral: bool,
    passed_nodes: List[str],
    failed_nodes: List[str],
    skipped_nodes: List[str],
    timestamp: float,
    secret: Optional[bytes] = None,
) -> str:
    payload = _canonical_record_payload(
        run_id=run_id,
        runner=runner,
        command=command,
        exit_code=exit_code,
        total=total,
        passed=passed,
        failed=failed,
        skipped=skipped,
        ephemeral=ephemeral,
        passed_nodes=passed_nodes,
        failed_nodes=failed_nodes,
        skipped_nodes=skipped_nodes,
        timestamp=timestamp,
    )
    key = secret or get_verification_secret()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def issue_trusted_execution_record(
    run_id: str,
    runner: str,
    command: str,
    exit_code: int,
    total: int,
    passed: int,
    failed: int,
    passed_nodes: List[str],
    failed_nodes: Optional[List[str]] = None,
    skipped: int = 0,
    skipped_nodes: Optional[List[str]] = None,
    ephemeral: Optional[bool] = None,
    secret: Optional[bytes] = None,
) -> TrustedExecutionRecord:
    """
    Issues an authentic, tamper-evident execution record from the verification subsystem.
    All security-relevant fields are canonically serialized via deterministic JSON and signed with HMAC-SHA256.
    Rejects zero-test reports, zero-pass reports, and count-inconsistent reports.
    """
    if total <= 0 or passed <= 0 or (passed + failed + skipped != total):
        raise ValueError(
            f"Invalid execution record counts: total={total}, passed={passed}, failed={failed}, skipped={skipped}. "
            "Zero-test, zero-pass, or count-inconsistent reports cannot receive trusted records."
        )

    ts = time.time()
    fn = failed_nodes or []
    sn = skipped_nodes or []
    is_eph = is_ephemeral_mode() if ephemeral is None else bool(ephemeral)

    sig = _compute_record_digest(
        run_id=run_id,
        runner=runner,
        command=command,
        exit_code=exit_code,
        total=total,
        passed=passed,
        failed=failed,
        skipped=skipped,
        ephemeral=is_eph,
        passed_nodes=passed_nodes,
        failed_nodes=fn,
        skipped_nodes=sn,
        timestamp=ts,
        secret=secret,
    )
    return TrustedExecutionRecord(
        run_id=run_id,
        runner=runner,
        command=command,
        exit_code=exit_code,
        total=total,
        passed=passed,
        failed=failed,
        skipped=skipped,
        ephemeral=is_eph,
        passed_nodes=passed_nodes,
        failed_nodes=fn,
        skipped_nodes=sn,
        timestamp=ts,
        signature=sig,
    )


def verify_trusted_execution_record(record: Any, secret: Optional[bytes] = None) -> bool:
    """
    Validates provenance, cryptographic integrity, and count consistency of a verification execution record.
    Returns True only if the record was authentic, issued by the runtime, and untampered.
    """
    if record is None:
        return False

    if isinstance(record, dict):
        try:
            record = TrustedExecutionRecord(**record)
        except Exception:
            return False
    elif not isinstance(record, TrustedExecutionRecord):
        return False

    if record.exit_code != 0:
        return False

    if record.total <= 0 or record.passed <= 0 or (record.passed + record.failed + record.skipped != record.total):
        return False

    if not record.signature:
        return False

    expected_sig = _compute_record_digest(
        run_id=record.run_id,
        runner=record.runner,
        command=record.command,
        exit_code=record.exit_code,
        total=record.total,
        passed=record.passed,
        failed=record.failed,
        skipped=record.skipped,
        ephemeral=getattr(record, "ephemeral", False),
        passed_nodes=record.passed_nodes,
        failed_nodes=record.failed_nodes,
        skipped_nodes=record.skipped_nodes,
        timestamp=record.timestamp,
        secret=secret,
    )

    return hmac.compare_digest(record.signature, expected_sig)
