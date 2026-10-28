"""
Provenance and cryptographic trust boundary for verification execution records.
Guarantees that test execution records cannot be forged, fabricated, or tampered with.
Uses canonical JSON serialization (RFC 8785 semantics) and HMAC-SHA256 signatures.
Provides an OS-backed persistent secret lifecycle with environment override and fallback.
"""
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

_CACHED_SECRET: Optional[bytes] = None


def get_secret_storage_path(config_dir: Optional[str] = None) -> str:
    """Returns the absolute file path for the persistent verification key."""
    base_dir = config_dir or os.path.expanduser("~/.config/ai_execution_agent")
    return os.path.join(base_dir, "verification.key")


def get_verification_secret(config_dir: Optional[str] = None) -> bytes:
    """
    Retrieves or initializes the 256-bit cryptographic verification secret.

    Secret Lifecycle & Trust Model:
    1. Environment Variable: If 'AGENT_VERIFICATION_SECRET' is defined, its value is derived
       (SHA-256 digested if raw string, or parsed if 64-char hex) and used.
    2. Persistent Storage: Otherwise, loads or generates a 32-byte secret persisted at
       '~/.config/ai_execution_agent/verification.key'.
       - On POSIX, directory is secured to 0o700, and file is secured to 0o600.
       - Symlinks are rejected to prevent symlink hijack attacks.
       - Atomic rename avoids partial write races during concurrent initialization.
    3. Ephemeral Fallback: If disk persistence is blocked, gracefully falls back to an
       ephemeral process-isolated 32-byte token.
    """
    global _CACHED_SECRET
    if _CACHED_SECRET is not None:
        return _CACHED_SECRET

    # 1. Check environment variable override
    env_secret = os.environ.get("AGENT_VERIFICATION_SECRET")
    if env_secret:
        if len(env_secret) == 64:
            try:
                _CACHED_SECRET = bytes.fromhex(env_secret)
                return _CACHED_SECRET
            except ValueError:
                pass
        _CACHED_SECRET = hashlib.sha256(env_secret.encode("utf-8")).digest()
        return _CACHED_SECRET

    # 2. Check persistent key file
    key_file = get_secret_storage_path(config_dir)
    key_dir = os.path.dirname(key_file)

    try:
        if os.path.islink(key_dir):
            raise RuntimeError(f"Symlink detected at key directory: {key_dir}")
        if os.path.islink(key_file):
            raise RuntimeError(f"Symlink detected at key file: {key_file}")

        if os.path.exists(key_file):
            # Check permissions on POSIX
            if sys.platform != "win32":
                file_stat = os.stat(key_file)
                mode = stat.S_IMODE(file_stat.st_mode)
                if mode & 0o077 != 0:
                    # Insecure permissions detected; enforce 0o600
                    os.chmod(key_file, 0o600)
            with open(key_file, "rb") as f:
                content = f.read()
                if len(content) == 32:
                    _CACHED_SECRET = content
                    return _CACHED_SECRET

        # Generate new 32-byte secret and persist atomically
        os.makedirs(key_dir, mode=0o700, exist_ok=True)
        new_secret = secrets.token_bytes(32)

        # Write to temp file first with restrictive mode
        tmp_fd, tmp_path = tempfile.mkstemp(dir=key_dir, prefix=".vkey_")
        try:
            if sys.platform != "win32":
                os.chmod(tmp_path, 0o600)
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(new_secret)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, key_file)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

        _CACHED_SECRET = new_secret
        return _CACHED_SECRET
    except Exception:
        # Fallback to ephemeral process-local secret
        _CACHED_SECRET = secrets.token_bytes(32)
        return _CACHED_SECRET


def set_verification_secret(secret: Optional[bytes]) -> None:
    """Sets or clears the cached in-memory verification secret (for testing or lifecycle isolation)."""
    global _CACHED_SECRET
    _CACHED_SECRET = secret


def reset_verification_secret() -> None:
    """Resets the cached verification secret to force re-evaluation from environment or persistent file."""
    global _CACHED_SECRET
    _CACHED_SECRET = None


class TrustedExecutionRecord(BaseModel):
    run_id: str
    runner: str
    command: str
    exit_code: int
    total: int
    passed: int
    failed: int
    skipped: int = 0
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
    passed_nodes: List[str],
    failed_nodes: List[str],
    skipped_nodes: List[str],
    timestamp: float,
) -> bytes:
    """
    Produces deterministic, canonical JSON serialization of all security-relevant fields.
    Complies with RFC 8785 semantics: keys alphabetically sorted, compact separators, normalized types.
    Eliminates delimiter collisions and formatting ambiguities.
    """
    canonical_dict = {
        "command": command.strip(),
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
    sig = _compute_record_digest(
        run_id=run_id,
        runner=runner,
        command=command,
        exit_code=exit_code,
        total=total,
        passed=passed,
        failed=failed,
        skipped=skipped,
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
        passed_nodes=record.passed_nodes,
        failed_nodes=record.failed_nodes,
        skipped_nodes=record.skipped_nodes,
        timestamp=record.timestamp,
        secret=secret,
    )

    return hmac.compare_digest(record.signature, expected_sig)
