"""
Provenance and cryptographic trust boundary for verification execution records.
Guarantees that test execution records cannot be forged, fabricated, or tampered with.
"""
import hashlib
import hmac
import secrets
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

# Runtime-isolated secret key for signing legitimate verification outcomes
_VERIFICATION_SECRET: bytes = secrets.token_bytes(32)


class TrustedExecutionRecord(BaseModel):
    run_id: str
    runner: str
    command: str
    exit_code: int
    total: int
    passed: int
    failed: int
    passed_nodes: List[str]
    failed_nodes: List[str] = Field(default_factory=list)
    timestamp: float = Field(default_factory=time.time)
    signature: str = ""


def _compute_record_digest(
    run_id: str,
    runner: str,
    command: str,
    exit_code: int,
    total: int,
    passed: int,
    failed: int,
    passed_nodes: List[str],
    failed_nodes: List[str],
    timestamp: float,
) -> str:
    sorted_passed = ",".join(sorted(n.strip().lower() for n in passed_nodes))
    sorted_failed = ",".join(sorted(n.strip().lower() for n in (failed_nodes or [])))
    payload = (
        f"{run_id}:{runner}:{command.strip()}:{exit_code}:"
        f"{total}:{passed}:{failed}:"
        f"{sorted_passed}:{sorted_failed}:{timestamp:.3f}"
    )
    return hmac.new(_VERIFICATION_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()


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
) -> TrustedExecutionRecord:
    """
    Issues an authentic, tamper-evident execution record from the verification subsystem.
    All security-relevant fields (run_id, command, exit_code, counts, nodes, timestamp) are signed.
    Rejects zero-test reports and inconsistent counts.
    """
    if total <= 0 or passed <= 0 or (passed + failed != total):
        raise ValueError(
            f"Invalid execution record counts: total={total}, passed={passed}, failed={failed}. "
            "Zero-test or inconsistent reports cannot receive trusted records."
        )

    ts = time.time()
    fn = failed_nodes or []
    sig = _compute_record_digest(
        run_id=run_id,
        runner=runner,
        command=command,
        exit_code=exit_code,
        total=total,
        passed=passed,
        failed=failed,
        passed_nodes=passed_nodes,
        failed_nodes=fn,
        timestamp=ts,
    )
    return TrustedExecutionRecord(
        run_id=run_id,
        runner=runner,
        command=command,
        exit_code=exit_code,
        total=total,
        passed=passed,
        failed=failed,
        passed_nodes=passed_nodes,
        failed_nodes=fn,
        timestamp=ts,
        signature=sig,
    )


def verify_trusted_execution_record(record: Any) -> bool:
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

    if record.total <= 0 or record.passed <= 0 or (record.passed + record.failed != record.total):
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
        passed_nodes=record.passed_nodes,
        failed_nodes=record.failed_nodes,
        timestamp=record.timestamp,
    )

    return hmac.compare_digest(record.signature, expected_sig)

