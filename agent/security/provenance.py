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
    passed_nodes: List[str],
    timestamp: float,
) -> str:
    sorted_nodes = ",".join(sorted(n.strip().lower() for n in passed_nodes))
    payload = f"{run_id}:{runner}:{command.strip()}:{exit_code}:{sorted_nodes}:{timestamp:.3f}"
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
    """
    ts = time.time()
    sig = _compute_record_digest(
        run_id=run_id,
        runner=runner,
        command=command,
        exit_code=exit_code,
        passed_nodes=passed_nodes,
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
        failed_nodes=failed_nodes or [],
        timestamp=ts,
        signature=sig,
    )


def verify_trusted_execution_record(record: Any) -> bool:
    """
    Validates provenance and integrity of a verification execution record.
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

    if not record.signature:
        return False

    expected_sig = _compute_record_digest(
        run_id=record.run_id,
        runner=record.runner,
        command=record.command,
        exit_code=record.exit_code,
        passed_nodes=record.passed_nodes,
        timestamp=record.timestamp,
    )

    return hmac.compare_digest(record.signature, expected_sig)
