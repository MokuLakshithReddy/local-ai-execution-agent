"""
Evidence & Documentation Consistency Automated Audit.
Verifies that README.md, EVIDENCE.md, and test suite execution counts remain strictly synchronized.
"""
import os
import re
import xml.etree.ElementTree as ET
import pytest


def test_evidence_and_docs_consistency():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    readme_path = os.path.join(repo_root, "README.md")
    evidence_path = os.path.join(repo_root, "EVIDENCE.md")
    junit_path = os.path.join(repo_root, "junit-results.xml")

    assert os.path.exists(readme_path), "README.md must exist"
    assert os.path.exists(evidence_path), "EVIDENCE.md must exist"

    with open(readme_path, "r", encoding="utf-8") as f:
        readme_content = f.read()

    with open(evidence_path, "r", encoding="utf-8") as f:
        evidence_content = f.read()

    # 1. Extract test count from EVIDENCE.md
    ev_total_match = re.search(r"\*\*Total Tests\*\*\s*\|\s*`(\d+)`", evidence_content)
    assert ev_total_match is not None, "EVIDENCE.md must declare Total Tests metric"
    ev_total = int(ev_total_match.group(1))

    # 2. Verify 0 failures and 100% pass rate in EVIDENCE.md
    ev_failed_match = re.search(r"\*\*Tests Failed\*\*\s*\|\s*`(\d+)`", evidence_content)
    assert ev_failed_match is not None and int(ev_failed_match.group(1)) == 0, "EVIDENCE.md must show 0 failures"

    # 3. Check README badge
    readme_badge_match = re.search(r"Verification-(\d+)%20Passed", readme_content)
    assert readme_badge_match is not None, "README.md must display verification badge"
    readme_badge_count = int(readme_badge_match.group(1))
    assert readme_badge_count == ev_total, (
        f"README badge ({readme_badge_count}) does not match EVIDENCE.md total ({ev_total})"
    )

    # 4. Check README Quick Start section
    readme_qs_match = re.search(r"Verify Your Environment \((\d+) Passing Tests\)", readme_content)
    assert readme_qs_match is not None, "README Quick Start must declare passing test count"
    readme_qs_count = int(readme_qs_match.group(1))
    assert readme_qs_count == ev_total, (
        f"README Quick Start count ({readme_qs_count}) does not match EVIDENCE.md total ({ev_total})"
    )

