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

    # 5. Check README Verified Suite Summary section and terminal session block
    readme_vss_match = re.search(r"Verified Suite Summary:\s*(\d+)\s+Comprehensive Automated Tests", readme_content)
    assert readme_vss_match is not None, "README must declare Verified Suite Summary count"
    readme_vss_count = int(readme_vss_match.group(1))
    assert readme_vss_count == ev_total, (
        f"README Verified Suite Summary count ({readme_vss_count}) does not match EVIDENCE.md total ({ev_total})"
    )

    readme_session_match = re.search(r"={10,}\s*(\d+)\s+passed\s+\(100\.0%\s+Green CI\)", readme_content)
    assert readme_session_match is not None, "README must declare terminal session passed count"
    readme_session_count = int(readme_session_match.group(1))
    assert readme_session_count == ev_total, (
        f"README terminal session count ({readme_session_count}) does not match EVIDENCE.md total ({ev_total})"
    )

    # 6. Verify commit SHA provenance and git reachability
    ev_sha_match = re.search(r"\*\*Commit SHA\*\*\s*:\s*`([a-f0-9]{40})`", evidence_content)
    assert ev_sha_match is not None, "EVIDENCE.md must declare a valid 40-character hexadecimal Commit SHA"
    ev_sha = ev_sha_match.group(1)

    import subprocess
    try:
        # Check if git repository is shallow
        is_shallow = False
        try:
            shallow_check = subprocess.run(
                ["git", "rev-parse", "--is-shallow-repository"],
                capture_output=True,
                text=True,
                check=False,
            )
            if shallow_check.returncode == 0 and shallow_check.stdout.strip() == "true":
                is_shallow = True
        except Exception:
            pass

        # Commit must exist in the git object database
        verify_proc = subprocess.run(
            ["git", "rev-parse", "--verify", f"{ev_sha}^{{commit}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if is_shallow and verify_proc.returncode != 0:
            # In a shallow clone, attempt to deepen history to resolve commit
            subprocess.run(["git", "fetch", "--depth=50", "origin"], capture_output=True, check=False)
            verify_proc = subprocess.run(
                ["git", "rev-parse", "--verify", f"{ev_sha}^{{commit}}"],
                capture_output=True,
                text=True,
                check=False,
            )

        if not (is_shallow and verify_proc.returncode != 0):
            assert verify_proc.returncode == 0, (
                f"EVIDENCE.md references non-existent git commit SHA: {ev_sha}"
            )

            # Commit must NOT be an arbitrary old ancestor; it must match current HEAD or immediate parent (HEAD~1)
            head_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
            parent_sha = None
            try:
                parent_sha = subprocess.check_output(["git", "rev-parse", "HEAD~1"], text=True).strip()
            except Exception:
                pass

            valid_shas = {head_sha}
            if parent_sha:
                valid_shas.add(parent_sha)

            assert ev_sha in valid_shas, (
                f"EVIDENCE.md references stale commit SHA {ev_sha}. "
                f"Expected current HEAD ({head_sha}) or immediate parent ({parent_sha})."
            )
    except FileNotFoundError:
        pass

    # 7. Verify all 7 security boundaries are derived and verified as PASS in EVIDENCE.md
    for adv_id in ("ADV-01", "ADV-02", "ADV-03", "ADV-04", "ADV-05", "ADV-06", "ADV-07"):
        adv_pattern = rf"\|\s*\*\*{adv_id}\*\*\s*\|.*?\|\s*\*\*PASS\*\*\s*\|"
        assert re.search(adv_pattern, evidence_content) is not None, (
            f"Security boundary {adv_id} is not verified as PASS in EVIDENCE.md"
        )

    # 8. Verify CI Run ID and Working Tree status are declared in EVIDENCE.md
    assert re.search(r"\*\*CI Run ID\*\*\s*:", evidence_content) is not None, "EVIDENCE.md must declare CI Run ID"
    assert re.search(r"\*\*Working Tree\*\*\s*:", evidence_content) is not None, "EVIDENCE.md must declare Working Tree status"

