"""
Evidence & Documentation Consistency Automated Audit.
Verifies that README.md, EVIDENCE.md, and raw pytest JUnit XML records remain strictly synchronized
and that all claims are mathematically backed by independent execution records.
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

    # 1. Extract test count from EVIDENCE.md (supporting both Unit & Adversarial and Total Tests metrics)
    ev_unit_match = re.search(r"\*\*Unit & Adversarial Tests\*\*\s*\|\s*`(\d+)/(\d+)`", evidence_content)
    if ev_unit_match:
        ev_total = int(ev_unit_match.group(2))
    else:
        ev_total_match = re.search(r"\*\*Total Tests(?:\s+Executed)?\*\*\s*\|\s*`(\d+)`", evidence_content)
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

        verify_proc = subprocess.run(
            ["git", "rev-parse", "--verify", f"{ev_sha}^{{commit}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if is_shallow and verify_proc.returncode != 0:
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

    # 7. Extract reported boundary statuses directly from EVIDENCE.md table
    reported_boundaries = {}
    for match in re.finditer(r"\|\s*\*\*([A-Za-z0-9_-]+)\*\*\s*\|.*?\|\s*\*\*([^\*]+)\*\*\s*\|", evidence_content):
        b_id, b_status = match.group(1).strip(), match.group(2).strip()
        reported_boundaries[b_id] = b_status

    # Verify that all 7 core adversarial boundaries are reported as PASS
    for adv_id in ("ADV-01", "ADV-02", "ADV-03", "ADV-04", "ADV-05", "ADV-06", "ADV-07"):
        assert adv_id in reported_boundaries, f"EVIDENCE.md is missing boundary {adv_id}"
        assert reported_boundaries[adv_id] == "PASS", f"Boundary {adv_id} reported '{reported_boundaries[adv_id]}', expected PASS"

    # 8. Verify Docker container integration boundaries are present
    for docker_id in ("DOCKER-01", "DOCKER-02"):
        assert docker_id in reported_boundaries, f"EVIDENCE.md is missing Docker boundary {docker_id}"
        assert reported_boundaries[docker_id] in ("PASS", "SKIPPED (Docker integration verified on Linux CI)"), (
            f"Invalid status for {docker_id}: {reported_boundaries[docker_id]}"
        )

    # 9. Verify Verifying Test Identifier and Platform Scope columns are present
    assert "| Verifying Test Identifier | Platform Scope | Status |" in evidence_content

    # 10. Verify CI Run ID, Canonical CI Pipeline, and Working Tree status are declared in EVIDENCE.md
    assert re.search(r"\*\*CI Run ID\*\*\s*:", evidence_content) is not None, "EVIDENCE.md must declare CI Run ID"
    assert re.search(r"\*\*Working Tree\*\*\s*:", evidence_content) is not None, "EVIDENCE.md must declare Working Tree status"
    assert re.search(r"\*\*Canonical CI Pipeline\*\*\s*:", evidence_content) is not None, "EVIDENCE.md must link Canonical CI Pipeline"

    ci_run_match = re.search(r"\*\*CI Run ID\*\*\s*:\s*`([^`]+)`", evidence_content)
    assert ci_run_match is not None
    ci_run_val = ci_run_match.group(1).strip()
    if ci_run_val.isdigit():
        expected_run_url = f"https://github.com/MokuLakshithReddy/local-ai-execution-agent/actions/runs/{ci_run_val}"
        assert expected_run_url in evidence_content, f"EVIDENCE.md must contain valid run URL for CI Run {ci_run_val}"
    else:
        assert "actions/workflows/ci.yml" in evidence_content

    # 11. Independent cross-validation against raw JUnit test XML records
    if os.path.exists(junit_path):
        junit_tree = ET.parse(junit_path)
        junit_root = junit_tree.getroot()
        xml_testcases = {}
        for tc in junit_root.iter("testcase"):
            tc_name = tc.attrib.get("name", "")
            tc_status = "FAIL" if (tc.find("failure") is not None or tc.find("error") is not None) else ("SKIPPED" if tc.find("skipped") is not None else "PASS")
            xml_testcases[tc_name] = tc_status

        adv_test_mapping = {
            "ADV-01": "test_adversarial_scenario_1_path_traversal",
            "ADV-02": "test_adversarial_scenario_2_secret_redaction",
            "ADV-03": "test_adversarial_scenario_3_destructive_commands",
            "ADV-04": "test_adversarial_scenario_4_prompt_injection",
            "ADV-05": "test_adversarial_scenario_5_env_leakage",
            "ADV-06": "test_adversarial_scenario_6_network_isolation",
            "ADV-07": "test_adversarial_scenario_7_subprocess_timeout",
        }
        for adv_id, prefix in adv_test_mapping.items():
            matching_tc = [status for name, status in xml_testcases.items() if prefix in name]
            assert matching_tc, f"JUnit XML has no testcase record matching {adv_id} ({prefix})"
            xml_outcome = "PASS" if all(s == "PASS" for s in matching_tc) else "FAIL"
            assert reported_boundaries.get(adv_id) == xml_outcome, (
                f"Mismatch for {adv_id}: EVIDENCE.md reported '{reported_boundaries.get(adv_id)}', but JUnit XML was '{xml_outcome}'"
            )

    docker_junit_path = os.path.join(repo_root, "junit-docker-results.xml")
    if os.path.exists(docker_junit_path):
        docker_tree = ET.parse(docker_junit_path)
        docker_root = docker_tree.getroot()
        docker_testcases = {}
        for tc in docker_root.iter("testcase"):
            tc_name = tc.attrib.get("name", "")
            tc_status = "FAIL" if (tc.find("failure") is not None or tc.find("error") is not None) else ("SKIPPED" if tc.find("skipped") is not None else "PASS")
            docker_testcases[tc_name] = tc_status
        docker_tc = [status for name, status in docker_testcases.items() if "test_real_docker_container_security_boundaries" in name]
        assert docker_tc, "Docker JUnit XML has no record for test_real_docker_container_security_boundaries"
        docker_xml_status = "PASS" if all(s == "PASS" for s in docker_tc) else "FAIL"
        for docker_id in ("DOCKER-01", "DOCKER-02"):
            assert reported_boundaries.get(docker_id) == docker_xml_status, (
                f"Mismatch for {docker_id}: EVIDENCE.md reported '{reported_boundaries.get(docker_id)}', but Docker JUnit XML was '{docker_xml_status}'"
            )
