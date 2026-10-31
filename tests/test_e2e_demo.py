"""
Automated Pytest for End-to-End Demonstration.
Ensures that the 3 end-to-end scenarios execute reliably and produce demonstration evidence.
"""
import os
import pytest
from scripts.demonstrate_e2e import EndToEndDemonstrator


@pytest.mark.asyncio
async def test_end_to_end_demonstrator_full_flow(tmp_path):
    demo = EndToEndDemonstrator()
    temp_report = str(tmp_path / "DEMO_TEST.md")
    report_md = await demo.run(report_path=temp_report)
    assert os.path.exists(temp_report)
    assert "# End-to-End Execution Demonstration Report" in report_md
    assert "Scenario 1: Successful Code Fix & Cryptographic Verification" in report_md
    assert "Scenario 2: Failed Verification / Rejection of False Claims" in report_md
    assert "Scenario 3: Human Approval Lifecycle on Sensitive Actions" in report_md
    assert "HMAC-SHA256" in report_md
    assert "Git Diff Output" in report_md
