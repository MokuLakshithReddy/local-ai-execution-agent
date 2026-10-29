"""
Pytest integration for the Adversarial Execution Benchmark.
Ensures that all 7 security boundary attack scenarios execute and pass deterministically.
"""
import pytest
from agent.security.adversarial_benchmark import AdversarialBenchmarkRunner


@pytest.mark.asyncio
async def test_adversarial_scenario_1_path_traversal():
    runner = AdversarialBenchmarkRunner()
    result = await runner.run_scenario_1_path_traversal()
    assert result.passed is True, f"Path traversal boundary failed: {result.observed_outcome}"


@pytest.mark.asyncio
async def test_adversarial_scenario_2_secret_redaction():
    runner = AdversarialBenchmarkRunner()
    result = await runner.run_scenario_2_fake_secret_redaction()
    assert result.passed is True, f"Secret redaction boundary failed: {result.observed_outcome}"


@pytest.mark.asyncio
async def test_adversarial_scenario_3_destructive_commands():
    runner = AdversarialBenchmarkRunner()
    result = await runner.run_scenario_3_destructive_commands()
    assert result.passed is True, f"Destructive command boundary failed: {result.observed_outcome}"


@pytest.mark.asyncio
async def test_adversarial_scenario_4_prompt_injection():
    runner = AdversarialBenchmarkRunner()
    result = await runner.run_scenario_4_hostile_repo_instructions()
    assert result.passed is True, f"Prompt injection boundary failed: {result.observed_outcome}"


@pytest.mark.asyncio
async def test_adversarial_scenario_5_env_leakage():
    runner = AdversarialBenchmarkRunner()
    result = await runner.run_scenario_5_env_leakage()
    assert result.passed is True, f"Environment leakage boundary failed: {result.observed_outcome}"


@pytest.mark.asyncio
async def test_adversarial_scenario_6_network_isolation():
    runner = AdversarialBenchmarkRunner()
    result = await runner.run_scenario_6_network_isolation()
    assert result.passed is True, f"Network isolation boundary failed: {result.observed_outcome}"


@pytest.mark.asyncio
async def test_adversarial_scenario_7_subprocess_timeout():
    runner = AdversarialBenchmarkRunner()
    result = await runner.run_scenario_7_timeout_and_process_cleanup()
    assert result.passed is True, f"Timeout and cleanup boundary failed: {result.observed_outcome}"


@pytest.mark.asyncio
async def test_adversarial_benchmark_runner_full_suite():
    runner = AdversarialBenchmarkRunner()
    results = await runner.run_all()
    assert len(results) == 7
    assert all(r.passed for r in results), "One or more adversarial scenarios failed in full run."
    markdown_report = runner.generate_markdown_report()
    assert "# Adversarial Execution Benchmark Report" in markdown_report
    assert "**Pass Rate**: 100.0%" in markdown_report
