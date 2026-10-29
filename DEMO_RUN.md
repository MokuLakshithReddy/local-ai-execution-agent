# End-to-End Execution Demonstration Report

> **Summary**: Real-world demonstration of the Local AI Execution Agent performing code inspection, repair, automated pytest verification, cryptographic HMAC signing, false-claim rejection, and human-in-the-loop approval lifecycle in a disposable git repository.

## Scenario 1: Successful Code Fix & Cryptographic Verification

- **Task Goal**: Fix discount calculation bug in `pricing.py` and verify all unit tests pass.
- **Defect Identified**: `pricing.py` line 6 added the discount instead of subtracting it (`subtotal + discount`).
- **Action Executed**: `WriteFileTool` applied bugfix using `subtotal - discount` formula.
- **Verification Executed**: Real `pytest -v tests/test_pricing.py` executed within controlled workspace.
- **Verification Evidence**:
  - **Total Tests**: 3
  - **Passed Tests**: 3 (`test_standard_discount, test_zero_discount, tests/test_pricing.py::test_zero_discount, test_half_discount, tests/test_pricing.py::test_half_discount, tests/test_pricing.py, test_pricing, test_pricing.py, tests/test_pricing.py::test_standard_discount`)
  - **Exit Code**: 0
  - **HMAC-SHA256 Signature**: `11e6d7a6536e39f3078331611bac91e302f4240ab4d310549008213385dbf133`
  - **Verification Status**: `TaskStatus.COMPLETED` (Acceptance Criteria Satisfied: `True`)

### Git Diff Output
```diff
diff --git a/pricing.py b/pricing.py
index 067b2f7..e4a86bd 100644
--- a/pricing.py
+++ b/pricing.py
@@ -2,5 +2,5 @@
 
 def calculate_discounted_total(subtotal: float, discount_percent: float) -> float:
     """Calculates discounted total given subtotal and percentage discount."""
-    # BUG: adds discount instead of subtracting it
-    return round(subtotal + (subtotal * (discount_percent / 100.0)), 2)
+    # FIXED: subtracts discount properly
+    return round(subtotal - (subtotal * (discount_percent / 100.0)), 2)
```

---

## Scenario 2: Failed Verification / Rejection of False Claims

- **Task Goal**: Verify that verbal completion claims are rejected when code remains broken or tests fail.
- **Condition Tested**: `pricing.py` modified to return broken stub `return 0.0`.
- **Model Claim**: `"The bug is fixed and tests are all passing!"` (Verbal assertion without execution evidence).
- **Observed Outcome**: Verification check exited non-zero (`Exit code: 1`).
- **Verifier Decision**: Rejected verbal claim. Task Status = `TaskStatus.PARTIALLY_COMPLETED` (Acceptance Satisfied: `False`).

---

## Scenario 3: Human Approval Lifecycle on Sensitive Actions

- **Policy**: `PermissionPolicy.PROMPT_ON_SENSITIVE`
- **Rejection Path**:
  - Action: `run_command(command="git clean -fdx")`
  - Approval ID: `142b9b26-e909-4a28-b818-f220bbf55975`
  - Resolution: `REJECTED` by `User:SecurityReviewer`
  - Security Outcome: Action terminated before command execution; zero filesystem changes.
- **Approval Path**:
  - Action: `run_command(command="git status --short")`
  - Approval ID: `cd0f1bf7-7037-41f1-ba74-e63033979069`
  - Resolution: `APPROVED` by `User:Developer`
  - Security Outcome: Verified approval permitted execution in sandbox; output captured safely.

---

## Reproduction Instructions

To reproduce this entire end-to-end demonstration locally:
```bash
# Run the end-to-end demonstration script
python scripts/demonstrate_e2e.py

# Or execute the automated pytest verification test
pytest tests/test_e2e_demo.py -v
```
