# Security Check Test Suite

Regression tests for the CI security scanner's check functions. Run these before deploying any changes to Agent 2 (Security).

## Quick start

```bash
# From the project root (where agent-security-scanner-v3.py lives):
unzip tests.zip

# Run all tests:
python3 tests/test_security_checks.py
```

Expected output:
```
Running 16 tests...

  PASS   prt CRITICAL: broad perms + auto trigger + PR head checkout
  PASS   prt MEDIUM: maintainer-gated (labeled) + broad perms
  ...
  PASS   REAL: Texera email notif — injection LOW (pull_request trigger, not prt)

============================================================
Results: 19 passed, 0 failed, 0 errors
============================================================
```

## What's tested

### prt_checkout — severity matrix (6 tests)

The `pull_request_target` + checkout check uses a 2×2 severity matrix based on **permissions** and **trigger type**:

|                        | Broad permissions | Limited permissions |
|------------------------|-------------------|---------------------|
| **Auto-trigger**       | CRITICAL          | MEDIUM              |
| **Maintainer-gated**   | MEDIUM            | LOW                 |

Additional cases: INFO for default ref (safe), None when no prt trigger.

### self_hosted_runner — severity matrix (5 tests)

Same 2×2 pattern as prt_checkout but with HIGH ceiling (runner compromise is serious but doesn't directly grant base repo secrets like prt_checkout):

|                        | Broad permissions | Limited permissions |
|------------------------|-------------------|---------------------|
| **Auto-trigger**       | HIGH              | MEDIUM              |
| **Maintainer-gated**   | MEDIUM            | LOW                 |

Additional case: INFO for push-only (no PR trigger).

### run_block_injection — trigger-aware (3 tests)

Interpolation of untrusted values (`event.pull_request.title`, etc.) in `run:` blocks. Severity depends on whether the trigger is `pull_request` (fork PRs don't get secrets → LOW) or `pull_request_target` (fork PRs DO get secrets → CRITICAL). Secrets interpolation is always LOW.

### Other checks (2 tests)

- `cache_poisoning`: INFO when actions/cache + PR trigger
- `permissions`: HIGH for write-all

### Real-world regressions (3 tests)

Actual workflow files from the Apache scan, manually verified:

| Fixture | Repo | Expected | Why |
|---------|------|----------|-----|
| `beam-users-permissions.yml` | apache/beam | MEDIUM | prt + PR head checkout, but only `pull-requests: write` — no publishing secrets |
| `opendal-full-ci-promote.yml` | apache/opendal | MEDIUM | prt + PR head checkout, but trigger restricted to `labeled` — maintainer must act |
| `texera-email-notif.yml` | apache/texera | LOW | `pull_request` (not prt) — fork PRs don't get secrets |

## Structure

```
tests/
├── README.md                          ← you are here
├── security_checks.py                 ← extracted check functions (keep in sync with Agent 2)
├── test_security_checks.py            ← test runner
└── fixtures/
    ├── synthetic/                     ← minimal YAML snippets isolating each pattern
    │   ├── prt-critical-broad-perms.yml
    │   ├── prt-medium-labeled.yml
    │   ├── prt-medium-limited-perms.yml
    │   ├── prt-low-both-mitigations.yml
    │   ├── prt-info-default-ref.yml
    │   ├── no-prt-none.yml
    │   ├── injection-critical-prt-trigger.yml
    │   ├── injection-low-pr-trigger.yml
    │   ├── injection-low-secret.yml
    │   ├── self-hosted-high-pr.yml
    │   ├── self-hosted-medium-limited-perms.yml
    │   ├── self-hosted-medium-labeled.yml
    │   ├── self-hosted-low-both-mitigations.yml
    │   ├── self-hosted-info-push.yml
    │   ├── cache-poisoning-info.yml
    │   └── broad-perms-high.yml
    └── real-world/                    ← actual workflows, manually reviewed
        ├── beam-users-permissions.yml
        ├── opendal-full-ci-promote.yml
        └── texera-email-notif.yml
```

## Adding tests

### When you change a check in Agent 2

1. Update `security_checks.py` to match the new logic
2. Run `python3 tests/test_security_checks.py`
3. If a test fails, either fix the logic or update the expected severity
4. Deploy only when all tests pass

### When the security team reports a false positive

1. Copy the actual workflow YAML to `fixtures/real-world/`
2. Add a test case to `TESTS` in `test_security_checks.py` with the correct expected severity
3. Run the tests — the new test should fail (confirming the false positive)
4. Fix the check logic in both `security_checks.py` and Agent 2
5. Run tests — all should pass, including the new regression test

### When you add a new check to Agent 2

1. Add the check function to `security_checks.py`
2. Add a handler in `run_check()` in the test runner
3. Create synthetic fixtures covering the severity levels
4. Add test cases to `TESTS`
