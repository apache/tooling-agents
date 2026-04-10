#!/usr/bin/env python3
"""
Test suite for security check functions.
Run from the project root: python3 tests/test_security_checks.py

Each test case loads a YAML fixture and asserts the expected check name
and severity. Tests cover both synthetic patterns and real-world
workflows that have been manually reviewed.
"""
import os
import sys

# Add tests/ to path so we can import security_checks
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security_checks import (
    check_prt_checkout,
    check_self_hosted,
    check_permissions,
    check_cache_poisoning,
    find_injection_in_run_blocks,
    extract_triggers,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(subdir, name):
    path = os.path.join(FIXTURES_DIR, subdir, name)
    with open(path) as f:
        return f.read()


# Each test: (description, fixture_subdir, fixture_file, check_function, expected)
# expected is (severity, check_name) or None
# For checks returning a list, expected is [(severity, check_name), ...]
TESTS = [
    # ===== prt_checkout: severity matrix =====
    {
        "name": "prt CRITICAL: broad perms + auto trigger + PR head checkout",
        "fixture": ("synthetic", "prt-critical-broad-perms.yml"),
        "check": "prt_checkout",
        "expected_severity": "CRITICAL",
    },
    {
        "name": "prt MEDIUM: maintainer-gated (labeled) + broad perms",
        "fixture": ("synthetic", "prt-medium-labeled.yml"),
        "check": "prt_checkout",
        "expected_severity": "MEDIUM",
    },
    {
        "name": "prt MEDIUM: limited perms (pull-requests:write) + auto trigger",
        "fixture": ("synthetic", "prt-medium-limited-perms.yml"),
        "check": "prt_checkout",
        "expected_severity": "MEDIUM",
    },
    {
        "name": "prt LOW: both mitigating factors (labeled + limited perms)",
        "fixture": ("synthetic", "prt-low-both-mitigations.yml"),
        "check": "prt_checkout",
        "expected_severity": "LOW",
    },
    {
        "name": "prt INFO: default ref (no ref: parameter)",
        "fixture": ("synthetic", "prt-info-default-ref.yml"),
        "check": "prt_checkout",
        "expected_severity": "INFO",
    },
    {
        "name": "prt None: no pull_request_target trigger",
        "fixture": ("synthetic", "no-prt-none.yml"),
        "check": "prt_checkout",
        "expected_severity": None,
    },

    # ===== run_block_injection: trigger-aware =====
    {
        "name": "injection CRITICAL: prt trigger + PR title interpolation",
        "fixture": ("synthetic", "injection-critical-prt-trigger.yml"),
        "check": "run_block_injection",
        "expected_severity": "CRITICAL",
    },
    {
        "name": "injection LOW: pull_request trigger + PR title interpolation",
        "fixture": ("synthetic", "injection-low-pr-trigger.yml"),
        "check": "run_block_injection",
        "expected_severity": "LOW",
    },
    {
        "name": "injection LOW: secret interpolated in run block",
        "fixture": ("synthetic", "injection-low-secret.yml"),
        "check": "run_block_injection",
        "expected_severity": "LOW",
    },

    # ===== self_hosted =====
    {
        "name": "self-hosted HIGH: PR trigger",
        "fixture": ("synthetic", "self-hosted-high-pr.yml"),
        "check": "self_hosted",
        "expected_severity": "HIGH",
    },
    {
        "name": "self-hosted INFO: push-only trigger",
        "fixture": ("synthetic", "self-hosted-info-push.yml"),
        "check": "self_hosted",
        "expected_severity": "INFO",
    },

    # ===== cache_poisoning =====
    {
        "name": "cache poisoning INFO: actions/cache + PR trigger",
        "fixture": ("synthetic", "cache-poisoning-info.yml"),
        "check": "cache_poisoning",
        "expected_severity": "INFO",
    },

    # ===== broad_permissions =====
    {
        "name": "broad permissions HIGH: write-all",
        "fixture": ("synthetic", "broad-perms-high.yml"),
        "check": "permissions",
        "expected_severity": "HIGH",
    },

    # ===== Real-world regressions =====
    {
        "name": "REAL: Beam UsersPermissions — prt MEDIUM (limited perms: pull-requests only)",
        "fixture": ("real-world", "beam-users-permissions.yml"),
        "check": "prt_checkout",
        "expected_severity": "MEDIUM",
    },
    {
        "name": "REAL: OpenDAL full-ci-promote — prt MEDIUM (maintainer-gated: labeled)",
        "fixture": ("real-world", "opendal-full-ci-promote.yml"),
        "check": "prt_checkout",
        "expected_severity": "MEDIUM",
    },
    {
        "name": "REAL: Texera email notif — injection LOW (pull_request trigger, not prt)",
        "fixture": ("real-world", "texera-email-notif.yml"),
        "check": "run_block_injection",
        "expected_severity": "LOW",
    },
]


def run_check(check_name, content):
    """Run a named check and return (severity, detail) or None."""
    triggers = extract_triggers(content)

    if check_name == "prt_checkout":
        return check_prt_checkout(content)

    elif check_name == "self_hosted":
        return check_self_hosted(content, triggers)

    elif check_name == "cache_poisoning":
        return check_cache_poisoning(content, triggers)

    elif check_name == "permissions":
        results = check_permissions(content)
        if results:
            # Return worst severity
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            results.sort(key=lambda x: sev_order.get(x[0], 5))
            return results[0]
        return None

    elif check_name == "run_block_injection":
        results = find_injection_in_run_blocks(
            content, context_label="test", triggers=triggers)
        if results:
            # Return worst severity
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            results.sort(key=lambda x: sev_order.get(x[0], 5))
            return results[0]
        return None

    else:
        raise ValueError(f"Unknown check: {check_name}")


def main():
    passed = 0
    failed = 0
    errors = 0

    print(f"Running {len(TESTS)} tests...\n")

    for test in TESTS:
        name = test["name"]
        subdir, fixture_file = test["fixture"]
        check_name = test["check"]
        expected = test["expected_severity"]

        try:
            content = load_fixture(subdir, fixture_file)
        except FileNotFoundError:
            print(f"  ERROR  {name}")
            print(f"         Fixture not found: {subdir}/{fixture_file}")
            errors += 1
            continue

        try:
            result = run_check(check_name, content)
        except Exception as e:
            print(f"  ERROR  {name}")
            print(f"         Exception: {e}")
            errors += 1
            continue

        actual = result[0] if result else None

        if actual == expected:
            print(f"  PASS   {name}")
            passed += 1
        else:
            print(f"  FAIL   {name}")
            print(f"         Expected: {expected}")
            print(f"         Got:      {actual}")
            if result:
                # Truncate detail for readability
                detail = result[1][:120] + "..." if len(result[1]) > 120 else result[1]
                print(f"         Detail:   {detail}")
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"Results: {passed} passed, {failed} failed, {errors} errors")
    print(f"{'=' * 60}")

    return 0 if (failed == 0 and errors == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
