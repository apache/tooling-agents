# Security Issues

---
## Issue: FINDING-001 - User identification based on `email` claim instead of immutable `sub` claim enables account takeover upon email reassignment
**Labels:** security, priority:medium
**Description:**

### Summary
The deprecated `google_openid.py` auth backend identifies users by the `email` claim from Google ID tokens instead of the immutable `sub` claim. If a Google Workspace admin reassigns an email address from a departing employee to a new employee, the new holder inherits the previous user's Airflow identity, roles, and permissions.

### Details
- **CWE:** CWE-289
- **ASVS:** 10.3.3, 10.5.2 (Level L2)
- **Affected File:** `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py`

The `sub` claim is available in the `id_info` dictionary but is never used for user identification. This violates OIDC best practices requiring use of claims that cannot be reassigned (typically `iss` + `sub` combination). While the module is deprecated (removal planned in v15.0.0), this represents a real risk until removed. 

Mitigating factors include: email_verified check, user must pre-exist in Airflow, is_active check, and requires organizational process failure.

### Remediation
For the Airflow 3.x replacement authentication mechanism, use the `sub` claim (combined with `iss` to scope per-provider) as the primary user identifier. Consider a migration strategy that falls back to email for backward compatibility during transition. Given the module's deprecated status and planned removal in v15.0.0, remediation effort should focus on the replacement mechanism rather than patching the deprecated code.

### Acceptance Criteria
- [ ] Fixed: Replacement auth mechanism uses `sub` + `iss` for user identification
- [ ] Test added: Verify user identity persistence across email changes
- [ ] Migration strategy documented for existing email-based users

### References
- Related findings: None
- Source reports: 10.3.3.md, 10.5.2.md

### Priority
Medium

---
## Issue: FINDING-002 - Differential HTTP Response Codes Enable Limited User Registration Enumeration in Google OpenID Auth Backend
**Labels:** security, priority:low
**Description:**

### Summary
The `requires_authentication` decorator in `google_openid.py` returns HTTP 401 for invalid/missing tokens but HTTP 403 when a valid token's email is not found in the local user database. This differential response allows an attacker with a valid Google account to determine whether their email is registered in the Airflow instance.

### Details
- **CWE:** CWE-204
- **ASVS:** 6.3.8 (Level L3)
- **Affected File:** `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py`

Exploitability is limited since attackers can only check their own email (tokens are bound to the account owner), and the module is deprecated.

### Remediation
Return a uniform 401 response for all authentication/authorization failures to prevent distinguishing between 'token invalid' and 'user not registered'. Change the 403 response to 401 in the `user not found` branch.

### Acceptance Criteria
- [ ] Fixed: All auth failures return HTTP 401
- [ ] Test added: Verify uniform response codes for various failure scenarios

### References
- Related findings: None
- Source reports: 6.3.8.md

### Priority
Low

---
## Issue: FINDING-003 - User Identity Lookup by Email Alone Without IdP Namespace Prefix
**Labels:** security, priority:low
**Description:**

### Summary
The `_lookup_user` function in `google_openid.py` resolves users by email alone without an IdP namespace prefix. In deployments with multiple auth backends sharing the same user store, a user authenticated by one IdP could potentially map to a user intended for another IdP.

### Details
- **CWE:** CWE-290
- **ASVS:** 6.8.1 (Level L2)
- **Affected File:** `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py`

Mitigated by issuer validation and user pre-existence requirement.

### Remediation
For deployments using multiple IdPs, user records in the FAB user store should include the IdP source (e.g., storing the issuer alongside the email). This is primarily an architectural concern for the FAB AuthManager rather than this specific module.

### Acceptance Criteria
- [ ] Fixed: User records include IdP source identifier
- [ ] Test added: Verify proper user isolation across multiple IdPs
- [ ] Documentation updated for multi-IdP deployment guidance

### References
- Related findings: None
- Source reports: 6.8.1.md

### Priority
Low

---
## Issue: FINDING-004 - Credential File Written Without Explicit Restrictive Permissions
**Labels:** security, priority:low
**Description:**

### Summary
Credential file written via standard open() inherits process umask (typically 0644) instead of explicit 0600 permissions, unlike SSL cert temp files which use NamedTemporaryFile. A local user with filesystem access could read the service account key file.

### Details
- **CWE:** CWE-732
- **ASVS:** 2.2.3 (Level L2)
- **Affected File:** `providers/google/src/airflow/providers/google/cloud/hooks/cloud_sql.py`

### Remediation
Set explicit restrictive permissions on the credentials file using os.open() with 0o600 mode, consistent with SSL temp file handling already present in the codebase.

### Acceptance Criteria
- [ ] Fixed: Credential files created with explicit 0600 permissions
- [ ] Test added: Verify file permissions on credential files

### References
- Related findings: None
- Source reports: 2.2.3.md

### Priority
Low

---
## Issue: FINDING-005 - GCS blob names used directly in local path construction without traversal validation in sync_to_local_dir
**Labels:** security, priority:low
**Description:**

### Summary
GCS blob listing (`blob.name`) is used in path construction via `Path()` → `relative_to(prefix)` → `joinpath()` with `local_dir_path` without path containment validation. GCS allows object names containing `..` path components. An attacker with write access to the source GCS bucket could write files outside the intended `local_dir` directory.

### Details
- **CWE:** CWE-22
- **ASVS:** 5.3.2 (Level L1)
- **Affected File:** `providers/google/src/airflow/providers/google/cloud/hooks/gcs.py`

### Remediation
Add path containment check: resolve the final path and verify it remains within the target directory using `is_relative_to()`.

### Acceptance Criteria
- [ ] Fixed: Path traversal validation implemented
- [ ] Test added: Verify rejection of blob names with `..` components

### References
- Related findings: FINDING-006
- Source reports: 5.3.2.md

### Priority
Low

---
## Issue: FINDING-006 - GCS blob names used directly in local path construction without traversal validation in GCSTimeSpanFileTransformOperator._download
**Labels:** security, priority:low
**Description:**

### Summary
`blob_name` from `list_by_timespan()` is joined directly with `temp_input_dir_path` without path containment validation. An attacker with write access to the source GCS bucket could place objects with `..` segments in their names, causing files to be written outside the temporary directory on the Airflow worker.

### Details
- **CWE:** CWE-22
- **ASVS:** 5.3.2 (Level L1)
- **Affected File:** `providers/google/src/airflow/providers/google/cloud/operators/gcs.py`

### Remediation
Resolve the destination path and verify it remains within `temp_input_dir_path` using `is_relative_to()` before writing.

### Acceptance Criteria
- [ ] Fixed: Path containment validation implemented in _download method
- [ ] Test added: Verify rejection of malicious blob names

### References
- Related findings: FINDING-005
- Source reports: 5.3.2.md

### Priority
Low

---
## Issue: FINDING-007 - Exception objects logged without sanitization may contain sensitive connection details
**Labels:** security, priority:low
**Description:**

### Summary
Exception objects from the Google Cloud Storage client library are logged directly using `%s` formatting. GCS client exceptions may include request details, authentication context, or connection parameters in their string representation.

### Details
- **CWE:** CWE-209
- **ASVS:** 16.2.5 (Level L2)
- **Affected File:** `providers/google/src/airflow/providers/google/cloud/log/gcs_task_handler.py`

While these are operational handler logs (not task output logs), they go through the same Python logging infrastructure and could be captured by other handlers or shipped to monitoring systems.

### Remediation
Sanitize exception messages before logging, or use structured exception handling that extracts only safe fields: log type and safe message without full exception details, truncated to prevent verbose dumps.

### Acceptance Criteria
- [ ] Fixed: Exception logging sanitized to remove sensitive details
- [ ] Test added: Verify sensitive information not exposed in logs

### References
- Related findings: FINDING-010
- Source reports: 16.2.5.md

### Priority
Low

---
## Issue: FINDING-008 - Silent swallowing of connection configuration failure in GCS log handler
**Labels:** bug, priority:low
**Description:**

### Summary
A misconfigured `remote_log_conn_id` setting that points to a non-existent connection is silently ignored. The handler falls back to Application Default Credentials without any log message. This means a security control misconfiguration (log transport using wrong credentials) goes undetected.

### Details
- **ASVS:** 16.3.4 (Level L2)
- **Affected File:** `providers/google/src/airflow/providers/google/cloud/log/gcs_task_handler.py`

### Remediation
Add `self.log.warning(...)` when `AirflowNotFoundException` is caught for a configured `remote_log_conn_id` to improve operational visibility.

### Acceptance Criteria
- [ ] Fixed: Warning logged when configured connection not found
- [ ] Test added: Verify warning message for misconfigured connection

### References
- Related findings: None
- Source reports: 16.3.4.md

### Priority
Low

---
## Issue: FINDING-009 - No alerting or retry mechanism when log transmission to remote storage fails
**Labels:** bug, priority:low
**Description:**

### Summary
When GCS upload fails, the error is logged locally and the method returns False with no retry. If an attacker prevents remote log transmission, forensic evidence remains only on the compromised host where it can be tampered with.

### Details
- **ASVS:** 16.4.3 (Level L2)
- **Affected File:** `providers/google/src/airflow/providers/google/cloud/log/gcs_task_handler.py`

### Remediation
Implement a retry mechanism with exponential backoff for transient failures, and emit a metric or alert when log transmission consistently fails.

### Acceptance Criteria
- [ ] Fixed: Retry mechanism implemented with exponential backoff
- [ ] Fixed: Metric/alert emitted on consistent failures
- [ ] Test added: Verify retry behavior and alerting

### References
- Related findings: None
- Source reports: 16.4.3.md

### Priority
Low

---
## Issue: FINDING-010 - Stackdriver handler read path may expose internal details via unhandled exceptions
**Labels:** security, priority:low
**Description:**

### Summary
The `_read_single_logs_page` method has no exception handling. gRPC errors propagate with project IDs, resource names, and service account info to the caller, potentially reaching error responses visible to authenticated users.

### Details
- **CWE:** CWE-209
- **ASVS:** 16.5.1 (Level L2)
- **Affected File:** `providers/google/src/airflow/providers/google/cloud/log/stackdriver_task_handler.py`

### Remediation
Add exception handling in the read path to catch gRPC exceptions and return generic error messages without internal details.

### Acceptance Criteria
- [ ] Fixed: Exception handling added to _read_single_logs_page
- [ ] Test added: Verify generic error messages without internal details

### References
- Related findings: FINDING-007
- Source reports: 16.5.1.md

### Priority
Low

---
## Issue: FINDING-011 - Stackdriver handler read operation has no graceful degradation when Cloud Logging is unavailable
**Labels:** bug, priority:low
**Description:**

### Summary
The Stackdriver handler's `read()` method has no try/except around `_read_logs()`. When Cloud Logging is unavailable, gRPC exceptions propagate unhandled, resulting in HTTP 500 for the log viewing feature instead of a graceful degradation message.

### Details
- **ASVS:** 16.5.2 (Level L2)
- **Affected File:** `providers/google/src/airflow/providers/google/cloud/log/stackdriver_task_handler.py`

### Remediation
Wrap the read operation with exception handling and return a graceful degradation message indicating Cloud Logging service may be temporarily unavailable.

### Acceptance Criteria
- [ ] Fixed: Exception handling added to read() method
- [ ] Fixed: Graceful degradation message returned on service unavailability
- [ ] Test added: Verify graceful degradation behavior

### References
- Related findings: None
- Source reports: 16.5.2.md

### Priority
Low

---
## Issue: FINDING-012 - GCS handler write method may silently truncate existing remote logs on transient read failure
**Labels:** bug, priority:low
**Description:**

### Summary
When `download_as_bytes()` fails with a non-404 error (transient failure), the exception is caught and execution falls through to upload with only new content, overwriting the existing blob and losing previous log entries.

### Details
- **ASVS:** 16.5.3 (Level L2)
- **Affected File:** `providers/google/src/airflow/providers/google/cloud/log/gcs_task_handler.py`

### Remediation
Fail closed when existing log content cannot be read for non-404 errors: refuse to write and return False to prevent data loss, preserving local logs for later retry.

### Acceptance Criteria
- [ ] Fixed: Write operation fails closed on transient read errors
- [ ] Test added: Verify log preservation on transient failures

### References
- Related findings: None
- Source reports: 16.5.3.md

### Priority
Low

---
## Issue: FINDING-013 - Stackdriver handler close() method lacks exception handling around transport flush
**Labels:** bug, priority:low
**Description:**

### Summary
The `close()` method calls `self._transport.flush()` without exception handling. If flush raises during shutdown (e.g., Cloud Logging unavailable), buffered log entries may be lost and the exception may not be properly captured.

### Details
- **ASVS:** 16.5.4 (Level L3)
- **Affected File:** `providers/google/src/airflow/providers/google/cloud/log/stackdriver_task_handler.py`

### Remediation
Add try/except around `_transport.flush()` in `close()` to ensure graceful shutdown, printing to stderr as last resort since logging may be shutting down.

### Acceptance Criteria
- [ ] Fixed: Exception handling added to close() method
- [ ] Test added: Verify graceful shutdown behavior

### References
- Related findings: None
- Source reports: 16.5.4.md

### Priority
Low

---
## Issue: FINDING-014 - No Automated SBOM Generation in Build Pipeline
**Labels:** bug, priority:low
**Description:**

### Summary
The project declares all direct third-party dependencies in `pyproject.toml` files with version constraints and maintains a committed `uv.lock` file that provides a complete snapshot of all resolved dependency versions (direct and transitive). However, no formal SBOM in a standard format (CycloneDX, SPDX) is automatically generated as part of the build/release pipeline.

### Details
- **CWE:** CWE-1059
- **ASVS:** 15.1.2 (Level L2)
- **Affected File:** `providers/google/pyproject.toml`

### Remediation
Integrate CycloneDX or SPDX SBOM generation into CI/CD pipeline using existing uv.lock as input.

### Acceptance Criteria
- [ ] Fixed: SBOM generation integrated into CI/CD pipeline
- [ ] Fixed: SBOM artifacts published with releases
- [ ] Test added: Verify SBOM completeness and format compliance

### References
- Related findings: None
- Source reports: 15.1.2.md

### Priority
Low

---
## Issue: FINDING-015 - Dead Code Paths for Unsupported Python Versions in Vendored Library
**Labels:** bug, priority:low
**Description:**

### Summary
The vendored library contains code branches for Python < 3.2. Project requires Python >= 3.10 per pyproject.toml. Minimal impact - increases maintenance burden marginally but no direct security impact.

### Details
- **ASVS:** 15.2.3 (Level L2)
- **Affected File:** `providers/google/src/airflow/providers/google/_vendor/json_merge_patch.py`

### Remediation
Remove Python < 3.2 compatibility code: result.move_to_end(key, False)

### Acceptance Criteria
- [ ] Fixed: Dead code removed from vendored library
- [ ] Test added: Verify functionality maintained on supported Python versions

### References
- Related findings: None
- Source reports: 15.2.3.md

### Priority
Low

---
## Issue: FINDING-016 - Majority of Dependencies Lack Explicit Source Repository Pinning
**Labels:** security, priority:low
**Description:**

### Summary
~60+ dependencies resolved from default PyPI index without explicit repository restriction. Mitigated by uv.lock with integrity hashes, workspace source pinning for internal packages, and all external packages from well-known organizationally-owned namespaces.

### Details
- **ASVS:** 15.2.4 (Level L3)
- **Affected File:** `providers/google/pyproject.toml`

### Remediation
Add [tool.uv] index-url = 'https://pypi.org/simple/' and no-extra-index-url = true. Ensure uv.lock integrity hashes verified during production builds.

### Acceptance Criteria
- [ ] Fixed: Explicit repository pinning configured
- [ ] Fixed: Integrity hash verification enforced in production builds
- [ ] Test added: Verify dependency resolution from pinned repository only

### References
- Related findings: None
- Source reports: 15.2.4.md

### Priority
Low

---
## Issue: FINDING-017 - External Service Communication Dependencies Not Consolidated in Code Documentation
**Labels:** bug, priority:low
**Description:**

### Summary
While individual operators document their parameters and connection requirements in docstrings, there is no consolidated service inventory documenting all GCP API endpoints called, auxiliary services used, and cases where DAG-author-provided parameters may cause the application to connect to user-specified external locations.

### Details
- **ASVS:** 13.1.1 (Level L2)
- **Affected Files:** 
  - `providers/google/src/airflow/providers/google/cloud/operators/dataflow.py`
  - `providers/google/src/airflow/providers/google/cloud/operators/dataproc.py`
  - `providers/google/src/airflow/providers/google/cloud/operators/cloud_batch.py`
  - `providers/google/src/airflow/providers/google/cloud/operators/kubernetes_engine.py`
  - `providers/google/src/airflow/providers/google/cloud/operators/vertex_ai/custom_job.py`
  - `providers/google/src/airflow/providers/google/cloud/triggers/cloud_batch.py`

### Remediation
Add a module-level or package-level docstring (or COMMUNICATIONS.md) documenting all GCP services these operators communicate with, including any user-controllable destination parameters.

### Acceptance Criteria
- [ ] Fixed: Consolidated service inventory documentation created
- [ ] Documentation includes all GCP API endpoints
- [ ] Documentation includes user-controllable parameters

### References
- Related findings: None
- Source reports: 13.1.1.md

### Priority
Low

---
## Issue: FINDING-018 - Inconsistent Timeout Defaults Across Operators for Same Service Category
**Labels:** bug, priority:low
**Description:**

### Summary
Operators communicating with similar GCP services have inconsistent timeout defaults (some None, some explicit), which could lead to undefined resource-hold behavior. DAG authors are trusted per guidance, and Airflow has task-level execution timeout, but the inconsistency is a documentation/design concern.

### Details
- **ASVS:** 13.1.3 (Level L3)
- **Affected Files:**
  - `providers/google/src/airflow/providers/google/cloud/operators/cloud_batch.py`
  - `providers/google/src/airflow/providers/google/cloud/operators/dataproc.py`
  - `providers/google/src/airflow/providers/google/cloud/operators/dataflow.py`
  - `providers/google/src/airflow/providers/google/cloud/operators/kubernetes_engine.py`
  - `providers/google/src/airflow/providers/google/cloud/operators/vertex_ai/custom_job.py`

### Remediation
Document the resource management strategy for each operator family, including why some operators default to None timeout and the expected maximum duration for each operation type.

### Acceptance Criteria
- [ ] Fixed: Timeout strategy documented for each operator family
- [ ] Documentation includes rationale for default values
- [ ] Documentation includes expected maximum durations

### References
- Related findings: None
- Source reports: 13.1.3.md

### Priority
Low

---
## Issue: FINDING-019 - Resource Management Strategies Implemented but Not Formally Documented with Retry Limits, Back-off Algorithms, and Timeout Rationale
**Labels:** bug, priority:low
**Description:**

### Summary
Wait methods use exponential_sleep_generator or fixed retry intervals without explicit documentation of maximum retry count, back-off algorithms, or failure handling rationale. Implementations are functionally sound and bounded by timeouts, but documentation doesn't define total expected wait time or why specific intervals were chosen.

### Details
- **ASVS:** 13.1.3 (Level L3)
- **Affected Files:**
  - `providers/google/src/airflow/providers/google/cloud/operators/dataproc.py`
  - `providers/google/src/airflow/providers/google/cloud/operators/kubernetes_engine.py`
  - `providers/google/src/airflow/providers/google/cloud/triggers/cloud_batch.py`

### Remediation
Document resource management strategies including retry limits, chosen intervals with rationale, timeout defaults and their relationship to GCP API SLAs, and failure modes when timeouts are exceeded.

### Acceptance Criteria
- [ ] Fixed: Resource management strategies documented
- [ ] Documentation includes retry limits and back-off algorithms
- [ ] Documentation includes timeout rationale and relationship to GCP API SLAs
- [ ] Documentation includes failure mode descriptions

### References
- Related findings: None
- Source reports: 13.1.3.md

### Priority
Low

---
## Issue: FINDING-020 - No Explicit Token Type Claim Validation
**Labels:** security, priority:low
**Description:**

### Summary
The `_verify_id_token` function does not explicitly validate token type (e.g., by checking for `sub` claim presence per OIDC spec). While implicit type checking exists via claim requirements (iss, email_verified, email), no explicit token type validation control is applied.

### Details
- **ASVS:** 9.2.2 (Level L2)
- **Affected File:** `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py`

Currently not exploitable under Google's OAuth2 architecture where access tokens are opaque, but represents a defense-in-depth gap if Google were to introduce new JWT token types sharing the same signing keys.

### Remediation
Add an explicit token type check by verifying the `sub` claim is present, which is mandatory in OIDC ID tokens but may not be present in other hypothetical JWT types.

### Acceptance Criteria
- [ ] Fixed: Explicit token type validation added
- [ ] Test added: Verify rejection of tokens without `sub` claim

### References
- Related findings: None
- Source reports: 9.2.2.md

### Priority
Low