# Security Issues

## Issue: FINDING-001 - Path Traversal in sync_to_local_dir Function
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `sync_to_local_dir()` function in gcs.py does not validate that resolved file paths remain within the intended local directory. GCS blob names (untrusted if bucket has shared write access) are used directly to construct local file paths via `Path.joinpath()` without checking if the resolved path escapes the base directory.

### Details
An attacker with write access to the GCS bucket can create blobs with names containing path traversal sequences (`../`) to write files to arbitrary locations on the local filesystem. This vulnerability is classified as CWE-22 (Path Traversal) and violates ASVS 5.3.2 (L1).

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/hooks/gcs.py` (lines 760-790)

### Remediation
Add path traversal protection by resolving both the base directory and target path, then validating that the target is relative to the base using `Path.is_relative_to()`. Log and skip any blobs that would resolve outside the intended directory. Use `Path.resolve()` to normalize paths before comparison.

### Acceptance Criteria
- [ ] Path validation implemented using `Path.resolve()` and `Path.is_relative_to()`
- [ ] Test added for path traversal attack scenarios
- [ ] Logging added for skipped blobs with invalid paths
- [ ] Code review completed

### References
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- ASVS 5.3.2
- Related findings: FINDING-007, FINDING-008, FINDING-009, FINDING-010, FINDING-015

### Priority
**High** - Allows arbitrary file write on worker filesystem

---

## Issue: FINDING-002 - SQL Injection in Dataproc Metastore HiveQL Queries
**Labels:** bug, security, priority:high
**Description:**
### Summary
SQL injection vulnerability in `list_hive_partitions()` function. The `table` and `partition_names` parameters are interpolated directly into a HiveQL query using f-strings without sanitization or parameterization.

### Details
Data flows from DAG parameters (user-controlled) through f-string interpolation into SQL queries executed on Dataproc Metastore. An attacker can inject malicious SQL by crafting table names like `'; DROP TABLE PARTITIONS; --` or partition names like `ds=1' OR '1'='1`. This is exploitable if DAG parameters are sourced from XCom, trigger parameters, or external systems, potentially allowing attackers to read, modify, or delete metadata.

**Affected Files:**
- `dataproc_metastore.py` (lines 459-516)

**CWE:** CWE-89 (SQL Injection)
**ASVS:** 1.2.4, 2.2.1 (L1)

### Remediation
Add identifier validation using regex to sanitize SQL identifiers. Implement a `_sanitize_identifier()` method that validates input against a whitelist pattern (e.g., `'^[a-zA-Z_][a-zA-Z0-9_]{0,127}$'` for table names and `'^[a-zA-Z_][a-zA-Z0-9_]*=[^;'\"\\\\]+$'` for partition names) and raises `ValueError` for invalid identifiers. Apply this sanitization to both `table` and `partition_names` parameters before query construction.

### Acceptance Criteria
- [ ] `_sanitize_identifier()` method implemented with regex validation
- [ ] Validation applied to all SQL identifier parameters
- [ ] Unit tests added for valid and malicious inputs
- [ ] ValueError raised for invalid identifiers with clear error message

### References
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- ASVS 1.2.4, 2.2.1
- Related findings: FINDING-035

### Priority
**High** - SQL injection can lead to data breach or loss

---

## Issue: FINDING-003 - No session token regeneration on authentication in Google OpenID backend
**Labels:** security, priority:medium
**Description:**
### Summary
The authentication backend verifies the user's identity but does not trigger the generation of a new Airflow session token. While this is a stateless API authentication pattern, if Flask/FAB creates or extends a session cookie as a side effect, session fixation could theoretically occur.

### Details
The backend only sets the user context for the current request via `_set_current_user`. If this backend is used in conjunction with Flask sessions, an attacker who obtains a pre-authentication session ID could maintain access through a legitimate user's authentication.

**Mitigating context:** This is explicitly documented as an API auth backend for Airflow 2.x (deprecated for Airflow 3). The stateless per-request verification pattern means no persistent session state is maintained by this module itself.

**Affected Files:**
- `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py` (lines 108-128)

**ASVS:** 7.2.4 (L1)

### Remediation
If this backend is used with session cookies, add session regeneration after successful authentication:
```python
from flask import session
# After successful authentication
_set_current_user(user)
session.regenerate()  # or equivalent Flask-Login mechanism
```

### Acceptance Criteria
- [ ] Session regeneration implemented if backend uses session cookies
- [ ] Documentation updated to clarify session handling behavior
- [ ] Test added to verify session regeneration on authentication

### References
- ASVS 7.2.4
- Session Fixation vulnerability pattern

### Priority
**Medium** - Theoretical risk mitigated by stateless design

---

## Issue: FINDING-004 - Non-SSL public database connections transmit credentials in cleartext
**Labels:** security, priority:medium
**Description:**
### Summary
Database connections allow creating direct public internet connections without any transport encryption when `use_proxy=False` and `use_ssl=False`. This sends database credentials (username/password) unencrypted over the network.

### Details
The default configuration (`use_proxy=False`, `use_ssl=False`) is the least secure path. A connection configured with these settings results in a connection URI of `postgresql://user:password@<public_ip>:5432/db` where all traffic including authentication is unencrypted.

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/hooks/cloud_sql.py` (lines 710-714, 973-1018, 1020-1083, 999-1002)

**ASVS:** 12.2.1 (L1)

### Remediation
Consider logging a warning or raising an error when `use_proxy=False` and `use_ssl=False` for public connections. Add a runtime warning for unencrypted public database connections. Consider making `use_ssl=True` the default for public (non-proxy) connections in a future major version.

Example implementation: Add validation in `_validate_inputs()` to log a warning when neither Cloud SQL Proxy nor SSL is configured, informing users that database credentials will be transmitted unencrypted and recommending `use_proxy=True` or `use_ssl=True` for production use.

### Acceptance Criteria
- [ ] Warning logged when unencrypted public connection is configured
- [ ] Documentation updated with security best practices
- [ ] Deprecation notice added for insecure default in future major version

### References
- ASVS 12.2.1
- Cloud SQL security best practices

### Priority
**Medium** - Credentials exposed in transit on insecure configurations

---

## Issue: FINDING-005 - GCS download() method lacks file size validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `download()` method in GCS hook downloads objects to local filesystem without checking file size beforehand. A GCS bucket containing a multi-GB object can be synced to a worker with limited disk space, causing disk exhaustion and potential denial of service.

### Details
The hook explicitly acknowledges this gap via a TODO comment but has not implemented any mitigation. Large files can exhaust worker disk space, impacting co-located tasks.

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/hooks/gcs.py` (line 300)

**ASVS:** 5.2.1 (L1)

### Remediation
Add optional aggregate size limit (`max_total_bytes`) and per-file size limit (`max_file_bytes`) parameters. For each blob, reload metadata to get size, validate against per-file limit, track cumulative bytes downloaded, and raise `AirflowException` if aggregate limit would be exceeded.

### Acceptance Criteria
- [ ] `max_total_bytes` parameter added
- [ ] `max_file_bytes` parameter added
- [ ] Size validation implemented before download
- [ ] AirflowException raised when limits exceeded
- [ ] Tests added for size limit enforcement

### References
- ASVS 5.2.1
- TODO comment in code acknowledging the gap

### Priority
**Medium** - Can cause worker disk exhaustion and DoS

---

## Issue: FINDING-006 - http_to_gcs operator loads entire HTTP response into memory without size validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `execute()` method loads the entire HTTP response into memory via `response.content` before uploading to GCS, with no maximum response size validation. This can cause memory exhaustion on the worker.

### Details
If the configured HTTP endpoint returns a response of several GB (maliciously or due to misconfiguration), the worker's memory will be exhausted, causing OOM and potential denial of service to other tasks running on the same worker.

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/transfers/http_to_gcs.py` (line 168)

**ASVS:** 5.2.1 (L1)

### Remediation
Add configurable `MAX_RESPONSE_SIZE` limit (e.g., 5GB). Use streaming mode for HTTP requests. Check `Content-Length` header if available and validate against limit before loading content. Consider streaming upload directly to GCS when possible to avoid loading entire response into memory.

### Acceptance Criteria
- [ ] `MAX_RESPONSE_SIZE` parameter added with default value
- [ ] Streaming mode implemented for HTTP requests
- [ ] Content-Length validation added
- [ ] Direct streaming upload to GCS implemented where possible
- [ ] Tests added for size limit enforcement

### References
- ASVS 5.2.1

### Priority
**Medium** - Can cause worker OOM and DoS

---

## Issue: FINDING-007 - Path Traversal in _calculate_sync_destination_path Function
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `_calculate_sync_destination_path()` function uses `os.path.join()` without sanitizing the blob name suffix. If the remaining blob name after prefix stripping starts with `/`, `os.path.join()` treats it as an absolute path on POSIX systems.

### Details
This causes objects to be written to unintended GCS paths outside the intended prefix namespace. The vulnerability is classified as CWE-22 (Path Traversal).

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/hooks/gcs.py` (line 850)

**CWE:** CWE-22
**ASVS:** 5.3.2 (L1)

### Remediation
Strip leading slashes from the relative blob name using `lstrip('/')` and remove path traversal components (`.` and `..`) by filtering split path parts. Use string concatenation with explicit separator rather than `os.path.join()` to prevent absolute path interpretation.

### Acceptance Criteria
- [ ] Leading slash stripping implemented
- [ ] Path traversal component filtering added
- [ ] String concatenation used instead of os.path.join()
- [ ] Tests added for various path traversal scenarios

### References
- CWE-22
- ASVS 5.3.2
- Related findings: FINDING-001, FINDING-008, FINDING-009, FINDING-010, FINDING-015

### Priority
**Medium** - Can write to unintended GCS paths

---

## Issue: FINDING-008 - Path Traversal in GCS to SFTP Transfer Operator
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `_resolve_destination_path()` function in gcs_to_sftp.py does not sanitize GCS object names before constructing SFTP destination paths. When `keep_directory_structure=True`, GCS object names containing path traversal sequences (`../`) are passed directly to `os.path.join()`.

### Details
An attacker with write access to the source GCS bucket can create objects with crafted names to write files to arbitrary locations on the SFTP server.

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_sftp.py` (lines 156, 130)

**CWE:** CWE-22
**ASVS:** 5.3.2 (L1)

### Remediation
Normalize the destination path using `os.path.normpath()` and validate that it starts with the base `destination_path`. Raise `AirflowException` if the resolved path would escape the intended directory. Add validation before calling `sftp_hook.store_file()`.

### Acceptance Criteria
- [ ] Path normalization implemented
- [ ] Base path validation added
- [ ] AirflowException raised for invalid paths
- [ ] Tests added for path traversal scenarios

### References
- CWE-22
- ASVS 5.3.2
- Related findings: FINDING-001, FINDING-007, FINDING-009, FINDING-010, FINDING-015

### Priority
**Medium** - Can write arbitrary files to SFTP server

---

## Issue: FINDING-009 - Inconsistent Path Sanitization in GCS to SFTP with Prefix
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `_resolve_destination_path()` function uses `os.path.relpath()` when `keep_directory_structure=False` and a prefix is provided. This function can produce `../` sequences when there is a mismatch between the source object path and the prefix.

### Details
This can potentially lead to path traversal on the SFTP server. Lower severity because the `os.path.basename()` fallback (when no prefix is used) is safe.

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_sftp.py` (line 156)

**CWE:** CWE-22
**ASVS:** 5.3.2 (L1)

### Remediation
Apply the same path normalization and containment validation as recommended for FINDING-008. Validate that the result of `os.path.relpath()` does not contain `..` components before using it to construct the destination path.

### Acceptance Criteria
- [ ] Path normalization applied to relpath results
- [ ] Validation added to reject paths with .. components
- [ ] Tests added for various prefix/path combinations

### References
- CWE-22
- ASVS 5.3.2
- Related findings: FINDING-001, FINDING-007, FINDING-008, FINDING-010, FINDING-015

### Priority
**Medium** - Path traversal risk with specific configurations

---

## Issue: FINDING-010 - Path Traversal in Gen AI Result File Writing
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `_prepare_results_for_xcom()` function in gen_ai.py constructs file paths using unsanitized `job.display_name` or `job.name` values. An attacker who can control these values could use path traversal sequences to write arbitrary files.

### Details
The vulnerable code uses `os.path.abspath()` which resolves path traversal sequences but does not validate that the resulting path remains within the intended `results_folder` directory. An attacker could write to paths like `../../etc/cron.d/malicious`.

**Affected Files:**
- `gen_ai.py` (lines 388, 616)

**CWE:** CWE-22
**ASVS:** 1.2.5 (L1)

### Remediation
Sanitize the file name using `os.path.basename()` to remove any directory components, strip `..` sequences, and validate that the resolved path remains within the `results_folder` directory before writing.

Implementation:
```python
safe_file_name = os.path.basename(file_name).replace('..', '')
path_to_file = os.path.join(os.path.abspath(self.results_folder), f'{safe_file_name}.jsonl')
if not path_to_file.startswith(os.path.abspath(self.results_folder)):
    raise AirflowException(f'Path {path_to_file} escapes results_folder')
```

### Acceptance Criteria
- [ ] File name sanitization implemented
- [ ] Path containment validation added
- [ ] AirflowException raised for invalid paths
- [ ] Tests added for path traversal scenarios

### References
- CWE-22
- ASVS 1.2.5
- Related findings: FINDING-001, FINDING-007, FINDING-008, FINDING-009, FINDING-015

### Priority
**Medium** - Can write arbitrary files on worker node

---

## Issue: FINDING-011 - Missing Reserved Flag Validation in Dataflow YAML Jobs
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `launch_beam_yaml_job()` function allows user-supplied options to override reserved flags including `project`, `format`, and `region`. When options dictionary is provided, it can override critical parameters like `project_id`.

### Details
This could cause jobs to run in unintended projects or break job ID parsing by overriding the format flag. DAG authors could accidentally run jobs in wrong project or break job ID parsing.

**Affected Files:**
- `dataflow.py` (line 555)

**ASVS:** 2.2.2 (L1)

### Remediation
Implement reserved flag protection by defining `RESERVED_FLAGS` set containing `'project'`, `'format'`, `'region'`, `'yaml-pipeline-file'`, and `'jinja-variables'`. Before updating `gcp_flags` with user options, check for conflicts and raise `AirflowException` if any reserved flags are present in the options dictionary.

### Acceptance Criteria
- [ ] RESERVED_FLAGS set defined
- [ ] Validation added to check for reserved flag conflicts
- [ ] AirflowException raised with clear error message
- [ ] Tests added for reserved flag scenarios

### References
- ASVS 2.2.2

### Priority
**Medium** - Can cause jobs to run in wrong project

---

## Issue: FINDING-012 - Deferrable Mode Skips Job Deletion in S3ToGCS Operator
**Labels:** bug, priority:medium
**Description:**
### Summary
The S3ToGCS operator skips the job deletion step when operating in deferrable mode. The `execute_complete` callback does not implement the deletion logic, causing transfer jobs to persist indefinitely despite `delete_job_after_completion=True`.

### Details
In non-deferrable mode, the operator correctly waits for the transfer job to complete and then deletes it if `delete_job_after_completion` is True. This represents a business logic flow inconsistency where a critical cleanup step is skipped based on execution mode.

**Affected Files:**
- `cloud_storage_transfer_service.py`

**ASVS:** 2.3.1 (L1)

### Remediation
Add deletion logic to the `execute_complete` callback method:
```python
def execute_complete(self, context, event):
    if event["status"] == "error":
        raise AirflowException(event["message"])
    
    if self.delete_job_after_completion:
        hook = CloudDataTransferServiceHook(
            gcp_conn_id=self.gcp_conn_id,
            impersonation_chain=self.google_impersonation_chain,
        )
        hook.delete_transfer_job(
            job_name=event.get("job_name") or self._transfer_job[NAME],
            project_id=self.project_id,
        )
```

### Acceptance Criteria
- [ ] Job deletion logic added to execute_complete
- [ ] Tests added for deferrable mode with delete_job_after_completion=True
- [ ] Behavior consistent between deferrable and non-deferrable modes

### References
- ASVS 2.3.1

### Priority
**Medium** - Resource leak, jobs not cleaned up

---

## Issue: FINDING-013 - Deferrable Mode Skips Job Deletion in GCSToGCS Operator
**Labels:** bug, priority:medium
**Description:**
### Summary
The GCSToGCS operator skips the job deletion step when operating in deferrable mode. The `execute_complete` callback does not implement the deletion logic, causing transfer jobs to persist indefinitely despite `delete_job_after_completion=True`.

### Details
In non-deferrable mode, the operator correctly waits for the transfer job to complete and then deletes it if `delete_job_after_completion` is True. This represents a business logic flow inconsistency where a critical cleanup step is skipped based on execution mode.

**Affected Files:**
- `cloud_storage_transfer_service.py`

**ASVS:** 2.3.1 (L1)

### Remediation
Add deletion logic to the `execute_complete` callback method:
```python
def execute_complete(self, context, event):
    if event["status"] == "error":
        raise AirflowException(event["message"])
    
    if self.delete_job_after_completion:
        hook = CloudDataTransferServiceHook(
            gcp_conn_id=self.gcp_conn_id,
            impersonation_chain=self.google_impersonation_chain,
        )
        hook.delete_transfer_job(
            job_name=event.get("job_name") or self._transfer_job[NAME],
            project_id=self.project_id,
        )
```

### Acceptance Criteria
- [ ] Job deletion logic added to execute_complete
- [ ] Tests added for deferrable mode with delete_job_after_completion=True
- [ ] Behavior consistent between deferrable and non-deferrable modes

### References
- ASVS 2.3.1

### Priority
**Medium** - Resource leak, jobs not cleaned up

---

## Issue: FINDING-014 - Path Traversal in Cloud Composer DAG Trigger
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Path traversal vulnerability in authenticated HTTP requests to Composer Airflow web server. The `composer_dag_id` parameter flows from operator parameter through f-string interpolation to `urljoin()` without URL encoding.

### Details
While DAG authors are trusted administrators, URL encoding is a defense-in-depth measure and aligns with best practices.

Proof of concept: `composer_dag_id = '../../admin'` results in `/api/v1/dags/../../admin/dagRuns` which after `urljoin` becomes `https://composer-env.example.com/admin/dagRuns`

**Affected Files:**
- `cloud_composer.py`

**ASVS:** 1.2.2 (L1)

### Remediation
Apply `urllib.parse.quote()` to `composer_dag_id` before interpolation:
```python
from urllib.parse import quote
safe_dag_id = quote(composer_dag_id, safe='')
resource_path = f"/api/{self.get_airflow_rest_api_version(composer_airflow_version)}/dags/{safe_dag_id}/dagRuns"
```

Affected methods: `trigger_dag_run`, `get_dag_runs`, `get_task_instances` in both `CloudComposerHook` and `CloudComposerAsyncHook` (6 methods total).

### Acceptance Criteria
- [ ] URL encoding applied to all composer_dag_id usages
- [ ] All 6 affected methods updated
- [ ] Tests added for special characters in DAG IDs

### References
- ASVS 1.2.2

### Priority
**Medium** - Path traversal in authenticated requests

---

## Issue: FINDING-015 - Path Traversal in GCS Sync to Local Directory
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Path traversal vulnerability in GCS sync functionality. The `sync_to_local_dir` function constructs local file paths from GCS blob names without validating that the resulting path stays within the intended directory.

### Details
Data flows from GCS blob names (attacker-controllable) through Path operations that preserve `..` sequences, allowing writes outside the target directory. An attacker can create a GCS object named `data/../../tmp/exploit_payload` which, when synced with prefix `data/`, results in writing to `/tmp/exploit_payload` instead of the intended sync directory.

This enables:
- Writing arbitrary files to the Airflow worker filesystem
- Potential code execution by overwriting Python imports
- Configuration manipulation

**Affected Files:**
- `gcs.py` (line 557)

**CWE:** CWE-22
**ASVS:** 2.2.1 (L1)

### Remediation
Add path validation to ensure constructed paths remain within the intended directory. Use `.resolve()` to normalize paths and validate that the resolved target path starts with the resolved base directory path. Skip blobs that attempt path traversal with a warning log.

Example implementation:
```python
if not str(local_target_path).startswith(str(local_dir_path) + os.sep):
    self.log.warning(f"Skipping blob {blob.name}: path traversal detected")
    continue
```

### Acceptance Criteria
- [ ] Path validation implemented using resolve()
- [ ] Containment check added
- [ ] Warning logged for skipped blobs
- [ ] Tests added for path traversal scenarios

### References
- CWE-22
- ASVS 2.2.1
- Related findings: FINDING-001, FINDING-007, FINDING-008, FINDING-009, FINDING-010

### Priority
**Medium** - Allows arbitrary file write on worker

---

## Issue: FINDING-016 - Inconsistent URL Encoding in DataFusion Pipeline Operations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Inconsistent application of URL encoding in DataFusion pipeline operations. The `delete_pipeline` function uses `quote()` for the `pipeline_name` parameter but fails to apply URL encoding to the `version_id` parameter.

### Details
This is a Type B gap where the security control exists but is not consistently applied. The missing encoding for `version_id` could allow URL path injection via crafted version identifiers, potentially redirecting API requests to unintended endpoints.

**Affected Files:**
- `datafusion.py` (lines 282-286)

**CWE:** CWE-116
**ASVS:** 1.2.2, 2.2.1 (L1)

### Remediation
Apply URL encoding consistently to all user-provided parameters in URL construction. Add `quote()` call for `version_id`:
```python
url = os.path.join(url, 'versions', quote(version_id, safe=''))
```

Audit all URL construction in the file to ensure consistent encoding of dynamic parameters.

### Acceptance Criteria
- [ ] URL encoding applied to version_id parameter
- [ ] All URL constructions in file audited for consistent encoding
- [ ] Tests added for special characters in parameters

### References
- CWE-116
- ASVS 1.2.2, 2.2.1

### Priority
**Medium** - Inconsistent security control application

---

## Issue: FINDING-017 - Error responses served with incorrect Content-Type (text/html for plain text bodies)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Flask's `Response` class defaults to `mimetype='text/html'` when no explicit content type is specified. The response bodies ("Unauthorized", "Forbidden") are plain text strings, not HTML documents. The `Content-Type: text/html; charset=utf-8` header does not match the actual content.

### Details
This violates multiple ASVS requirements:
1. ASVS 4.1.1 requires Content-Type must match actual response content
2. ASVS 3.2.1 requires security controls to prevent browsers from rendering content in an incorrect context
3. ASVS 3.2.2 requires text content to be handled to prevent unintended execution

While no user-controlled data is reflected in these specific responses (mitigating XSS risk), serving plain text as HTML sets a poor precedent and could enable content-sniffing attacks if the pattern is replicated elsewhere with dynamic content.

**Affected Files:**
- `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py` (lines 131, 135, 139)

**ASVS:** 3.2.1, 3.2.2, 4.1.1 (L1)

### Remediation
Specify the correct content type explicitly:
```python
return Response("Unauthorized", 401, content_type="text/plain; charset=utf-8")
```

Alternatively, use JSON responses with proper content type for API consistency:
```python
return Response(json.dumps({"error": message}), status=status, content_type="application/json; charset=utf-8")
```

### Acceptance Criteria
- [ ] Correct Content-Type set for all three error responses
- [ ] Tests verify Content-Type header
- [ ] Consistent error response format across auth backend

### References
- ASVS 3.2.1, 3.2.2, 4.1.1

### Priority
**Medium** - Content-Type mismatch, poor security precedent

---

## Issue: FINDING-018 - Missing Strict-Transport-Security header on authentication error responses
**Labels:** security, priority:medium
**Description:**
### Summary
The HTTP responses generated directly by this authentication backend (401 and 403 error responses) do not include a `Strict-Transport-Security` header. HSTS should be present on all responses including error responses.

### Details
These three response paths bypass any downstream middleware that might add HSTS headers to successful responses, since the function returns early before the wrapped function executes. If an attacker can downgrade the connection to HTTP (e.g., on first visit or after HSTS expiry), they could intercept subsequent Bearer tokens. Without HSTS on error responses, the browser doesn't learn to enforce HTTPS if only error responses are received.

**Affected Files:**
- `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py` (lines 131, 135, 139)

**ASVS:** 3.4.1 (L1)

### Remediation
HSTS should ideally be configured at the Flask application middleware level (e.g., using `flask-talisman` or `after_request` hook) to ensure all responses include it.

Better approach is application-wide middleware:
```python
@app.after_request
def add_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
```

If middleware is not possible, add it to the direct responses:
```python
HSTS_HEADER = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
return Response("Unauthorized", 401, headers=HSTS_HEADER, content_type="text/plain")
```

### Acceptance Criteria
- [ ] HSTS header added to all error responses
- [ ] Middleware approach implemented if possible
- [ ] Tests verify HSTS header presence

### References
- ASVS 3.4.1

### Priority
**Medium** - Missing HSTS allows downgrade attacks

---

## Issue: FINDING-019 - No documented risk-based remediation timeframes for 3rd party logging component vulnerabilities
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The provided codebase and documentation (AGENTS.md) do not define risk-based remediation timeframes for vulnerabilities found in third-party components used by the logging infrastructure.

### Details
Without defined remediation timeframes, there is no enforceable standard for when vulnerable components must be patched. This creates ambiguity in incident response and allows known-vulnerable versions to persist indefinitely without accountability. This absence of documented timeframes also prevents verification of compliance with ASVS 15.2.1.

**Affected Files:**
- Repository-wide (specifically providers/google/ logging domain)
- stackdriver_task_handler.py
- gcs_task_handler.py
- stackdriver.py

**ASVS:** 15.1.1, 15.2.1 (L1)

### Remediation
Create a security remediation policy document (e.g., SECURITY_REMEDIATION.md) that defines:

1. **Remediation Timeframes by severity:**
   - Critical (CVSS ≥ 9.0): 72 hours
   - High (CVSS 7.0-8.9): 7 calendar days
   - Medium (CVSS 4.0-6.9): 30 calendar days
   - Low (CVSS < 4.0): Next scheduled release

2. **General Update Policy:**
   - All 3rd party dependencies reviewed quarterly
   - Dependencies reaching EOL replaced within 90 days
   - Components with dangerous functionality prioritized

3. **Risky Component Registry:**
   - protobuf (dangerous functionality - binary data parsing)
   - google-cloud-storage (standard - network I/O)
   - google-cloud-logging (standard - external API client)

4. **Monitoring:**
   - Dependabot/Renovate alerts reviewed within 24 hours
   - uv.lock updates verified against CVE databases before merge

### Acceptance Criteria
- [ ] SECURITY_REMEDIATION.md document created
- [ ] Remediation timeframes defined for all severity levels
- [ ] Risky component registry established
- [ ] Monitoring procedures documented
- [ ] Automated compliance checking implemented

### References
- ASVS 15.1.1, 15.2.1

### Priority
**Medium** - Missing security policy documentation

---

## Issue: FINDING-020 - Missing documentation for rate limiting and anti-automation controls in GCP connection authentication
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The Google Cloud connection documentation does not define how rate limiting, anti-automation, or adaptive response controls are used to defend against credential stuffing or brute force attacks against connection authentication attempts.

### Details
The documentation describes retry behavior for outbound API calls (client-side retry logic), but does not document:
1. How inbound authentication attempts against Airflow's connection system are rate-limited
2. Anti-automation controls to prevent automated attacks against stored connection credentials
3. Adaptive response mechanisms (e.g., progressive delays, temporary lockouts)
4. How legitimate access is preserved while malicious attempts are blocked

**Affected Files:**
- `providers/google/docs/connections/gcp.rst` (entire document)

**ASVS:** 6.1.1 (L1)

### Remediation
Add a security section to the GCP connection documentation that describes:

**Security Controls - Rate Limiting and Anti-Automation:**
- Airflow API rate limiting: The Airflow API server enforces rate limits on authentication endpoints
- Google Cloud API protections: Google Cloud APIs enforce their own rate limiting with exponential backoff
- Account lockout prevention: Failed authentication attempts are logged but do not lock out the Airflow connection
- Adaptive response: After N failed attempts within a time window, additional delays are introduced

### Acceptance Criteria
- [ ] Security section added to GCP connection documentation
- [ ] Rate limiting controls documented
- [ ] Anti-automation measures described
- [ ] Configuration references provided

### References
- ASVS 6.1.1

### Priority
**Medium** - Missing security documentation

---

## Issue: FINDING-021 - No documented password minimum length requirements for connection credentials
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
Neither connection documentation defines minimum length requirements for credential fields that could contain user-set passwords. While GCP connections primarily use service account keys and OAuth tokens, connection configurations may include database passwords (e.g., for Cloud SQL) or API keys.

### Details
There is no documented enforcement of minimum length (8 characters per ASVS, 15 recommended) for any credential field in the connection system. If users store short or weak passwords in Airflow connection password fields for services like Cloud SQL, no minimum length enforcement is documented.

**Affected Files:**
- `providers/google/docs/connections/gcp.rst`
- `providers/google/docs/connections/google_ads.rst`

**ASVS:** 6.2.1 (L1)

### Remediation
Document password length requirements for connection credentials that are user-set. Add a section stating:

"When configuring connection credentials that involve user-set passwords (e.g., database passwords for Cloud SQL connections), passwords must be at least 8 characters in length. A minimum of 15 characters is strongly recommended for all credential fields. Note: Service account keys, OAuth tokens, and other Google-generated credentials are not subject to this policy as they are generated with sufficient entropy by Google Cloud."

### Acceptance Criteria
- [ ] Password length requirements documented
- [ ] Distinction made between user-set and generated credentials
- [ ] Minimum 8 characters required, 15 recommended

### References
- ASVS 6.2.1

### Priority
**Medium** - Missing password policy documentation

---

## Issue: FINDING-022 - Connection documentation does not describe current credential verification requirement
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The connection documentation does not describe a requirement to verify the current credential/password before allowing a credential change. When connection credentials are updated (via UI, REST API, or environment variables), there is no documented requirement for the user to provide the existing credential.

### Details
The documentation does not address:
1. Whether changing a connection's credentials requires presenting the current credential
2. Whether the Airflow connection management interface validates the current password/key before accepting a replacement
3. Authentication requirements for accessing the connection management interface itself

Without requiring the current credential for verification, an attacker with access to the Airflow admin interface could replace connection credentials without proving knowledge of the existing ones.

**Affected Files:**
- `providers/google/docs/connections/gcp.rst` (entire document)

**ASVS:** 6.2.3 (L1)

### Remediation
Document the credential change verification process:

```rst
Changing Connection Credentials
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When updating connection credentials, Airflow requires:

1. Appropriate RBAC permissions (``can_edit`` on Connections)
2. For password-type credentials: the current password must be provided
   alongside the new password to verify authorization
3. All credential changes are audited in Airflow's audit log

For service account key rotation, use Google Cloud IAM's key rotation
features or Secret Manager versioning rather than direct connection edits.
```

### Acceptance Criteria
- [ ] Credential change process documented
- [ ] Current credential verification requirement described
- [ ] RBAC requirements specified
- [ ] Audit logging mentioned

### References
- ASVS 6.2.3

### Priority
**Medium** - Missing credential change policy documentation

---

## Issue: FINDING-023 - No breached password detection documented for user-set credentials
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
Neither the GCP connection documentation nor the Google Ads connection documentation describes any mechanism for checking credentials against known breached password databases (top 3000 or otherwise).

### Details
While Google-generated credentials (service account keys, OAuth tokens) are not subject to breach database checks (they are cryptographically random), any user-set password fields should be verified against known breached passwords.

The documentation does not:
1. Reference any breached password list or API (e.g., Have I Been Pwned, NIST bad password list)
2. Describe validation of credentials during connection creation or update
3. Differentiate between generated credentials (exempt) and user-set passwords (should be checked)

**Affected Files:**
- `providers/google/docs/connections/gcp.rst`
- `providers/google/docs/connections/google_ads.rst`

**ASVS:** 6.2.4 (L1)

### Remediation
Document breached password detection for user-set credentials:

"When user-set passwords are provided in connection configuration (e.g., database passwords for Cloud SQL connections), Airflow validates them against a list of at least 3,000 commonly breached passwords that meet the minimum length requirement. This check applies during: Connection creation and Password/credential changes. Note: This check does not apply to Google-generated credentials such as service account keys, OAuth tokens, or API keys, as these are generated with sufficient cryptographic entropy."

### Acceptance Criteria
- [ ] Breached password detection documented
- [ ] Scope of checks clearly defined
- [ ] Exemptions for generated credentials noted
- [ ] Validation timing described

### References
- ASVS 6.2.4

### Priority
**Medium** - Missing password security documentation

---

## Issue: FINDING-024 - Self-contained tokens cannot be immediately revoked on session termination
**Labels:** security, priority:low
**Description:**
### Summary
The authentication backend uses self-contained tokens (Google JWTs) which cannot be revoked by the application. There is no mechanism (such as a revocation list, per-user token validity timestamp, or token blacklist) to immediately invalidate a previously-accepted token.

### Details
A valid Google ID token will continue to be accepted until its natural expiration (typically 1 hour). After logout or session termination is triggered, a previously valid Google ID token could still be used for API requests until it expires.

**Practical risk is mitigated by:**
1. The `_lookup_user` check validates `user.is_active` on every request
2. Google ID tokens have short lifetimes (typically 3600 seconds)
3. This is a stateless API authentication pattern without server-side sessions

**Affected Files:**
- `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py` (lines 77-93, 108-128)

**ASVS:** 7.4.1 (L1)

### Remediation
For applications requiring immediate token invalidation, implement a per-user 'token not before' timestamp:
```python
if user and user.token_not_before and iat < user.token_not_before:
    return None
```

Check the `iat` claim against a `user.token_not_before` field and reject tokens issued before the session invalidation timestamp.

### Acceptance Criteria
- [ ] Token not before mechanism documented
- [ ] Implementation guidance provided for applications requiring immediate revocation
- [ ] Trade-offs documented

### References
- ASVS 7.4.1

### Priority
**Low** - Mitigated by short token lifetime and active check

---

## Issue: FINDING-025 - No proactive session termination for disabled user accounts in Google OpenID auth backend
**Labels:** security, priority:low
**Description:**
### Summary
While the `_lookup_user` function correctly checks `user.is_active` on each request, this module does not proactively terminate or invalidate any active Airflow web sessions or cached tokens that may exist for the disabled user.

### Details
The responsibility for proactive session termination when a user account is disabled falls entirely on Airflow's core session management system. For API requests through this auth backend, each request independently verifies user status, providing effective mitigation. However, cached `_CredentialsToken` instances in service-to-service auth do not check user account status, though these are service credentials rather than user sessions.

**Affected Files:**
- `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py` (lines 96-104)

**ASVS:** 7.4.2 (L1)

### Remediation
This is properly an Airflow core responsibility. If immediate session termination is required for disabled accounts, implement a signal/event handler at the application level that invalidates all sessions for a user when their account is deactivated.

### Acceptance Criteria
- [ ] Documentation clarifies responsibility boundary
- [ ] Integration guidance provided for core session management
- [ ] Per-request active check confirmed working

### References
- ASVS 7.4.2

### Priority
**Low** - Per-request validation provides effective mitigation

---

## Issue: FINDING-026 - No explicit TLS minimum version enforcement on outbound connections
**Labels:** security, priority:low
**Description:**
### Summary
Code initiates HTTPS connections without explicitly setting `minimum_version = TLSVersion.TLSv1_2`. On Python versions < 3.10 with OpenSSL configurations that haven't deprecated TLS 1.0/1.1, the TLS handshake could potentially negotiate an older TLS version.

### Details
In practice, Google APIs enforce TLS 1.2+ server-side, significantly mitigating this risk. However, explicit client-side enforcement provides defense-in-depth.

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/hooks/cloud_sql.py` (lines 398-405, 286-296)

**ASVS:** 12.1.1 (L1)

### Remediation
Add explicit SSL context with minimum TLS version enforcement:

```python
import ssl
import httpx

ssl_context = ssl.create_default_context()
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

# For httpx
response = httpx.get(download_url, follow_redirects=True, verify=ssl_context)
```

### Acceptance Criteria
- [ ] SSL context with TLS 1.2 minimum configured
- [ ] Applied to all outbound HTTPS connections
- [ ] Tests verify TLS version enforcement

### References
- ASVS 12.1.1

### Priority
**Low** - Mitigated by server-side enforcement

---

## Issue: FINDING-027 - Client-side field filtering in get_query_results() fetches all columns before filtering
**Labels:** bug, performance, priority:low
**Description:**
### Summary
When `selected_fields` is provided to `get_query_results()`, ALL columns are still fetched from BigQuery and materialized into dictionaries before being filtered client-side. This means network bandwidth is consumed for unwanted columns and memory contains the full dataset briefly.

### Details
This contrasts with `list_rows()` which passes `selected_fields` to the API for server-side filtering. If the query returns sensitive columns, they transit through the application even when not requested.

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/hooks/bigquery.py` (line 700)

**ASVS:** 15.3.1 (L1)

### Remediation
The filtering should ideally be done server-side. However, since `job.result()` doesn't support column selection, document this limitation and ensure callers use `list_rows()` with `selected_fields` when possible.

Add documentation:
"Note: selected_fields filtering is applied client-side after full row retrieval. For server-side column filtering, use list_rows() with selected_fields instead."

### Acceptance Criteria
- [ ] Limitation documented in method docstring
- [ ] Guidance to use list_rows() for server-side filtering provided
- [ ] Example added to documentation

### References
- ASVS 15.3.1

### Priority
**Low** - Performance and data minimization concern

---

## Issue: FINDING-028 - BigQueryToSqlOperator transfers all fields by default without enforcement
**Labels:** security, priority:low
**Description:**
### Summary
When `selected_fields` is not specified (default `None`), ALL fields from the BigQuery table are transferred to the destination database without any enforcement of field-level filtering. Sensitive fields in BigQuery tables may be transferred to destination databases with less restrictive access controls.

### Details
While this is by design for a data transfer tool, there is no warning when all fields are being transferred, which could lead to unintended data exposure.

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/transfers/bigquery_to_sql.py` (line 105)

**ASVS:** 15.3.1 (L1)

### Remediation
Consider adding a warning log when `selected_fields` is None:
"No 'selected_fields' specified. All fields from the source table will be transferred. Consider specifying only required fields to minimize data exposure."

### Acceptance Criteria
- [ ] Warning logged when selected_fields is None
- [ ] Documentation updated with data minimization guidance
- [ ] Example showing selective field transfer

### References
- ASVS 15.3.1

### Priority
**Low** - Design as intended, but could benefit from warning

---

## Issue: FINDING-029 - Azure transfer operators lack file size limits when downloading to temporary files
**Labels:** bug, security, priority:low
**Description:**
### Summary
Transfer operators (adls_to_gcs.py, azure_blob_to_gcs.py, azure_fileshare_to_gcs.py) download files from external sources (Azure, ADLS) to temporary files without size limits, potentially exhausting disk space on the worker.

### Details
Large files from Azure sources could fill worker disk space, causing denial of service for co-located tasks.

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/transfers/adls_to_gcs.py`
- `providers/google/src/airflow/providers/google/cloud/transfers/azure_blob_to_gcs.py`
- `providers/google/src/airflow/providers/google/cloud/transfers/azure_fileshare_to_gcs.py`

**ASVS:** 5.2.1 (L1)

### Remediation
Add configurable `max_file_size_bytes` parameter to transfer operators. Validate file size before or during download to temporary files.

### Acceptance Criteria
- [ ] max_file_size_bytes parameter added to all three operators
- [ ] File size validation implemented before download
- [ ] AirflowException raised when limit exceeded
- [ ] Tests added for size limit enforcement

### References
- ASVS 5.2.1

### Priority
**Low** - Requires large files from external source

---

## Issue: FINDING-030 - Missing content-type validation in GCS upload
**Labels:** bug, security, priority:low
**Description:**
### Summary
In the GCS `upload()` function, when a file is uploaded with a specified `mime_type`, there is no validation that the file content actually matches the declared MIME type. Files could be uploaded with incorrect MIME types that could bypass downstream content-based security controls.

### Details
The `mime_type` is set but content is not validated against it. For L1, this is acceptable if no business/security decisions are made based on file type.

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/hooks/gcs.py` (line 450)

**ASVS:** 5.2.2 (L1)

### Remediation
For L2+, add optional content validation using python-magic library to detect actual content type and compare against declared `mime_type`. Raise `AirflowException` on mismatch when `validate_content_type` parameter is enabled.

### Acceptance Criteria
- [ ] Optional validate_content_type parameter added
- [ ] Content type detection using python-magic
- [ ] Validation only enforced when parameter enabled
- [ ] Tests added for content type mismatch scenarios

### References
- ASVS 5.2.2

### Priority
**Low** - L1 acceptable, L2+ enhancement

---

## Issue: FINDING-031 - No validation that downloaded schema object is JSON
**Labels:** bug, security, priority:low
**Description:**
### Summary
In the GCS to BigQuery transfer operator, when downloading a schema file from GCS, there is no validation that the downloaded object is actually a JSON file. No extension check, magic bytes validation, or content-type validation is performed.

### Details
The primary risk is unexpected schema definitions if the file is replaced with valid but malicious JSON. This is mitigated by the JSON parsing step and BigQuery's schema validation.

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_bigquery.py` (line 239)

**ASVS:** 5.2.2 (L1)

### Remediation
Consider adding a JSON schema validator for the schema file structure to ensure it conforms to expected schema definition format.

### Acceptance Criteria
- [ ] JSON schema validation added for schema files
- [ ] Schema structure validated against expected format
- [ ] Tests added for invalid schema formats

### References
- ASVS 5.2.2

### Priority
**Low** - Mitigated by downstream validation

---

## Issue: FINDING-032 - Validation Timing Issue in Text-to-Speech
**Labels:** bug, priority:low
**Description:**
### Summary
The `_validate_inputs()` method in text_to_speech.py is called in `__init__` before template rendering occurs. This timing issue means validation executes before Airflow templates are resolved, potentially missing empty or invalid values.

### Details
Input validation should occur in the `execute()` method to ensure that validation happens as part of the sequential business logic flow, after template rendering is complete.

**Affected Files:**
- `text_to_speech.py`

**ASVS:** 2.2.2, 2.3.1 (L1)

### Remediation
Move validation logic from `__init__` to the `execute()` method to ensure validation occurs after template rendering is complete.

### Acceptance Criteria
- [ ] Validation moved to execute() method
- [ ] Tests verify validation occurs after template rendering
- [ ] Templated values properly validated

### References
- ASVS 2.2.2, 2.3.1

### Priority
**Low** - Validation timing issue

---

## Issue: FINDING-033 - Missing Error State Check After Cluster Restart
**Labels:** bug, priority:low
**Description:**
### Summary
In dataproc.py, the `_reconcile_cluster_state()` method does not call `_handle_error_state()` after restarting a STOPPED cluster. This is inconsistent with the CREATING and DELETING paths which do perform error state checks.

### Details
After restarting a cluster, the operator should verify that the cluster did not enter an error state during the restart process, ensuring complete sequential validation of the business logic flow.

**Affected Files:**
- `dataproc.py`

**ASVS:** 2.3.1 (L1)

### Remediation
Add error state handling after cluster restart in the STOPPED state reconciliation path:

```python
elif cluster.status.state == cluster.status.State.STOPPED:
    self.log.info("Cluster %s is in STOPPED state.", self.cluster_name)
    self._start_cluster(hook)
    cluster = self._get_cluster(hook)
    self._handle_error_state(hook, cluster)  # Add this line
```

### Acceptance Criteria
- [ ] Error state check added after cluster restart
- [ ] Consistent with other state reconciliation paths
- [ ] Tests added for error state after restart

### References
- ASVS 2.3.1

### Priority
**Low** - Missing consistency in error handling

---

## Issue: FINDING-034 - Missing IAM Permission Documentation
**Labels:** documentation, priority:low
**Description:**
### Summary
Operators document the `impersonation_chain` mechanism but do not specify which IAM roles/permissions are required for each operation. This documentation gap makes it difficult for administrators to verify least-privilege configurations.

### Details
Operator documentation does not consistently specify:
- Required IAM permissions with scope
- Minimum IAM roles needed
- Conditional permissions (e.g., when service accounts are specified)

This potentially leads to over-permissioned service accounts being deployed.

**Affected Files:**
- All operator files

**ASVS:** 8.1.1 (L1)

### Remediation
Add comprehensive IAM permission documentation to all operator classes. Include:
- Required IAM Permissions with scope
- Minimum IAM Roles needed
- Conditional permissions

Example:
```python
class DataflowTemplatedJobStartOperator(GoogleCloudBaseOperator):
    """
    Start a Dataflow job from a template.
    
    Required IAM Permissions:
        - dataflow.jobs.create (on the project)
        - dataflow.jobs.get (on the project, for monitoring)
        - iam.serviceAccounts.actAs (on service_account, if specified)
    
    Minimum IAM Roles:
        - roles/dataflow.developer
        - roles/iam.serviceAccountUser (if using custom service account)
    
    :param impersonation_chain: Optional service account to impersonate...
    """
```

### Acceptance Criteria
- [ ] IAM permissions documented for all operators
- [ ] Minimum roles specified
- [ ] Conditional permissions clearly marked
- [ ] Documentation review completed

### References
- ASVS 8.1.1

### Priority
**Low** - Documentation enhancement for least-privilege

---

## Issue: FINDING-035 - Non-Parameterized BigQuery Metadata Query
**Labels:** bug, security, priority:low
**Description:**
### Summary
SQL injection vulnerability in `BigQueryAsyncHook.create_job_for_partition_get()` function. The `table_id` parameter is interpolated directly into a BigQuery SQL WHERE clause using f-strings.

### Details
Practical risk is low because:
- DAG authors are trusted administrators
- BigQuery doesn't support multi-statement queries
- The query targets metadata (INFORMATION_SCHEMA)

However, this violates best practices for parameterized queries.

**Affected Files:**
- `bigquery.py`

**CWE:** CWE-89
**ASVS:** 1.2.4 (L1)

### Remediation
Convert to use BigQuery's native query parameters. Replace the string-interpolated WHERE clause with parameterized query syntax using `@table_name` placeholder, set `parameterMode` to 'NAMED', and provide `queryParameters` array with proper parameter type and value definitions.

### Acceptance Criteria
- [ ] Query converted to use parameterized syntax
- [ ] Parameter mode set to NAMED
- [ ] Query parameters properly defined
- [ ] Tests verify parameterized query execution

### References
- CWE-89
- ASVS 1.2.4
- Related findings: FINDING-002

### Priority
**Low** - Best practice violation, low practical risk

---

## Issue: FINDING-036 - Incorrect Query Parameter Handling in Data Fusion list_pipelines
**Labels:** bug, priority:low
**Description:**
### Summary
Functional bug in datafusion.py `list_pipelines()` function. Query parameters are incorrectly appended as path segments using `os.path.join()` instead of being properly formatted as query string with `?` separator.

### Details
Current code: `if query: url = os.path.join(url, urlencode(query))`

This creates malformed URLs where query parameters appear as path segments.

**Affected Files:**
- `datafusion.py` (line 310)

**ASVS:** 1.2.2 (L1)

### Remediation
Use proper query string separator:
```python
if query:
    url = f"{url}?{urlencode(query)}"
```

### Acceptance Criteria
- [ ] Query string properly formatted with ? separator
- [ ] Tests added for query parameter handling
- [ ] Functional verification of list_pipelines with parameters

### References
- ASVS 1.2.2

### Priority
**Low** - Functional bug, incorrect URL construction

---

## Issue: FINDING-037 - Missing URL Encoding in Cloud SQL Operation Name
**Labels:** bug, security, priority:low
**Description:**
### Summary
Path segments in URL construction are not URL-encoded in cloud_sql.py `CloudSQLAsyncHook.get_operation_name()`. Impact is very low as values originate from trusted DAG authors and are validated by Google APIs.

### Details
Current code: `url = f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{project_id}/operations/{operation_name}"`

URL encoding provides defense-in-depth even when values are trusted.

**Affected Files:**
- `cloud_sql.py` (line 413)

**ASVS:** 1.2.2 (L1)

### Remediation
Apply URL encoding to path parameters:
```python
from urllib.parse import quote
url = f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{quote(project_id, safe='')}/operations/{quote(operation_name, safe='')}"
```

### Acceptance Criteria
- [ ] URL encoding applied to project_id and operation_name
- [ ] Tests added for special characters in parameters

### References
- ASVS 1.2.2

### Priority
**Low** - Defense-in-depth, low practical risk

---

## Issue: FINDING-038 - Missing URL Encoding in Dataproc Metastore UI Links
**Labels:** bug, security, priority:low
**Description:**
### Summary
Path parameters in UI links are not URL-encoded in dataproc_metastore.py functions `DataprocMetastoreLink.get_link()` and `DataprocMetastoreDetailedLink.get_link()`.

### Details
Current code: `return conf["url"].format(region=conf["region"], service_id=conf["service_id"], project_id=conf["project_id"])`

Impact is low as base protocol is hardcoded (https://console.cloud.google.com), preventing protocol injection.

**Affected Files:**
- `dataproc_metastore.py`

**ASVS:** 1.2.2 (L1)

### Remediation
Apply URL encoding to all path parameters:
```python
from urllib.parse import quote
return conf["url"].format(
    region=quote(conf["region"], safe=""),
    service_id=quote(conf["service_id"], safe=""),
    project_id=quote(conf["project_id"], safe="")
)
```

### Acceptance Criteria
- [ ] URL encoding applied to all path parameters
- [ ] Tests added for special characters in parameters
- [ ] UI links verified to work correctly

### References
- ASVS 1.2.2

### Priority
**Low** - Defense-in-depth for UI links

---

## Issue: FINDING-039 - Subprocess Execution with Templated Script Path in GCS Transform Operator
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `transform_script` field is in `template_fields`, enabling Jinja2 rendering. While DAG authors are trusted, this executes on the Airflow worker (not a sandboxed container). If template rendering sources runtime values from untrusted XCom or external variables, arbitrary command execution is possible.

### Details
The `transform_script` (templated operator parameter) flows to cmd list and then to `subprocess.Popen(args=cmd)`. Flagged at LOW because it matches the known false positive pattern about operators executing arbitrary user code, but occurs on the Airflow worker rather than a sandboxed environment.

**Affected Files:**
- `gcs.py` (line 393)

**ASVS:** 1.3.2 (L1)

### Remediation
Add validation to restrict `transform_script` to an allowlist. Example:
```python
ALLOWED_TRANSFORM_SCRIPTS = ["/opt/airflow/scripts/transform.py"]
```

Create a `_validate_transform_script()` method that checks if the script is in the allowlist and raises `AirflowException` if not. Additionally, document that `transform_script` should not source values from untrusted runtime data.

### Acceptance Criteria
- [ ] Allowlist for transform scripts defined
- [ ] Validation method implemented
- [ ] Documentation added warning against untrusted template sources
- [ ] Tests added for allowlist validation

### References
- ASVS 1.3.2

### Priority
**Low** - Trusted DAG authors, but defense-in-depth recommended

---

## Issue: FINDING-040 - Input Validation Rules Scattered Without Centralized Specification
**Labels:** documentation, priority:low
**Description:**
### Summary
Parameters have format expectations described in natural language docstrings but lack formal regex patterns, machine-readable constraints, centralized validation rule definitions, and type annotations with constraints.

### Details
Without centralized validation specifications:
- Developers cannot systematically verify input constraints
- Inconsistent validation across operators
- Harder to audit compliance with business rules
- Reliance on runtime API errors for format validation

**Affected Files:**
- alloy_db.py (request_id UUID format)
- cloud_composer.py (HTTP method values)
- datafusion.py (pipeline_name, version_id, namespace)
- dataproc_metastore.py (table and partition_names)
- dataplex.py (resource identifiers)
- dataprep.py (body_request schema)
- dlp.py (dlp_job_id, template_id)
- gen_ai.py (model name and API key formats)

**ASVS:** 2.1.1 (L1)

### Remediation
Create a centralized validation rules document or schema. Example: Define `VALIDATION_RULES` dictionary with patterns, length constraints, and descriptions for common parameter types (workflow_id, cluster_id, request_id, etc.). Implement validation middleware/decorator for reusable validation across operators. Reference formal validation rules from operator docstrings. Implement as JSON Schema or Pydantic models for machine-readable constraints.

### Acceptance Criteria
- [ ] Centralized validation rules document created
- [ ] Common parameter patterns defined with regex
- [ ] Validation middleware/decorator implemented
- [ ] Operator docstrings reference centralized rules
- [ ] Machine-readable format (JSON Schema or Pydantic)

### References
- ASVS 2.1.1

### Priority
**Low** - Code quality and maintainability improvement

## Issue: FINDING-041 - BigQuery Label Validation Gap
**Labels:** bug, security, priority:low
**Description:**
### Summary
BigQuery label validation using `LABEL_REGEX` is applied to auto-generated labels but not consistently applied to user-provided labels, creating inconsistent validation controls.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.1 (Level L1)
- **Affected Files:** `bigquery.py:1232`
- The `_add_job_labels()` function contains a `LABEL_REGEX` pattern but only applies it to auto-generated labels
- User-provided labels bypass this validation, relying solely on API-level rejection
- This creates inconsistent defense-in-depth where validation exists but isn't uniformly applied

### Remediation
Extend `LABEL_REGEX` validation to all label sources in the `_add_job_labels()` function, including user-provided labels. This provides defense-in-depth against API rejection and ensures consistent validation.

### Acceptance Criteria
- [ ] Fixed: Apply `LABEL_REGEX` validation to all label sources (auto-generated and user-provided)
- [ ] Test added: Unit tests covering user-provided label validation with valid and invalid patterns

### References
- Source Report: 2.2.1.md
- Related Findings: FINDING-042, FINDING-043, FINDING-044, FINDING-045, FINDING-046, FINDING-047

### Priority
Low - Validation gap with API-level fallback protection

---

## Issue: FINDING-042 - Cloud Functions Overly Permissive Regex Patterns
**Labels:** bug, security, priority:low
**Description:**
### Summary
Cloud Functions validation uses overly permissive regex patterns like `^.+$` for structured fields (runtime, timeout, entryPoint) that should have format-specific validation.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.1 (Level L1)
- **Affected Files:** `functions.py:49-52`
- Generic `^.+$` patterns accept any non-empty string
- Fields like `runtime` have expected formats (e.g., 'python39', 'nodejs16') that aren't validated
- This allows malformed inputs to pass client-side validation and fail at API level

### Remediation
Replace generic `^.+$` patterns with specific validation patterns for each field type:
- Runtime: `^[a-z]+\d+(\.\d+)?$` to match formats like 'python39' or 'nodejs16'
- Timeout: Numeric validation with range constraints
- EntryPoint: Valid function name pattern

### Acceptance Criteria
- [ ] Fixed: Implement field-specific regex patterns for runtime, timeout, and entryPoint
- [ ] Test added: Unit tests for valid and invalid format strings for each field type

### References
- Source Report: 2.2.1.md
- Related Findings: FINDING-041, FINDING-043, FINDING-044, FINDING-045, FINDING-046, FINDING-047

### Priority
Low - Permissive validation with API-level enforcement

---

## Issue: FINDING-043 - Dataflow Missing None-Check in Job Name Append Function
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `_append_uuid_to_job_name()` function in Dataflow lacks None-check and structure validation before accessing nested body fields, risking AttributeError or TypeError.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.1 (Level L1)
- **Affected Files:** `dataflow.py:464-469`
- Function directly accesses nested fields without validating body structure
- Missing validation that body is a dictionary with expected keys
- Could lead to runtime exceptions if body is None or malformed

### Remediation
Add None-check and structure validation before accessing nested body fields:
```python
if body is None or not isinstance(body, dict):
    raise ValueError("Invalid body structure")
if 'expected_key' not in body:
    raise ValueError("Missing required field in body")
```

### Acceptance Criteria
- [ ] Fixed: Add structure validation at function entry
- [ ] Test added: Unit tests for None body, non-dict body, and missing keys

### References
- Source Report: 2.2.1.md
- Related Findings: FINDING-041, FINDING-042, FINDING-044, FINDING-045, FINDING-046, FINDING-047

### Priority
Low - Defensive coding improvement

---

## Issue: FINDING-044 - Transfer Service Delayed Validation Timing
**Labels:** bug, security, priority:low
**Description:**
### Summary
Transfer Service `request_filter` parameter validation occurs in `execute()` method instead of `__init__()`, delaying error detection from DAG parse time to runtime.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.1 (Level L1)
- **Affected Files:** `cloud_storage_transfer_service.py:426`
- Validation happens at execution time rather than initialization
- Configuration errors discovered late in the workflow
- Reduces fail-fast behavior and increases debugging time

### Remediation
Move `request_filter` validation to the `__init__()` method to provide early validation and fail-fast behavior. This catches configuration errors at DAG parse time rather than execution time, improving developer experience and reducing runtime failures.

### Acceptance Criteria
- [ ] Fixed: Move validation logic from `execute()` to `__init__()`
- [ ] Test added: Unit tests verifying validation occurs at initialization

### References
- Source Report: 2.2.1.md
- Related Findings: FINDING-041, FINDING-042, FINDING-043, FINDING-045, FINDING-046, FINDING-047

### Priority
Low - Timing improvement for better developer experience

---

## Issue: FINDING-045 - Dataplex Catalog Inconsistent Validation Pattern
**Labels:** bug, security, priority:low
**Description:**
### Summary
Dataplex catalog operators apply `_validate_fields()` only in Entry creation but not in other catalog operators, creating inconsistent validation across similar operations.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.1 (Level L1)
- **Affected Files:** `dataplex.py`
- Entry creation operator has validation pattern
- Other catalog operators performing similar operations lack this validation
- Inconsistent security posture across functionally similar code paths

### Remediation
Extend `_validate_fields()` pattern to all Dataplex catalog operators to ensure consistent validation across similar operations. Identify all catalog operators and apply uniform validation standards.

### Acceptance Criteria
- [ ] Fixed: Apply `_validate_fields()` to all Dataplex catalog operators
- [ ] Test added: Validation tests for all catalog operator types

### References
- Source Report: 2.2.1.md
- Related Findings: FINDING-041, FINDING-042, FINDING-043, FINDING-044, FINDING-046, FINDING-047

### Priority
Low - Consistency improvement across operator family

---

## Issue: FINDING-046 - Text-to-Speech Validation Pattern Not Extended to Other Operators
**Labels:** bug, security, priority:low
**Description:**
### Summary
Text-to-Speech implements `_validate_inputs()` pattern but this validation approach is not standardized or extended to other operators that could benefit from similar input validation.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.1 (Level L1)
- **Affected Files:** `text_to_speech.py:127`
- Good validation pattern exists but isn't reused
- Other operators with required parameters lack consistent validation
- Missed opportunity for standardized fail-fast behavior

### Remediation
Standardize and extend the `_validate_inputs()` pattern to all operators with required parameters. Create a base validation mixin or utility function that can be reused across operators for consistent fail-fast behavior and clear error messages.

### Acceptance Criteria
- [ ] Fixed: Create reusable validation pattern/mixin
- [ ] Test added: Apply to at least 3 additional operator types with tests

### References
- Source Report: 2.2.1.md
- Related Findings: FINDING-041, FINDING-042, FINDING-043, FINDING-044, FINDING-045, FINDING-047

### Priority
Low - Code quality and consistency improvement

---

## Issue: FINDING-047 - Vertex AI Format Constraints Not Enforced
**Labels:** bug, security, priority:low
**Description:**
### Summary
Vertex AI operators document format constraints for parameters like `endpoint_id` and `cluster_name` in docstrings but do not enforce these constraints in code.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.1 (Level L1)
- **Affected Files:** `endpoint_service.py`, `ray.py`
- Docstrings describe expected formats
- No validation logic enforces documented constraints
- Relies entirely on server-side validation
- Documentation-code mismatch

### Remediation
Implement validation for documented format constraints. Add regex patterns or other validation logic to enforce the constraints described in docstrings, providing fail-fast behavior and better error messages. Ensure documentation and validation logic stay synchronized.

### Acceptance Criteria
- [ ] Fixed: Implement validation matching all documented format constraints
- [ ] Test added: Tests covering valid and invalid formats per documentation

### References
- Source Report: 2.2.1.md
- Related Findings: FINDING-041, FINDING-042, FINDING-043, FINDING-044, FINDING-045, FINDING-046

### Priority
Low - Documentation-code alignment improvement

---

## Issue: FINDING-048 - Error Responses from Authentication Decorator Missing CORS Headers
**Labels:** bug, security, priority:low
**Description:**
### Summary
Error responses (401/403) returned directly from the authentication decorator do not include CORS headers, potentially causing inconsistent behavior if CORS is configured at middleware level.

### Details
- **CWE:** Not assigned
- **ASVS:** 3.4.2 (Level L1)
- **Affected Files:** `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:131,135,139`
- Absence of CORS headers defaults to restrictive same-origin policy (secure)
- May cause inconsistency if middleware adds CORS to successful responses
- Legitimate cross-origin clients with invalid tokens receive confusing errors
- Module deprecated for Airflow 3

### Remediation
1. Verify no middleware adds wildcard or reflected `Access-Control-Allow-Origin` to error responses
2. Ensure CORS configuration is consistent across success and error responses
3. For Airflow 3 replacement, implement CORS with explicit allowlist at middleware level
4. If cross-origin access required, configure validated allowlist of origins

### Acceptance Criteria
- [ ] Fixed: Document CORS behavior for error responses or implement consistent headers
- [ ] Test added: Verify CORS header consistency across response types

### References
- Source Report: 3.4.2.md

### Priority
Low - Secure default with potential UX improvement

---

## Issue: FINDING-049 - Authentication Decorator Missing HTTP Method and Sec-Fetch-* Validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `requires_authentication` decorator performs no HTTP method or `Sec-Fetch-*` header validation, allowing any HTTP method to pass through without verification.

### Details
- **CWE:** Not assigned
- **ASVS:** 3.5.3 (Level L1)
- **Affected Files:** `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:123-145`
- Requests of any method (GET, HEAD, OPTIONS) pass through
- State-changing operations could be triggered via safe HTTP methods
- Potential for bookmark/history replay if token leaked
- Bearer token requirement prevents unsigned cross-origin abuse
- Module deprecated for removal

### Remediation
1. Add `Sec-Fetch-Site` header validation in decorator for defense-in-depth
   - Check if value is in ("same-origin", "same-site", "none")
   - Return 403 Forbidden if not
2. Ensure all Flask routes using `@requires_authentication` that handle state-changing operations specify `methods=['POST']` at route registration level
3. Document that method enforcement is primary responsibility of route configuration

### Acceptance Criteria
- [ ] Fixed: Add optional Sec-Fetch-* validation to decorator
- [ ] Test added: Verify method restrictions at route level for state-changing endpoints

### References
- Source Report: 3.5.3.md

### Priority
Low - Defense-in-depth enhancement for deprecated module

---

## Issue: FINDING-050 - Protobuf Not Classified as Component with Dangerous Functionality
**Labels:** bug, security, priority:low
**Description:**
### Summary
The protobuf library performs binary data parsing and deserialization (dangerous functionality per ASVS 15.1.1) but is not documented as requiring elevated security attention or faster remediation cycles.

### Details
- **CWE:** Not assigned
- **ASVS:** 15.1.1 (Level L1)
- **Affected Files:** `providers/google/src/airflow/providers/google/cloud/hooks/stackdriver.py:30`
- Protobuf performs binary parsing - explicitly classified as dangerous in ASVS
- Well-maintained Google library but vulnerabilities tend toward high severity (DoS, memory corruption)
- No classification means same update priority as less critical dependencies
- Missing from dangerous functionality component registry

### Remediation
1. Create/update documented 'dangerous functionality' component registry
2. Include protobuf with classification: "binary data parsing and deserialization"
3. Assign accelerated remediation timeframes for protobuf vulnerabilities
4. Document elevated security attention requirements

### Acceptance Criteria
- [ ] Fixed: Add protobuf to dangerous functionality registry with classification
- [ ] Test added: Document and verify accelerated remediation process exists

### References
- Source Report: 15.1.1.md

### Priority
Low - Process documentation improvement

---

## Issue: FINDING-051 - No Automated Alerting for Logging Dependencies Breaching Update Timeframes
**Labels:** bug, security, priority:low
**Description:**
### Summary
While `uv.lock` provides version pinning, no automated alerting or blocking mechanism prevents deployments with components that have breached remediation timeframes.

### Details
- **CWE:** Not assigned
- **ASVS:** 15.2.1 (Level L1)
- **Affected Files:** CI/CD pipeline
- Process control gap rather than immediate vulnerability
- uv.lock provides foundation but lacks enforcement mechanism
- No CI gates block merges for dependencies exceeding remediation timeframes
- Missing component inventory tracking last-verified dates

### Remediation
1. Implement CI gates blocking merges when dependencies have known vulnerabilities exceeding remediation timeframe
2. Configure tools like pip-audit, safety, or GitHub Dependabot with severity-based policies
3. Create `dependency-compliance.toml` tracking:
   - current_version
   - last_security_review
   - known_cves
   - status
4. Add GitHub Actions workflow for weekly dependency compliance checks and PR validation

### Acceptance Criteria
- [ ] Fixed: Implement CI gate blocking vulnerable dependencies
- [ ] Test added: Verify gate blocks PRs with out-of-compliance dependencies

### References
- Source Report: 15.2.1.md

### Priority
Low - Process automation improvement

---

## Issue: FINDING-052 - Missing Rate Limiting Guidance for Google Ads OAuth2 Credential Management
**Labels:** bug, security, priority:low
**Description:**
### Summary
Google Ads connection documentation stores OAuth2 client secrets and refresh tokens but provides no guidance on rate limiting or anti-automation for credential management operations.

### Details
- **CWE:** Not assigned
- **ASVS:** 6.1.1 (Level L1)
- **Affected Files:** `providers/google/docs/connections/google_ads.rst` (entire document)
- Documentation gap for OAuth2 credential management protection
- No guidance on rate limiting for credential operations
- Missing reference to anti-automation controls
- OAuth2 credentials stored but protection mechanisms undocumented

### Remediation
Add security note to documentation:
1. Reference Airflow's core authentication controls
2. Mention Google Ads API-level rate limiting protections
3. Link to relevant Airflow security documentation
4. Brief guidance on credential management best practices

### Acceptance Criteria
- [ ] Fixed: Add security section to google_ads.rst documentation
- [ ] Test added: Documentation review confirms security guidance present

### References
- Source Report: 6.1.1.md

### Priority
Low - Documentation enhancement