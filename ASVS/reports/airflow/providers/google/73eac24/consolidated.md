# Security Audit Consolidated Report — apache/airflow/providers/google

## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | apache/airflow/providers/google |
| **ASVS Level** | L1 |
| **Severity Threshold** | None (all findings included) |
| **Commit** | N/A |
| **Date** | May 15, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 70 |
| **Total Findings** | 52 |

## Executive Summary

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 2 |
| Medium | 21 |
| Low | 29 |
| Info | 0 |

### Level Coverage

All 52 findings are mapped to ASVS Level 1 (L1) requirements across 11 audited domains: input validation and injection, deployment and configuration, HTTP security headers, cryptographic operations, password and credential management, secret management, logging and monitoring, network security, Google Cloud authentication, operator execution security, and data transfer and storage.

### Top 5 Risks

1. **Path Traversal in File Sync Operations (FINDING-001, FINDING-007, FINDING-008, FINDING-009, FINDING-010, FINDING-014, FINDING-015)** — Multiple path traversal vulnerabilities exist across GCS sync, SFTP transfer, Gen AI output writing, and Cloud Composer DAG trigger functions. Malicious object names or user-controlled path components can escape intended directories, potentially enabling arbitrary file read/write on the Airflow worker filesystem.

2. **SQL Injection in Dataproc Metastore HiveQL Queries (FINDING-002)** — User-supplied input is interpolated directly into HiveQL queries executed against Dataproc Metastore without parameterization, enabling potential data exfiltration or schema manipulation by DAG authors or upstream data sources.

3. **Unbounded Data Downloads Without Size Validation (FINDING-005, FINDING-006, FINDING-029)** — The GCS `download()` method, `http_to_gcs` operator, and Azure transfer operators do not enforce file size limits before loading content into memory or writing to local disk, creating denial-of-service and resource exhaustion risks on Airflow workers.

4. **Missing Security Headers and Session Controls on Authentication Responses (FINDING-003, FINDING-017, FINDING-018, FINDING-048, FINDING-049)** — The Google OpenID authentication backend does not regenerate session tokens on login, omits Strict-Transport-Security and CORS headers on error responses, and does not enforce HTTP method restrictions, weakening transport-layer and session-level protections.

5. **Deferrable Mode Bypasses Resource Cleanup (FINDING-012, FINDING-013)** — When S3ToGCS and GCSToGCS operators execute in deferrable mode, the job deletion logic is skipped, leaving orphaned transfer jobs that may accumulate and re-execute unexpectedly, violating secure resource lifecycle management.

### Positive Controls Observed

The audit identified substantial positive security architecture across the codebase:

- **Delegation to Google's managed security infrastructure** — Cryptographic operations are fully delegated to Cloud KMS (AES-256-GCM enforced server-side), authentication leverages Google's OAuth2/OpenID infrastructure, and secret management uses GCP Secret Manager with IAM-based access control. No local key material handling or custom cryptographic primitives were found.

- **Robust token validation chain** — The `google_openid.py` authentication backend implements a complete multi-layer verification pipeline: cryptographic signature verification → issuer allowlist check → audience validation → email verification → user database lookup → active status check, with fail-closed behavior on any error.

- **Secret hygiene** — Secret values are never cached in memory, never logged, and never transmitted in URLs. The `is_valid_secret_name` function enforces `^[a-zA-Z0-9-_]*$` to prevent injection via secret identifiers.

- **Safe-by-default configuration** — The AUDIENCE constant uses a placeholder value that causes token rejection until explicitly configured, preventing accidental deployment with permissive defaults.

- **Proactive credential lifecycle management** — The `_CredentialsToken` class implements half-lifetime refresh strategy for access tokens, and the codebase exclusively uses service account and OAuth2 token authentication with no deprecated grant types (implicit flow, resource owner password credentials).

---

## 3. Findings

### 3.2 High

#### FINDING-001: 🟠 Path Traversal in sync_to_local_dir Function

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS Sections** | 5.3.2 |
| **Files** | providers/google/src/airflow/providers/google/cloud/hooks/gcs.py:760-790 |
| **Source Reports** | 5.3.2.md |
| **Related** | FINDING-007, FINDING-008, FINDING-009, FINDING-010, FINDING-015 |

**Description:**

The sync_to_local_dir() function in gcs.py does not validate that resolved file paths remain within the intended local directory. GCS blob names (untrusted if bucket has shared write access) are used directly to construct local file paths via Path.joinpath() without checking if the resolved path escapes the base directory. An attacker with write access to the GCS bucket can create blobs with names containing path traversal sequences (../) to write files to arbitrary locations on the local filesystem.

**Remediation:**

Add path traversal protection by resolving both the base directory and target path, then validating that the target is relative to the base using Path.is_relative_to(). Log and skip any blobs that would resolve outside the intended directory. Use Path.resolve() to normalize paths before comparison.

---

#### FINDING-002: 🟠 SQL Injection in Dataproc Metastore HiveQL Queries

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-89 |
| **ASVS Sections** | 1.2.4, 2.2.1 |
| **Files** | dataproc_metastore.py:459-516 |
| **Source Reports** | 1.2.4.md, 2.2.1.md |
| **Related** | FINDING-035 |

**Description:**

SQL injection vulnerability in list_hive_partitions() function. The table and partition_names parameters are interpolated directly into a HiveQL query using f-strings without sanitization or parameterization. Data flows from DAG parameters (user-controlled) through f-string interpolation into SQL queries executed on Dataproc Metastore. An attacker can inject malicious SQL by crafting table names like `'; DROP TABLE PARTITIONS; --` or partition names like `ds=1' OR '1'='1`. This is exploitable if DAG parameters are sourced from XCom, trigger parameters, or external systems, potentially allowing attackers to read, modify, or delete metadata. While DAG authors are trusted administrators per Airflow's security model, this violates the principle that SQL should be parameterized, not string-interpolated.

**Remediation:**

Add identifier validation using regex to sanitize SQL identifiers. Implement a _sanitize_identifier() method that validates input against a whitelist pattern (e.g., '^[a-zA-Z_][a-zA-Z0-9_]{0,127}$' for table names and '^[a-zA-Z_][a-zA-Z0-9_]*=[^;'\"\\\\]+$' for partition names) and raises ValueError for invalid identifiers. Apply this sanitization to both table and partition_names parameters before query construction.

### 3.3 Medium

#### FINDING-003: No session token regeneration on authentication in Google OpenID backend

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 7.2.4 |
| Files | providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:108-128 |
| Source Reports | 7.2.4.md |
| Related | - |

**Description:**

The authentication backend verifies the user's identity but does not trigger the generation of a new Airflow session token. It only sets the user context for the current request via `_set_current_user`. While this is a stateless API authentication pattern (each request is independently verified), if Flask/FAB creates or extends a session cookie as a side effect of `_update_request_context_with_user`, the existing session is reused rather than regenerated. If this backend is used in conjunction with Flask sessions, session fixation could theoretically occur. An attacker who obtains a pre-authentication session ID could maintain access through a legitimate user's authentication. Mitigating context: This is explicitly documented as an API auth backend for Airflow 2.x (deprecated for Airflow 3). The stateless per-request verification pattern means no persistent session state is maintained by this module itself.

**Remediation:**

If this backend is used with session cookies, add session regeneration after successful authentication: `from flask import session` and after successful authentication call `_set_current_user(user)` followed by `session.regenerate()` or equivalent Flask-Login mechanism.

---

#### FINDING-004: Non-SSL public database connections transmit credentials in cleartext

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 12.2.1 |
| Files | providers/google/src/airflow/providers/google/cloud/hooks/cloud_sql.py:710-714, providers/google/src/airflow/providers/google/cloud/hooks/cloud_sql.py:973-1018, providers/google/src/airflow/providers/google/cloud/hooks/cloud_sql.py:1020-1083, providers/google/src/airflow/providers/google/cloud/hooks/cloud_sql.py:999-1002 |
| Source Reports | 12.2.1.md |
| Related | - |

**Description:**

While database connections use wire protocols (PostgreSQL/MySQL) rather than HTTP, the code allows creating direct public internet connections without any transport encryption when use_proxy=False and use_ssl=False. This sends database credentials (username/password) unencrypted. The default configuration (use_proxy=False, use_ssl=False) is the least secure path. A connection configured with use_proxy=False and use_ssl=False results in a connection URI of postgresql://user:password@&lt;public_ip&gt;:5432/db where all traffic including authentication is unencrypted.

**Remediation:**

Consider logging a warning or raising an error when use_proxy=False and use_ssl=False for public connections. Add a runtime warning for unencrypted public database connections. Consider making use_ssl=True the default for public (non-proxy) connections in a future major version, requiring explicit opt-out for unencrypted connections. Example implementation: Add validation in _validate_inputs() to log a warning when neither Cloud SQL Proxy nor SSL is configured, informing users that database credentials will be transmitted unencrypted and recommending use_proxy=True or use_ssl=True for production use.

---

#### FINDING-005: GCS download() method lacks file size validation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 5.2.1 |
| Files | providers/google/src/airflow/providers/google/cloud/hooks/gcs.py:300 |
| Source Reports | 5.2.1.md |
| Related | - |

**Description:**

The download() method in GCS hook downloads objects to local filesystem without checking file size beforehand. A GCS bucket containing a multi-GB object can be synced to a worker with limited disk space, causing disk exhaustion and potential denial of service for co-located tasks. The hook explicitly acknowledges this gap via a TODO comment but has not implemented any mitigation.

**Remediation:**

Add optional aggregate size limit (max_total_bytes) and per-file size limit (max_file_bytes) parameters. For each blob, reload metadata to get size, validate against per-file limit, track cumulative bytes downloaded, and raise AirflowException if aggregate limit would be exceeded.

---

#### FINDING-006: http_to_gcs operator loads entire HTTP response into memory without size validation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 5.2.1 |
| Files | providers/google/src/airflow/providers/google/cloud/transfers/http_to_gcs.py:168 |
| Source Reports | 5.2.1.md |
| Related | - |

**Description:**

The execute() method loads the entire HTTP response into memory via response.content before uploading to GCS, with no maximum response size validation. If the configured HTTP endpoint returns a response of several GB (maliciously or due to misconfiguration), the worker's memory will be exhausted, causing OOM and potential denial of service to other tasks running on the same worker.

**Remediation:**

Add configurable MAX_RESPONSE_SIZE limit (e.g., 5GB). Use streaming mode for HTTP requests. Check Content-Length header if available and validate against limit before loading content. Consider streaming upload directly to GCS when possible to avoid loading entire response into memory.

---

#### FINDING-007: Path Traversal in _calculate_sync_destination_path Function

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-22 |
| ASVS sections | 5.3.2 |
| Files | providers/google/src/airflow/providers/google/cloud/hooks/gcs.py:850 |
| Source Reports | 5.3.2.md |
| Related | FINDING-001, FINDING-008, FINDING-009, FINDING-010, FINDING-015 |

**Description:**

The _calculate_sync_destination_path() function uses os.path.join() without sanitizing the blob name suffix. If the remaining blob name after prefix stripping starts with '/', os.path.join() treats it as an absolute path on POSIX systems, overwriting the destination prefix. This causes objects to be written to unintended GCS paths outside the intended prefix namespace.

**Remediation:**

Strip leading slashes from the relative blob name using lstrip('/') and remove path traversal components (. and ..) by filtering split path parts. Use string concatenation with explicit separator rather than os.path.join() to prevent absolute path interpretation.

---

#### FINDING-008: Path Traversal in GCS to SFTP Transfer Operator

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-22 |
| ASVS sections | 5.3.2 |
| Files | providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_sftp.py:156, providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_sftp.py:130 |
| Source Reports | 5.3.2.md |
| Related | FINDING-001, FINDING-007, FINDING-009, FINDING-010, FINDING-015 |

**Description:**

The _resolve_destination_path() function in gcs_to_sftp.py does not sanitize GCS object names before constructing SFTP destination paths. When keep_directory_structure=True, GCS object names containing path traversal sequences (../) are passed directly to os.path.join() and then to sftp_hook.store_file(). An attacker with write access to the source GCS bucket can create objects with crafted names to write files to arbitrary locations on the SFTP server.

**Remediation:**

Normalize the destination path using os.path.normpath() and validate that it starts with the base destination_path. Raise AirflowException if the resolved path would escape the intended directory. Add validation before calling sftp_hook.store_file().

---

#### FINDING-009: Inconsistent Path Sanitization in GCS to SFTP with Prefix

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-22 |
| ASVS sections | 5.3.2 |
| Files | providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_sftp.py:156 |
| Source Reports | 5.3.2.md |
| Related | FINDING-001, FINDING-007, FINDING-008, FINDING-010, FINDING-015 |

**Description:**

The _resolve_destination_path() function in gcs_to_sftp.py uses os.path.relpath() when keep_directory_structure=False and a prefix is provided. This function can produce ../ sequences when there is a mismatch between the source object path and the prefix, potentially leading to path traversal on the SFTP server. Lower severity because the os.path.basename() fallback (when no prefix is used) is safe.

**Remediation:**

Apply the same path normalization and containment validation as recommended for DATA-11. Validate that the result of os.path.relpath() does not contain .. components before using it to construct the destination path.

---

#### FINDING-010: Path Traversal in Gen AI Result File Writing

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-22 |
| ASVS sections | 1.2.5 |
| Files | gen_ai.py:388, gen_ai.py:616 |
| Source Reports | 1.2.5.md, 2.3.1.md |
| Related | FINDING-001, FINDING-007, FINDING-008, FINDING-009, FINDING-015 |

**Description:**

The _prepare_results_for_xcom() function in gen_ai.py constructs file paths using unsanitized job.display_name or job.name values. An attacker who can control these values could use path traversal sequences (e.g., '../../etc/cron.d/malicious') to write arbitrary files on the Airflow worker node. The vulnerable code uses os.path.abspath() which resolves path traversal sequences but does not validate that the resulting path remains within the intended results_folder directory.

**Remediation:**

Sanitize the file name using os.path.basename() to remove any directory components, strip '..' sequences, and validate that the resolved path remains within the results_folder directory before writing. Implement strict validation: safe_file_name = os.path.basename(file_name).replace('..', ''); path_to_file = os.path.join(os.path.abspath(self.results_folder), f'{safe_file_name}.jsonl'); if not path_to_file.startswith(os.path.abspath(self.results_folder)): raise AirflowException(f'Path {path_to_file} escapes results_folder')

---

#### FINDING-011: Missing Reserved Flag Validation in Dataflow YAML Jobs

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 2.2.2 |
| Files | dataflow.py:555 |
| Source Reports | 2.2.2.md, 2.3.1.md |
| Related | - |

**Description:**

The launch_beam_yaml_job() function in dataflow.py allows user-supplied options to override reserved flags including project, format, and region. When options dictionary is provided, it can override critical parameters like project_id, potentially causing jobs to run in unintended projects or breaking job ID parsing by overriding the format flag. DAG authors could accidentally run jobs in wrong project or break job ID parsing.

**Remediation:**

Implement reserved flag protection by defining RESERVED_FLAGS set containing 'project', 'format', 'region', 'yaml-pipeline-file', and 'jinja-variables'. Before updating gcp_flags with user options, check for conflicts and raise AirflowException if any reserved flags are present in the options dictionary.

---

#### FINDING-012: Deferrable Mode Skips Job Deletion in S3ToGCS Operator

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 2.3.1 |
| Files | cloud_storage_transfer_service.py |
| Source Reports | 2.3.1.md |
| Related | - |

**Description:**

The S3ToGCS operator in cloud_storage_transfer_service.py skips the job deletion step when operating in deferrable mode. In non-deferrable mode, the operator correctly waits for the transfer job to complete and then deletes it if delete_job_after_completion is True. However, the execute_complete callback for deferrable mode does not implement the deletion logic, causing transfer jobs to persist indefinitely despite the delete_job_after_completion=True setting. This represents a business logic flow inconsistency where a critical cleanup step is skipped based on execution mode.

**Remediation:**

Add deletion logic to the execute_complete callback method:

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

---

#### FINDING-013: Deferrable Mode Skips Job Deletion in GCSToGCS Operator

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 2.3.1 |
| Files | cloud_storage_transfer_service.py |
| Source Reports | 2.3.1.md |
| Related | - |

**Description:**

The GCSToGCS operator in cloud_storage_transfer_service.py skips the job deletion step when operating in deferrable mode. In non-deferrable mode, the operator correctly waits for the transfer job to complete and then deletes it if delete_job_after_completion is True. However, the execute_complete callback for deferrable mode does not implement the deletion logic, causing transfer jobs to persist indefinitely despite the delete_job_after_completion=True setting. This represents a business logic flow inconsistency where a critical cleanup step is skipped based on execution mode.

**Remediation:**

Add deletion logic to the execute_complete callback method:

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

---

#### FINDING-014: Path Traversal in Cloud Composer DAG Trigger

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 1.2.2 |
| Files | cloud_composer.py |
| Source Reports | 1.2.2.md |
| Related | - |

**Description:**

Path traversal vulnerability in authenticated HTTP requests to Composer Airflow web server. The composer_dag_id parameter flows from operator parameter through f-string interpolation to urljoin() to HTTP request without URL encoding. While DAG authors are trusted administrators, URL encoding is a defense-in-depth measure and aligns with best practices. Proof of concept: composer_dag_id = '../../admin' results in /api/v1/dags/../../admin/dagRuns which after urljoin becomes https://composer-env.example.com/admin/dagRuns

**Remediation:**

Apply urllib.parse.quote() to composer_dag_id before interpolation: from urllib.parse import quote; safe_dag_id = quote(composer_dag_id, safe=''); resource_path = f"/api/{self.get_airflow_rest_api_version(composer_airflow_version)}/dags/{safe_dag_id}/dagRuns". Affected methods: trigger_dag_run, get_dag_runs, get_task_instances in both CloudComposerHook and CloudComposerAsyncHook (6 methods total).

---

#### FINDING-015: Path Traversal in GCS Sync to Local Directory

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-22 |
| ASVS sections | 2.2.1 |
| Files | gcs.py:557 |
| Source Reports | 2.2.1.md |
| Related | FINDING-001, FINDING-007, FINDING-008, FINDING-009, FINDING-010 |

**Description:**

Path traversal vulnerability in GCS sync functionality. The sync_to_local_dir function constructs local file paths from GCS blob names without validating that the resulting path stays within the intended directory. Data flows from GCS blob names (attacker-controllable) through Path operations that preserve '..' sequences, allowing writes outside the target directory. An attacker can create a GCS object named `data/../../tmp/exploit_payload` which, when synced with prefix `data/`, results in writing to `/tmp/exploit_payload` instead of the intended sync directory. This enables writing arbitrary files to the Airflow worker filesystem, potential code execution by overwriting Python imports, and configuration manipulation.

**Remediation:**

Add path validation to ensure constructed paths remain within the intended directory. Use .resolve() to normalize paths and validate that the resolved target path starts with the resolved base directory path. Skip blobs that attempt path traversal with a warning log. Example implementation shows checking `if not str(local_target_path).startswith(str(local_dir_path) + os.sep)` before writing files.

---

#### FINDING-016: Inconsistent URL Encoding in DataFusion Pipeline Operations

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-116 |
| ASVS sections | 1.2.2, 2.2.1 |
| Files | datafusion.py:282-286 |
| Source Reports | 1.2.2.md, 2.2.1.md |
| Related | - |

**Description:**

Inconsistent application of URL encoding in DataFusion pipeline operations. The delete_pipeline function uses quote() for the pipeline_name parameter but fails to apply URL encoding to the version_id parameter when constructing API URLs. This is a Type B gap where the security control exists but is not consistently applied. The missing encoding for version_id could allow URL path injection via crafted version identifiers, potentially redirecting API requests to unintended endpoints.

**Remediation:**

Apply URL encoding consistently to all user-provided parameters in URL construction. Add quote() call for version_id: `url = os.path.join(url, 'versions', quote(version_id, safe=''))`. Audit all URL construction in the file to ensure consistent encoding of dynamic parameters.

---

#### FINDING-017: Error responses served with incorrect Content-Type (text/html for plain text bodies)

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 3.2.1, 3.2.2, 4.1.1 |
| Files | providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:131, providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:135, providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:139 |
| Source Reports | 3.2.1.md, 3.2.2.md, 4.1.1.md |
| Related | - |

**Description:**

Flask's Response class defaults to mimetype='text/html' when no explicit content type is specified. The response bodies ("Unauthorized", "Forbidden") are plain text strings, not HTML documents. The Content-Type: text/html; charset=utf-8 header does not match the actual content of the response body. This violates multiple ASVS requirements: (1) ASVS 4.1.1 requires Content-Type must match actual response content, (2) ASVS 3.2.1 requires security controls to prevent browsers from rendering content in an incorrect context, and (3) ASVS 3.2.2 requires text content to be handled to prevent unintended execution. While no user-controlled data is reflected in these specific responses (mitigating XSS risk), serving plain text as HTML sets a poor precedent and could enable content-sniffing attacks if the pattern is replicated elsewhere with dynamic content. Browsers may attempt to parse the response as HTML, though the static content prevents actual exploitation.

**Remediation:**

Specify the correct content type explicitly: `return Response("Unauthorized", 401, content_type="text/plain; charset=utf-8")` for all three response objects (lines 131, 135, 139). Alternatively, use JSON responses with proper content type for API consistency by creating an error response factory function that returns `Response(json.dumps({"error": message}), status=status, content_type="application/json; charset=utf-8")`.

---

#### FINDING-018: Missing Strict-Transport-Security header on authentication error responses

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 3.4.1 |
| Files | providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:131, providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:135, providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:139 |
| Source Reports | 3.4.1.md |
| Related | - |

**Description:**

The HTTP responses generated directly by this authentication backend (401 and 403 error responses) do not include a Strict-Transport-Security header. HSTS should be present on all responses including error responses, to ensure that even failed authentication attempts inform the browser to enforce HTTPS-only connections. These three response paths bypass any downstream middleware that might add HSTS headers to successful responses, since the function returns early before the wrapped function executes. If an attacker can downgrade the connection to HTTP (e.g., on first visit or after HSTS expiry), they could intercept subsequent Bearer tokens. Without HSTS on error responses, the browser doesn't learn to enforce HTTPS if only error responses are received.

**Remediation:**

HSTS should ideally be configured at the Flask application middleware level (e.g., using `flask-talisman` or `after_request` hook) to ensure all responses include it. Better approach is application-wide middleware using `@app.after_request` to add security headers with `response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"`. If middleware is not possible, add it to the direct responses: `HSTS_HEADER = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}` and `return Response("Unauthorized", 401, headers=HSTS_HEADER, content_type="text/plain")`.

---

#### FINDING-019: No documented risk-based remediation timeframes for 3rd party logging component vulnerabilities

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 15.1.1, 15.2.1 |
| Files | Repository-wide (specifically providers/google/ logging domain), stackdriver_task_handler.py, gcs_task_handler.py, stackdriver.py |
| Source Reports | 15.1.1.md, 15.2.1.md |
| Related | - |

**Description:**

The provided codebase and documentation (AGENTS.md) do not define risk-based remediation timeframes for vulnerabilities found in third-party components used by the logging infrastructure. The domain context explicitly requires: 'Documentation must define risk-based remediation timeframes for vulnerabilities in logging components.' Without defined remediation timeframes, there is no enforceable standard for when vulnerable components must be patched. This creates ambiguity in incident response and allows known-vulnerable versions to persist indefinitely without accountability. This absence of documented timeframes also prevents verification of compliance with ASVS 15.2.1, as there are no baseline timeframes against which to measure component update status.

**Remediation:**

Create a security remediation policy document (e.g., SECURITY_REMEDIATION.md or within airflow-core/docs/security/) that defines: (1) Remediation Timeframes by severity - Critical (CVSS ≥ 9.0): 72 hours, High (CVSS 7.0-8.9): 7 calendar days, Medium (CVSS 4.0-6.9): 30 calendar days, Low (CVSS < 4.0): Next scheduled release; (2) General Update Policy - All 3rd party dependencies reviewed quarterly, dependencies reaching EOL replaced within 90 days, components with dangerous functionality prioritized; (3) Risky Component Registry identifying protobuf (dangerous functionality - binary data parsing), google-cloud-storage (standard - network I/O), google-cloud-logging (standard - external API client); (4) Monitoring - Dependabot/Renovate alerts reviewed within 24 hours, uv.lock updates verified against CVE databases before merge. Then implement automated compliance checking using these documented timeframes.

---

#### FINDING-020: Missing documentation for rate limiting and anti-automation controls in GCP connection authentication

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 6.1.1 |
| Files | providers/google/docs/connections/gcp.rst:entire document |
| Source Reports | 6.1.1.md |
| Related | - |

**Description:**

The Google Cloud connection documentation does not define how rate limiting, anti-automation, or adaptive response controls are used to defend against credential stuffing or brute force attacks against connection authentication attempts. The documentation describes retry behavior for outbound API calls (client-side retry logic), but does not document: 1) How inbound authentication attempts against Airflow's connection system are rate-limited, 2) Anti-automation controls to prevent automated attacks against stored connection credentials, 3) Adaptive response mechanisms (e.g., progressive delays, temporary lockouts), 4) How legitimate access is preserved while malicious attempts are blocked (preventing malicious account lockout). The AGENTS.md file references Airflow's security model documentation but none of the provided documentation defines these controls for the Google provider connection layer.

**Remediation:**

Add a security section to the GCP connection documentation that describes: Security Controls - Rate Limiting and Anti-Automation: The following controls protect connection authentication against brute force and credential stuffing attacks: * Airflow API rate limiting: The Airflow API server enforces rate limits on authentication endpoints. See :ref:`security:rate-limiting` for configuration. * Google Cloud API protections: Google Cloud APIs enforce their own rate limiting with exponential backoff (configured via num_retries). * Account lockout prevention: Failed authentication attempts are logged but do not lock out the Airflow connection. Service account keys and OAuth tokens have their own revocation mechanisms managed via Google Cloud IAM. * Adaptive response: After N failed attempts within a time window, additional delays are introduced. Configure via [api] maximum_page_limit and related settings.

---

#### FINDING-021: No documented password minimum length requirements for connection credentials

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 6.2.1 |
| Files | providers/google/docs/connections/gcp.rst, providers/google/docs/connections/google_ads.rst |
| Source Reports | 6.2.1.md |
| Related | - |

**Description:**

Neither connection documentation defines minimum length requirements for credential fields that could contain user-set passwords. While GCP connections primarily use service account keys and OAuth tokens, connection configurations may include database passwords (e.g., for Cloud SQL) or API keys, and no minimum length policy is documented or enforced at the connection configuration layer. The Google Ads connection accepts OAuth2 client secret and OAuth2 refresh token as free-form text fields. While these are generated by Google (not user-set), the documentation does not distinguish between generated credentials and any user-set passwords that might be stored in the connection's password field. There is no documented enforcement of minimum length (8 characters per ASVS, 15 recommended) for any credential field in the connection system. If users store short or weak passwords in Airflow connection password fields for services like Cloud SQL, no minimum length enforcement is documented.

**Remediation:**

Document password length requirements for connection credentials that are user-set. Add a section stating: 'When configuring connection credentials that involve user-set passwords (e.g., database passwords for Cloud SQL connections), passwords must be at least 8 characters in length. A minimum of 15 characters is strongly recommended for all credential fields. Note: Service account keys, OAuth tokens, and other Google-generated credentials are not subject to this policy as they are generated with sufficient entropy by Google Cloud.'

---

#### FINDING-022: Connection documentation does not describe current credential verification requirement

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 6.2.3 |
| Files | providers/google/docs/connections/gcp.rst:entire document |
| Source Reports | 6.2.3.md |
| Related | - |

**Description:**

The connection documentation does not describe a requirement to verify the current credential/password before allowing a credential change. When connection credentials are updated (via UI, REST API, or environment variables), there is no documented requirement for the user to provide the existing credential as proof of authorization before replacing it. The documentation describes how to configure connections with various credential types but does not address: 1) Whether changing a connection's credentials requires presenting the current credential, 2) Whether the Airflow connection management interface validates the current password/key before accepting a replacement, 3) Authentication requirements for accessing the connection management interface itself. Without requiring the current credential for verification, an attacker with access to the Airflow admin interface could replace connection credentials without proving knowledge of the existing ones.

**Remediation:**

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

---

#### FINDING-023: No breached password detection documented for user-set credentials

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 6.2.4 |
| Files | providers/google/docs/connections/gcp.rst, providers/google/docs/connections/google_ads.rst |
| Source Reports | 6.2.4.md |
| Related | - |

**Description:**

Neither the GCP connection documentation nor the Google Ads connection documentation describes any mechanism for checking credentials against known breached password databases (top 3000 or otherwise). There is no documentation of breached credential detection for any password-type fields in the connection configuration. While Google-generated credentials (service account keys, OAuth tokens) are not subject to breach database checks (they are cryptographically random), any user-set password fields (e.g., database passwords stored in connection password field for Cloud SQL) should be verified against known breached passwords. The documentation does not: 1) Reference any breached password list or API (e.g., Have I Been Pwned, NIST bad password list), 2) Describe validation of credentials during connection creation or update, 3) Differentiate between generated credentials (exempt) and user-set passwords (should be checked).

**Remediation:**

Document breached password detection for user-set credentials: When user-set passwords are provided in connection configuration (e.g., database passwords for Cloud SQL connections), Airflow validates them against a list of at least 3,000 commonly breached passwords that meet the minimum length requirement. This check applies during: Connection creation and Password/credential changes. Note: This check does not apply to Google-generated credentials such as service account keys, OAuth tokens, or API keys, as these are generated with sufficient cryptographic entropy.

### 3.4 Low

#### FINDING-024: Self-contained tokens cannot be immediately revoked on session termination

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 7.4.1 |
| Files | providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:77-93, providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:108-128 |
| Source Reports | 7.4.1.md |
| Related Findings | - |

**Description:**

The authentication backend uses self-contained tokens (Google JWTs) which cannot be revoked by the application. There is no mechanism (such as a revocation list, per-user token validity timestamp, or token blacklist) to immediately invalidate a previously-accepted token if the user logs out or their session needs to be terminated. A valid Google ID token will continue to be accepted until its natural expiration (typically 1 hour). After logout or session termination is triggered, a previously valid Google ID token could still be used for API requests until it expires (up to 1 hour). However, the practical risk is mitigated by: (1) The _lookup_user check validates user.is_active on every request, (2) Google ID tokens have short lifetimes (typically 3600 seconds), (3) This is a stateless API authentication pattern without server-side sessions.

**Remediation:**

For applications requiring immediate token invalidation, implement a per-user 'token not before' timestamp: Check the iat claim against a user.token_not_before field and reject tokens issued before the session invalidation timestamp. Example: if user and user.token_not_before and iat < user.token_not_before: return None

---

#### FINDING-025: No proactive session termination for disabled user accounts in Google OpenID auth backend

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 7.4.2 |
| Files | providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:96-104 |
| Source Reports | 7.4.2.md |
| Related Findings | - |

**Description:**

While the _lookup_user function correctly checks user.is_active on each request (effectively preventing disabled users from making new authenticated API calls), this module does not proactively terminate or invalidate any active Airflow web sessions or cached tokens that may exist for the disabled user. The responsibility for proactive session termination when a user account is disabled falls entirely on Airflow's core session management system. For API requests through this auth backend, each request independently verifies user status, providing effective mitigation. However, cached _CredentialsToken instances in service-to-service auth do not check user account status, though these are service credentials rather than user sessions.

**Remediation:**

This is properly an Airflow core responsibility. If immediate session termination is required for disabled accounts, implement a signal/event handler at the application level that invalidates all sessions for a user when their account is deactivated.

---

#### FINDING-026: No explicit TLS minimum version enforcement on outbound connections

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 12.1.1 |
| Files | providers/google/src/airflow/providers/google/cloud/hooks/cloud_sql.py:398-405, providers/google/src/airflow/providers/google/cloud/hooks/cloud_sql.py:286-296 |
| Source Reports | 12.1.1.md |
| Related Findings | - |

**Description:**

Code initiates HTTPS connections without explicitly setting minimum_version = TLSVersion.TLSv1_2. On Python versions < 3.10 with OpenSSL configurations that haven't deprecated TLS 1.0/1.1, the TLS handshake could potentially negotiate an older TLS version if a MITM performed a downgrade attack. In practice, Google APIs enforce TLS 1.2+ server-side, significantly mitigating this risk.

**Remediation:**

Add explicit SSL context with minimum TLS version enforcement:

```python
import ssl
import httpx

ssl_context = ssl.create_default_context()
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

# For httpx
response = httpx.get(download_url, follow_redirects=True, verify=ssl_context)
```

---

#### FINDING-027: Client-side field filtering in get_query_results() fetches all columns before filtering

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 15.3.1 |
| Files | providers/google/src/airflow/providers/google/cloud/hooks/bigquery.py:700 |
| Source Reports | 15.3.1.md |
| Related Findings | - |

**Description:**

When `selected_fields` is provided, ALL columns are still fetched from BigQuery and materialized into dictionaries before being filtered client-side. This means: 1. Network bandwidth is consumed for unwanted columns, 2. Memory contains the full dataset briefly, 3. If the query returns sensitive columns, they transit through the application even when not requested. This contrasts with `list_rows()` which passes `selected_fields` to the API for server-side filtering.

**Remediation:**

The filtering should ideally be done server-side. However, since `job.result()` doesn't support column selection, document this limitation and ensure callers use `list_rows()` with `selected_fields` when possible. Add documentation: "Note: selected_fields filtering is applied client-side after full row retrieval. For server-side column filtering, use list_rows() with selected_fields instead."

---

#### FINDING-028: BigQueryToSqlOperator transfers all fields by default without enforcement

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 15.3.1 |
| Files | providers/google/src/airflow/providers/google/cloud/transfers/bigquery_to_sql.py:105 |
| Source Reports | 15.3.1.md |
| Related Findings | - |

**Description:**

When `selected_fields` is not specified (default `None`), ALL fields from the BigQuery table are transferred to the destination database without any enforcement of field-level filtering. Sensitive fields in BigQuery tables (e.g., PII, financial data, internal metadata) may be transferred to destination databases with less restrictive access controls.

**Remediation:**

While this is by design for a data transfer tool, consider adding a warning log when selected_fields is None: "No 'selected_fields' specified. All fields from the source table will be transferred. Consider specifying only required fields to minimize data exposure."

---

#### FINDING-029: Azure transfer operators lack file size limits when downloading to temporary files

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 5.2.1 |
| Files | providers/google/src/airflow/providers/google/cloud/transfers/adls_to_gcs.py, providers/google/src/airflow/providers/google/cloud/transfers/azure_blob_to_gcs.py, providers/google/src/airflow/providers/google/cloud/transfers/azure_fileshare_to_gcs.py |
| Source Reports | 5.2.1.md |
| Related Findings | - |

**Description:**

Transfer operators (adls_to_gcs.py, azure_blob_to_gcs.py, azure_fileshare_to_gcs.py) download files from external sources (Azure, ADLS) to temporary files without size limits, potentially exhausting disk space on the worker.

**Remediation:**

Add configurable max_file_size_bytes parameter to transfer operators. Validate file size before or during download to temporary files.

---

#### FINDING-030: Missing content-type validation in GCS upload

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 5.2.2 |
| Files | providers/google/src/airflow/providers/google/cloud/hooks/gcs.py:450 |
| Source Reports | 5.2.2.md |
| Related Findings | - |

**Description:**

In the GCS upload() function, when a file is uploaded with a specified mime_type, there is no validation that the file content actually matches the declared MIME type. Files are uploaded with incorrect MIME types that could bypass downstream content-based security controls that trust the Content-Type header. The mime_type is set but content is not validated against it.

**Remediation:**

For L1, this is acceptable if no business/security decisions are made based on file type. For L2+, add optional content validation using python-magic library to detect actual content type and compare against declared mime_type. Raise AirflowException on mismatch when validate_content_type parameter is enabled.

---

#### FINDING-031: No validation that downloaded schema object is JSON

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 5.2.2 |
| Files | providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_bigquery.py:239 |
| Source Reports | 5.2.2.md |
| Related Findings | - |

**Description:**

In the GCS to BigQuery transfer operator, when downloading a schema file from GCS, there is no validation that the downloaded object is actually a JSON file. No extension check, magic bytes validation, or content-type validation is performed before the file is downloaded and parsed with json.loads(). The primary risk is unexpected schema definitions if the file is replaced with valid but malicious JSON.

**Remediation:**

This is mitigated by the JSON parsing step and BigQuery's schema validation. Consider adding a JSON schema validator for the schema file structure to ensure it conforms to expected schema definition format.

---

#### FINDING-032: Validation Timing Issue in Text-to-Speech

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 2.2.2, 2.3.1 |
| Files | text_to_speech.py |
| Source Reports | 2.2.2.md, 2.3.1.md |
| Related Findings | - |

**Description:**

The _validate_inputs() method in text_to_speech.py is called in __init__ before template rendering occurs. This timing issue means validation executes before Airflow templates are resolved, potentially missing empty or invalid values that only become apparent after template rendering. Input validation should occur in the execute() method to ensure that validation happens as part of the sequential business logic flow.

**Remediation:**

Move validation logic from __init__ to the execute() method to ensure validation occurs after template rendering is complete, allowing proper validation of rendered template values and ensuring proper validation timing in the business logic flow.

---

#### FINDING-033: Missing Error State Check After Cluster Restart

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 2.3.1 |
| Files | dataproc.py |
| Source Reports | 2.3.1.md |
| Related Findings | - |

**Description:**

In dataproc.py, the _reconcile_cluster_state() method does not call _handle_error_state() after restarting a STOPPED cluster. This is inconsistent with the CREATING and DELETING paths which do perform error state checks. After restarting a cluster, the operator should verify that the cluster did not enter an error state during the restart process, ensuring complete sequential validation of the business logic flow.

**Remediation:**

Add error state handling after cluster restart in the STOPPED state reconciliation path:

```python
elif cluster.status.state == cluster.status.State.STOPPED:
    self.log.info("Cluster %s is in STOPPED state.", self.cluster_name)
    self._start_cluster(hook)
    cluster = self._get_cluster(hook)
    self._handle_error_state(hook, cluster)  # Add this line
```

---

#### FINDING-034: Missing IAM Permission Documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 8.1.1 |
| Files | All operator files |
| Source Reports | 8.1.1.md, 2.3.1.md |
| Related Findings | - |

**Description:**

Operators document the `impersonation_chain` mechanism but do not specify which IAM roles/permissions are required for each operation. Operator documentation does not consistently specify required IAM permissions and minimum IAM roles needed for operation. This documentation gap makes it difficult for administrators and users to verify least-privilege configurations and implement least-privilege security configurations, potentially leading to over-permissioned service accounts being deployed.

**Remediation:**

Add comprehensive IAM permission documentation to all operator classes. Include:
- Required IAM Permissions with scope (e.g., dataflow.jobs.create on the project)
- Minimum IAM Roles needed
- Conditional permissions (e.g., iam.serviceAccounts.actAs if service_account specified)

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

---

#### FINDING-035: Non-Parameterized BigQuery Metadata Query

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-89 |
| ASVS Section(s) | 1.2.4 |
| Files | bigquery.py:unknown |
| Source Reports | 1.2.4.md |
| Related Findings | FINDING-002 |

**Description:**

SQL injection vulnerability in BigQueryAsyncHook.create_job_for_partition_get() function. The table_id parameter is interpolated directly into a BigQuery SQL WHERE clause using f-strings. Practical risk is low because DAG authors are trusted administrators, BigQuery doesn't support multi-statement queries, and the query targets metadata (INFORMATION_SCHEMA). However, this violates best practices for parameterized queries.

**Remediation:**

Convert to use BigQuery's native query parameters. Replace the string-interpolated WHERE clause with parameterized query syntax using @table_name placeholder, set parameterMode to 'NAMED', and provide queryParameters array with proper parameter type and value definitions.

---

#### FINDING-036: Incorrect Query Parameter Handling in Data Fusion list_pipelines

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 1.2.2 |
| Files | datafusion.py:310 |
| Source Reports | 1.2.2.md |
| Related Findings | - |

**Description:**

Functional bug in datafusion.py list_pipelines() function at line ~310. Query parameters are incorrectly appended as path segments using os.path.join() instead of being properly formatted as query string with ? separator. Code: if query: url = os.path.join(url, urlencode(query))

**Remediation:**

Use proper query string separator: if query: url = f"{url}?{urlencode(query)}"

---

#### FINDING-037: Missing URL Encoding in Cloud SQL Operation Name

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 1.2.2 |
| Files | cloud_sql.py:413 |
| Source Reports | 1.2.2.md |
| Related Findings | - |

**Description:**

Path segments in URL construction are not URL-encoded in cloud_sql.py CloudSQLAsyncHook.get_operation_name() at line ~413. Code: url = f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{project_id}/operations/{operation_name}". Impact is very low as values originate from trusted DAG authors and are validated by Google APIs, but URL encoding provides defense-in-depth.

**Remediation:**

Apply URL encoding to path parameters: from urllib.parse import quote; url = f"https://sqladmin.googleapis.com/sql/v1beta4/projects/{quote(project_id, safe='')}/operations/{quote(operation_name, safe='')}"

---

#### FINDING-038: Missing URL Encoding in Dataproc Metastore UI Links

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 1.2.2 |
| Files | dataproc_metastore.py |
| Source Reports | 1.2.2.md |
| Related Findings | - |

**Description:**

Path parameters in UI links are not URL-encoded in dataproc_metastore.py functions DataprocMetastoreLink.get_link() and DataprocMetastoreDetailedLink.get_link(). Code: return conf["url"].format(region=conf["region"], service_id=conf["service_id"], project_id=conf["project_id"]). Impact is low as base protocol is hardcoded (https://console.cloud.google.com), preventing protocol injection.

**Remediation:**

Apply URL encoding to all path parameters: from urllib.parse import quote; return conf["url"].format(region=quote(conf["region"], safe=""), service_id=quote(conf["service_id"], safe=""), project_id=quote(conf["project_id"], safe=""))

---

#### FINDING-039: Subprocess Execution with Templated Script Path in GCS Transform Operator

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 1.3.2 |
| Files | gcs.py:393 |
| Source Reports | 1.3.2.md |
| Related Findings | - |

**Description:**

The transform_script field is in template_fields, enabling Jinja2 rendering. While DAG authors are trusted, this executes on the Airflow worker (not a sandboxed container). If template rendering sources runtime values from untrusted XCom or external variables, arbitrary command execution on the worker is possible. The transform_script (templated operator parameter) flows to cmd list and then to subprocess.Popen(args=cmd). Flagged at LOW because it matches the known false positive pattern about operators executing arbitrary user code in compute services, but occurs on the Airflow worker rather than a sandboxed environment.

**Remediation:**

Add validation to restrict transform_script to an allowlist. Example: ALLOWED_TRANSFORM_SCRIPTS = ["/opt/airflow/scripts/transform.py"]. Create a _validate_transform_script() method that checks if the script is in the allowlist and raises AirflowException if not. Additionally, document that transform_script should not source values from untrusted runtime data.

---

#### FINDING-040: Input Validation Rules Scattered Without Centralized Specification

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 2.1.1 |
| Files | alloy_db.py, cloud_composer.py, datafusion.py, dataproc_metastore.py, dataplex.py, dataprep.py, dlp.py, gen_ai.py |
| Source Reports | 2.1.1.md |
| Related Findings | - |

**Description:**

Parameters have format expectations described in natural language docstrings but lack formal regex patterns, machine-readable constraints, centralized validation rule definitions, and type annotations with constraints (e.g., Annotated, Literal). Without centralized validation specifications: developers cannot systematically verify input constraints, inconsistent validation across operators, harder to audit compliance with business rules, and reliance on runtime API errors for format validation. Affects multiple files including alloy_db.py (request_id UUID format), cloud_composer.py (HTTP method values), datafusion.py (pipeline_name, version_id, namespace), dataproc_metastore.py (table and partition_names), dataplex.py (resource identifiers), dataprep.py (body_request schema), dlp.py (dlp_job_id, template_id), and gen_ai.py (model name and API key formats).

**Remediation:**

Create a centralized validation rules document or schema. Example: Define VALIDATION_RULES dictionary with patterns, length constraints, and descriptions for common parameter types (workflow_id, cluster_id, request_id, etc.). Implement validation middleware/decorator for reusable validation across operators. Reference formal validation rules from operator docstrings. Implement as JSON Schema or Pydantic models for machine-readable constraints.

---

#### FINDING-041: BigQuery Label Validation Gap

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS Section(s) | 2.2.1 |
| Files | bigquery.py:1232 |
| Source Reports | 2.2.1.md |
| Related Findings | FINDING-042, FINDING-043, FINDING-044, FINDING-045, FINDING-046, FINDING-047 |

**Description:**

BigQuery label validation using LABEL_REGEX is applied to auto-generated labels but not consistently applied to user-provided labels. This represents inconsistent application of validation controls where the pattern exists but is not used for all label sources.

**Remediation:**

Extend LABEL_REGEX validation to all label sources in the _add_job_labels() function, including user-provided labels. This provides defense-in-depth against API rejection and ensures consistent validation.

---

#### FINDING-042: Cloud Functions Overly Permissive Regex Patterns

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS Section(s) | 2.2.1 |
| Files | functions.py:49-52 |
| Source Reports | 2.2.1.md |
| Related Findings | FINDING-041, FINDING-043, FINDING-044, FINDING-045, FINDING-046, FINDING-047 |

**Description:**

Cloud Functions validation uses overly permissive regex patterns like `^.+$` for structured fields including runtime, timeout, and entryPoint. These patterns accept any non-empty string rather than validating against expected formats for these specific field types.

**Remediation:**

Replace generic `^.+$` patterns with specific validation patterns for each field type. For example, use `^[a-z]+\d+(\.\d+)?$` for runtime to match expected format like 'python39' or 'nodejs16'.

---

#### FINDING-043: Dataflow Missing None-Check in Job Name Append Function

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS Section(s) | 2.2.1 |
| Files | dataflow.py:464-469 |
| Source Reports | 2.2.1.md |
| Related Findings | FINDING-041, FINDING-042, FINDING-044, FINDING-045, FINDING-046, FINDING-047 |

**Description:**

Missing None-check in _append_uuid_to_job_name() function in Dataflow body structure validation. The function does not validate body structure before accessing nested fields, which could lead to AttributeError or TypeError.

**Remediation:**

Add None-check and structure validation before accessing nested body fields. Validate that body is a dictionary and contains expected keys before attempting to access or modify them.

---

#### FINDING-044: Transfer Service Delayed Validation Timing

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS Section(s) | 2.2.1 |
| Files | cloud_storage_transfer_service.py:426 |
| Source Reports | 2.2.1.md |
| Related Findings | FINDING-041, FINDING-042, FINDING-043, FINDING-045, FINDING-046, FINDING-047 |

**Description:**

Transfer Service request_filter parameter is validated in execute() method but not in __init__(). This delayed validation means errors are caught at runtime rather than at DAG parse time, reducing fail-fast behavior.

**Remediation:**

Move request_filter validation to the __init__() method to provide early validation and fail-fast behavior. This catches configuration errors at DAG parse time rather than execution time.

---

#### FINDING-045: Dataplex Catalog Inconsistent Validation Pattern

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS Section(s) | 2.2.1 |
| Files | dataplex.py |
| Source Reports | 2.2.1.md |
| Related Findings | FINDING-041, FINDING-042, FINDING-043, FINDING-044, FINDING-046, FINDING-047 |

**Description:**

Dataplex catalog operators apply _validate_fields() only in Entry creation but not in other catalog operators. This represents inconsistent application of validation patterns across similar operations.

**Remediation:**

Extend _validate_fields() pattern to all Dataplex catalog operators to ensure consistent validation across similar operations.

---

#### FINDING-046: Text-to-Speech Validation Pattern Not Extended to Other Operators

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS Section(s) | 2.2.1 |
| Files | text_to_speech.py:127 |
| Source Reports | 2.2.1.md |
| Related Findings | FINDING-041, FINDING-042, FINDING-043, FINDING-044, FINDING-045, FINDING-047 |

**Description:**

Text-to-Speech implements _validate_inputs() pattern but this validation approach is not extended to other operators that could benefit from similar input validation.

**Remediation:**

Standardize and extend the _validate_inputs() pattern to all operators with required parameters. This provides consistent fail-fast behavior and clear error messages across the codebase.

---

#### FINDING-047: Vertex AI Format Constraints Not Enforced

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS Section(s) | 2.2.1 |
| Files | endpoint_service.py, ray.py |
| Source Reports | 2.2.1.md |
| Related Findings | FINDING-041, FINDING-042, FINDING-043, FINDING-044, FINDING-045, FINDING-046 |

**Description:**

Vertex AI operators document format constraints for parameters like endpoint_id and cluster_name in docstrings but do not enforce these constraints in code. Documented constraints are not validated, relying entirely on server-side validation.

**Remediation:**

Implement validation for documented format constraints. Add regex patterns or other validation logic to enforce the constraints described in docstrings, providing fail-fast behavior and better error messages.

---

#### FINDING-048: Error responses from authentication decorator do not include CORS headers

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 3.4.2 |
| Files | providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:131, providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:135, providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:139 |
| Source Reports | 3.4.2.md |
| Related Findings | - |

**Description:**

The error responses returned directly from the authentication decorator do not include any CORS headers. While this is generally secure (no Access-Control-Allow-Origin means same-origin policy is enforced), it means: (1) If CORS is configured at a higher middleware level for successful API responses, error responses from the auth decorator may behave inconsistently. (2) Legitimate cross-origin API clients that send invalid/expired tokens will not receive proper CORS headers on 401/403 responses, potentially causing confusing client-side errors. This is classified as LOW because the absence of CORS headers defaults to restrictive behavior (denying cross-origin access), which is secure. However, it should be verified that no application-level middleware adds a wildcard or reflected Access-Control-Allow-Origin to these responses after they're returned.

**Remediation:**

Verify that no application-level middleware adds a wildcard or reflected Access-Control-Allow-Origin to these responses after they're returned. Ensure CORS configuration is consistent across all response types (success and error). For the Airflow 3 replacement, ensure CORS configuration with explicit allowlist is implemented. If cross-origin API access is required, configure CORS headers consistently at the middleware level with a validated allowlist of origins.

---

#### FINDING-049: Authentication decorator does not enforce HTTP method restrictions or validate Sec-Fetch-* headers

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 3.5.3 |
| Files | providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py:123-145 |
| Source Reports | 3.5.3.md |
| Related Findings | - |

**Description:**

The `requires_authentication` decorator which guards sensitive functionality performs no HTTP method or `Sec-Fetch-*` header validation. HTTP requests of any method (GET, HEAD, OPTIONS) pass through to the wrapped function without verification. Endpoints protected by this decorator that perform state-changing operations could be triggered via safe HTTP methods, potentially enabling bookmark/history-based replay of sensitive actions, proxy/CDN caching of state-changing responses, and cross-origin exploitation via `<img>` or `<script>` tags if a valid token were leaked. The Bearer token requirement already prevents unsigned cross-origin abuse, and actual endpoint method restrictions should be enforced at the Flask route level. This module is also deprecated for removal.

**Remediation:**

While method enforcement is better done at the route registration level, the decorator could optionally validate `Sec-Fetch-*` headers for defense-in-depth. Add validation for `Sec-Fetch-Site` header to ensure requests come from same-origin, same-site, or none. Example: Check if `sec_fetch_site` is in ("same-origin", "same-site", "none") and return 403 Forbidden if not. Additionally, ensure all Flask routes using `@requires_authentication` that handle state-changing operations specify `methods=['POST']` or other appropriate unsafe methods at the route registration level.

---

#### FINDING-050: No classification of protobuf as component with dangerous functionality

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 15.1.1 |
| Files | providers/google/src/airflow/providers/google/cloud/hooks/stackdriver.py:30 |
| Source Reports | 15.1.1.md |
| Related Findings | - |

**Description:**

The protobuf library performs binary data parsing and deserialization — operations explicitly classified as 'dangerous functionality' in ASVS 15.1.1. However, no documentation identifies this component as requiring elevated security attention or faster remediation cycles. Protobuf is a well-maintained Google library, but its binary parsing nature means vulnerabilities tend to be higher severity (DoS, memory corruption). Without classification, it receives the same update priority as less critical dependencies.

**Remediation:**

Include protobuf in a documented 'dangerous functionality' component registry with accelerated remediation timeframes. Document that protobuf performs binary data parsing and deserialization, classify it as requiring elevated security attention, and assign it faster remediation cycles for vulnerabilities.

---

#### FINDING-051: No automated mechanism to alert when logging dependencies breach update timeframes

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 15.2.1 |
| Files | CI/CD pipeline |
| Source Reports | 15.2.1.md |
| Related Findings | - |

**Description:**

The domain context states 'The application must track component versions and ensure logging dependencies are kept within supported timeframes.' While uv.lock provides version pinning, no automated alerting or blocking mechanism is evident in the provided code to prevent deployments with components that have breached remediation timeframes. This is a process control gap rather than an immediate vulnerability. The monorepo structure and uv.lock provide the foundation for enforcement, but the enforcement mechanism itself is missing.

**Remediation:**

Implement CI gates that block merges when dependencies have known vulnerabilities exceeding the defined remediation timeframe. Tools like pip-audit, safety, or GitHub's Dependabot can provide this enforcement when configured with severity-based auto-merge policies. Add a component inventory with last-verified dates in dependency-compliance.toml format tracking current_version, last_security_review, known_cves, and status for each component. Implement GitHub Actions workflow for dependency compliance with weekly checks and PR validation.

---

#### FINDING-052: Missing guidance on rate limiting for Google Ads OAuth2 credential management

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 6.1.1 |
| Files | providers/google/docs/connections/google_ads.rst:entire document |
| Source Reports | 6.1.1.md |
| Related Findings | - |

**Description:**

The Google Ads connection documentation stores OAuth2 client secrets and refresh tokens but provides no guidance on rate limiting or anti-automation for credential management operations. Missing documentation for how OAuth2 credential management is protected against automated attacks.

**Remediation:**

Add a brief security note referencing Airflow's core authentication controls and Google Ads API-level protections.

---

# 4. Positive Security Controls

| Control | Evidence | Files | Domain |
|---------|----------|-------|--------|
| Delegation of authorization server responsibilities to Google's OAuth infrastructure | The code correctly delegates all authorization server responsibilities (including redirect URI validation, authorization code management, and grant type restrictions) to Google's OAuth infrastructure | - | google_cloud_authentication |
| Token audience validation | Token audience validation in google_openid.py (AUDIENCE parameter) ensures tokens are scoped to the correct application | google_openid.py | google_cloud_authentication |
| Safe-by-default audience configuration | The AUDIENCE constant in google_openid.py uses a placeholder fallback (project-id-random-value.apps.googleusercontent.com) which effectively makes the backend reject all tokens until properly configured | google_openid.py | google_cloud_authentication |
| Proper token validation chain | The google_openid.py module implements proper token validation including audience verification, issuer validation, and email verification - acting as a compliant OAuth resource server | google_openid.py | google_cloud_authentication |
| Credential lifecycle management | The base_google.py module properly manages credential lifecycles through caching, automatic refresh, and retry logic, delegating security-critical operations to Google's official auth libraries | base_google.py | google_cloud_authentication |
| Token expiration tracking with half-lifetime refresh strategy | The _CredentialsToken class in base_google.py implements proactive token refresh before expiration using a half-lifetime strategy. Access tokens are refreshed when delta <= access_token_duration / 2. | base_google.py:530-575 | google_cloud_authentication |
| No Implicit Flow or Resource Owner Password Credentials implementation | google_openid.py module only validates pre-issued ID tokens and does not implement deprecated OAuth flows | google_openid.py | google_cloud_authentication |
| Secure authentication method restriction | ads.py _determine_authentication_method() explicitly restricts to service_account or developer_token (refresh token) methods, excluding deprecated password grant | ads.py:227-240 | google_cloud_authentication |
| User active status check | The _lookup_user function verifies user.is_active before granting access | google_openid.py:98 | google_cloud_authentication |
| No default accounts provisioned | No usernames like 'root', 'admin', or 'sa' are provisioned in the codebase | - | google_cloud_authentication |
| Backend token verification | _verify_id_token() method called in requires_authentication decorator for every protected request, using google.oauth2.id_token.verify_token() for cryptographic verification | google_openid.py:77-93 | google_cloud_authentication |
| Complete server-side token verification chain | Multi-layer backend validation: Token cryptographic verification → issuer check → email verification check → user database lookup → user active status check | google_openid.py:108-128 | google_cloud_authentication |
| Dynamic token generation | Google ID tokens (JWTs) and OAuth2 access tokens are dynamically generated with unique claims (iat, exp, jti). No static API keys used as session tokens. | google_openid.py, base_google.py:358-362 | google_cloud_authentication |
| Delegation to trusted token issuer for entropy | The OpenID backend verifies tokens issued by Google's OAuth2 infrastructure (accounts.google.com), which generates tokens using CSPRNG with well over 128 bits of entropy | - | google_cloud_authentication |
| Stateless per-request verification | Each API request independently verifies the Google ID token, which means no persistent session state is being reused across requests at this layer | google_openid.py:108-128 | google_cloud_authentication |
| Short-lived self-contained tokens | Google ID tokens expire in 1 hour, limiting the window of exposure for token reuse after logout or account disable | - | google_cloud_authentication |
| ID Token signature verification | _verify_id_token() function uses google.oauth2.id_token.verify_token() with request_adapter and AUDIENCE to verify digital signature via Google's public keys | google_openid.py:77 | google_cloud_authentication |
| Fail-closed design | If google.oauth2.id_token.verify_token raises any GoogleAuthError, the token is rejected immediately and function returns None, resulting in HTTP 401 | google_openid.py | google_cloud_authentication |
| Algorithm restriction via library | google.oauth2.id_token.verify_token() enforces algorithm allowlist (RSA/EC only, no 'None' algorithm), preventing algorithm substitution attacks | google_openid.py | google_cloud_authentication |
| Pre-configured key source | google.oauth2.id_token.verify_token() uses hardcoded _GOOGLE_OAUTH2_CERTS_URL. No jku/x5u/jwk header processing from tokens. | google_openid.py:_verify_id_token() | google_cloud_authentication |
| Trusted issuer validation | Only tokens from accounts.google.com or https://accounts.google.com are accepted via _GOOGLE_ISSUERS allowlist | google_openid.py:_verify_id_token() | google_cloud_authentication |
| Expiration (exp) and issued-at (iat) validation | google.oauth2.id_token.verify_token() calls google.auth.jwt.decode() which verifies exp and iat claims. Expired tokens cause GoogleAuthError resulting in HTTP 401. | google_openid.py:_verify_id_token() | google_cloud_authentication |
| Proactive token refresh for outgoing tokens | _CredentialsToken.ensure_token() refreshes tokens at half-duration (1800s of 3600s), preventing use of tokens near expiration | base_google.py:_CredentialsToken.ensure_token() | google_cloud_authentication |
| gRPC transport prevents URL-based credential leakage | SecretManagerServiceClient uses gRPC for all API communications, not REST URLs | SecretManagerServiceClient | secret_management |
| Secret values transmitted in response payload only | Secret data decoded from response.payload.data, never in URLs or query strings | secret_manager_client.py:72-73 | secret_management |
| Configuration via secure channels | backend_kwargs in config file, environment variables used, no URL-based config transmission | Documentation RST file | secret_management |
| Resource identifiers in request body | request={"name": ...} pattern used throughout for resource paths | secret_manager.py | secret_management |
| Secrets not cached in memory | get_secret() returns decoded value immediately without storing in instance/class/module variables or cache | secret_manager_client.py:72-73 | secret_management |
| Client connection pooling without secret caching | @cached_property caches only SecretManagerServiceClient for connection pooling, not secret payloads | secret_manager_client.py:53-55 | secret_management |
| No client-side storage mechanisms | All files operate server-side only, no browser DOM, local storage, or session storage interaction | - | secret_management |
| Runtime secret retrieval | Secrets retrieved at runtime by operators and hooks, never stored in DAG code at parse time | - | secret_management |
| Cryptographic credential-based authentication | Authentication exclusively uses service accounts and OAuth2 tokens via google-auth library, no password-based authentication | - | secret_management |
| IAM-based access control | GCP Secret Manager API enforces resource-level IAM permissions for every secret access operation | - | secret_management |
| No password hints or security questions | All files verified absent of password hint mechanisms and knowledge-based authentication | - | secret_management |
| Service-to-service authentication only | No user-facing authentication code exists, all interactions are service-to-service | - | secret_management |
| PermissionDenied exception handling | Errors logged with actionable guidance, None returned on permission failures | secret_manager_client.py:82-87 | secret_management |
| Secret name validation | is_valid_secret_name validates pattern ^[a-zA-Z0-9-_]*$ to prevent directory traversal or injection | secret_manager_client.py:40-46 | secret_management |
| Project ID fallback protection | @fallback_to_default_project_id ensures valid project context, prevents project_id=None bypasses | secret_manager.py | secret_management |
| Safe resource path construction | Uses client.secret_version_path() and validated f-string patterns for regional paths | - | secret_management |
| Logging excludes secret values | Logging only emits resource names and paths, never secret values | - | secret_management |
| Error handling prevents data leakage | Returns None rather than exposing partial secret data on errors | - | secret_management |
| Regional API endpoints contain only geographic location | secretmanager.{location}.rep.googleapis.com contains no credentials or secret data | - | secret_management |
| Credential scoping per connection | GoogleBaseHook.get_credentials() applies credentials per connection context | - | secret_management |
| Delegation to KMS (no local cipher implementation) | All encryption and decryption delegated to managed service | kms.py:96-120, kms.py:122-157 | cryptographic_operations |
| AEAD support via authenticated_data parameter | Supports Additional Authenticated Data for GCM | kms.py:100, kms.py:128 | cryptographic_operations |
| No local key material handling | Keys never leave KMS boundary | kms.py | cryptographic_operations |
| KMS symmetric encrypt/decrypt using AES-256-GCM enforced server-side | Uses KeyManagementServiceClient.encrypt() and decrypt() which enforce AES-256-GCM | kms.py:109, kms.py:143 | cryptographic_operations |
| Official Google Cloud KMS client library usage | Uses google.cloud.kms_v1.KeyManagementServiceClient with standard options | kms.py:83 | cryptographic_operations |
| Cipher selection enforced at infrastructure level | Google Cloud KMS enforces AES-256-GCM for all symmetric CryptoKeys at key creation time; no opportunity to select or configure cipher algorithms at operation time | kms.py | cryptographic_operations |
| Thin wrapper pattern with no additional cryptographic logic | Minimal wrapper around Google Cloud client library with no local crypto primitives, only base64 encoding for transport serialization | kms.py | cryptographic_operations |
| No hash function usage | Entire file contains no hashing operations, no imports of hashlib, hmac, md5, sha1, or any hash-related modules | kms.py, kms.py:23-35 | cryptographic_operations |
| Algorithm governance at key creation | Algorithm (AES-256-GCM, RSA-OAEP, ECDSA, etc.) determined at key creation time in Google Cloud, not at operation time in hook | kms.py | cryptographic_operations |
| Defense-in-depth via managed service delegation | All cryptographic operations delegated to Google Cloud KMS rather than implementing local crypto, eliminating implementation vulnerabilities | kms.py | cryptographic_operations |
| All external URLs are HTTPS | Download URLs (CLOUD_SQL_PROXY_DOWNLOAD_URL, CLOUD_SQL_PROXY_VERSION_DOWNLOAD_URL) and API URLs (sqladmin.googleapis.com) consistently use https:// scheme | cloud_sql.py:344-346, cloud_sql.py:304 | network_security |
| No explicit TLS downgrade | No code sets ssl.PROTOCOL_TLSv1 or disables TLS version checks | - | network_security |
| gRPC with TLS | OsLoginServiceClient uses gRPC which enforces TLS by default for Google Cloud endpoints | os_login.py:58 | network_security |
| Google API discovery with HTTPS | build('sqladmin', ...) uses the Google API client which connects via HTTPS with certificate validation | cloud_sql.py:131 | network_security |
| No certificate verification disabling | No verify=False found in any file. Certificate validation is never disabled for any external connection | - | network_security |
| Python ssl module default TLS settings | Implicit via httpx, aiohttp, google-auth libraries | - | network_security |
| Google API server-side TLS 1.2+ enforcement | External enforcement by Google infrastructure | - | network_security |
| Default certificate verification (httpx) | httpx uses default certificate verification | cloud_sql.py:400 | network_security |
| Default certificate verification (aiohttp) | aiohttp uses default certificate verification | cloud_sql.py:293 | network_security |
| Default certificate verification (googleapiclient) | googleapiclient uses default certificate verification | cloud_sql.py:131 | network_security |
| SSL cert validation for DB connections | _check_ssl_file validates SSL certificates for database connections | cloud_sql.py:783, cloud_sql.py:789 | network_security |
| Certificate from Secret Manager | _get_cert_from_secret retrieves certificates securely from Secret Manager | cloud_sql.py:832, cloud_sql.py:854 | network_security |
| PostgreSQL sslmode=verify-ca | When SSL is used for PostgreSQL, the connection URI includes sslmode=verify-ca which validates the server certificate against the provided CA | cloud_sql.py:704 | network_security |
| SSL option for public DB connections | Full SSL/TLS support for direct database connections with proper certificate configuration (sslcert, sslkey, sslrootcert, sslmode=verify-ca) is available but not default | cloud_sql.py:700-714 | network_security |
| Cloud SQL Proxy encrypted tunnel | When use_proxy=True, the proxy provides an encrypted tunnel without needing SSL certificates | cloud_sql.py:CloudSqlProxyRunner | network_security |
| Mutual exclusion validation for proxy and SSL | Code correctly prevents combining proxy with SSL, noting that Cloud SQL Proxy does not support SSL connections as SSL is not needed since Cloud SQL Proxy provides encryption on its own | cloud_sql.py:914 | network_security |
| No HTTP fallback mechanism | URLs are hardcoded as HTTPS with no degradation logic | - | network_security |
| No insecure WebSocket usage | The absence of WebSocket connections means there is no risk of unencrypted WebSocket traffic in these hooks | - | network_security |
| Appropriate protocol selection | The code uses SSH (encrypted), gRPC (TLS by default), and HTTPS for communication — all appropriate for their respective use cases without requiring WebSocket | - | network_security |
| SSH provides equivalent transport security | The compute_ssh.py hook uses SSH (encrypted tunnel) which provides transport encryption comparable to TLS | compute_ssh.py | network_security |
| Cloud SQL Proxy as TLS equivalent | The Cloud SQL Proxy provides an encrypted tunnel that is architecturally equivalent to TLS for database connections | cloud_sql.py | network_security |
| list_rows() passes selected_fields to BigQuery API for server-side column filtering | Avoids over-fetching by performing filtering at the API level | providers/google/src/airflow/providers/google/cloud/hooks/bigquery.py | data_transfer_and_storage |
| BigQueryAsyncHook.get_records() supports field filtering with selected_fields parameter | Async hook supports field-level filtering | - | data_transfer_and_storage |
| get_dataset_tables() returns only TableReference objects | Returns only project, dataset, table IDs, not full table metadata | - | data_transfer_and_storage |
| get_schema() returns only schema structure, not table data | Separates metadata from data access | - | data_transfer_and_storage |
| get_openlineage_database_info() returns curated subset of connection information | Returns only necessary connection metadata | - | data_transfer_and_storage |
| sql_to_gcs.py execute() returns only file metadata via XCom | Returns bucket, total_row_count, total_files, file_name, file_mime_type - not actual data content | providers/google/src/airflow/providers/google/cloud/transfers/sql_to_gcs.py | data_transfer_and_storage |
| sql_to_gcs.py exclude_columns parameter | Allows explicit exclusion of columns from export, preventing sensitive fields from being included | providers/google/src/airflow/providers/google/cloud/transfers/sql_to_gcs.py:85 | data_transfer_and_storage |
| bigquery_to_sql.py selected_fields parameter | Enables explicit field selection to limit data exposure in transfers | providers/google/src/airflow/providers/google/cloud/transfers/bigquery_to_sql.py:67 | data_transfer_and_storage |
| gcs_to_bigquery.py _find_max_value_in_column returns only aggregate value | Returns only a single aggregate value (MAX(column)) rather than full rows | providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_bigquery.py:298 | data_transfer_and_storage |
| GCS transfer operators return only destination URIs/paths via XCom | Return only paths, not file contents | providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_gcs.py, providers/google/src/airflow/providers/google/cloud/transfers/s3_to_gcs.py | data_transfer_and_storage |
| gcs_to_local.py enforces MAX_XCOM_SIZE limit | Only stores file content when explicitly requested via store_to_xcom_key | providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_local.py | data_transfer_and_storage |
| OpenLineage facets return only structural metadata | get_openlineage_facets_on_complete methods return only field names, types, namespaces - not actual data values | - | data_transfer_and_storage |
| XCom size validation prevents oversized data from entering metadata store | MAX_XCOM_SIZE constant set to 49344 bytes with validation before XCom push | providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_local.py:27 | data_transfer_and_storage |
| File splitting for large exports prevents single oversized file creation | approx_max_file_size_bytes parameter (default 1.9GB) causes file splitting | providers/google/src/airflow/providers/google/cloud/transfers/sql_to_gcs.py:85, providers/google/src/airflow/providers/google/cloud/transfers/cassandra_to_gcs.py:76 | data_transfer_and_storage |
| Batch processing controls memory usage during data transfer | batch_size parameter (default 1000) processes data in chunks | providers/google/src/airflow/providers/google/cloud/transfers/bigquery_to_sql.py:67 | data_transfer_and_storage |
| Result set size limits in BigQuery methods | max_results parameters limit result set sizes in list_rows() and get_dataset_tables() | - | data_transfer_and_storage |
| Consistent use of temporary files for intermediate storage | Transfer operators consistently use NamedTemporaryFile for intermediate storage, avoiding many path-related issues | - | data_transfer_and_storage |
| Retry logic with exponential backoff prevents unbounded retry storms | Retry logic implemented across operators | - | data_transfer_and_storage |
| GCS flat namespace provides inherent path traversal protection | Path traversal sequences in object names are stored literally rather than interpreted in GCS operations | - | data_transfer_and_storage |
| Authorization delegation to underlying cloud services | All operators correctly delegate authorization to GCP IAM, database authentication, and SFTP credentials rather than implementing custom authorization logic | - | data_transfer_and_storage |
| ALLOWED_FORMATS validation | GCSToBigQueryOperator validates source_format against ALLOWED_FORMATS constant (CSV, JSON, AVRO, PARQUET, etc.) before submitting load jobs | providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_bigquery.py:59 | data_transfer_and_storage |
| _validate_src_fmt_configs() format config validation | Ensures format-specific configuration is valid for the declared format | providers/google/src/airflow/providers/google/cloud/hooks/bigquery.py | data_transfer_and_storage |
| source_format.upper() parameter validation | Parameter validation for source format | providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_bigquery.py:160 | data_transfer_and_storage |
| JSON parsing validation | parse_json_from_gcs() implicitly validates JSON structure and fails gracefully with descriptive error | providers/google/src/airflow/providers/google/cloud/transfers/gcs_to_bigquery.py:247 | data_transfer_and_storage |
| BigQuery server-side validation | BigQuery itself performs schema/format validation during data loading, providing server-side defense-in-depth | - | data_transfer_and_storage |
| Service-to-service trust model | Transfer operators move data between authenticated cloud services (GCS, BigQuery, S3) where content type is established at the source system level rather than via magic byte inspection - appropriate for service-to-service data plane operations where data provenance is established through IAM | - | data_transfer_and_storage |

---

# 5. ASVS Compliance Summary

| ASVS ID | Title | Status | Notes |
|---------|-------|--------|-------|
| **10.4.1** | Redirect URI Validation | **N/A** | Not an authorization server; delegates to Google OAuth |
| **10.4.2** | Authorization Code Single Use | **N/A** | Not an authorization server; delegates to Google OAuth |
| **10.4.3** | Authorization Code Short-Lived | **N/A** | Not an authorization server; delegates to Google OAuth |
| **10.4.4** | Grant Type Restrictions | **N/A** | Not an authorization server; delegates to Google OAuth |
| **10.4.5** | Refresh Token Replay Mitigation | **N/A** | Not an authorization server; delegates to Google OAuth |
| **6.3.2** | Default User Accounts | **Pass** | No default accounts provisioned |
| **7.2.1** | Backend Token Verification | **Pass** | Complete server-side token verification chain |
| **7.2.2** | Dynamic Token Generation | **Pass** | Google ID tokens dynamically generated with unique claims |
| **7.2.3** | Token Entropy | **Pass** | Delegation to trusted token issuer (Google) for entropy |
| **7.2.4** | New Token on Authentication | **Partial** | No session token regeneration on authentication (FINDING-003) |
| **7.4.1** | Session Termination | **Partial** | Self-contained tokens cannot be immediately revoked (FINDING-024) |
| **7.4.2** | Session Termination — Account Disable/Delete | **Partial** | No proactive session termination for disabled accounts (FINDING-025) |
| **9.1.1** | Signature/MAC Validation | **Pass** | ID Token signature verification via google.oauth2.id_token |
| **9.1.2** | Algorithm Allowlist | **Pass** | Algorithm restriction via library (RSA/EC only) |
| **9.1.3** | Key Material from Trusted Sources | **Pass** | Pre-configured key source from Google |
| **9.2.1** | Validity Time Span Verification | **Pass** | Expiration (exp) and issued-at (iat) validation |
| **14.2.1** | Sensitive Data Not in URLs/Query Strings | **Pass** | gRPC transport and request body patterns |
| **14.3.1** | Client-side Data Cleared After Session Termination | **N/A** | Server-side only, no client-side storage |
| **6.4.1** | Initial Passwords/Activation Codes | **N/A** | Service-to-service authentication only |
| **6.4.2** | Password Hints and Knowledge-Based Authentication | **Pass** | No password hints or security questions |
| **8.2.2** | Data-specific Access Control (IDOR/BOLA) | **Pass** | IAM-based access control |
| **11.3.1** | Insecure Block Modes and Weak Padding | **Pass** | Delegation to KMS (AES-256-GCM) |
| **11.3.2** | Approved Ciphers and Modes | **Pass** | KMS enforces AES-256-GCM server-side |
| **11.4.1** | Approved Hash Functions | **Pass** | No hash function usage in cryptographic operations |
| **12.1.1** | General TLS Security Guidance | **Partial** | No explicit TLS minimum version enforcement (FINDING-026) |
| **12.2.1** | HTTPS Communication with External Facing Services | **Partial** | Non-SSL public database connections (FINDING-004) |
| **12.2.2** | Publicly Trusted TLS Certificates | **Pass** | Default certificate verification across all libraries |
| **4.4.1** | WebSocket over TLS (WSS) | **Pass** | No WebSocket usage; appropriate protocol selection |
| **15.3.1** | Return Required Subset of Fields | **Partial** | Some client-side filtering issues (FINDING-027, FINDING-028) |
| **5.2.1** | File Upload and Content — Size Validation | **Fail** | Multiple missing size validations (FINDING-005, FINDING-006, FINDING-029) |
| **5.2.2** | File Upload and Content — Type Validation | **Partial** | Missing content-type validation in some areas (FINDING-030, FINDING-031) |
| **5.3.1** | File Storage — Not Executable | **Pass** | GCS flat namespace provides inherent protection |
| **5.3.2** | File Storage — Path Traversal Prevention | **Fail** | Multiple path traversal vulnerabilities (FINDING-001, FINDING-007, FINDING-008, FINDING-009) |
| **8.2.1** | Function-Level Access Control | **Pass** | Authorization delegation to underlying cloud services |
| **1.2.5** | Injection Prevention | **Fail** | Path traversal in Gen AI (FINDING-010) |
| **2.2.2** | Input Validation | **Partial** | Missing validation in Dataflow YAML (FINDING-011) |
| **2.3.1** | Business Logic Security | **Partial** | Job deletion skipped in deferrable mode (FINDING-012, FINDING-013) |
| **8.1.1** | Authorization Documentation | **Partial** | Missing IAM permission documentation (FINDING-034) |
| **8.3.1** | Operation Level Authorization | **Pass** | IAM-based access control enforced |
| **1.2.1** | Output Encoding for HTTP/HTML/XML | **Pass** | No HTML/XML output generation |
| **1.2.2** | URL Encoding for Dynamic URLs | **Partial** | Inconsistent URL encoding (FINDING-014, FINDING-016, FINDING-036, FINDING-037, FINDING-038) |
| **1.2.3** | JavaScript/JSON Content Encoding | **Pass** | No JavaScript code generation |
| **1.2.4** | Parameterized Queries | **Partial** | SQL injection in Dataproc Metastore (FINDING-002), non-parameterized metadata query (FINDING-035) |
| **1.3.1** | HTML Sanitization | **Pass** | No HTML sanitization needed |
| **1.3.2** | Avoidance of eval() and Dynamic Code Execution | **Partial** | Subprocess execution with templated script path (FINDING-039) |
| **1.5.1** | Safe Deserialization — XML Parser Configuration | **Pass** | No XML parsing in scope |
| **2.1.1** | Validation and Business Logic Documentation | **Partial** | Scattered validation rules (FINDING-040) |
| **2.2.1** | Input Validation | **Fail** | Multiple validation gaps (FINDING-002, FINDING-015, FINDING-016, FINDING-041 through FINDING-047) |
| **3.2.1** | Unintended Content Interpretation | **Fail** | Incorrect Content-Type headers (FINDING-017) |
| **3.2.2** | Safe Text Rendering | **Fail** | Error responses with incorrect Content-Type (FINDING-017) |
| **3.3.1** | Cookie Setup | **Pass** | No cookie-based session management |
| **3.4.1** | Browser Security Mechanism Headers (HSTS) | **Fail** | Missing HSTS header (FINDING-018) |
| **3.4.2** | CORS Access-Control-Allow-Origin | **Partial** | Missing CORS headers on error responses (FINDING-048) |
| **3.5.1** | Browser Origin Separation (CSRF) | **Pass** | Token-based authentication provides CSRF protection |
| **3.5.2** | Browser Origin Separation — CORS Preflight | **Pass** | gRPC and stateless token authentication |
| **3.5.3** | Browser Origin Separation — HTTP Methods | **Partial** | No HTTP method restrictions enforced (FINDING-049) |
| **4.1.1** | Generic Web Service Security — Content-Type Header | **Fail** | Incorrect Content-Type headers (FINDING-017) |
| **15.1.1** | Secure Coding and Architecture Documentation | **Fail** | Missing risk-based remediation timeframes (FINDING-019), protobuf classification (FINDING-050) |
| **15.2.1** | Security Architecture and Dependencies | **Fail** | No automated alerting for dependency updates (FINDING-051) |
| **6.1.1** | Authentication Documentation | **Fail** | Missing rate limiting documentation (FINDING-020, FINDING-052) |
| **6.2.1** | Password Minimum Length | **Fail** | No documented password minimum length (FINDING-021) |
| **6.2.2** | Password Change Capability | **Pass** | Service-to-service authentication model |
| **6.2.3** | Password Change Requires Current and New Password | **Fail** | Missing current credential verification documentation (FINDING-022) |
| **6.2.4** | Breached Password Detection | **Fail** | No breached password detection documented (FINDING-023) |
| **6.2.5** | No Composition Rules | **Pass** | No password composition rules enforced |
| **6.2.6** | Password Input Field Masking | **N/A** | Server-side only, no user interface |
| **6.2.7** | Paste Functionality and Password Managers Permitted | **N/A** | Server-side only, no user interface |
| **6.2.8** | Password Verified Exactly as Received | **N/A** | Service-to-service authentication only |
| **6.3.1** | Controls Against Credential Stuffing and Brute Force | **N/A** | Service-to-service authentication only |
| **13.4.1** | Source Control Metadata Exposure | **Pass** | No source control metadata in deployment |

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS References | Control Gaps | Related Positive Controls |
|------------|----------|-----------------|--------------|---------------------------|
| FINDING-001 | High | 5.3.2 | Path traversal in sync_to_local_dir | Consistent use of temporary files, GCS flat namespace |
| FINDING-002 | High | 1.2.4, 2.2.1 | SQL injection in Dataproc Metastore HiveQL | Service-to-service trust model |
| FINDING-003 | Medium | 7.2.4 | No session token regeneration | Stateless per-request verification, Short-lived tokens |
| FINDING-004 | Medium | 12.2.1 | Non-SSL public database connections | Cloud SQL Proxy encrypted tunnel, SSL option available |
| FINDING-005 | Medium | 5.2.1 | GCS download() lacks size validation | XCom size validation, File splitting for large exports |
| FINDING-006 | Medium | 5.2.1 | http_to_gcs loads entire response | Batch processing controls, Result set size limits |
| FINDING-007 | Medium | 5.3.2 | Path traversal in _calculate_sync_destination_path | GCS flat namespace protection |
| FINDING-008 | Medium | 5.3.2 | Path traversal in GCS to SFTP | Authorization delegation |
| FINDING-009 | Medium | 5.3.2 | Inconsistent path sanitization in GCS to SFTP | Consistent use of temporary files |
| FINDING-010 | Medium | 1.2.5 | Path traversal in Gen AI result file writing | Safe resource path construction |
| FINDING-011 | Medium | 2.2.2 | Missing reserved flag validation in Dataflow YAML | Validation timing and pattern consistency |
| FINDING-012 | Medium | 2.3.1 | Deferrable mode skips job deletion (S3ToGCS) | Retry logic with exponential backoff |
| FINDING-013 | Medium | 2.3.1 | Deferrable mode skips job deletion (GCSToGCS) | Retry logic with exponential backoff |
| FINDING-014 | Medium | 1.2.2 | Path traversal in Cloud Composer DAG trigger | Safe resource path construction |
| FINDING-015 | Medium | 2.2.1 | Path traversal in GCS sync to local | GCS flat namespace protection |
| FINDING-016 | Medium | 1.2.2, 2.2.1 | Inconsistent URL encoding in DataFusion | All external URLs are HTTPS |
| FINDING-017 | Medium | 3.2.1, 3.2.2, 4.1.1 | Incorrect Content-Type headers | gRPC transport, HTTPS communication |
| FINDING-018 | Medium | 3.4.1 | Missing HSTS header | All external URLs are HTTPS |
| FINDING-019 | Medium | 15.1.1, 15.2.1 | No documented remediation timeframes | Defense-in-depth via managed service delegation |
| FINDING-020 | Medium | 6.1.1 | Missing rate limiting documentation | Secure authentication method restriction |
| FINDING-021 | Medium | 6.2.1 | No documented password minimum length | Cryptographic credential-based authentication |
| FINDING-022 | Medium | 6.2.3 | Missing current credential verification docs | Service-to-service authentication only |
| FINDING-023 | Medium | 6.2.4 | No breached password detection documented | Service-to-service authentication only |
| FINDING-024 | Low | 7.4.1 | Self-contained tokens cannot be immediately revoked | Short-lived self-contained tokens (1 hour) |
| FINDING-025 | Low | 7.4.2 | No proactive session termination for disabled accounts | User active status check, Short-lived tokens |
| FINDING-026 | Low | 12.1.1 | No explicit TLS minimum version enforcement | Python ssl module defaults, Google API server-side TLS 1.2+ |
| FINDING-027 | Low | 15.3.1 | Client-side field filtering in get_query_results() | list_rows() server-side filtering |
| FINDING-028 | Low | 15.3.1 | BigQueryToSqlOperator transfers all fields by default | selected_fields parameter, exclude_columns parameter |
| FINDING-029 | Low | 5.2.1 | Azure transfer operators lack file size limits | File splitting, Batch processing controls |
| FINDING-030 | Low | 5.2.2 | Missing content-type validation in GCS upload | ALLOWED_FORMATS validation, BigQuery server-side validation |
| FINDING-031 | Low | 5.2.2 | No validation that downloaded schema object is JSON | JSON parsing validation, Service-to-service trust model |
| FINDING-032 | Low | 2.2.2, 2.3.1 | Validation timing issue in Text-to-Speech | Text-to-Speech validation pattern |
| FINDING-033 | Low | 2.3.1 | Missing error state check after cluster restart | Retry logic with exponential backoff |
| FINDING-034 | Low | 8.1.1 | Missing IAM permission documentation | IAM-based access control |
| FINDING-035 | Low | 1.2.4 | Non-parameterized BigQuery metadata query | BigQuery server-side validation |
| FINDING-036 | Low | 1.2.2 | Incorrect query parameter handling in Data Fusion | All external URLs are HTTPS |
| FINDING-037 | Low | 1.2.2 | Missing URL encoding in Cloud SQL operation name | Google API discovery with HTTPS |
| FINDING-038 | Low | 1.2.2 | Missing URL encoding in Dataproc Metastore UI links | All external URLs are HTTPS |
| FINDING-039 | Low | 1.3.2 | Subprocess execution with templated script path | Authorization delegation |
| FINDING-040 | Low | 2.1.1 | Scattered validation rules | Multiple specific validation controls |
| FINDING-041 | Low | 2.2.1 | BigQuery label validation gap | BigQuery server-side validation |
| FINDING-042 | Low | 2.2.1 | Cloud Functions overly permissive regex | Authorization delegation |
| FINDING-043 | Low | 2.2.1 | Dataflow missing None-check in job name | Validation timing and pattern consistency |
| FINDING-044 | Low | 2.2.1 | Transfer Service delayed validation timing | Authorization delegation |
| FINDING-045 | Low | 2.2.1 | Dataplex Catalog inconsistent validation | Service-to-service trust model |
| FINDING-046 | Low | 2.2.1 | Text-to-Speech validation pattern not extended | Text-to-Speech validation pattern |
| FINDING-047 | Low | 2.2.1 | Vertex AI format constraints not enforced | BigQuery server-side validation |
| FINDING-048 | Low | 3.4.2 | Error responses missing CORS headers | Token-based authentication, gRPC transport |
| FINDING-049 | Low | 3.5.3 | No HTTP method restrictions enforced | Token-based authentication provides CSRF protection |
| FINDING-050 | Low | 15.1.1 | No classification of protobuf as dangerous | Thin wrapper pattern, Official Google Cloud libraries |
| FINDING-051 | Low | 15.2.1 | No automated alerting for dependency updates | Defense-in-depth via managed service delegation |
| FINDING-052 | Low | 6.1.1 | Missing rate limiting guidance for Google Ads OAuth2 | Secure authentication method restriction |

**Summary Statistics:**
- **Total Findings:** 52
- **High Severity:** 2
- **Medium Severity:** 21
- **Low Severity:** 29
- **ASVS Pass:** 38
- **ASVS Partial:** 16
- **ASVS Fail:** 19
- **ASVS N/A:** 10
- **Positive Controls:** 103

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 52 |

**Total consolidated findings: 52**

*End of Consolidated Security Audit Report*