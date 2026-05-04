# Security Issues

## Issue: FINDING-001 - Remote S3/GCS URL paths may contain sensitive bucket names or object keys in logs
**Labels:** bug, security, priority:low

**Description:**

### Summary
User-supplied S3/GCS URL paths containing bucket names and object keys may be exposed in error messages and logs, potentially leaking sensitive information such as customer IDs, dataset names, or internal project identifiers.

### Details
The `encode_from_parquet` function in `qdp/qdp-core/src/lib.rs` accepts remote URL paths as string arguments that flow through the platform module and may be included in error messages via the `MahoutError::Io(String)` variant. While query strings are explicitly rejected (a positive security pattern), the bucket names and object key paths themselves are not sanitized before being logged or included in error output.

**Example sensitive paths:**
- `s3://customer-12345-data/pii-exports/users.parquet`
- `gs://internal-project-alpha/confidential/dataset.parquet`

**Affected Components:**
- `qdp/qdp-core/src/lib.rs` - `encode_from_parquet` function and path handling
- `docs/qdp/getting-started.md` - remote URL examples

**CWE:** N/A  
**ASVS:** 14.2.1 (Level L1)

### Remediation
1. Implement a `sanitize_remote_path()` function that redacts sensitive portions of S3/GCS URLs before including them in error messages or logs
2. Use structured logging that separates path components for selective redaction
3. Example sanitization pattern: `s3://bucket-name/path/to/file.parquet` → `s3://<redacted-bucket>/<redacted-path>/file.parquet`
4. Apply sanitization consistently across all error handling paths that may expose user-supplied URLs

**Suggested implementation:**
```rust
fn sanitize_remote_path(url: &str) -> String {
    // Redact bucket and key portions while preserving protocol and filename
    // e.g., "s3://bucket/key/file.parquet" -> "s3://<redacted>/<redacted>/file.parquet"
}
```

### Acceptance Criteria
- [ ] Fixed - Implement path sanitization function for S3/GCS URLs
- [ ] Test added - Unit tests verify bucket names and keys are redacted in error messages
- [ ] Test added - Verify sanitized paths still provide useful debugging context
- [ ] Documentation updated to reflect secure logging practices
- [ ] Code review confirms all error paths apply sanitization

### References
- Source Report: `14.2.1.md`
- Related IDs: ASVS-1421-LOW-001
- ASVS Section: 14.2.1 - Safe File Uploads

### Priority
**Low** - Information disclosure risk through logs/errors. Does not directly expose data contents but may reveal internal infrastructure details or customer identifiers to unauthorized parties with access to logs.