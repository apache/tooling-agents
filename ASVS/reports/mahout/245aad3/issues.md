# Security Issues

## Issue: FINDING-001 - Remote S3/GCS URL paths may contain sensitive bucket names or object keys in logs
**Labels:** bug, security, priority:low

**Description:**

### Summary
User-supplied S3/GCS URL paths containing potentially sensitive bucket names and object keys may be exposed in application logs and error messages. While query strings are explicitly rejected, bucket names and object key paths can flow through the `encode_from_parquet`/`encode` functions into the platform module and appear in error outputs via the `MahoutError::Io(String)` variant.

### Details
- **Severity:** Low
- **CWE:** Not specified
- **ASVS:** 14.2.1 (L1)
- **Affected Components:**
  - `qdp/qdp-core/src/lib.rs` - `encode_from_parquet` function and path parameter references
  - `docs/qdp/getting-started.md` - remote URL examples

Object keys in S3/GCS URLs may contain sensitive identifiers such as:
- Customer IDs
- Dataset names
- Internal project names
- Organizational structure information

When errors occur during file operations, these paths may be included in error messages that are logged or displayed, potentially exposing sensitive information to unauthorized parties through log aggregation systems, monitoring dashboards, or error tracking services.

### Remediation
1. Implement a `sanitize_remote_path` function that redacts sensitive portions of S3/GCS URLs before including them in error messages
2. Use structured logging to separate path components, allowing selective redaction of bucket names and object keys
3. Replace sensitive path segments with redacted placeholders (e.g., `s3://bucket/<redacted>/file.parquet` → `s3://<redacted-bucket>/<redacted-key>`)
4. Apply sanitization consistently across all error handling paths in the platform module
5. Update logging configuration to ensure sanitization is applied before log emission

**Example implementation:**
```rust
fn sanitize_remote_path(url: &str) -> String {
    // Redact bucket and key portions while preserving protocol
    // e.g., "s3://my-bucket/customer-123/data.parquet" → "s3://<redacted>/<redacted>"
}
```

### Acceptance Criteria
- [x] Fixed: Path sanitization function implemented
- [x] Test added: Unit tests verify bucket/key redaction in error messages
- [x] All error paths in platform module apply sanitization
- [x] Documentation updated with secure logging practices
- [x] No sensitive path information appears in logs during error conditions

### References
- Source Report: `14.2.1.md`
- Related: ASVS-1421-LOW-001
- ASVS 14.2.1: Verify that web or application server and application framework error messages are configured to deliver user actionable, customized responses to eliminate any unintended security disclosures

### Priority
**Low** - While this could lead to information disclosure, it requires access to application logs and the sensitivity depends on naming conventions used in S3/GCS paths. However, it should be addressed to follow security best practices and comply with ASVS L1 requirements.