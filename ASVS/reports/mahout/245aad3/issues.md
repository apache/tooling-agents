# Security Issues

## Issue: FINDING-001 - Remote S3/GCS URL paths may contain sensitive bucket names or object keys in logs
**Labels:** bug, security, priority:low

**Description:**

### Summary
User-supplied S3/GCS URL paths containing potentially sensitive bucket names and object keys may be exposed in error messages and logs. While query strings are properly rejected, the bucket names and object key paths can propagate through the error handling chain and appear in logs, potentially leaking sensitive identifiers such as customer IDs, dataset names, or internal project names.

### Details
- **Severity:** Low
- **CWE:** Not specified
- **ASVS:** 14.2.1 (Level L1)
- **Affected Components:**
  - `qdp/qdp-core/src/lib.rs` - `encode_from_parquet` function and path parameter references
  - `docs/qdp/getting-started.md` - remote URL examples
- **Data Flow:** User URL → `encode_from_parquet`/`encode` → platform module → `MahoutError::Io(String)` → logs/error messages

The `MahoutError::Io(String)` variant can propagate complete S3/GCS paths (e.g., `s3://sensitive-bucket-name/customer-123/dataset.parquet`) into error messages and logs, exposing:
- Internal bucket naming conventions
- Customer identifiers in object keys
- Project or dataset names
- Organizational structure information

### Remediation
Implement path sanitization in error messages to redact sensitive components of remote URLs:

1. Create a `sanitize_remote_path()` function that:
   - Detects S3/GCS URL patterns
   - Redacts bucket names (e.g., `s3://<redacted-bucket>/...`)
   - Redacts or truncates object key paths (e.g., `.../customer-123/<redacted>`)
   - Preserves enough context for debugging (protocol, file extension)

2. Apply sanitization before constructing error messages in `MahoutError::Io`

3. Implement structured logging that separates path components, allowing selective redaction of sensitive parts while preserving non-sensitive debugging information

**Example implementation:**
```rust
fn sanitize_remote_path(path: &str) -> String {
    // Redact bucket and key details while preserving protocol
    if path.starts_with("s3://") || path.starts_with("gs://") {
        format!("{}://<redacted>", &path[..path.find("://").unwrap()])
    } else {
        path.to_string()
    }
}
```

### Acceptance Criteria
- [ ] Path sanitization function implemented for S3/GCS URLs
- [ ] Error messages in `MahoutError::Io` sanitize remote paths before logging
- [ ] Structured logging implemented to separate sensitive path components
- [ ] Unit tests added verifying path redaction in error scenarios
- [ ] Integration tests confirm no sensitive paths appear in logs
- [ ] Documentation updated with security considerations for remote URL handling

### References
- Source Report: `14.2.1.md`
- Related ASVS: 14.2.1 - Ensure the application server only accepts the HTTP methods in use by the application/API
- Merged From: ASVS-1421-LOW-001

### Priority
**Low** - While this could leak internal naming conventions and identifiers, it requires error conditions to trigger and does not directly expose credentials or allow unauthorized access. However, it should be addressed to follow defense-in-depth principles and prevent information disclosure.