# Security Issues

---

## Issue: FINDING-001 - No Proactive Session Invalidation on User Deactivation — Relies on Token Expiry Window

**Labels:** security, priority:low

**Description:**

### Summary
The `requires_authentication` decorator checks `user.is_active` on every request, which correctly rejects deactivated users on their next API call. However, for stateless JWT tokens, there is no proactive session termination—access is blocked only when the next request occurs, not instantly upon user deactivation.

### Details
- **File:** `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py`
- **ASVS:** 7.4.2 (L1)
- **Domain:** GCP Authentication & Credentials

The `_lookup_user` check effectively serves as a per-request revocation mechanism by verifying user status on every request. This is the correct approach for stateless authentication backends. The gap between deactivation and enforcement is at most the time until the user's next request. Risk is theoretical only—no actual vulnerability exists in the current implementation.

### Remediation
**No code change required.** The per-request `user.is_active` check provides effective protection for a stateless authentication backend. For environments requiring zero-delay revocation, the current check is already sufficient since every request is independently verified.

For documentation purposes, consider adding a comment explaining this design decision for future maintainers.

### Acceptance Criteria
- [x] Verified current implementation is secure for stateless auth
- [ ] Documentation added explaining per-request validation approach
- [ ] Architectural decision recorded if zero-delay revocation is needed in future

### References
- ASVS 7.4.2: Session Binding
- Related: GCP-AUTH-1, ASVS-742-LOW-001

### Priority
**Low** - No security vulnerability; design is appropriate for stateless authentication pattern.

---

## Issue: FINDING-002 - Incomplete Exception Handling for Token Expiration May Produce 500 Errors Instead of 401

**Labels:** bug, security, priority:low

**Description:**

### Summary
The `google.auth.jwt.decode` function raises `ValueError` for expired tokens and time-based validation failures, but the exception handler only catches `GoogleAuthError`. This causes expired tokens to trigger unhandled exceptions resulting in HTTP 500 errors instead of proper 401 Unauthorized responses.

### Details
- **File:** `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py`
- **ASVS:** 9.2.1 (L1)
- **Domain:** GCP Authentication & Credentials

**This is NOT a security bypass**—expired tokens are still rejected (the 500 response prevents access). However, it produces:
- Incorrect HTTP status codes (500 instead of 401)
- Potential information leakage via stack traces in debug mode
- Poor user experience for legitimate expired token scenarios

The token validity time span IS effectively enforced, but the error handling is incomplete.

### Remediation
Add `ValueError` to the exception catch clause:

```python
except (exceptions.GoogleAuthError, ValueError):
    return None
```

This ensures all token validation failures (including expiration) return proper 401 responses.

### Acceptance Criteria
- [ ] `ValueError` added to exception handler
- [ ] Test added for expired token scenario
- [ ] Test verifies 401 response (not 500) for expired tokens
- [ ] Test added for "not yet valid" token scenario

### References
- ASVS 9.2.1: Communications Security
- Related: GCP-AUTH-2, ASVS-921-LOW-001
- Google Auth Library documentation on `jwt.decode` exceptions

### Priority
**Low** - No security bypass, but incorrect error handling affects observability and user experience.

---

## Issue: FINDING-003 - Error responses use default `text/html` Content-Type for plain text body content

**Labels:** bug, security, priority:low

**Description:**

### Summary
Flask/Werkzeug's `Response` class defaults to `Content-Type: text/html; charset=utf-8` when no explicit content type is specified. The authentication error responses return plain text strings, not HTML documents, creating a Content-Type mismatch.

### Details
- **File:** `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py`
- **Lines:** 140, 144, 148
- **CWE:** CWE-436 (Interpretation Conflict)
- **ASVS:** 4.1.1 (L1)
- **Domain:** HTTP Response Security

The `requires_authentication()` function returns error responses with plain text bodies but serves them with `text/html` content type headers. This mismatch can cause:
- Browser misinterpretation of response content
- Potential XSS vectors if error messages ever include user input
- API client confusion when parsing responses

### Remediation
Specify explicit Content-Type on all error responses:

```python
Response("Unauthorized", 401, content_type="text/plain; charset=utf-8")
Response("Forbidden", 403, content_type="text/plain; charset=utf-8")
Response("Bad request", 400, content_type="text/plain; charset=utf-8")
```

Alternatively, use JSON responses for consistency with REST API best practices:

```python
Response('{"error": "Unauthorized"}', 401, content_type="application/json")
```

### Acceptance Criteria
- [ ] Fixed at line 140 (Unauthorized response)
- [ ] Fixed at line 144 (Forbidden response)
- [ ] Fixed at line 148 (Bad request response)
- [ ] Test added verifying correct Content-Type headers
- [ ] Verified no other Response() calls have same issue

### References
- ASVS 4.1.1: General Access Control Design
- CWE-436: Interpretation Conflict
- Related: HTTP-RESP-1, ASVS-411-LOW-001

### Priority
**Low** - Content-Type mismatch; no active exploit but violates HTTP standards and defense-in-depth principles.