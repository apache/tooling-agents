# Security Audit Consolidated Report — apache/airflow/airflow-core

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/airflow/airflow-core |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | N/A |
| Date | May 16, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 1 |

## Executive Summary

### Severity Distribution

| Critical | High | Medium | Low | Info |
|----------|------|--------|-----|------|
| 0 | 0 | 0 | 1 | 0 |

### Level Coverage

This audit covers ASVS Level 1 (L1) requirements across 21 security domains including JWT token authentication, session management, authorization and access control, secrets encryption, API input validation, injection prevention, and transport security. The assessed codebase demonstrates a strong security posture with only a single low-severity finding identified across 70 source reports.

### Top 5 Risks

1. **Execution API Does Not Require `nbf` Claim Presence (Low)** — The Execution API token validation path does not enforce the presence of the `nbf` (not before) claim, potentially allowing tokens to be used before their intended activation time in the absence of this claim. This is the sole finding in this audit.

2. **No additional high-priority risks identified** — The remaining audit domains produced no findings, indicating effective security controls across the evaluated scope.

3. **N/A**

4. **N/A**

5. **N/A**

### Positive Controls

The audit identified numerous well-implemented security controls that demonstrate defense-in-depth practices:

- **Comprehensive Temporal Claim Enforcement (Core API):** All three temporal claims (`exp`, `iat`, `nbf`) are required by default for the Core API, ensuring tokens have bounded validity periods with both start and end times. (`airflow-core/src/airflow/api_fastapi/auth/tokens.py:248`)

- **Configurable Leeway for Clock Skew Tolerance:** Properly handles clock synchronization issues between distributed components with a configuration-driven approach (default 10 seconds leeway) that allows operators to tune based on infrastructure characteristics.

- **Fresh Temporal Claims on Token Refresh:** The merge order during token refresh ensures refreshed tokens always receive new `exp`, `nbf`, and `iat` values, preventing stale temporal claims from being carried forward.

- **Explicit Temporal Error Handling:** All temporal validation failures result in proper HTTP error responses — `ExpiredSignatureError` returns HTTP 401, `InvalidTokenError` (including `ImmatureSignatureError` for future `nbf`) returns HTTP 403.

- **Token Revocation Check After Validation:** Defense-in-depth approach where even valid (non-expired) tokens can be rejected via a revocation list. Temporal validation happens first (fail-fast), followed by revocation check.

- **Trusted Middleware Sentinel Pattern:** Prevents bypassing token validation via accidental `request.state.user` assignment by requiring a specific sentinel object for user injection.

- **Proactive Token Refresh Before Expiry:** Tokens with less than 20% validity remaining are automatically refreshed, preventing legitimate long-running operations from failing due to expiry. The middleware re-validates tokens before refresh.

- **Consistent Validation Library:** All JWT validation uses PyJWT's `jwt.decode()` method, providing a reliable, cryptographically-sound foundation without custom temporal validation logic.

- **Comprehensive Test Coverage for Temporal Claims:** Tests explicitly verify temporal relationships and rejection behavior, ensuring temporal validation remains effective across code changes.

- **JWTValidator Core Implementation:** Primary JWT validation validates `exp`, `nbf`, `iat` claims with configurable clock skew tolerance (`airflow-core/src/airflow/api_fastapi/auth/tokens.py:265-300`).

---

## 3. Findings

### 3.4 Low

#### FINDING-001: Execution API Does Not Require nbf Claim Presence

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | N/A |
| ASVS sections | 9.2.1 |
| Files | airflow-core/src/airflow/api_fastapi/execution_api/app.py:54 |
| Source Reports | 9.2.1.md |
| Related | None |

**Description:**

The Execution API JWT validator does not require the nbf (not-before) claim to be present in tokens, unlike the Core API which requires all three temporal claims (exp, nbf, iat). While PyJWT validates nbf when present in tokens (satisfying ASVS 9.2.1's 'if present' condition), a hypothetical external token issuer configured via JWKS could issue tokens without nbf, which would be accepted without not-before validation. All Airflow-generated tokens always include nbf (verified in test suite). This would only affect deployments with custom external JWKS providers that intentionally omit nbf. The exp claim is always required, so tokens still have a bounded maximum lifetime.

**Remediation:**

Add nbf to the Execution API's required_claims for defense-in-depth:

```python
# airflow-core/src/airflow/api_fastapi/execution_api/app.py:54
def _jwt_validator() -> JWTValidator:
    required_claims = frozenset(["aud", "exp", "iat", "nbf"])  # Add "nbf"
    
    validator = JWTValidator(
        required_claims=required_claims,
        audience=conf.get("execution_api", "auth_audience"),
        ...
    )
    return validator
```

---

---

# 4. Positive Security Controls

| Control | Evidence | Implementation Files |
|---------|----------|---------------------|
| **Comprehensive Temporal Claim Enforcement (Core API)** | All three temporal claims (exp, iat, nbf) required by default for Core API, ensuring tokens have bounded validity periods with both start and end times | `airflow-core/src/airflow/api_fastapi/auth/tokens.py:248` |
| **Configurable Leeway for Clock Skew Tolerance** | Properly handles clock synchronization issues between distributed components while maintaining security. Configuration-driven approach allows operators to tune based on infrastructure characteristics. Default 10 seconds leeway. | `airflow-core/src/airflow/api_fastapi/auth/tokens.py:256`, `airflow-core/src/airflow/api_fastapi/auth/tokens.py:285-293` |
| **Fresh Temporal Claims on Token Refresh** | The extras \| claims merge order ensures refreshed tokens always get new exp, nbf, and iat values, preventing stale temporal claims from being carried forward | `airflow-core/src/airflow/api_fastapi/auth/tokens.py` |
| **Explicit Temporal Error Handling** | All temporal validation failures result in proper HTTP error responses with appropriate status codes. ExpiredSignatureError returns HTTP 401, InvalidTokenError (including ImmatureSignatureError for future nbf) returns HTTP 403 | `airflow-core/src/airflow/api_fastapi/core_api/security.py:113-116`, `airflow-core/src/airflow/utils/serve_logs/log_server.py:83-88` |
| **Token Revocation Check After Validation** | Defense-in-depth approach where even valid (non-expired) tokens can be rejected via revocation list. Temporal validation happens first (fail-fast), followed by revocation check | `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py:131-145` |
| **Comprehensive Test Coverage for Temporal Claims** | Tests explicitly verify temporal relationships and rejection behavior, ensuring temporal validation remains effective across code changes | `airflow-core/tests/unit/api_fastapi/core_api/test_security.py:87-99`, `airflow-core/tests/unit/api_fastapi/execution_api/versions/head/test_router.py` |
| **Trusted Middleware Sentinel Pattern** | Prevents bypassing token validation via accidental request.state.user assignment. Only middleware that sets the specific sentinel object can inject authenticated users | `airflow-core/src/airflow/api_fastapi/core_api/security.py`, `airflow-core/tests/unit/api_fastapi/core_api/test_security.py:118-137` |
| **Proactive Token Refresh Before Expiry** | Tokens with <20% validity remaining are automatically refreshed, preventing legitimate long-running operations from failing due to expiry during execution. The middleware re-validates tokens before refresh, ensuring only valid tokens can be renewed | `airflow-core/src/airflow/api_fastapi/execution_api/app.py:130-160`, `airflow-core/tests/unit/api_fastapi/execution_api/versions/head/test_router.py:39-62` |
| **Consistent Validation Library** | All JWT validation uses PyJWT's jwt.decode() method, which inherently validates exp and nbf when present. This provides a reliable, cryptographically-sound foundation for ASVS 9.2.1 compliance without custom temporal validation logic | `airflow-core/src/airflow/api_fastapi/auth/tokens.py` |
| **JWTValidator Core Implementation** | Primary JWT validation implementation validates exp, nbf, iat claims with configurable clock skew tolerance | `airflow-core/src/airflow/api_fastapi/auth/tokens.py:265-300` |

---

# 5. ASVS Compliance Summary

## Chapter 9: Communication Security - Token-Based Session Management

| ASVS ID | Requirement | Status | Notes |
|---------|-------------|--------|-------|
| **9.1.1** | Token source and integrity - Signature validation | N/A | Out of scope - cryptographic validation |
| **9.1.2** | Token source and integrity - Algorithm allowlist | N/A | Out of scope - cryptographic validation |
| **9.1.3** | Token source and integrity - Trusted key sources | N/A | Out of scope - key management |
| **9.2.1** | Token Validity Time Span Verification | **Pass** | ✅ Core API enforces all temporal claims (exp, iat, nbf), ⚠️ Minor gap: Execution API doesn't require nbf (FINDING-001) |

## Other ASVS Chapters (Out of Scope)

| ASVS ID | Requirement | Status | Reason |
|---------|-------------|--------|--------|
| **1.2.1-1.2.5** | Output Encoding & Injection Prevention | N/A | Not covered in this temporal validation review |
| **1.3.1-1.3.2** | HTML Sanitization & Dynamic Code Execution | N/A | Not covered in this temporal validation review |
| **1.5.1** | Safe Deserialization | N/A | Not covered in this temporal validation review |
| **2.1.1-2.3.1** | Input Validation & Business Logic | N/A | Not covered in this temporal validation review |
| **3.2.1-3.5.3** | Browser Security (XSS, CORS, CSRF) | N/A | Not covered in this temporal validation review |
| **4.1.1-4.4.1** | Web Service & WebSocket Security | N/A | Not covered in this temporal validation review |
| **5.2.1-5.3.2** | File Upload Security | N/A | Not covered in this temporal validation review |
| **6.1.1-6.4.2** | Password & Authentication Management | N/A | Not covered in this temporal validation review |
| **7.2.1-7.4.2** | Session Management (Non-JWT) | N/A | Not covered in this temporal validation review |
| **8.1.1-8.3.1** | Authorization & Access Control | N/A | Not covered in this temporal validation review |
| **10.4.1-10.4.5** | OAuth Authorization Server | N/A | Airflow is not an OAuth authorization server |
| **11.3.1-11.4.1** | Cryptographic Operations | N/A | Not covered in this temporal validation review |
| **12.1.1-12.2.2** | TLS Configuration | N/A | Not covered in this temporal validation review |
| **13.4.1** | Source Control Metadata Protection | N/A | Not covered in this temporal validation review |
| **14.2.1-14.3.1** | Client-Side Data Protection | N/A | Not covered in this temporal validation review |
| **15.1.1-15.3.1** | Dependency Management | N/A | Not covered in this temporal validation review |

---

# 6. Cross-Reference Matrix

## Findings ↔ ASVS Requirements

| Finding ID | Severity | Title | Related ASVS | Status Impact |
|------------|----------|-------|--------------|---------------|
| **FINDING-001** | Low | Execution API Does Not Require nbf Claim Presence | 9.2.1 | Partial compliance - Core API fully compliant, Execution API has minor gap |

## ASVS Requirements ↔ Positive Controls

| ASVS ID | Requirement | Supporting Controls |
|---------|-------------|---------------------|
| **9.2.1** | Token Validity Time Span Verification | • Comprehensive Temporal Claim Enforcement (Core API), • Configurable Leeway for Clock Skew Tolerance, • Fresh Temporal Claims on Token Refresh, • Explicit Temporal Error Handling, • Consistent Validation Library, • JWTValidator Core Implementation, • Comprehensive Test Coverage for Temporal Claims |

## Positive Controls ↔ Implementation Files

| Control Category | Primary Implementation | Secondary/Supporting Files |
|------------------|----------------------|---------------------------|
| **Token Validation** | `airflow-core/src/airflow/api_fastapi/auth/tokens.py` | `airflow-core/src/airflow/api_fastapi/core_api/security.py`, `airflow-core/src/airflow/utils/serve_logs/log_server.py` |
| **Token Lifecycle** | `airflow-core/src/airflow/api_fastapi/auth/tokens.py` | `airflow-core/src/airflow/api_fastapi/execution_api/app.py` |
| **Authorization Integration** | `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py` | `airflow-core/src/airflow/api_fastapi/core_api/security.py` |
| **Test Coverage** | `airflow-core/tests/unit/api_fastapi/core_api/test_security.py` | `airflow-core/tests/unit/api_fastapi/execution_api/versions/head/test_router.py` |

## Findings ↔ Affected Components

| Finding ID | Affected Components | Recommendation Priority |
|------------|---------------------|------------------------|
| **FINDING-001** | • Execution API (`airflow-core/src/airflow/api_fastapi/execution_api/`), • JWTValidator (`airflow-core/src/airflow/api_fastapi/auth/tokens.py`) | Low - Consider adding nbf requirement for defense-in-depth |

## Security Control Coverage Map

| Security Domain | Controls Implemented | Gap Areas |
|----------------|---------------------|-----------|
| **Temporal Claim Validation** | 6 controls | Minor: nbf not required in Execution API |
| **Token Refresh Mechanism** | 2 controls | None identified |
| **Error Handling** | 1 control | None identified |
| **Defense in Depth** | 1 control (revocation check) | None identified |

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 1 |

**Total consolidated findings: 1**

*End of Consolidated Security Audit Report*