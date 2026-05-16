# Security Issues

## Issue: FINDING-001 - Execution API Does Not Require nbf Claim Presence

**Labels:** bug, security, priority:low

**Description:**

### Summary
The Execution API JWT validator does not require the `nbf` (not-before) claim to be present in tokens, creating a potential gap in temporal validation for tokens issued by external JWKS providers. While PyJWT validates `nbf` when present (satisfying ASVS 9.2.1), the lack of a requirement means external token issuers could omit this claim entirely, bypassing not-before validation.

### Details
- **Location:** `airflow-core/src/airflow/api_fastapi/execution_api/app.py:54`
- **Current Behavior:** The Execution API requires only `["aud", "exp", "iat"]` claims, unlike the Core API which requires all three temporal claims (`exp`, `nbf`, `iat`)
- **Risk Scenario:** A custom external JWKS provider could issue tokens without `nbf` claims, which would be accepted without not-before validation
- **Mitigating Factors:**
  - All Airflow-generated tokens always include `nbf` (verified in test suite)
  - The `exp` claim is always required, providing bounded token lifetime
  - Only affects deployments with custom external JWKS providers that intentionally omit `nbf`
- **ASVS Reference:** 9.2.1 (Level 1)

### Remediation
Add `nbf` to the Execution API's `required_claims` for defense-in-depth consistency with the Core API:

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

### Acceptance Criteria
- [ ] Fixed - `nbf` added to `required_claims` in Execution API JWT validator
- [ ] Test added - Verify tokens without `nbf` claim are rejected by Execution API
- [ ] Consistency verified - Both Core API and Execution API require same temporal claims

### References
- Source Report: `9.2.1.md`
- Related: Core API implementation (already requires `nbf`)
- ASVS 9.2.1: Token validation requirements

### Priority
**Low** - This is a defense-in-depth improvement. Current risk is minimal due to:
- All internal tokens include `nbf`
- `exp` validation still enforces maximum lifetime
- Only hypothetically affects custom external JWKS configurations

---

**Merged from:** ASVS-921-LOW-001