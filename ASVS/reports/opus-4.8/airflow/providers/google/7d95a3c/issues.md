# Security Issues

---
## Issue: FINDING-001 - User identification relies on reassignable email claim instead of immutable iss+sub

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The Google OpenID authentication backend identifies Airflow users by matching the `email` claim from validated ID tokens against the user database, instead of using the immutable `sub` (subject) claim. This creates an account takeover risk when email addresses are reassigned across different Google identities.

### Details
**CWE:** CWE-287 (Improper Authentication)  
**ASVS:** 10.3.3 (Level 2)

The authentication flow in `google_openid.py` validates Google-issued ID tokens but binds user identity solely to the `email` claim. Email addresses can be reassigned through:
- Corporate email reassignment after employee departure
- Domain recycling
- Shared-audience email reuse

An attacker who obtains a valid Google-issued ID token for the configured OAuth2 audience with an email matching a target Airflow user can authenticate as that user, even though the underlying Google identity (`sub`) differs. This enables account takeover with privileges bounded by the target user's roles, including Admin.

**Affected Files:**
- `providers/google/src/airflow/providers/google/common/auth_backend/google_openid.py` (lines 75-94, 96-106, 115-144)

### Remediation
Bind Airflow user identities to the immutable `iss`+`sub` pair instead of the `email` claim:

1. Store the Google `sub` claim on user records
2. Match federated identities using `(iss, sub)` as the composite key
3. If backward compatibility requires email-based matching, document that deployments MUST guarantee email addresses are never reassigned
4. Strongly recommend migrating to `sub`-based binding for new deployments

### Acceptance Criteria
- [ ] User authentication binds to `iss`+`sub` instead of `email`
- [ ] Database schema updated to store `sub` claim
- [ ] Migration path documented for existing deployments
- [ ] Test added validating that different `sub` with same `email` cannot authenticate
- [ ] Security documentation updated

### References
- CWE-287: https://cwe.mitre.org/data/definitions/287.html
- ASVS 10.3.3
- OpenID Connect Core spec (sub claim): https://openid.net/specs/openid-connect-core-1_0.html#IDToken

### Priority
**Medium** - Requires specific conditions (email reassignment) but enables full account takeover when exploited.

---
## Issue: FINDING-002 - _CredentialsToken.refresh hardcodes 3600s token lifetime ignoring actual credential expiry

**Labels:** bug, priority:low

**Description:**

### Summary
The `_CredentialsToken.refresh` method hardcodes a 3600-second token lifetime regardless of the underlying credential's actual expiry time, causing incorrect token-validity bookkeeping and potential authentication failures with short-lived credentials.

### Details
**CWE:** CWE-613 (Insufficient Session Expiration)  
**ASVS:** 13.3.4 (Level 3)

In `base_google.py`, the refresh method sets `access_token_duration = 3600` unconditionally. For short-lived credentials (e.g., impersonated credentials with expiry < 3600s), this causes:

- Incorrect token-validity bookkeeping
- `ensure_token` method won't refresh until 1800s elapsed
- Potential use of expired tokens in async/deferrable trigger paths
- Intermittent authentication failures (availability impact)

This is a correctness defect, not an attacker-controlled vulnerability. The token cannot actually outlive GCP's server-side expiry, so there is no confidentiality or integrity exposure.

**Affected Files:**
- `providers/google/src/airflow/providers/google/common/hooks/base_google.py`

### Remediation
Derive token duration from the credential's actual `expiry` attribute:

```python
async def refresh(self, *, timeout: int) -> TokenResponse:
    await sync_to_async(self.credentials.refresh)(google.auth.transport.requests.Request())
    self.access_token = cast("str", self.credentials.token)
    expiry = getattr(self.credentials, "expiry", None)
    if expiry is not None:
        self.access_token_duration = max(
            0, int((expiry - datetime.datetime.utcnow()).total_seconds())
        )
    else:
        self.access_token_duration = 3600
    self.access_token_acquired_at = self._now()
    return TokenResponse(value=self.access_token, expires_in=self.access_token_duration)
```

### Acceptance Criteria
- [ ] Token duration derived from credential's actual expiry
- [ ] Fallback to 3600s when expiry unavailable
- [ ] Test added with short-lived impersonated credentials
- [ ] Verify no spurious authentication failures in async triggers
- [ ] UTC timestamp handling validated

### References
- CWE-613: https://cwe.mitre.org/data/definitions/613.html
- ASVS 13.3.4
- Google Auth Python library documentation

### Priority
**Low** - Causes intermittent failures but no security exposure; impacts availability only.

---
## Issue: FINDING-003 - Privileged-by-default SSH login user (user="root") in ComputeEngineSSHHook

**Labels:** bug, security, priority:low

**Description:**

### Summary
The `ComputeEngineSSHHook` constructor defaults to `user="root"`, causing SSH connections to GCE instances to use the root account by default when `use_oslogin=False`. This privileged-by-default configuration increases blast radius if credentials are compromised.

### Details
**CWE:** CWE-250 (Execution with Unnecessary Privileges)  
**ASVS:** 6.3.2 (Level 1)

The hook's constructor sets `user="root"` as the default SSH username in `_connect_to_instance` when using the metadata-key authentication flow. While this requires:
- A trusted DAG author to instantiate the hook
- The target instance to permit root SSH via metadata keys
- Not externally exploitable

...it represents a privileged-by-default foot-gun. When the metadata-key flow is used and the target instance allows it, connections default to the most privileged account, maximizing the blast radius of any compromised ephemeral key or command execution.

**Note:** This is not a shipped/enabled default account vulnerability. The application does not create or ship a root/admin/sa account; root is only the default target login name for the remote instance.

**Affected Files:**
- `providers/google/src/airflow/providers/google/cloud/hooks/compute_ssh.py`

### Remediation
1. Default to a non-privileged user, OR
2. Require the user to be specified explicitly (e.g., `user: str | None = None` and raise if not set for the metadata-key path)
3. At minimum, document the privilege implication prominently
4. Recommend a dedicated low-privilege account for SSH connections in documentation

### Acceptance Criteria
- [ ] Default user changed to non-privileged account or made required parameter
- [ ] Exception raised if user not specified for metadata-key path
- [ ] Documentation updated with security best practices
- [ ] Test added verifying non-root default behavior
- [ ] Migration guide provided for existing DAGs

### References
- CWE-250: https://cwe.mitre.org/data/definitions/250.html
- ASVS 6.3.2
- Principle of Least Privilege

### Priority
**Low** - Requires trusted DAG author and permissive instance configuration; defense-in-depth improvement.