# Security Issues

---

## Issue: FINDING-001 - Pagination Offset Validation Bypassed Due to Typo

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The pagination validation function contains a critical typo that prevents offset validation from executing. The code checks `hasattr(query_args, 'offest')` instead of `hasattr(query_args, 'offset')`, causing the validation block to never execute. This allows unbounded offset values to reach database queries, enabling attackers to trigger expensive database queries that force SQLite to scan millions of rows, causing performance degradation and potential denial of service.

### Details
**Affected Files and Lines:**
- `atr/api/__init__.py:45-56` - Typo in hasattr check prevents offset validation

The typo causes the entire validation block to be unreachable dead code. Attackers can specify arbitrarily large offset values (e.g., 999,999,999) in API requests, forcing the database to perform sequential scans through millions of rows. This affects both authenticated and unauthenticated API endpoints.

### Recommended Remediation
Fix the typo on the line checking the offset attribute:

```python
# Change from:
if hasattr(query_args, 'offest'):
    
# To:
if hasattr(query_args, 'offset'):
```

Additionally, add validation to enforce that offset is between 0 and 1,000,000, and limit is between 1 and 1,000. Add unit tests specifically covering offset validation with boundary values (0, 1000000, 1000001, -1).

### Acceptance Criteria
- [ ] Typo corrected from 'offest' to 'offset'
- [ ] Offset validation enforces range 0-1,000,000
- [ ] Limit validation enforces range 1-1,000
- [ ] Unit test verifying offset=1000001 is rejected
- [ ] Unit test verifying offset=-1 is rejected
- [ ] Unit test verifying offset=0 is accepted
- [ ] Unit test verifying the fix

### References
- Source reports: L2:1.3.3.md
- Related findings: None
- ASVS sections: 1.3.3

### Priority
Critical

---

## Issue: FINDING-002 - Pagination Offset Validation Completely Bypassed Due to Typo

**Labels:** bug, security, priority:critical, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The pagination validation function contains a typo that completely bypasses offset validation. The code checks `hasattr(query_args, 'offest')` instead of `hasattr(query_args, 'offset')`, causing the validation block to never execute. This allows arbitrarily large offset values, enabling attackers to force expensive database queries with unbounded offset values, causing SQLite to sequentially scan millions of rows, leading to performance degradation, resource exhaustion, and potential denial of service. This affects both authenticated and unauthenticated API endpoints.

### Details
**Affected Files and Lines:**
- `atr/api/__init__.py:45-51` - Typo in offset validation check
- `atr/api/__init__.py:570-582` - Affected endpoint
- `atr/api/__init__.py:1290` - Affected endpoint
- `atr/api/__init__.py:44-56` - Validation function with typo

The typo prevents the validation block from ever executing, allowing unbounded database queries that can cause severe performance issues. Multiple API endpoints are affected, creating a systemic vulnerability across the application.

### Recommended Remediation
Fix the typo from 'offest' to 'offset' in the hasattr() check:

```python
# Change:
hasattr(query_args, 'offest')

# To:
hasattr(query_args, 'offset')
```

Add validation to enforce offset is between 0 and 1,000,000, and limit is between 1 and 1,000. Add unit tests specifically covering offset validation with boundary values (0, 1000000, 1000001, -1). Add integration tests and consider using a linter that detects typos in string literals used for attribute access. Add rate limiting to public API endpoints to mitigate abuse potential.

### Acceptance Criteria
- [ ] Typo corrected in hasattr() check
- [ ] Offset validation enforces 0-1,000,000 range
- [ ] Limit validation enforces 1-1,000 range
- [ ] Unit tests cover boundary values
- [ ] Integration tests verify all affected endpoints
- [ ] Rate limiting applied to public endpoints
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.1.1.md, L1:2.2.1.md, L1:2.2.2.md, L2:2.1.2.md, L1:2.3.1.md, L2:2.3.2.md, L2:2.2.3.md
- Related findings: None
- ASVS sections: 2.1.1, 2.2.1, 2.2.2, 2.2.3, 2.3.1, 2.3.2

### Priority
Critical

---

## Issue: FINDING-003 - Vote Duration Not Stored, Preventing Resolution Time Enforcement

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The vote duration is not stored on the Release model, only in task arguments. This architectural gap makes it impossible to enforce that votes remain open for their specified duration before resolution. Committee members can approve releases immediately without the mandatory review period, bypassing Apache governance requirements and potentially invalidating votes.

### Details
**Affected Files and Lines:**
- `atr/storage/writers/vote.py:160-195` - Vote start function without duration storage
- `atr/storage/writers/vote.py:199-233` - Vote resolution without duration check
- `atr/models/sql.py` - Missing vote_duration_hours field

The vote duration is passed as a task argument but never persisted to the database. Without this information stored on the Release model, there is no way to validate at resolution time whether the required voting period has elapsed. This creates a governance bypass where votes can be resolved immediately after starting.

### Recommended Remediation
Add `vote_duration_hours` field to the Release model:

```python
# In atr/models/sql.py
vote_duration_hours: int | None = Field(default=None)
```

Store the duration when the vote starts in `promote_to_candidate()`:

```python
release.vote_duration_hours = vote_duration_choice
```

Create a `_validate_vote_duration_elapsed()` helper function and call it in both `resolve()` and `resolve_manually()` methods before allowing vote resolution. Add database migration for the new column.

### Acceptance Criteria
- [ ] vote_duration_hours field added to Release model
- [ ] Duration stored when vote starts
- [ ] Validation function prevents premature resolution
- [ ] Validation applied in resolve() method
- [ ] Validation applied in resolve_manually() method
- [ ] Database migration created and tested
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.3.2.md
- Related findings: FINDING-026, FINDING-104
- ASVS sections: 2.3.2

### Priority
Critical

---

## Issue: FINDING-004 - SSH Server Lacks Brute Force Protection

**Labels:** bug, security, priority:critical, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The SSH server accepts unlimited connection and authentication attempts without any rate limiting or brute force protection. While the server only supports public key authentication (not passwords), the complete absence of connection-level controls creates multiple attack vectors including username enumeration via timing side-channels, connection flooding leading to denial of service, unlimited key testing for stolen/leaked SSH keys without detection, workflow key probing within 20-minute TTL window at unlimited speed, and server resource exhaustion through connection flooding.

### Details
**Affected Files and Lines:**
- `atr/ssh.py:57-159` - SSH server implementation without rate limiting

This gap is acknowledged in project Issue #723. The lack of connection-level rate limiting allows attackers to make unlimited authentication attempts, test stolen keys at high speed, enumerate valid usernames through timing attacks, and exhaust server resources through connection flooding.

### Recommended Remediation
Implement connection-level rate limiting with IP-based blocking:

```python
_failed_attempts: dict[str, list[float]] = {}
_BLOCK_THRESHOLD = 10
_BLOCK_WINDOW = 3600  # seconds
_BLOCK_DURATION = 900  # seconds

def _check_rate_limit(ip_address: str) -> bool:
    """Check if IP should be blocked based on failed attempts."""
    now = time.time()
    if ip_address in _failed_attempts:
        # Remove old attempts outside window
        _failed_attempts[ip_address] = [
            t for t in _failed_attempts[ip_address] 
            if now - t < _BLOCK_WINDOW
        ]
        if len(_failed_attempts[ip_address]) >= _BLOCK_THRESHOLD:
            return False  # Block
    return True  # Allow
```

Implement:
1. Connection rate limiting per IP
2. Failed authentication attempt counter
3. Progressive delay or temporary IP blocking
4. Maximum authentication attempts per connection
5. Integration of authentication failures with blocking mechanism

### Acceptance Criteria
- [ ] IP-based connection tracking implemented
- [ ] Failed authentication counter added
- [ ] Blocking mechanism enforces threshold
- [ ] Maximum attempts per connection enforced
- [ ] Integration with authentication failure logging
- [ ] Unit test verifying the fix

### References
- Source reports: L1:6.3.1.md
- Related findings: FINDING-126
- ASVS sections: 6.3.1

### Priority
Critical

---

## Issue: FINDING-005 - No Server-Side Session Store Prevents Session Termination and Revocation

**Labels:** bug, security, priority:critical, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The application uses Quart's SecureCookieSessionInterface which stores all session data in client-side signed cookies (self-contained tokens). No server-side session registry, revocation list, or session store exists. This architectural limitation prevents server-side invalidation of sessions on logout (captured cookies remain valid for up to 72 hours after logout), enumeration of active sessions for a user, termination of sessions on other devices after authentication factor changes, admin termination of individual user sessions, and admin termination of all sessions globally. All session validation (idle timeout, absolute lifetime) is performed against timestamps embedded in the client-side cookie, not against any server-side state.

### Details
**Affected Files and Lines:**
- `src/asfquart/session.py:31-68` - SecureCookieSessionInterface implementation
- `src/asfquart/session.py:107-120` - Session read/write without server-side tracking
- `src/asfquart/base.py:345-347` - Session initialization

This violates ASVS 7.4.1's requirement that 'the application disallows any further use of the session' when termination is triggered. The client-side cookie architecture makes true session revocation impossible without server-side state.

### Recommended Remediation
**Option A (Recommended): Per-User Revocation Timestamp**

Add `sessions_invalid_before` timestamp column to users table:

```sql
ALTER TABLE users ADD COLUMN sessions_invalid_before TIMESTAMP DEFAULT '1970-01-01';
```

Update logout handler:

```python
UPDATE users SET sessions_invalid_before = NOW() WHERE uid = current_user;
```

Add validation in `authenticate()` and `validate_session_lifetime()` hooks:

```python
if session_data.get('cts') < user.sessions_invalid_before:
    session.clear()
    return redirect('/auth?reason=session_revoked')
```

**Option B: Full Server-Side Session Store**

Implement ActiveSession table with session_id, asf_uid, created_at, last_active, user_agent, ip_address for granular session management with individual session termination capability.

### Acceptance Criteria
- [ ] Server-side session tracking implemented
- [ ] Logout invalidates all user sessions
- [ ] Session termination on authentication factor changes
- [ ] Admin can terminate individual sessions
- [ ] Admin can terminate all sessions globally
- [ ] Migration script created and tested
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.4.1.md, L2:7.4.3.md, L2:7.4.5.md
- Related findings: FINDING-034, FINDING-006, FINDING-007, FINDING-035, FINDING-036, FINDING-037
- ASVS sections: 7.4.1, 7.4.3, 7.4.5

### Priority
Critical

---

## Issue: FINDING-006 - SSH Authentication Completely Bypasses LDAP Account Status Checks

**Labels:** bug, security, priority:critical, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
SSH authentication paths (both persistent keys in `begin_auth()` and GitHub workflow keys in `validate_public_key()`) do not check LDAP account status using `ldap.is_active()` before allowing authentication. The control exists in `atr/ldap.py` and is properly used in web/JWT authentication paths, but is never called during SSH authentication. This allows disabled/banned users to retain full SSH access to artifact repositories for rsync operations indefinitely.

### Details
**Affected Files and Lines:**
- `atr/ssh.py:90-118` - begin_auth() without account status check
- `atr/ssh.py:124-148` - validate_public_key() without account status check

This is a Type B vulnerability where the control exists but is not called in critical paths. Disabled users can continue using SSH access even after their accounts have been disabled in LDAP, bypassing access control entirely.

### Recommended Remediation
Add `ldap.is_active()` checks in both SSH authentication paths:

```python
# atr/ssh.py - begin_auth() for persistent keys (after line 99)
if not self._ldap.is_active(username):
    log.failed_authentication('ssh_account_disabled', extra={'username': username})
    raise asyncssh.PermissionDenied('Account disabled')

# atr/ssh.py - validate_public_key() for workflow keys (after line 107)
if not self._ldap.is_active(username):
    log.failed_authentication('ssh_workflow_account_disabled', extra={'username': username})
    return False

# Defense-in-depth: Add revalidation in _step_02_handle_safely() (after line 148)
if not self._ldap.is_active(self._github_asf_uid):
    log.failed_authentication('ssh_account_disabled_during_operation')
    raise asyncssh.BreakReceived('Account disabled')
```

### Acceptance Criteria
- [ ] Account status check added to begin_auth()
- [ ] Account status check added to validate_public_key()
- [ ] Defense-in-depth check added to operation handler
- [ ] Failed authentication logging implemented
- [ ] Integration test verifying disabled accounts cannot SSH
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.4.2.md
- Related findings: FINDING-129
- ASVS sections: 7.4.2

### Priority
Critical

---

## Issue: FINDING-007 - Global Session Validation Hook Checks Age But Not Account Status

**Labels:** bug, security, priority:critical, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `validate_session_lifetime()` function runs as a `@app.before_request` hook on every HTTP request but only validates session age (created_at timestamp), not LDAP account status. The `ldap.is_active()` control exists and is used in `authenticate()` for specific routes, but is not called in this global hook. This creates inconsistent protection where some routes check account status via `authenticate()` while others rely solely on the global hook which only validates session age, leading to false security confidence.

### Details
**Affected Files and Lines:**
- `atr/server.py:308-331` - validate_session_lifetime() without account status check

The infrastructure for global validation exists but the critical account status check is missing. This means disabled accounts can continue to access routes that don't explicitly call `authenticate()`, creating an authorization bypass.

### Recommended Remediation
Add periodic account status revalidation to `validate_session_lifetime()` hook with caching to balance security vs LDAP load:

```python
# atr/server.py - in validate_session_lifetime() hook
ACCOUNT_CHECK_INTERVAL = 300  # 5 minutes

if session_data:
    account_checked_at = session_data.get('account_checked_at', 0)
    current_time = time.time()
    
    if current_time - account_checked_at > ACCOUNT_CHECK_INTERVAL:
        if not ldap.is_active(session_data['uid']):
            log.info('session_invalidated_account_disabled', extra={'asf_uid': session_data['uid']})
            asfquart.session.clear()
            return quart.redirect('/auth?reason=account_disabled')
        session_data['account_checked_at'] = current_time
        asfquart.session.write(session_data)
```

### Acceptance Criteria
- [ ] Account status check added to global hook
- [ ] Caching mechanism prevents LDAP overload
- [ ] Session cleared when account disabled
- [ ] User redirected with appropriate message
- [ ] Last check timestamp stored in session
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.4.2.md
- Related findings: FINDING-006, FINDING-129
- ASVS sections: 7.4.2

### Priority
Critical

---

## Issue: FINDING-008 - Trusted Publisher JWT Not Bound to Target Project

**Labels:** bug, security, priority:critical, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The `update_distribution_task_status` API endpoint accepts GitHub Actions OIDC tokens to authenticate workflow status updates. However, the endpoint explicitly discards the JWT payload and asf_uid return values (underscore-prefixed variables), then accepts a user-supplied `project_key` parameter without verifying it matches the repository in the JWT's claims. This allows a GitHub Actions workflow from apache/repo-X to update workflow status, register SSH keys, or record distributions for apache/repo-Y, enabling cross-project privilege escalation and violating BOPLA principles.

### Details
**Affected Files and Lines:**
- `atr/api/__init__.py:575` - JWT validation with discarded results
- `atr/api/__init__.py:670` - User-supplied project_key without validation
- `atr/api/__init__.py:1091-1112` - JWT verification function
- `atr/db/interaction.py:440` - Direct database access bypassing authorization

The endpoint validates the JWT signature but never verifies that the authenticated repository matches the target project. This creates a cross-project authorization bypass where any Apache project's workflow can impersonate another project.

### Recommended Remediation
1. Validate JWT and capture results instead of discarding them:

```python
# Don't use underscore prefix
payload, asf_uid = trusted_jwt_for_dist(...)
```

2. Derive project from JWT payload (authoritative source) using `_trusted_project()`:

```python
jwt_project = _trusted_project(payload)
```

3. Verify user-supplied project_key matches JWT source repository:

```python
if project_key != jwt_project:
    raise base.ASFQuartException('Project mismatch', errorcode=403)
```

4. Use storage authorization layer instead of direct DB access with `write_as_committee_member()`
5. Apply same fix to `trusted_jwt_for_dist()` and all callers
6. Add integration test verifying cross-project JWT rejection
7. Add audit log entry for all trusted publisher operations

### Acceptance Criteria
- [ ] JWT payload captured and validated
- [ ] Project derived from JWT claims
- [ ] User-supplied project_key validated against JWT
- [ ] Storage authorization layer used
- [ ] Integration test prevents cross-project access
- [ ] Audit logging implemented
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.1.1.md, L1:8.2.2.md, L2:8.2.3.md
- Related findings: FINDING-009
- ASVS sections: 8.1.1, 8.2.2, 8.2.3

### Priority
Critical

---

## Issue: FINDING-009 - Key-Committee Association Bypasses Storage Layer Authorization

**Labels:** bug, security, priority:critical, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The key details update endpoint allows authenticated users to modify which committees their OpenPGP key is associated with. While the endpoint verifies key ownership, it writes key-committee associations directly to the database, bypassing the storage layer's `as_committee_participant()` authorization check. The function performs committee membership authorization checks AFTER committing changes to the database. This allows any authenticated committer who owns a key to associate it with committees they do not belong to, potentially causing their key to appear in unauthorized committee KEYS files.

### Details
**Affected Files and Lines:**
- `atr/post/keys.py:89-119` - Key details update with direct DB writes
- `atr/post/keys.py:101-108` - Committee association without authorization
- `atr/post/keys.py:68-105` - Authorization check after commit
- `atr/post/keys.py:75` - Direct database manipulation
- `atr/post/keys.py:76-115` - Committee loop without validation
- `atr/post/keys.py:87-114` - Post-commit authorization (ineffective)

The authorization check that occurs post-commit silently ignores failures without rolling back the transaction, allowing unauthorized associations to persist.

### Recommended Remediation
Validate committee membership BEFORE any database modification. Replace direct database writes with storage layer authorization checks:

```python
# For each committee disassociation
write.as_committee_participant(committee_key).keys.disassociate_fingerprint(fingerprint)

# For each committee association
write.as_committee_participant(committee_key).keys.associate_fingerprint(fingerprint)
```

Handle `AccessError` exceptions and display appropriate error messages to users. Add integration test attempting unauthorized committee association. Audit existing key-committee associations for unauthorized entries. Add audit log entry for all key-committee association changes.

### Acceptance Criteria
- [ ] Committee membership validated before DB changes
- [ ] Storage layer authorization used for associations
- [ ] AccessError exceptions handled properly
- [ ] Integration test verifies authorization enforcement
- [ ] Audit of existing associations completed
- [ ] Audit logging added
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.1.1.md, L1:8.2.1.md, L1:8.2.2.md, L1:8.3.1.md, L2:8.2.3.md
- Related findings: FINDING-008
- ASVS sections: 8.1.1, 8.2.1, 8.2.2, 8.3.1, 8.2.3

### Priority
Critical

---

## Issue: FINDING-010 - OAuth Session Display Returns Full Session Without Anti-Caching Headers

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The OAuth `/auth` endpoint returns complete session data including user identity, email, organizational roles, committee memberships, and admin status without anti-caching headers. The `ClientSession` object exposes highly sensitive authorization information that should never be cached. On shared workstations, this reveals privileged user identity and access levels to subsequent users through browser cache.

### Details
**Affected Files and Lines:**
- `src/asfquart/generics.py:121-127` - OAuth session display without cache headers

Data flow: Session cookie → `asfquart.session.read()` → `ClientSession` dict (uid, email, committees, membership flags) → no Cache-Control → browser cache. Full session data including organizational roles, committee memberships, and admin status cached in browser.

### Recommended Remediation
Create a `quart.Response` object from the session data and set `response.headers['Cache-Control'] = 'no-store'` before returning:

```python
response = quart.jsonify(dict(client_session))
response.headers['Cache-Control'] = 'no-store'
return response
```

### Acceptance Criteria
- [ ] Response object created explicitly
- [ ] Cache-Control: no-store header set
- [ ] Session data still returned correctly
- [ ] Integration test verifies header presence
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.3.2.md
- Related findings: None
- ASVS sections: 14.3.2

### Priority
Critical

---

## Issue: FINDING-011 - No Global Anti-Caching Middleware (Architectural Gap)

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The application lacks any global or blueprint-level middleware to enforce anti-caching headers. While individual endpoints can set headers (as demonstrated by `jwt_post`), there is no architectural enforcement mechanism. This creates a systemic vulnerability where every new endpoint automatically lacks protection unless developers manually remember to add headers. All four blueprints define `before_request` hooks but none define `after_request` hooks that would add security headers. Only ~6% of sensitive endpoints are protected (1 out of ~16 endpoints), and every new endpoint added automatically lacks anti-caching headers.

### Details
**Affected Files and Lines:**
- `atr/blueprints/api.py` - No after_request hook
- `atr/blueprints/admin.py` - No after_request hook
- `atr/blueprints/get.py` - No after_request hook
- `atr/blueprints/post.py` - No after_request hook
- `src/asfquart/generics.py` - No global middleware

This is a Type B gap with minimal coverage. The lack of architectural enforcement means vulnerabilities are introduced by default rather than requiring explicit mistakes.

### Recommended Remediation
Add application-wide `@app.after_request` hook to set security headers on all responses:

```python
@app.after_request
async def add_cache_control_headers(response):
    response.headers.setdefault('Cache-Control', 'no-store')
    response.headers.setdefault('Pragma', 'no-cache')
    return response
```

Alternatively, add per-blueprint `@_BLUEPRINT.after_request` hooks for targeted enforcement. This is Priority 1 action that fixes all current and future endpoints.

### Acceptance Criteria
- [ ] Global after_request hook implemented
- [ ] Cache-Control headers set on all responses
- [ ] Pragma header set for HTTP/1.0 compatibility
- [ ] Existing endpoints verified to receive headers
- [ ] New endpoints automatically protected
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.3.2.md
- Related findings: FINDING-047, FINDING-048, FINDING-049, FINDING-191
- ASVS sections: 14.3.2

### Priority
Critical

---

## Issue: FINDING-012 - Pagination Offset Validation Completely Bypassed Due to Typo

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The pagination validation function contains a critical typo that renders offset validation completely ineffective. The code checks for `hasattr(query_args, "offest")` instead of `hasattr(query_args, "offset")`, making the entire validation block unreachable dead code. This allows attackers to specify arbitrary offset values (e.g., 999,999,999), forcing the database to perform full table scans through millions of rows, causing resource exhaustion, service degradation, and potential denial of service. The issue affects multiple API endpoints including releases_list, tasks_list, and ssh_keys_list.

### Details
**Affected Files and Lines:**
- `atr/api/__init__.py:805-825` - Pagination validation with typo
- `atr/api/__init__.py:665` - releases_list endpoint
- `atr/api/__init__.py:720` - tasks_list endpoint
- `atr/api/__init__.py:775` - ssh_keys_list endpoint

The typo makes the entire offset validation unreachable, allowing unbounded database queries across multiple endpoints.

### Recommended Remediation
Fix the typo in the validation function:

```python
# Change:
hasattr(query_args, "offest")

# To:
hasattr(query_args, "offset")
```

Add explicit `isinstance(limit, int)` and `isinstance(offset, int)` checks before performing comparison operations. Add unit tests specifically validating offset rejection with large values (>1,000,000). Add integration test creating archives with interleaved metadata files to verify size limit enforcement. Consider adding database-level query timeout protection as defense-in-depth.

### Acceptance Criteria
- [ ] Typo corrected in hasattr check
- [ ] Type checks added for limit and offset
- [ ] Unit tests verify large offset rejection
- [ ] Integration tests verify all affected endpoints
- [ ] Database timeout protection considered
- [ ] Unit test verifying the fix

### References
- Source reports: L2:15.1.3.md, L2:15.2.2.md, L2:15.3.5.md, L2:15.3.7.md
- Related findings: FINDING-050, FINDING-206
- ASVS sections: 15.1.3, 15.2.2, 15.3.5, 15.3.7

### Priority
Critical

---

## Issue: FINDING-013 - SVN Operations Disable TLS Certificate Verification (Supply Chain Risk)

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
SVN export and import operations explicitly disable TLS certificate verification using `--trust-server-cert-failures` flags (unknown-ca, cn-mismatch), accepting any certificate regardless of validity. This completely neutralizes the security benefits of HTTPS encryption, allowing man-in-the-middle attacks on release artifact imports. An attacker with network position could inject malicious code into release artifacts without detection at the transport layer.

### Details
**Affected Files and Lines:**
- `atr/tasks/svn.py:73-84` - SVN export with disabled cert verification
- `atr/tasks/svn.py:93-103` - SVN import with disabled cert verification

The `--trust-server-cert-failures` flag explicitly bypasses certificate validation, accepting unknown CAs and certificate name mismatches. This creates a supply chain security vulnerability where artifact integrity depends entirely on post-download verification.

### Recommended Remediation
Remove `--trust-server-cert-failures` and `unknown-ca,cn-mismatch` flags from the SVN export command:

```python
# Remove these flags:
'--trust-server-cert-failures', 'unknown-ca,cn-mismatch'
```

If custom CA is needed for ASF internal infrastructure, configure SVN to trust only that specific CA:

```python
'--config-option', 'servers:global:ssl-authority-files=/path/to/asf-ca.pem'
```

This approach maintains security while supporting internal certificate authorities if needed.

### Acceptance Criteria
- [ ] Certificate verification flags removed
- [ ] SVN operations verify certificates by default
- [ ] Custom CA configuration if needed
- [ ] Integration test verifies cert validation
- [ ] Documentation updated with security rationale
- [ ] Unit test verifying the fix

### References
- Source reports: L2:12.3.1.md, L2:12.3.3.md
- Related findings: None
- ASVS sections: 12.3.1, 12.3.3

### Priority
Critical

---

## Issue: FINDING-014 - Admin Environment Variable Endpoint Exposes All Secrets Without Redaction

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `/admin/env` endpoint exposes all environment variables including sensitive credentials (LDAP_BIND_PASSWORD, GITHUB_TOKEN, PUBSUB_PASSWORD, SVN_TOKEN, DATABASE_URL, JWT signing keys) in plaintext without any redaction. This contrasts with the `/admin/configuration` endpoint in the same file which properly implements secret redaction using pattern matching. While admin authentication is required, this creates an undocumented log broadcast channel that violates multiple ASVS requirements for secret protection and logging control.

### Details
**Affected Files and Lines:**
- `atr/admin/__init__.py:320-350` - Environment variable endpoint without redaction

The endpoint returns all environment variables without filtering, exposing database credentials, API tokens, and cryptographic keys. This creates unnecessary risk even with admin authentication, as compromised admin sessions or logging systems could capture these secrets.

### Recommended Remediation
Apply the same `sensitive_config_patterns` redaction logic used in `configuration()` to the `env()` endpoint:

```python
sensitive_patterns = ('PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'CREDENTIAL')

for key, value in os.environ.items():
    if any(pattern in key.upper() for pattern in sensitive_patterns):
        redacted_env[key] = '***REDACTED***'
    else:
        redacted_env[key] = value
```

Additionally, document this endpoint in the log inventory as a broadcast channel.

### Acceptance Criteria
- [ ] Sensitive pattern matching implemented
- [ ] Credentials redacted in response
- [ ] Redaction logic matches configuration endpoint
- [ ] Endpoint documented in log inventory
- [ ] Integration test verifies redaction
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.3.1.md, L2:13.3.2.md, L2:14.1.1.md, L2:16.2.3.md
- Related findings: FINDING-015
- ASVS sections: 13.3.1, 13.3.2, 14.1.1, 16.2.3

### Priority
Critical

---

## Issue: FINDING-015 - Pagination Offset Validation Completely Bypassed Due to Typo

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The pagination validation function contains a critical typo checking `hasattr(query_args, 'offest')` instead of `'offset'`, causing the entire offset validation block to be skipped for all requests. This allows unbounded database offset values that can cause performance degradation and potential denial of service across three API endpoints. The typo prevents validation of both upper bounds (max 1,000,000) and lower bounds (min 0), allowing negative offsets and arbitrarily large values.

### Details
**Affected Files and Lines:**
- `atr/api/__init__.py:~696` - Pagination validation with typo

The typo makes the validation block unreachable, allowing any offset value to pass through unchecked. This affects all endpoints using the pagination validation function.

### Recommended Remediation
Fix the typo:

```python
# Change:
hasattr(query_args, 'offest')

# To:
hasattr(query_args, 'offset')
```

Add unit tests specifically validating offset parameter rejection with boundary values (offset=0, offset=1000000, offset=1000001, offset=-1). Consider using Pydantic `Field(ge=0, le=1000000)` constraints on pagination models as primary defense.

### Acceptance Criteria
- [ ] Typo corrected in hasattr check
- [ ] Unit tests cover boundary values
- [ ] Negative offsets rejected
- [ ] Large offsets rejected
- [ ] Pydantic constraints considered
- [ ] Unit test verifying the fix

### References
- Source reports: L2:1.4.2.md, L2:13.3.2.md
- Related findings: FINDING-016
- ASVS sections: 1.4.2, 13.3.2

### Priority
Critical

---

## Issue: FINDING-016 - HMAC Signer Verification Always Returns False (Broken Cryptographic Control)

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `Signer.verify()` function has a critical bug where HMAC verification always returns False due to encoding mismatch. The function compares base64-encoded string (43 bytes ASCII) against base64-decoded raw bytes (32 bytes), which always fails. Root cause: `given_bytes` is base64-decoded raw HMAC digest while `expected` is base64-encoded string converted to ASCII bytes. This creates false confidence that HMAC integrity checks are working when they are completely broken.

### Details
**Affected Files and Lines:**
- `asfpy/crypto.py:109-121` - Signer.verify() with type mismatch

The function decodes the given signature to raw bytes but encodes the expected signature to a base64 string before comparison. Since these are different representations, `hmac.compare_digest()` always returns False, even for valid signatures.

### Recommended Remediation
Fix the `verify()` method to compare values in the same representation. Compare the base64 strings directly without encoding/decoding:

```python
def verify(self, *args: str, given: str) -> bool:
    """Verify a given HMAC signature is correct."""
    try:
        expected = self.sign(*args)  # Returns base64 string
        return hmac.compare_digest(expected, given)  # Compare strings
    except (base64.binascii.Error, ValueError):
        return False
```

Add comprehensive unit tests including valid signature verification, invalid signature rejection, and tampered data detection.

### Acceptance Criteria
- [ ] Type mismatch corrected
- [ ] Valid signatures verify successfully
- [ ] Invalid signatures rejected
- [ ] Tampered data detected
- [ ] Unit tests cover all scenarios
- [ ] Unit test verifying the fix

### References
- Source reports: L2:11.1.1.md, L2:11.1.2.md, L2:11.2.1.md
- Related findings: None
- ASVS sections: 11.1.1, 11.1.2, 11.2.1

### Priority
Critical

---

## Issue: FINDING-017 - Admin User Impersonation Has No Audit Trail

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
An administrator can impersonate any user account with zero audit logging. The only logging code present was explicitly commented out, and even that would have logged to the general log rather than the dedicated audit log. A compromised admin account used for malicious impersonation leaves zero forensic evidence, violating the fundamental principle that privileged operations must be auditable.

### Details
**Affected Files and Lines:**
- `atr/admin/__init__.py:135-165` - User impersonation without audit logging

The impersonation function modifies the session to impersonate another user but creates no audit trail. Even the commented-out logging would not have used the dedicated audit log infrastructure.

### Recommended Remediation
Add explicit audit logging before session modification using `storage.audit()`:

```python
storage.audit(
    operation='admin_impersonation',
    admin_asf_uid=current_session['uid'],
    target_asf_uid=target_username,
    remote_addr=request.remote_addr,
    user_agent=request.headers.get('User-Agent')
)
```

The audit log entry must be written BEFORE the session cookie is modified to ensure the event is captured even if subsequent operations fail.

### Acceptance Criteria
- [ ] Audit log entry created before impersonation
- [ ] Admin UID captured
- [ ] Target UID captured
- [ ] Remote address captured
- [ ] User agent captured
- [ ] Audit log persisted before session modification
- [ ] Unit test verifying the fix

### References
- Source reports: L2:16.2.1.md
- Related findings: FINDING-018, FINDING-019
- ASVS sections: 16.2.1

### Priority
Critical

---

## Issue: FINDING-018 - Committee Key Bulk Deletion Bypasses Storage Layer and Audit

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The admin route directly uses `db.session()` to delete committee signing keys, bypassing both the storage layer's authorization framework and its audit logging. The storage interface documentation explicitly warns against this pattern. Bulk deletion of committee signing keys — which are critical for release artifact verification — leaves no audit trail, making it impossible to investigate security incidents or track key lifecycle.

### Details
**Affected Files and Lines:**
- `atr/admin/__init__.py:290-340` - Committee key deletion with direct DB access

The function performs bulk deletion directly through the database session, completely bypassing the storage layer that provides authorization checks and audit logging. This violates documented architectural patterns.

### Recommended Remediation
**Option A (Recommended):** Use storage layer instead of direct DB access:

```python
for key in keys_to_delete:
    wafa.keys.delete_key(key.fingerprint)
```

**Option B:** If storage layer cannot be used, add explicit audit logging:

```python
storage.audit(
    operation='committee_keys_bulk_delete',
    admin_asf_uid=session['uid'],
    committee_key=committee_key,
    keys_deleted=len(keys_to_delete),
    fingerprints=[k.fingerprint for k in keys_to_delete]
)
```

### Acceptance Criteria
- [ ] Storage layer used for deletions OR
- [ ] Explicit audit logging implemented
- [ ] Admin UID captured
- [ ] Committee key captured
- [ ] Deleted key fingerprints captured
- [ ] Unit test verifying the fix

### References
- Source reports: L2:16.2.1.md
- Related findings: FINDING-017, FINDING-019
- ASVS sections: 16.2.1

### Priority
Critical

---

## Issue: FINDING-019 - OpenPGP Key Management Entirely Lacks Audit Logging

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The key management writer module contains an explicit '# TODO: Add auditing' comment on line 20. None of the security-critical operations — key deletion, insertion, association with committees, or import from files — call `self.__write_as.append_to_audit_log()`, despite this facility being available and consistently used in other writer modules. OpenPGP signing keys are the foundation of Apache release artifact verification, making their lifecycle events critical to audit.

### Details
**Affected Files and Lines:**
- `atr/storage/writers/keys.py:20-350` - Key management without audit logging

The TODO comment acknowledges the gap but no implementation exists. All key lifecycle operations (delete, insert, associate, import) lack audit trails, making forensic investigation impossible.

### Recommended Remediation
Add `self.__write_as.append_to_audit_log()` calls to all key management operations:

```python
# delete_key
self.__write_as.append_to_audit_log(
    operation='key_delete',
    fingerprint=fingerprint,
    key_owner=key.owner_uid,
    committees=key.committees
)

# __database_add_model
self.__write_as.append_to_audit_log(
    operation='key_insert',
    fingerprint=model.fingerprint,
    key_type=model.key_type
)

# associate_fingerprint
self.__write_as.append_to_audit_log(
    operation='key_associate_committee',
    fingerprint=fingerprint,
    committee_key=committee_key
)
```

Apply to: `delete_key`, `__database_add_model`, `associate_fingerprint`, `ensure_stored_one`, `import_keys_file`, and `test_user_delete_all`. Remove TODO comment on line 20 once implemented.

### Acceptance Criteria
- [ ] Audit logging added to delete_key
- [ ] Audit logging added to insert operations
- [ ] Audit logging added to association operations
- [ ] Audit logging added to import operations
- [ ] TODO comment removed
- [ ] Unit test verifying the fix

### References
- Source reports: L2:16.1.1.md, L2:16.2.1.md
- Related findings: FINDING-017, FINDING-018, FINDING-057
- ASVS sections: 16.1.1, 16.2.1

### Priority
Critical

---

## Issue: FINDING-020 - Unsanitized Markdown-to-HTML Conversion Allows Stored XSS in SBOM Vulnerability Descriptions

**Labels:** bug, security, priority:high, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The application converts markdown vulnerability descriptions from external sources (OSV API, CycloneDX SBOM files) to HTML using `cmarkgfm.github_flavored_markdown_to_html()`, then wraps the output in `markupsafe.Markup()` to bypass htpy's automatic escaping. The markdown library preserves raw HTML tags in the input, enabling stored XSS attacks. An attacker can upload a malicious CycloneDX SBOM file with crafted `vulnerability.detail` field containing embedded HTML/JavaScript, which executes in victim's browser when viewing SBOM reports. This affects authenticated committer sessions.

### Details
**Affected Files and Lines:**
- `atr/get/sbom.py:290-310` - Markdown conversion without sanitization
- `atr/get/sbom.py:370` - Markup() wrapper bypassing escaping

Data flow: Attacker uploads malicious CycloneDX SBOM file → SBOM contains crafted vulnerability.detail field with embedded HTML/JavaScript → cmarkgfm preserves raw HTML tags → markupsafe.Markup() marks output as safe, bypassing htpy escaping → htm.div[details] renders without escaping → JavaScript executes in victim's browser.

### Recommended Remediation
**Option A (Recommended):** Use cmarkgfm safe mode with `CMARK_OPT_SAFE` flag which replaces dangerous HTML with comments.

**Option B (Most Robust):** Use dedicated HTML sanitizer (nh3>=0.2.14 or bleach) with allowed tags whitelist:

```python
import nh3

allowed_tags = {'p', 'br', 'strong', 'em', 'code', 'pre', 'a', 'ul', 'ol', 'li', 
                'h1', 'h2', 'h3', 'h4', 'blockquote'}
allowed_attributes = {'a': {'href', 'title'}}

html = cmarkgfm.github_flavored_markdown_to_html(markdown_text)
sanitized_html = nh3.clean(html, tags=allowed_tags, attributes=allowed_attributes)
return markupsafe.Markup(sanitized_html)
```

Additional recommendations:
1. Audit all `markupsafe.Markup()` calls
2. Establish code review rule requiring sanitization before `Markup()` calls on non-constant values
3. Add automated XSS testing for SBOM uploads
4. Pin cmarkgfm version with known safe defaults

### Acceptance Criteria
- [ ] HTML sanitization implemented
- [ ] Allowed tags whitelist configured
- [ ] Allowed attributes whitelist configured
- [ ] XSS testing added for SBOM uploads
- [ ] Code review guidelines updated
- [ ] Unit test verifying the fix

### References
- Source reports: L1:1.2.3.md, L2:1.3.10.md
- Related findings: FINDING-065, FINDING-209
- ASVS sections: 1.2.3, 1.3.10

### Priority
High

---

## Issue: FINDING-021 - Trusted Publishing Cross-Field Validation Bypassed Via Web Form

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The web form path for editing trusted publishing configuration does not call the existing validation function `_normalise_trusted_publishing_update()`, while the API path does. This creates an inconsistency where invalid configurations can be saved via the web interface but would be rejected via the API. Specifically, workflow paths not starting with '.github/workflows/' could weaken trusted publisher verification, and repository names with slashes could cause path traversal issues in URL construction. The form-based endpoint bypasses critical business validation that is correctly applied to the API endpoint.

### Details
**Affected Files and Lines:**
- `atr/storage/writers/policy.py:178-188` - API path with validation
- `atr/storage/writers/policy.py:267-284` - Web form path without validation
- `atr/shared/projects.py:multiple` - Validation function

The API endpoint correctly applies cross-field validation, but the web form endpoint directly assigns form values without validation, creating a security bypass.

### Recommended Remediation
Call the existing `_normalise_trusted_publishing_update()` function in `edit_trusted_publishing()` to apply the same cross-field validation as the API path:

```python
# In edit_trusted_publishing()
values = {
    'repository': form_data.get('repository'),
    'workflow_path': form_data.get('workflow_path'),
    # ... other fields
}

# Apply validation
normalized_values = _normalise_trusted_publishing_update(values)

# Use normalized values
release_policy.repository = normalized_values['repository']
release_policy.workflow_path = normalized_values['workflow_path']
```

Apply the validation function in `edit_trusted_publishing()` before assigning form values to the release_policy object, matching the pattern used in `edit_policy()`.

### Acceptance Criteria
- [ ] Validation function called before form processing
- [ ] Workflow path validation enforced
- [ ] Repository name validation enforced
- [ ] Web form behavior matches API behavior
- [ ] Integration test verifies validation enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.1.1.md, L1:2.2.1.md
- Related findings: FINDING-022, FINDING-089
- ASVS sections: 2.1.1, 2.2.1

### Priority
High

---

## Issue: FINDING-022 - Vote Policy Form Bypasses Minimum Hours Range Check

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The form-based endpoint for editing vote policy bypasses the minimum hours range validation (72-144 hours or 0) that is correctly applied to the API endpoint. The validation function `_validate_min_hours()` exists in the policy layer but is not called when editing policies via the web form. This allows committee members to set voting periods that violate policy-mandated minimums via the web interface, potentially enabling governance bypass through extremely short or long voting periods.

### Details
**Affected Files and Lines:**
- `atr/storage/writers/policy.py:220-236` - API path with validation
- `atr/storage/writers/policy.py:238-252` - Web form path without validation

The validation function exists and is correctly applied in the API path, but the web form endpoint directly assigns values without calling the validation function.

### Recommended Remediation
Add `_validate_min_hours()` call in `__set_min_hours()` before assignment to enforce the 72-144 hour range (or 0) requirement:

```python
def __set_min_hours(self, value: int) -> None:
    """Set minimum hours with validation."""
    validated_value = _validate_min_hours(value)
    self.release_policy.min_hours = validated_value
```

Ensure validation is consistently applied across both web form and API endpoints.

### Acceptance Criteria
- [ ] Validation function called in web form path
- [ ] 72-144 hour range enforced
- [ ] Zero value allowed (disable minimum)
- [ ] Invalid values rejected
- [ ] Error messages displayed to user
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.1.md
- Related findings: FINDING-021, FINDING-089, FINDING-003
- ASVS sections: 2.2.1

### Priority
High

---

## Issue: FINDING-023 - Missing Phase Validation in Vote Start Flow

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `release_ready_for_vote()` function validates 9 conditions before allowing a vote to start (revision matching, committee existence, blocker checks, file presence, etc.) but does not validate the release phase. This allows committee members to initiate votes on releases in any phase, including RELEASE_CANDIDATE (already voted), RELEASE_PREVIEW (being finalized), and RELEASE (already announced). The function fetches the release without a phase filter, enabling multiple votes to be initiated on the same release and breaking the sequential lifecycle requirement.

### Details
**Affected Files and Lines:**
- `atr/db/interaction.py:220-270` - release_ready_for_vote() without phase validation
- `atr/get/voting.py` - Vote start UI
- `atr/post/voting.py` - Vote start handler
- `atr/get/manual.py` - Manual vote UI
- `atr/post/manual.py` - Manual vote handler

The function performs comprehensive validation but omits the critical phase check, allowing votes to start from inappropriate lifecycle stages.

### Recommended Remediation
Add phase validation to `release_ready_for_vote()` to enforce that votes can only start from RELEASE_CANDIDATE_DRAFT phase:

```python
# Add after fetching release
if release.phase != sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
    return (
        False,
        f"Cannot start vote: release is in {release.phase.value} phase. "
        f"Votes can only be started from RELEASE_CANDIDATE_DRAFT phase."
    )
```

Check `release.phase != sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT` and return an error message if the release is not in the draft phase before proceeding with other validations.

### Acceptance Criteria
- [ ] Phase validation added to function
- [ ] Only RELEASE_CANDIDATE_DRAFT phase allowed
- [ ] Descriptive error message returned
- [ ] Integration test verifies phase enforcement
- [ ] All vote start paths validated
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.3.1.md
- Related findings: FINDING-085, FINDING-086
- ASVS sections: 2.3.1

### Priority
High

---

## Issue: FINDING-024 - Key Committee Association Update Bypasses Storage Layer Authorization

**Labels:** bug, security, priority:high, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The `details()` function in `atr/post/keys.py` allows users to update which committees their PGP key is associated with by directly manipulating the database, bypassing the storage layer's `as_committee_participant()` authorization control. While the `add()` function correctly verifies committee membership through the storage layer, `details()` fetches committees directly from the database without membership validation and assigns them to the user's key. This enables users to associate their keys with any committee regardless of actual membership status, compromising supply chain trust.

### Details
**Affected Files and Lines:**
- `atr/post/keys.py:89-121` - details() with direct DB manipulation
- `atr/post/keys.py:82-102` - Committee assignment without validation
- `atr/storage/writers/keys.py` - Storage layer with authorization

The function bypasses the storage layer's authorization checks, allowing unauthorized committee associations.

### Recommended Remediation
Replace direct database manipulation with storage layer operations:

```python
# For each new committee being added
try:
    write.as_committee_participant(committee_key).keys.associate_fingerprint(fingerprint)
except AccessError:
    # User is not a member of this committee
    return error_response(f"Not authorized for committee {committee_key}")

# For each committee being removed
write.as_committee_participant(committee_key).keys.disassociate_fingerprint(fingerprint)
```

Use the storage layer's `associate_fingerprint()` and `disassociate_fingerprint()` methods to maintain audit trails and proper authorization. Regenerate KEYS files for all affected committees after changes. Validate user is a participant of all submitted committees before proceeding with update.

### Acceptance Criteria
- [ ] Storage layer used for all associations
- [ ] Committee membership validated before changes
- [ ] AccessError exceptions handled
- [ ] KEYS files regenerated after changes
- [ ] Audit trail maintained
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.3.1.md, L2:2.2.3.md
- Related findings: None
- ASVS sections: 2.3.1, 2.2.3

### Priority
High

---

## Issue: FINDING-025 - SBOM Task Functions Use File Paths Without Containment Validation

**Labels:** bug, security, priority:high, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
Four SBOM task functions (generate_sbom, score_tool, score_attestation, score_osv) use `args.file_path` and `args.revision_number` directly in file system path construction without validating that the path is contained within the expected project/revision directory. While the initial form submission validates the path using `safe.RelPath`, the task function re-uses the string value without re-validating containment, creating a TOCTOU-style vulnerability. Attackers who can modify database or task queue can inject path traversal to read/write files in other projects' directories.

### Details
**Affected Files and Lines:**
- `atr/tasks/sbom.py:50-120` - generate_sbom without path validation
- `atr/tasks/sbom.py:140-180` - score_tool without path validation
- `atr/tasks/sbom.py:200-240` - score_attestation without path validation
- `atr/tasks/sbom.py:260-300` - score_osv without path validation
- `atr/tasks/sbom.py:76` - Path construction point
- `atr/tasks/sbom.py:110` - Path construction point
- `atr/tasks/sbom.py:155` - Path construction point
- `atr/tasks/sbom.py:180` - Path construction point

The task model uses unvalidated path components, bypassing the safe type system and allowing path traversal if database/queue is compromised.

### Recommended Remediation
Re-validate `file_path` as `safe.RelPath` in task functions:

```python
# At start of each task function
validated_path = safe.RelPath(args.file_path)
validated_revision = safe.RevisionNumber(args.revision_number)

# Construct full path
full_path = project_dir / validated_revision / validated_path

# Add explicit containment check
if not full_path.resolve().is_relative_to(project_dir / validated_revision):
    raise ValueError("Path traversal detected")
```

Update `SBOMGenerateArgs` and `FileArgs` Pydantic models to use `safe.RelPath` and `safe.RevisionNumber` types instead of `str`. Apply fixes to all 4 affected functions. Add a Pydantic `@model_validator` to validate path components.

### Acceptance Criteria
- [ ] Path validation added to all 4 functions
- [ ] Containment check enforces directory boundaries
- [ ] Pydantic models use safe types
- [ ] Model validator added
- [ ] Integration test verifies path traversal prevention
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.2.md, L2:2.2.3.md
- Related findings: FINDING-093, FINDING-094
- ASVS sections: 2.2.2, 2.2.3

### Priority
High

---

## Issue: FINDING-026 - Vote Duration Not Validated Against Policy Minimum at Vote Start

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
When starting a vote, the user-supplied `vote_duration` is not validated against the project's configured `min_hours` policy. The validation function `_validate_min_hours()` exists in the policy module but is only called when editing policies, not when starting votes. This allows committee members to circumvent configured minimum voting periods, bypassing ASF voting policy requirements and potentially invalidating the vote.

### Details
**Affected Files and Lines:**
- `atr/storage/writers/vote.py:80-130` - vote.start() without duration validation
- `atr/post/voting.py:77-132` - Vote start handler

The validation function exists but is not applied when votes are initiated, allowing users to specify durations shorter than the policy minimum.

### Recommended Remediation
Add validation in `vote.start()` to check that `vote_duration_choice >= policy.min_hours` before creating the vote task:

```python
# Fetch release with policy information
release = db_session.get(sql.Release, release_key)
policy = release.project.policy

# Validate duration against policy
if policy.min_hours > 0 and vote_duration_choice < policy.min_hours:
    raise storage.AccessError(
        f"Vote duration ({vote_duration_choice}h) is below policy minimum ({policy.min_hours}h)"
    )
```

Fetch release with policy information and compare user-supplied duration against minimum. Raise `storage.AccessError` if duration is below minimum.

### Acceptance Criteria
- [ ] Duration validated against policy minimum
- [ ] AccessError raised for invalid durations
- [ ] Error message includes policy requirement
- [ ] Integration test verifies enforcement
- [ ] All vote start paths validated
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.3.2.md
- Related findings: FINDING-003, FINDING-022
- ASVS sections: 2.3.2

### Priority
High

---

## Issue: FINDING-027 - State-Changing API Endpoints Lack Per-Endpoint Rate Limits

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Critical state-changing API endpoints (release_create, release_upload, release_announce, vote_start, vote_resolve, distribution_record, policy_update, release_delete) rely only on the global rate limit (500 requests/hour) without per-endpoint throttling. This allows authenticated users to perform resource-intensive operations at rates that can cause service degradation, email flooding, and storage exhaustion.

### Details
**Affected Files and Lines:**
- `atr/api/__init__.py` - Multiple endpoints without per-endpoint rate limiting

The global rate limit of 500 requests/hour is too permissive for operations that send emails, modify critical state, or consume significant resources. Without per-endpoint limits, users can abuse individual operations within the global budget.

### Recommended Remediation
Apply tiered rate limiting decorators to state-changing endpoints:

**Tier 1 (5/hour)** for email-sending operations:
```python
@rate_limiter.rate_limit(5, datetime.timedelta(hours=1))
async def vote_start(...):
    ...

@rate_limiter.rate_limit(5, datetime.timedelta(hours=1))
async def release_announce(...):
    ...

@rate_limiter.rate_limit(5, datetime.timedelta(hours=1))
async def release_delete(...):
    ...
```

**Tier 2 (10/hour)** for state-changing operations:
```python
@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def release_create(...):
    ...

@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def release_upload(...):
    ...

@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def vote_resolve(...):
    ...
```

Use existing `@rate_limiter.rate_limit` decorator consistently across all sensitive endpoints.

### Acceptance Criteria
- [ ] Email-sending endpoints limited to 5/hour
- [ ] State-changing endpoints limited to 10/hour
- [ ] Rate limit decorators applied
- [ ] Error messages inform users of limits
- [ ] Integration test verifies enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.3.2.md
- Related findings: FINDING-028
- ASVS sections: 2.3.2

### Priority
High

---

## Issue: FINDING-028 - SSH Interface Lacks Rate Limiting for Write Operations

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The SSH rsync interface has no rate limiting on write operations, while the web interface has comprehensive rate limiting. This creates a bypass path where authenticated users can perform unlimited writes via SSH while being throttled on the web interface, enabling release object creation flooding, parallel upload flooding, and resource exhaustion.

### Details
**Affected Files and Lines:**
- `atr/ssh.py` - SSH interface without rate limiting

The SSH interface allows unlimited write operations, creating an alternative path to bypass web interface rate limits. This inconsistency undermines the rate limiting security controls.

### Recommended Remediation
Implement SSH-specific rate limiting:

```python
# Track operations per ASF UID
_ssh_rate_limits: dict[str, collections.deque] = {}

def _check_ssh_rate_limit(asf_uid: str) -> bool:
    """Check if user has exceeded SSH rate limits."""
    now = time.time()
    
    if asf_uid not in _ssh_rate_limits:
        _ssh_rate_limits[asf_uid] = collections.deque()
    
    operations = _ssh_rate_limits[asf_uid]
    
    # Remove operations outside 1-hour window
    while operations and now - operations[0] > 3600:
        operations.popleft()
    
    # Check limits: 10 writes/minute, 100 writes/hour
    recent_minute = sum(1 for t in operations if now - t < 60)
    if recent_minute >= 10:
        return False
    if len(operations) >= 100:
        return False
    
    operations.append(now)
    return True
```

Add `_check_ssh_rate_limit()` function and call it in `_step_02_handle_safely()` before processing write operations. Implement periodic cleanup task for rate limit tracking data. Make timeout configurable via `atr/config.py` with `SSH_RSYNC_TIMEOUT` parameter.

### Acceptance Criteria
- [ ] Rate limiting implemented for SSH writes
- [ ] 10 writes/minute limit enforced
- [ ] 100 writes/hour limit enforced
- [ ] Rate limit tracking per user
- [ ] Cleanup task prevents memory growth
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.3.2.md
- Related findings: FINDING-027
- ASVS sections: 2.3.2

### Priority
High

---

## Issue: FINDING-029 - Release Vote Logic Validation Always Passes Due to Catch-All Pattern

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The release vote logic validator is designed to ensure that `vote_resolved` cannot be set without `vote_started` being set first. However, a catch-all pattern match `(_, _)` appears before the intended validation case, causing the function to always return `True` regardless of the actual state. This undermines the documented business rule that 'cannot have vote_resolved without vote_started' and compromises data integrity.

### Details
**Affected Files and Lines:**
- `atr/validate.py:245-260` - Vote logic validation with incorrect pattern order

The catch-all pattern `(_, _)` matches all cases before the specific validation case `(None, _)` can be evaluated, making the validation ineffective.

### Recommended Remediation
Reorder pattern match cases to place `(None, _)` case before the catch-all `(_, _)` case, and uncomment the intended validation logic:

```python
match (release.vote_started, release.vote_resolved):
    case (None, None):
        # No vote started, no vote resolved - valid
        pass
    case (datetime(), None):
        # Vote started but not resolved - valid
        pass
    case (None, _):
        # Vote resolved without being started - INVALID
        return False, "Cannot have vote_resolved without vote_started"
    case (datetime(), datetime()):
        # Both set - valid
        pass
```

Add unit tests covering all four state combinations: (None, None), (datetime, None), (None, datetime), (datetime, datetime). Consider adding a SQL CHECK constraint as defense-in-depth. Run `validate.everything()` against production data to identify existing inconsistencies.

### Acceptance Criteria
- [ ] Pattern match cases reordered
- [ ] Validation logic uncommented
- [ ] Unit tests cover all state combinations
- [ ] SQL CHECK constraint considered
- [ ] Production data validated
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.1.2.md
- Related findings: None
- ASVS sections: 2.1.2

### Priority
High

---

## Issue: FINDING-030 - Vote Resolution Phase Transitions Lack Optimistic Locking

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Vote resolution lacks optimistic locking, allowing duplicate preview revisions and inconsistent state transitions. The functions `resolve_manually()` and `resolve_release()` use direct ORM attribute modification without WHERE phase guards, enabling race conditions where concurrent vote resolutions can create duplicate preview revisions, conflicting vote resolutions, or duplicate podling vote initiations to external systems.

### Details
**Affected Files and Lines:**
- `atr/storage/writers/vote.py:127-160` - resolve_manually() without optimistic locking
- `atr/storage/writers/vote.py:180-230` - resolve_release() without optimistic locking

The functions modify release phase and perform side effects without atomic phase transitions, allowing race conditions in concurrent operations.

### Recommended Remediation
Apply the existing optimistic locking pattern from `promote_to_candidate()`:

```python
# In resolve_manually()
result = db_session.execute(
    update(sql.Release)
    .where(sql.Release.key == release_key)
    .where(sql.Release.phase == 'RELEASE_CANDIDATE')  # WHERE phase guard
    .values(phase=new_phase)
)

if result.rowcount != 1:
    db_session.rollback()
    raise ConcurrentModificationError("Release phase changed during resolution")

# Only proceed with create_revision_with_quarantine() after confirmed phase transition
```

For `resolve_release()` with podling voting, add WHERE `podling_thread_id IS NULL` guard to prevent duplicate Incubator PMC vote initiation.

### Acceptance Criteria
- [ ] Optimistic locking applied to resolve_manually()
- [ ] Optimistic locking applied to resolve_release()
- [ ] WHERE phase guards implemented
- [ ] Rowcount checked after update
- [ ] Side effects only after confirmed transition
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.3.4.md
- Related findings: FINDING-106
- ASVS sections: 2.3.4

### Priority
High

---

## Issue: FINDING-031 - Upload Staging Endpoint Ignores Authentication Context

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `stage` endpoint accepts authentication and authorization parameters (`_session`, `_project_key`, `_version_key`) but does not use them to verify that the authenticated user has permission to upload to the specified project or that the `upload_session` token belongs to that user. The underscore prefix on these parameters indicates they are validated for format but not used within the function body. This creates an authorization bypass where any authenticated committer can inject files into another user's upload session.

### Details
**Affected Files and Lines:**
- `atr/post/upload.py:126-164` - stage endpoint without authorization checks
- `atr/post/upload.py:44-104` - Upload session creation

The parameters are accepted but ignored, allowing cross-user upload session manipulation.

### Recommended Remediation
Remove underscore prefixes from `session`, `project_key`, and `version_key` parameters. Implement authorization checks:

```python
# 1. Verify user has permission to upload to the project
storage.read().as_project_committee_participant(project_key)

# 2. Verify upload_session is bound to the authenticated user
session_metadata = get_upload_session_metadata(upload_session)
if session_metadata['user_id'] != session['uid']:
    raise web.ASFQuartException('Upload session does not belong to you', errorcode=403)
if session_metadata['project_key'] != project_key:
    raise web.ASFQuartException('Upload session project mismatch', errorcode=403)

# 3. Validate the upload_session has not expired
if session_metadata['expires_at'] < datetime.now():
    raise web.ASFQuartException('Upload session expired', errorcode=403)
```

Store upload session bindings when created and validate them in the stage endpoint.

### Acceptance Criteria
- [ ] Authorization parameters used (not ignored)
- [ ] Project permission verified
- [ ] Upload session ownership verified
- [ ] Upload session expiration checked
- [ ] Session bindings stored at creation
- [ ] Unit test verifying the fix

### References
- Source reports: L2:4.4.3.md
- Related findings: FINDING-119
- ASVS sections: 4.4.3

### Priority
High

---

## Issue: FINDING-032 - SSH/Rsync Upload Path Has No File Size Limit

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The SSH/rsync upload mechanism provides an alternative upload path for authenticated users that completely bypasses all HTTP-based security controls. While the HTTP upload endpoints are protected by MAX_CONTENT_LENGTH (512 MB), rate limiting, and multiple validation layers, the SSH path has no corresponding size restrictions. Files are written directly to the filesystem with no size checks, enabling authenticated users to exhaust disk space through arbitrarily large file uploads.

### Details
**Affected Files and Lines:**
- `atr/ssh.py:367-400` - Rsync execution without size limits
- `atr/storage/writers/revision.py` - Post-upload validation

When a user uploads via rsync: 1) Authentication occurs via SSH key validation, 2) The rsync subprocess is executed without size constraints, 3) Files are written directly to the filesystem with no size checks, 4) Post-upload validation in `create_revision_with_quarantine()` only checks file types, not sizes.

### Recommended Remediation
Implement defense-in-depth approach:

**PRIMARY CONTROL:** Add `--max-size` flag to rsync subprocess execution:

```python
modified_argv = [
    'rsync',
    '--server',
    '--max-size=512M',  # Add size limit matching HTTP
    # ... other flags
    destination_path
]
```

**DEFENSE-IN-DEPTH:** Add post-transfer validation in `create_revision_with_quarantine()`:

```python
total_size = sum(f.stat().st_size for f in revision_path.rglob('*') if f.is_file())
if total_size > MAX_CONTENT_LENGTH:
    raise ValueError(f"Upload exceeds size limit: {total_size} > {MAX_CONTENT_LENGTH}")
```

Add descriptive error messages indicating size limits when rejections occur. Verify legitimate uploads still function correctly after implementation.

### Acceptance Criteria
- [ ] Rsync --max-size flag added
- [ ] Post-transfer size validation added
- [ ] Error messages indicate size limits
- [ ] Legitimate uploads still work
- [ ] Integration test verifies enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L1:5.2.1.md
- Related findings: None
- ASVS sections: 5.2.1

### Priority
High

---

## Issue: FINDING-033 - Documented Rate Limits Missing on Multiple API Endpoints

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Security documentation explicitly states that sensitive endpoints have 10 requests per hour rate limits. However, multiple endpoints are documented with this limit but lack the `@rate_limiter.rate_limit` decorator in their implementation: `/api/key/delete`, `/api/distribute/record_from_workflow`, `/api/distribute/task/status`. This creates false confidence in the security posture. Authenticated users can call these endpoints up to 500 times per hour (API-wide limit) instead of the documented 10 times per hour.

### Details
**Affected Files and Lines:**
- `atr/api/__init__.py:~390-420` - key_delete without rate limit
- `atr/api/__init__.py:~270` - distribution_record_from_workflow without rate limit
- `atr/api/__init__.py:~540` - update_distribution_task_status without rate limit
- `security/ASVS/audit_guidance/authentication-security.md` - Documentation with rate limits

The documentation promises 10 requests/hour but the implementation allows 500 requests/hour, creating a 50x gap between documented and actual behavior.

### Recommended Remediation
Add `@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))` decorator to all three endpoints:

```python
@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def key_delete(...):
    ...

@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def distribution_record_from_workflow(...):
    ...

@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def update_distribution_task_status(...):
    ...
```

### Acceptance Criteria
- [ ] Rate limit decorator added to key_delete
- [ ] Rate limit decorator added to distribution_record_from_workflow
- [ ] Rate limit decorator added to update_distribution_task_status
- [ ] Implementation matches documentation
- [ ] Integration test verifies enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L1:6.1.1.md, L1:6.3.1.md
- Related findings: FINDING-124
- ASVS sections: 6.1.1, 6.3.1

### Priority
High

---

## Issue: FINDING-034 - OAuth Authentication Does Not Terminate Prior Session Token

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The primary OAuth authentication callback at `/auth` writes new session data without first terminating the existing session token, violating ASVS 7.2.4's explicit requirement to 'terminate the current session token' before generating a new one. The code calls `session.write(oauth_data)` directly without calling `session.clear()` first. While the application's signed cookie architecture provides inherent resistance to classical session fixation attacks, the implementation does not follow the defense-in-depth principle demonstrated in the admin browse-as flow where `session.clear()` is correctly called before writing new session data.

### Details
**Affected Files and Lines:**
- `src/asfquart/generics.py:~97-100` - OAuth callback without session.clear()
- `src/asfquart/session.py:107-117` - Session write implementation

The OAuth callback writes new session data without clearing the existing session first, violating ASVS requirements and best practices.

### Recommended Remediation
Add `session.clear()` before `session.write()` in the OAuth callback:

```python
# src/asfquart/generics.py — OAuth callback branch (line ~97)
oauth_data = await rv.json()
asfquart.session.clear()           # ← ADD: Terminate current session token (ASVS 7.2.4)
asfquart.session.write(oauth_data) # Generate new session token
```

**Alternative (Best Practice):** Create a dedicated `session.regenerate()` function that atomically calls `clear()` then `write()` to prevent future regressions:

```python
def regenerate(session_data: dict) -> None:
    """Atomically clear old session and write new session."""
    clear()
    write(session_data)
```

This function should be used at all authentication entry points.

### Acceptance Criteria
- [ ] session.clear() called before session.write()
- [ ] OAuth authentication terminates old session
- [ ] session.regenerate() function considered
- [ ] All authentication entry points reviewed
- [ ] Integration test verifies session termination
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.2.4.md
- Related findings: FINDING-005
- ASVS sections: 7.2.4

### Priority
High

---

## Issue: FINDING-035 - No Automatic Credential Revocation on Account Disable

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
No event-driven mechanism exists to automatically revoke credentials (PATs, SSH keys, sessions) when an account is disabled in LDAP. Manual admin action is required with no notification system. SSH keys have no bulk revocation method at all - must be deleted individually. PATs can be bulk-revoked manually via admin panel but this is not triggered automatically. Credentials persist indefinitely in database after account disable, with window of exposure lasting until manual cleanup (up to 72 hours for sessions, 180 days for PATs, indefinite for SSH keys).

### Details
**Affected Files and Lines:**
- `atr/storage/writers/tokens.py:143-157` - PAT revocation (manual only)
- `atr/storage/writers/ssh.py` - No bulk SSH key revocation method
- `atr/admin/__init__.py:revoke_user_tokens_post()` - Manual revocation UI

The lack of automatic revocation means disabled accounts retain active credentials until manual intervention, creating a significant security window.

### Recommended Remediation
Implement three-part solution:

**1. Add SSH key bulk revocation:**
```python
# In atr/storage/writers/ssh.py
def revoke_all_user_ssh_keys(self, asf_uid: str) -> int:
    """Revoke all SSH keys for a user."""
    keys = self.__db_session.query(sql.SSHKey).filter_by(owner_uid=asf_uid).all()
    for key in keys:
        self.__db_session.delete(key)
    self.__db_session.commit()
    return len(keys)
```

**2. Implement event handler:**
```python
def handle_ldap_account_disable(asf_uid: str) -> None:
    """Automatically revoke credentials when account disabled."""
    storage.write().tokens.revoke_all_user_tokens(asf_uid)
    storage.write().ssh.revoke_all_user_ssh_keys(asf_uid)
    # Add user to session deny list (requires FINDING-005 fix)
```

**3. Add periodic cleanup task:**
```python
async def periodic_credential_cleanup() -> None:
    """Check for disabled accounts with active credentials every 10 minutes."""
    # Query LDAP for disabled accounts
    # Check for active credentials
    # Revoke as needed
```

Long-term: integrate with LDAP pubsub events (GitHub Issue #872).

### Acceptance Criteria
- [ ] SSH key bulk revocation implemented
- [ ] Event handler for account disable
- [ ] Periodic cleanup task added
- [ ] Session deny list integration (requires FINDING-005)
- [ ] Integration test verifies automatic revocation
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.4.2.md
- Related findings: FINDING-006, FINDING-036, FINDING-130
- ASVS sections: 7.4.2

### Priority
High

---

## Issue: FINDING-036 - No Session Termination After PAT Deletion or Creation

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
When a user deletes or creates a Personal Access Token (an authentication factor), no option is presented to terminate all other active sessions. The PAT is added/removed from the database and an email notification is sent, but cookie-based web sessions and non-PAT-bound JWTs remain fully active for up to 72 hours. If a user deletes their PAT because of suspected compromise or creates a new PAT to replace a compromised one, they cannot force logout of potentially compromised sessions, creating a false sense of security.

### Details
**Affected Files and Lines:**
- `atr/post/tokens.py:63-78` - PAT deletion without session termination option
- `atr/post/tokens.py:80-85` - PAT creation without session termination option
- `atr/storage/writers/tokens.py:55-90` - _add_token implementation
- `atr/storage/writers/tokens.py:92-112` - _delete_token implementation

This violates ASVS 7.4.3's requirement to offer session termination after authentication factor changes.

### Recommended Remediation
Add 'terminate_other_sessions' boolean field to `AddTokenForm` and `DeleteTokenForm`:

```python
class DeleteTokenForm:
    token_id: int
    terminate_other_sessions: bool = False
```

Update `_add_token()` and `_delete_token()` handlers:

```python
if form.terminate_other_sessions:
    terminate_all_other_sessions(session.asf_uid, current_session_id)
```

Add checkbox to token forms with text: 'Terminate all other active sessions - Recommended if this token was compromised or if replacing a compromised token. You will remain logged in on this device.'

Display warning if user declines on deletion: 'Token deleted successfully. Consider terminating other sessions if this token was compromised.'

Note: Requires FINDING-005 fix first to implement session termination.

### Acceptance Criteria
- [ ] terminate_other_sessions field added to forms
- [ ] Checkbox added to UI
- [ ] Session termination triggered when checked
- [ ] Warning displayed when declined
- [ ] Current session preserved
- [ ] Unit test verifying the fix

### References
- Source reports: L2:7.4.3.md
- Related findings: FINDING-005, FINDING-037, FINDING-131
- ASVS sections: 7.4.3

### Priority
High

---

## Issue: FINDING-037 - Admin Token Revocation Does Not Terminate User Web Sessions

**Labels:** bug, security, priority:high, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
When an administrator revokes all tokens for a user via the admin panel (typically during security incident response), the target user's active cookie-based sessions are not terminated. The admin sees success message 'Revoked N tokens for username' but web sessions remain valid for up to 72 hours, allowing continued access to all authenticated endpoints. This creates dangerous false confidence where the admin believes they've locked out a compromised account, but the attacker's browser session continues to work. Additionally, no email notification is sent to the affected user about the admin-initiated revocation.

### Details
**Affected Files and Lines:**
- `atr/admin/__init__.py:380-393` - revoke_user_tokens_post() without session termination
- `atr/storage/writers/tokens.py:157-179` - Token revocation implementation

The function revokes PATs but does not terminate web sessions or SSH keys, creating an incomplete security response.

### Recommended Remediation
Extend `revoke_user_tokens_post()` to:

```python
# 1. Revoke PATs (existing)
count = storage.write().tokens.revoke_all_user_tokens(asf_uid)

# 2. Revoke SSH keys (from FINDING-035)
ssh_count = storage.write().ssh.revoke_all_user_ssh_keys(asf_uid)

# 3. Add user to session deny list (requires FINDING-005 fix)
storage.write().sessions.invalidate_all_user_sessions(asf_uid)

# 4. Send email notification to user
send_email(
    to=user.email,
    subject='Security Alert: Credentials Revoked',
    body='An administrator has revoked your access tokens and terminated your sessions.'
)

# 5. Clear principal authorization cache
clear_authorization_cache(asf_uid)

# 6. Update success message
flash(f'Revoked {count} tokens, terminated all sessions, and revoked {ssh_count} SSH keys for {username}')
```

Accept 30-minute window for active JWTs as acceptable risk given short TTL.

### Acceptance Criteria
- [ ] PAT revocation implemented (existing)
- [ ] SSH key revocation added
- [ ] Session termination added
- [ ] Email notification sent to user
- [ ] Authorization cache cleared
- [ ] Success message updated
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.4.2.md, L2:7.4.3.md, L2:7.4.5.md
- Related findings: FINDING-005, FINDING-035, FINDING-036, FINDING-132
- ASVS sections: 7.4.2, 7.4.3, 7.4.5

### Priority
High

---

## Issue: FINDING-038 - Bearer Token Value Logged to Standard Output

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The ASFQuart session handler contains a debug print statement that outputs the full Bearer token value to stdout when no token_handler is registered. This constitutes a direct violation of ASVS 7.2.2's requirement to avoid storing sensitive session tokens in logs. The vulnerable code prints the raw token value from Authorization: Bearer header to stdout, which persists in server log files, enabling potential replay attacks if logs are accessed. However, this is currently a dead code path as ATR registers JWT verification as the token handler in production, so the else branch is never executed.

### Details
**Affected Files and Lines:**
- `src/asfquart/session.py:73` - Debug print with token value
- `src/asfquart/session.py:88` - Debug print with token value

This appears to be debug code that was never removed. While currently unreachable in production, it represents a latent vulnerability.

### Recommended Remediation
Remove token value from log statement:

```python
# Replace:
print(f"Bearer {bearer}")

# With:
log.warning('Bearer token presented but no handler registered')
```

**Alternative:** Register a no-op token handler during application setup to prevent the debug path from executing:

```python
# In atr/server.py after app = ASFQuart(__name__)
async def _noop_token_handler(token: str):
    return None

app.token_handler = _noop_token_handler
```

### Acceptance Criteria
- [ ] Token value removed from log statement
- [ ] Warning logged without token value
- [ ] No-op handler considered
- [ ] Debug code path eliminated
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.2.1.md, L1:7.2.2.md
- Related findings: None
- ASVS sections: 7.2.1, 7.2.2

### Priority
High

---

## Issue: FINDING-039 - IDOR in Check Ignore Operations via Numeric ID

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The application allows committee members to delete or update check result ignores by numeric ID without verifying the ignore record belongs to the authorized project. A single committee can manage multiple projects. The authorization check validates committee membership, but the storage layer's `ignore_delete(id)` and `ignore_update(id, ...)` methods accept only the integer id parameter without verifying the ignore record's project_key matches the authorized project.

### Details
**Affected Files and Lines:**
- `atr/post/ignores.py:68` - ignore_delete without project verification
- `atr/post/ignores.py:80` - ignore_update without project verification
- `atr/api/__init__.py:274` - API endpoint with same issue
- `atr/storage/writers/checks.py` - Storage layer without project scoping

An attacker with access to one project can manipulate ignore records for any project managed by their committee by guessing or enumerating ignore IDs.

### Recommended Remediation
Add `project_key` parameter to `ignore_delete()` and `ignore_update()` methods in storage layer:

```python
# In atr/storage/writers/checks.py
def ignore_delete(self, ignore_id: int, project_key: str) -> None:
    """Delete ignore record with project verification."""
    # Validate project is in committee
    self.__validate_project_in_committee(project_key)
    
    # Fetch ignore with project filter
    ignore = self.__db_session.query(sql.CheckIgnore).filter_by(
        id=ignore_id,
        project_key=project_key
    ).first()
    
    if not ignore:
        raise ValueError("Ignore record not found or access denied")
    
    self.__db_session.delete(ignore)
```

Update all callers to pass `project_key` parameter. Apply same pattern to `ignore_update()`.

### Acceptance Criteria
- [ ] project_key parameter added to methods
- [ ] Project validation in storage layer
- [ ] Query filters include project_key
- [ ] All callers updated
- [ ] Integration test verifies IDOR prevention
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.2.2.md
- Related findings: FINDING-040
- ASVS sections: 8.2.2

### Priority
High

---

## Issue: FINDING-040 - IDOR on check_id in Check Result Data Endpoint

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The check result endpoint calls `session.check_access(project_key)` to verify the user has access to the specified project, but then fetches the check result record solely by its integer `check_id` without verifying it belongs to the validated release. This allows an authenticated committer to retrieve detailed check results from any project by guessing or enumerating check IDs. An attacker can authenticate for one project, pass that project's `project_key` to satisfy the authorization check, but provide a `check_id` from a different project to access cross-project check results.

### Details
**Affected Files and Lines:**
- `atr/get/result.py:33-62` - Check result endpoint with IDOR
- `atr/get/result.py:55` - Check result fetch without release scoping
- `atr/get/result.py:28` - Authorization check on project only

The authorization validates project access but the data fetch uses only the check_id, creating a cross-project data access vulnerability.

### Recommended Remediation
Scope check result query to validated release:

```python
# After fetching release
check_result = db_session.query(sql.CheckResult).filter_by(
    id=check_id,
    release_key=release.key  # Add release scoping
).first()

if not check_result:
    raise base.ASFQuartException('Check result not found', errorcode=404)
```

**Alternative:** Add explicit validation after fetching:

```python
check_result = db_session.get(sql.CheckResult, check_id)
if check_result.release_key != release.key:
    raise base.ASFQuartException('Check result not found', errorcode=404)
```

Audit all endpoints using integer IDs for similar IDOR vulnerabilities. Add integration test attempting cross-project check result access. Consider using composite keys (release_key + check_sequence) instead of global IDs. Add rate limiting to check result endpoints to prevent enumeration.

### Acceptance Criteria
- [ ] Check result query scoped to release
- [ ] Cross-project access prevented
- [ ] Integration test verifies IDOR prevention
- [ ] Other endpoints audited for similar issues
- [ ] Rate limiting considered
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.1.1.md, L1:8.2.2.md
- Related findings: FINDING-039
- ASVS sections: 8.1.1, 8.2.2

### Priority
High

---

## Issue: FINDING-041 - Missing Project-Level Access Control on Multiple GET Endpoints

**Labels:** bug, security, priority:high, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
Multiple GET endpoint handlers that display project-specific data fail to verify that the authenticated user has access to the requested project. While authentication is enforced (all require web.Committer session), authorization is missing, allowing any ASF committer to view data for projects they are not associated with. Affected endpoints include file viewing, distribution listing, check reports, SBOM reports, and revision checks. These endpoints allow access to file listings, file contents, security analysis results, CVE identifiers, vulnerability severity, dependency licenses, and detailed check results from any project's releases (including draft releases not yet public).

### Details
**Affected Files and Lines:**
- `atr/get/file.py:36` - file_list without access check
- `atr/get/file.py:41` - file_view without access check
- `atr/get/file.py:73` - file_download without access check
- `atr/get/file.py:109` - file_download_archive without access check
- `atr/get/file.py:30-102` - Multiple functions without authorization
- `atr/get/file.py:105-169` - Multiple functions without authorization
- `atr/get/distribution.py:38` - distributions without access check
- `atr/get/distribution.py:48` - distribution_create without access check
- `atr/get/checks.py:88` - checks without access check
- `atr/get/checks.py:101` - checks_selected without access check
- `atr/get/report.py:30` - report without access check
- `atr/get/report.py:36` - report_revision without access check
- `atr/get/sbom.py:48` - sbom_report without access check
- `atr/get/sbom.py:40` - sbom_list without access check
- `atr/get/projects.py:125` - revision_checks without access check

These endpoints authenticate users but do not authorize access to specific projects, allowing cross-project data access.

### Recommended Remediation
Add `await session.check_access(project_key)` at the beginning of each affected function before processing project-specific data:

```python
async def file_list(
    session: web.Committer,
    project_key: safe.ProjectKey,
    ...
) -> web.ElementResponse:
    """Display file list for a release."""
    await session.check_access(project_key)  # ADD THIS
    # ... rest of function
```

This applies the same authorization pattern successfully used in other GET endpoints like start.py, upload.py, revisions.py, voting.py, manual.py, finish.py, ignores.py, and result.py. Add integration tests verifying authorization for each endpoint.

### Acceptance Criteria
- [ ] Authorization check added to all affected endpoints
- [ ] session.check_access(project_key) called first
- [ ] Cross-project access prevented
- [ ] Integration tests verify authorization
- [ ] All GET endpoints reviewed
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.2.1.md, L1:8.2.2.md, L1:8.3.1.md
- Related findings: FINDING-139
- ASVS sections: 8.2.1, 8.2.2, 8.3.1

### Priority
High

---

## Issue: FINDING-042 - Broken HMAC Verification in Signer.verify() — Type Mismatch Causes All Verifications to Fail

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `Signer.verify()` method compares HMAC signatures using mismatched data types: it compares 43 bytes of base64-encoded text against 32 bytes of raw digest, causing all verifications to fail even for valid signatures. The method decodes the given signature to raw bytes but encodes the expected signature to ASCII base64 string before comparison. This type mismatch (bytes vs. string) means `hmac.compare_digest()` will always return False, rendering the HMAC verification control completely non-functional and violating ASVS 11.3.3's requirement that authenticated data be protected against unauthorized modification.

### Details
**Affected Files and Lines:**
- `asfpy/crypto.py:116-122` - Signer.verify() with type mismatch

The function performs: `given_bytes = base64.urlsafe_b64decode(given)` (produces bytes) and `expected = base64.urlsafe_b64encode(digest).decode('ascii')` (produces string), then compares them with `hmac.compare_digest()`, which always returns False due to type mismatch.

### Recommended Remediation
Fix the type mismatch by comparing both values in the same format.

**Recommended approach:** Compare base64-encoded strings directly without decoding:

```python
def verify(self, *args: str, given: str) -> bool:
    """Verify a given HMAC signature is correct."""
    try:
        expected = self.sign(*args)  # Returns base64 string
        return hmac.compare_digest(expected, given)  # Compare strings
    except (base64.binascii.Error, ValueError):
        return False
```

**Alternative:** Decode both to raw bytes before comparison:

```python
def verify(self, *args: str, given: str) -> bool:
    """Verify a given HMAC signature is correct."""
    try:
        expected_bytes = self._compute_digest(*args)  # Get raw digest
        given_bytes = base64.urlsafe_b64decode(given + '==')
        return hmac.compare_digest(expected_bytes, given_bytes)
    except (base64.binascii.Error, ValueError):
        return False
```

### Acceptance Criteria
- [ ] Type mismatch corrected
- [ ] Valid signatures verify successfully
- [ ] Invalid signatures rejected
- [ ] Tampered data detected
- [ ] Unit tests cover all scenarios
- [ ] Unit test verifying the fix

### References
- Source reports: L2:11.3.3.md
- Related findings: FINDING-171
- ASVS sections: 11.3.3

### Priority
High

---

## Issue: FINDING-043 - LDAP Account Passwords Hashed with Obsolete MD5 Crypt

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
LDAP account passwords for newly created accounts are stored using MD5 crypt (`$1$` scheme) via `passlib.hash.md5_crypt`. MD5 crypt is limited to approximately 1,000 iterations of the cryptographically broken MD5 hash function and can be cracked at rates of billions of hashes per second on modern GPUs (~5-8 billion hashes/second on RTX 4090). This is not an approved computationally intensive key derivation function per ASVS 11.4.2 or 11.4.4. If an attacker obtains the LDAP database, passwords can be cracked at extreme speed. This file is in the `asfpy` infrastructure library shared across ASF services.

### Details
**Affected Files and Lines:**
- `asfpy/ldapadmin.py:268` - MD5 crypt usage
- `asfpy/ldapadmin.py:261-270` - Password hashing function
- `asfpy/ldapadmin.py:320-328` - Account creation with MD5 crypt

MD5 crypt is explicitly rejected by OWASP Password Storage Cheat Sheet, NIST SP 800-63B, and all current guidance. The salt is only 6 characters from a 62-character alphabet (~35.7 bits of entropy), which is below the recommended minimum for modern KDFs.

### Recommended Remediation
Replace `md5_crypt` with an approved password hashing algorithm. Verify ASF LDAP server's supported userPassword schemes before implementation.

**Option 1 (Recommended - bcrypt):**
```python
import passlib.hash
password_crypted = passlib.hash.ldap_bcrypt.using(rounds=12).hash(password)
```
Bcrypt with rounds=12 provides ~4 billion iterations and is widely supported in LDAP servers.

**Option 2 (SHA-512 crypt):**
```python
password_crypted = passlib.hash.ldap_sha512_crypt.using(rounds=656000).hash(password)
```
SHA-512 crypt with 656k rounds meets OWASP 2023 guidance and is supported by most LDAP servers.

**Option 3 (Argon2id - if supported):**
```python
password_crypted = passlib.hash.argon2.using(
    type='id',
    memory_cost=19456,  # 19 MiB
    time_cost=2,
    parallelism=1,
    salt_size=16
).hash(password)
```

**Migration Strategy:** Implement gradual hash upgrade on user login if existing accounts exist. Test password authentication after migration. Note: This should be addressed by the ASF infrastructure team.

### Acceptance Criteria
- [ ] Modern KDF selected and implemented
- [ ] LDAP server compatibility verified
- [ ] Migration strategy for existing accounts
- [ ] Password authentication tested
- [ ] Security guidance updated
- [ ] Unit test verifying the fix

### References
- Source reports: L2:11.4.2.md, L2:11.4.4.md
- Related findings: None
- ASVS sections: 11.4.2, 11.4.4

### Priority
High

---

## Issue: FINDING-044 - ALLOW_TESTS Flag Enables Complete Authentication Bypass in Production Worker

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The ALLOW_TESTS flag is checked in the worker without verifying the application is actually in Debug mode. While `atr/config.py:get()` enforces that ALLOW_TESTS can only be True in Debug mode at configuration load time, this enforcement occurs during initialization. If the configuration is manipulated or misconfigured, the worker will honor the flag regardless of the actual Mode. Tasks with `asf_uid='test'` bypass all LDAP authentication, ban enforcement, and identity validation.

### Details
**Affected Files and Lines:**
- `atr/worker.py:215-220` - ALLOW_TESTS check without mode verification

The worker checks ALLOW_TESTS but does not verify the application is in Debug mode, creating a potential bypass if configuration is manipulated.

### Recommended Remediation
Reference mode system directly by importing `config.get_mode()` and only allowing test bypass when mode == config.Mode.Debug:

```python
# In atr/worker.py
if config.get_mode() == config.Mode.Debug and config.ALLOW_TESTS:
    if task.asf_uid == 'test':
        # Allow test bypass only in Debug mode
        ...
```

Alternatively, enforce ALLOW_TESTS=False in ProductionConfig with `__post_init__` validation:

```python
# In atr/config.py ProductionConfig
def __post_init__(self):
    if self.ALLOW_TESTS:
        raise RuntimeError("ALLOW_TESTS cannot be enabled in Production mode")
```

### Acceptance Criteria
- [ ] Mode check added to worker
- [ ] Test bypass only in Debug mode
- [ ] ProductionConfig validation considered
- [ ] Configuration manipulation prevented
- [ ] Integration test verifies enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.4.2.md
- Related findings: FINDING-045
- ASVS sections: 13.4.2

### Priority
High

---

## Issue: FINDING-045 - Runtime Environment Detection Bypasses LDAP Authentication

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `is_dev_environment()` function makes runtime determinations based on environment variables or hostname patterns. This bypass is not gated by the Mode system, creating a scenario where production mode can be active but LDAP authentication is still bypassed. This is broader than FINDING-044 because it affects all users (not just 'test' user) when `is_dev_environment()` returns True and LDAP is not configured.

### Details
**Affected Files and Lines:**
- `atr/worker.py:217-220` - Environment detection bypass

The runtime environment detection can bypass LDAP authentication even in Production mode, affecting all users rather than just test users.

### Recommended Remediation
Never bypass LDAP in Production mode. Check mode explicitly:

```python
# In atr/worker.py
if config.get_mode() == config.Mode.Production:
    # Always require LDAP authentication in Production
    if not ldap.is_configured():
        raise RuntimeError("LDAP must be configured in Production mode")
    # Proceed with LDAP authentication
elif config.get_mode() == config.Mode.Debug:
    # Only allow dev bypass in Debug mode
    if is_dev_environment() and not ldap.is_configured():
        # Allow bypass
        ...
```

Only allow dev bypass in Debug mode. Production mode must always require LDAP authentication.

### Acceptance Criteria
- [ ] Mode check enforced
- [ ] Production always requires LDAP
- [ ] Debug mode allows dev bypass
- [ ] Runtime detection gated by mode
- [ ] Integration test verifies enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.4.2.md
- Related findings: FINDING-044
- ASVS sections: 13.4.2

### Priority
High

---

## Issue: FINDING-046 - Admin Endpoints Exposing Secrets Lack Cache-Control Headers

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Admin endpoints expose highly sensitive data without HTTP cache-control headers, creating risk of intermediary caching by load balancers, reverse proxies, or CDNs. The application runs behind a reverse proxy (evidenced by hypercorn.middleware.proxy_fix), making cache-control headers critical. Endpoints exposing environment variables (containing LDAP passwords, API tokens, database credentials) and SSH key material from database browse endpoint lack Cache-Control headers.

### Details
**Affected Files and Lines:**
- `atr/admin/__init__.py:env()` - Environment variables without cache headers
- `atr/admin/__init__.py:configuration()` - Configuration without cache headers
- `atr/admin/__init__.py:data_model()` - Data model without cache headers
- `atr/admin/__init__.py:_data_browse()` - Database browse without cache headers
- `atr/server.py:add_security_headers()` - Security headers function

The endpoints return sensitive data but rely on implicit no-caching behavior rather than explicit headers, creating risk in proxied environments.

### Recommended Remediation
Add global Cache-Control headers in `atr/server.py` after_request hook:

```python
@app.after_request
async def add_security_headers(response: quart.Response) -> quart.Response:
    response.headers["Content-Security-Policy"] = csp_header
    response.headers["Permissions-Policy"] = permissions_policy
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    
    # NEW: Prevent caching of authenticated/sensitive responses
    if "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"  # HTTP/1.0 compatibility
    
    return response
```

### Acceptance Criteria
- [ ] Global after_request hook updated
- [ ] Cache-Control: no-store added
- [ ] Pragma: no-cache added
- [ ] Existing headers not overwritten
- [ ] All responses protected
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.2.md
- Related findings: FINDING-047, FINDING-184
- ASVS sections: 14.2.2

### Priority
High

---

## Issue: FINDING-047 - API JWT Creation Endpoint Missing Cache-Control Header

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The API endpoint for JWT creation returns credentials without cache-control headers, while the equivalent web endpoint correctly implements Cache-Control: no-store. This inconsistency creates a caching vulnerability in the API path. JWT credentials valid for 30 minutes could be cached by server-side components. If a shared cache (e.g., CDN with aggressive caching, misconfigured Varnish) stores the response, subsequent requests matching the cache key could receive another user's JWT.

### Details
**Affected Files and Lines:**
- `atr/api/__init__.py:398-415` - JWT creation without cache headers

The API endpoint returns JWTs without anti-caching headers while the web endpoint correctly implements them, creating an inconsistency.

### Recommended Remediation
Covered by global fix in FINDING-046. If implementing per-endpoint:

```python
@app.route('/api/jwt/create', methods=['POST'])
async def jwt_create(...):
    # ... JWT creation logic
    
    response = quart.jsonify({'jwt': token})
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response
```

### Acceptance Criteria
- [ ] Cache-Control header added to response
- [ ] Pragma header added for compatibility
- [ ] Consistency with web endpoint
- [ ] Integration test verifies headers
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.2.md, L2:14.3.2.md
- Related findings: FINDING-046, FINDING-011
- ASVS sections: 14.2.2, 14.3.2

### Priority
High

---

## Issue: FINDING-048 - OAuth Login Success Response Lacks Anti-Caching Headers

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The OAuth login success response displays the authenticated user's UID in plain text without anti-caching headers. Both the redirect and non-redirect variants of the response lack protection. User identity is cached in browser history, visible on shared workstations or through browser history inspection.

### Details
**Affected Files and Lines:**
- `src/asfquart/generics.py:103-119` - OAuth success response without cache headers

Data flow: OAuth callback → user identity in response body → no Cache-Control → browser cache. User identity cached in browser history.

### Recommended Remediation
Create the `quart.Response` object and add `response.headers['Cache-Control'] = 'no-store'` before setting the optional Refresh header and returning the response:

```python
# Create response
response = quart.Response(f'Login successful for {uid}')
response.headers['Cache-Control'] = 'no-store'
response.headers['Pragma'] = 'no-cache'

# Add optional Refresh header if needed
if redirect_to:
    response.headers['Refresh'] = f'0; url={redirect_to}'

return response
```

### Acceptance Criteria
- [ ] Response object created explicitly
- [ ] Cache-Control header set
- [ ] Pragma header set
- [ ] Refresh header still works
- [ ] Integration test verifies headers
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.3.2.md
- Related findings: FINDING-011
- ASVS sections: 14.3.2

### Priority
High

---

## Issue: FINDING-049 - Admin Endpoints Expose Sensitive System Data Without Anti-Caching Headers

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Admin endpoints expose highly sensitive system information including environment variables (with database credentials, API keys, LDAP passwords), application configuration, logs, and database records—all without anti-caching headers. The most critical is the `/admin/env` endpoint which exposes all environment variables including DATABASE_URL, SECRET_KEY, and LDAP_BIND_PASSWORD. All affected endpoints use `web.TextResponse` which does not set any caching headers. On shared administrative workstations, this represents a severe credential exposure risk.

### Details
**Affected Files and Lines:**
- `atr/admin/__init__.py:338` - Environment endpoint
- `atr/admin/__init__.py:152` - Configuration endpoint
- `atr/admin/__init__.py:468` - Logs endpoint
- `atr/admin/__init__.py:168` - Data model endpoint
- `atr/admin/__init__.py:202` - Data browse endpoint
- `atr/web.py` - TextResponse class

Environment variables (potentially containing database credentials, API keys, LDAP passwords) cached in browser.

### Recommended Remediation
See FINDING-046 for global fix, or add `self.headers['Cache-Control'] = 'no-store'` to the `TextResponse.__init__` method:

```python
class TextResponse(Response):
    def __init__(self, content: str, ...):
        super().__init__(content, ...)
        self.headers['Cache-Control'] = 'no-store'
        self.headers['Pragma'] = 'no-cache'
```

Also consider adding the same header to `ElementResponse` and other custom response classes.

### Acceptance Criteria
- [ ] Cache-Control added to TextResponse
- [ ] All admin endpoints protected
- [ ] Other response classes reviewed
- [ ] Integration test verifies headers
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.3.2.md
- Related findings: FINDING-011
- ASVS sections: 14.3.2

### Priority
High

---

## Issue: FINDING-050 - rsync Subprocess Execution Without Timeout

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
SSH rsync operations execute without timeout controls via indefinite `proc.wait()` blocking. Unlike worker processes which have comprehensive resource limits (300s CPU, 3GB memory), the SSH server runs in the main web server process. Hung rsync operations can exhaust server resources and affect HTTP request handling. Each connection holds asyncio task, subprocess, SSH session, and file descriptors indefinitely. Stalled network connections or malicious clients can cause resource exhaustion.

### Details
**Affected Files and Lines:**
- `atr/ssh.py:460` - proc.wait() without timeout
- `atr/ssh.py:_step_02_handle_safely` - Operation handler
- `atr/ssh.py:_step_07a_process_validated_rsync_read` - Read operation
- `atr/ssh.py:_step_07b_process_validated_rsync_write` - Write operation

While other subprocess operations correctly use `asyncio.wait_for(proc.communicate(), timeout=300)`, rsync has no timeout protection.

### Recommended Remediation
Add timeout to rsync subprocess execution:

```python
# In _step_07a_process_validated_rsync_read and _step_07b_process_validated_rsync_write
try:
    await asyncio.wait_for(proc.wait(), timeout=3600)  # 1 hour for large transfers
except asyncio.TimeoutError:
    proc.kill()
    await proc.wait()
    raise asyncssh.BreakReceived('rsync operation timed out')
```

Use 1-hour maximum for large transfers (aligned with 600s SVN timeout but allowing for larger file transfers). Make timeout configurable via `atr/config.py` with `SSH_RSYNC_TIMEOUT` parameter. Add monitoring/alerting for rsync operations exceeding threshold. Consider implementing progress tracking to distinguish stalled vs. active transfers.

### Acceptance Criteria
- [ ] Timeout added to rsync operations
- [ ] Process killed on timeout
- [ ] Timeout configurable
- [ ] Monitoring/alerting considered
- [ ] Progress tracking considered
- [ ] Unit test verifying the fix

### References
- Source reports: L2:15.1.3.md, L2:15.2.2.md
- Related findings: FINDING-012, FINDING-205
- ASVS sections: 15.1.3, 15.2.2

### Priority
High

---

## Issue: FINDING-051 - Pre-commit Ecosystem Dependabot Monitoring Disabled

**Labels:** bug, security, priority:high, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
Dependabot monitoring for the pre-commit ecosystem is explicitly disabled via commented-out configuration in `.github/dependabot.yml`. This leaves 16+ security-critical tools (including pip-audit v2.10.0, zizmor v1.23.1, shellcheck v0.11.0.1) without automated update monitoring, creating a gap in the dependency management policy. The configuration template exists but is disabled with a TODO comment about cooldown support. Security scanning tools used in the development pipeline could become outdated, potentially missing newly detectable vulnerabilities.

### Details
**Affected Files and Lines:**
- `.github/dependabot.yml:24-30` - Commented pre-commit configuration
- `.pre-commit-config.yaml` - 16+ tools without monitoring

The lack of proactive notifications means updates depend on manual processes rather than automated alerts.

### Recommended Remediation
**Option A** — Enable when Dependabot supports cooldowns: Uncomment and configure pre-commit ecosystem monitoring with appropriate cooldown when feature becomes available.

**Option B** — Implement custom monitoring script:

```python
# scripts/check_precommit_versions.py
# 1. Parse .pre-commit-config.yaml
# 2. Check age of each hook version via git ls-remote
# 3. Enforce 90-day maximum age for security tools
# 4. Integrate into CI pipeline via .github/workflows/analyze.yml
```

**Alternative:** Document manual update schedule in CONTRIBUTING.md requiring monthly execution of `pre-commit autoupdate`.

### Acceptance Criteria
- [ ] Pre-commit monitoring enabled OR
- [ ] Custom monitoring script implemented OR
- [ ] Manual update schedule documented
- [ ] 90-day age limit enforced
- [ ] CI integration if using script
- [ ] Unit test verifying the fix

### References
- Source reports: L1:15.2.1.md, L2:15.1.2.md
- Related findings: None
- ASVS sections: 15.1.2, 15.2.1

### Priority
High

---

## Issue: FINDING-052 - Missing Centralized Documentation of Resource-Intensive Operations

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
ASVS 15.1.3 explicitly requires documentation that identifies time-consuming or resource-demanding functionality, describes how to prevent availability loss, and explains how to avoid response timeout issues. The application has strong runtime controls but lacks a consolidated inventory of resource-intensive operations with their limits, timeout chains, and availability defenses. Without this documentation, operations cannot plan capacity, developers may introduce issues, and security reviews cannot verify completeness. This is fundamentally a documentation gap rather than a technical deficiency.

### Details
**Affected Files and Lines:**
- `atr/docs/resource-management.md` - MISSING DOCUMENT

The application implements comprehensive resource controls but lacks centralized documentation of these controls and the operations they protect.

### Recommended Remediation
Create `atr/docs/resource-management.md` documenting:

1. **Resource-intensive operations inventory** with time profiles and limits:
   - Archive extraction
   - SBOM generation
   - Signature verification
   - Rsync transfers
   - Git clone operations
   - SVN operations
   - Database pagination
   - etc.

2. **Timeout chain architecture** showing HTTP→Task Queue→Worker→Subprocess relationships

3. **Per-user and per-application limits**:
   - Rate limiting
   - Upload sizes
   - Worker resources

4. **Monitoring and alerting guidance**

5. **Capacity planning recommendations**

Include all 15+ identified resource-intensive operations with their defenses and consumer timeout handling patterns. Total effort: ~1-2 days.

### Acceptance Criteria
- [ ] Resource management document created
- [ ] All resource-intensive operations documented
- [ ] Timeout chains documented
- [ ] Limits and thresholds documented
- [ ] Monitoring guidance provided
- [ ] Capacity planning guidance provided

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-050, FINDING-053, FINDING-193, FINDING-194, FINDING-195, FINDING-196, FINDING-197
- ASVS sections: 15.1.3

### Priority
High

---

## Issue: FINDING-053 - Unbounded Directory Traversal and File Hashing in Signature Provenance Endpoint

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The signature provenance endpoint performs unbounded directory traversal and file I/O operations within a single HTTP request handler. For users associated with many committees, this triggers traversal of potentially thousands of files, reading each matching file and computing SHA3-256 hashes—all synchronously within the HTTP request context. Code comments acknowledge this is resource-intensive but no controls are applied. Rate limiting (10 requests/hour) and JWT authentication provide some protection, but each individual request can still cause significant resource consumption.

### Details
**Affected Files and Lines:**
- `atr/api/__init__.py:signature_provenance()` - Unbounded traversal
- `atr/api/__init__.py:_match_committee_keys()` - File iteration
- `atr/api/__init__.py:_match_unfinished()` - File iteration

The endpoint performs unbounded operations within HTTP request context, risking timeout and resource exhaustion.

### Recommended Remediation
**Offload to task queue (recommended approach):**

Convert to async task that returns task ID for polling status, benefiting from worker resource limits:

```python
@app.route('/api/signature/provenance')
async def signature_provenance(...):
    # Create task
    task_id = create_task('signature_provenance', fingerprint=fingerprint)
    return {'task_id': task_id, 'status': 'pending'}
```

**Alternative:** Add limits with early termination:

```python
_MAX_FILES_TO_SCAN = 10000
_MAX_COMMITTEES_TO_SCAN = 100

# Implement early termination after first match found
# Add file scan counter and abort if exceeded
```

Task queue approach aligns with application's existing architecture and provides consistent user experience.

### Acceptance Criteria
- [ ] Task queue implementation OR limits added
- [ ] Resource consumption bounded
- [ ] Timeout protection implemented
- [ ] Early termination on match
- [ ] Integration test verifies limits
- [ ] Unit test verifying the fix

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-052
- ASVS sections: 15.1.3

### Priority
High

---

## Issue: FINDING-054 - GitHub Actions CI Workflows Use Mutable References

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Several CI workflows use mutable GitHub Actions references that violate ASVS 15.2.1 compliance by preventing version tracking and creating supply chain attack vectors. While some workflows (build.yml, analyze.yml, codeql.yaml) properly use SHA-pinned references, others use mutable branch names (@master) or version tags (@v6, @v7). This creates inconsistent security posture and prevents effective tracking against update/remediation timeframes.

### Details
**Affected Files and Lines:**
- `.github/workflows/pylint.yml:20` - Mutable reference
- `.github/workflows/unittest.yml:20` - Mutable reference
- `.github/workflows/unit-tests.yml:20` - Mutable reference
- `.github/workflows/unit-tests.yml:25` - Mutable reference

The inconsistent use of pinning creates a mixed security posture where some workflows are protected but others are vulnerable.

### Recommended Remediation
Pin all GitHub Actions to full SHA commits with version comments following the pattern used in build.yml:

```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
  with:
    persist-credentials: false
```

**Verification Steps:**
1. Update all workflow files with SHA-pinned references
2. Verify Dependabot can generate update PRs for pinned actions
3. Add CI check to prevent merging workflows with mutable references
4. Document pinning policy in CONTRIBUTING.md

### Acceptance Criteria
- [ ] All actions pinned to SHA commits
- [ ] Version comments added
- [ ] persist-credentials: false added
- [ ] Dependabot compatibility verified
- [ ] CI check prevents mutable references
- [ ] Policy documented

### References
- Source reports: L1:15.2.1.md
- Related findings: None
- ASVS sections: 15.2.1

### Priority
High

---

## Issue: FINDING-055 - Archive Extraction Size Tracking Reset by Metadata Files

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The archive extraction functions return `0` instead of `total_extracted` when skipping certain members (metadata files, device files, unsafe paths). This resets the running size counter, allowing attackers to bypass the extraction size limit by interleaving skipped members with large files. Attackers can extract 150MB+ archives despite 100MB limits by interleaving metadata files.

### Details
**Affected Files and Lines:**
- `atr/archives.py:143-159` - TAR extraction with size reset
- `atr/archives.py:227-236` - ZIP extraction with size reset

When skipping members, the functions return 0 instead of preserving the accumulated total_extracted value, resetting the size counter.

### Recommended Remediation
Fix all return paths in both `_tar_archive_extract_member` and `_zip_archive_extract_member` to return `total_extracted` instead of `0` when skipping members:

```python
# In _tar_archive_extract_member
if should_skip_member:
    return total_extracted  # Don't reset counter

# In _zip_archive_extract_member
if should_skip_member:
    return total_extracted  # Don't reset counter
```

Add verification tests that create archives with interleaved metadata files and verify the size limit is enforced.

### Acceptance Criteria
- [ ] Size counter preserved when skipping
- [ ] All return paths fixed
- [ ] TAR extraction corrected
- [ ] ZIP extraction corrected
- [ ] Integration test with interleaved files
- [ ] Unit test verifying the fix

### References
- Source reports: L2:15.2.2.md
- Related findings: None
- ASVS sections: 15.2.2

### Priority
High

---

## Issue: FINDING-056 - Git Clone Operations Without Network Timeout

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Git clone operations for source tree comparison lack explicit network timeouts. While worker process limits provide coarse protection (300s wall-clock timeout), hung git operations consume worker threads until the entire worker process is killed. The `git_client.fetch()` operation has no timeout configured.

### Details
**Affected Files and Lines:**
- `atr/tasks/checks/compare.py:170-185` - Git clone without timeout

The git clone operation can hang indefinitely on network issues, consuming worker resources until process-level timeout kills the entire worker.

### Recommended Remediation
Wrap the `asyncio.to_thread(_clone_repo, ...)` call with `asyncio.wait_for()` using a 120-second timeout:

```python
try:
    repo = await asyncio.wait_for(
        asyncio.to_thread(_clone_repo, url, target_dir),
        timeout=120
    )
except asyncio.TimeoutError:
    log.error('Git clone timed out', extra={'url': url})
    return None
```

Add configuration option `GIT_CLONE_TIMEOUT` with default 120 seconds. Handle TimeoutError and return None to indicate failure.

### Acceptance Criteria
- [ ] Timeout wrapper added
- [ ] Timeout configurable
- [ ] TimeoutError handled gracefully
- [ ] Failure indicated by None return
- [ ] Integration test verifies timeout
- [ ] Unit test verifying the fix

### References
- Source reports: L2:15.2.2.md
- Related findings: FINDING-193
- ASVS sections: 15.2.2

### Priority
High

---

## Issue: FINDING-057 - Distribution Operations Have No Audit Logging

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The entire distributions.py writer module has no calls to `append_to_audit_log()`. Distribution operations include recording package uploads to platforms like Maven/PyPI/npm, automating GitHub Actions workflows, and deleting distribution records—all security-critical supply chain operations. An attacker with committee access could record fake distributions, trigger malicious distribution workflows, or delete distribution records with zero audit trail.

### Details
**Affected Files and Lines:**
- `atr/storage/writers/distributions.py` - Entire file without audit logging

All distribution lifecycle operations lack audit trails, making forensic investigation and compliance verification impossible.

### Recommended Remediation
Add audit logging to all distribution operations:

```python
# In automate()
self.__write_as.append_to_audit_log(
    operation='distribution_automate',
    release_key=release_key,
    platform=platform
)

# In record()
self.__write_as.append_to_audit_log(
    operation='distribution_record',
    release_key=release_key,
    platform=platform,
    package=package,
    version=version
)

# In delete_distribution()
self.__write_as.append_to_audit_log(
    operation='distribution_delete',
    distribution_id=distribution_id,
    release_key=distribution.release_key
)
```

Add `self.__write_as.append_to_audit_log()` calls after database commits with context including asf_uid, release_key, platform, package, and version.

### Acceptance Criteria
- [ ] Audit logging added to automate()
- [ ] Audit logging added to record()
- [ ] Audit logging added to delete_distribution()
- [ ] All operations captured
- [ ] Context information included
- [ ] Unit test verifying the fix

### References
- Source reports: L2:16.1.1.md
- Related findings: FINDING-019
- ASVS sections: 16.1.1

### Priority
High

---

## Issue: FINDING-058 - SSH Host Key Generated with RSA 2048-bit (~112 bits of security)

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The SSH server host key is generated using `asyncssh.generate_private_key('ssh-rsa')` without specifying a key size, which defaults to 2048 bits. According to NIST SP 800-57 Part 1 Rev. 5, RSA 2048-bit provides approximately 112 bits of security, falling short of the ASVS 11.2.3 requirement for a minimum of 128 bits of security (which requires RSA ≥3072 bits). Additionally, if a host key already exists at the specified path, it is loaded without verifying its algorithm or key size.

### Details
**Affected Files and Lines:**
- `atr/ssh.py:148-189` - Host key generation with insufficient strength

The default RSA 2048-bit key provides only 112 bits of security, below ASVS requirements. Existing keys are loaded without validation.

### Recommended Remediation
**Option A (Recommended):** Use Ed25519:

```python
host_key = asyncssh.generate_private_key('ssh-ed25519')
```

Ed25519 provides 128 bits of security and is more efficient than RSA.

**Option B:** Use RSA 4096-bit:

```python
host_key = asyncssh.generate_private_key('ssh-rsa', key_size=4096)
```

RSA 4096-bit provides ~140 bits of security.

Add validation logic to check existing keys when loading from disk:

```python
if host_key_path.exists():
    host_key = asyncssh.read_private_key(str(host_key_path))
    # Validate key strength
    if isinstance(host_key, asyncssh.SSHKeyPairRSA) and host_key.key_size < 3072:
        raise ValueError("Existing RSA host key too weak (< 3072 bits)")
```

### Acceptance Criteria
- [ ] Host key algorithm upgraded
- [ ] Key strength meets ASVS requirements
- [ ] Existing key validation added
- [ ] Weak keys rejected on load
- [ ] Documentation updated
- [ ] Unit test verifying the fix

### References
- Source reports: L2:11.2.3.md, L2:11.6.1.md
- Related findings: FINDING-059
- ASVS sections: 11.2.3, 11.6.1

### Priority
High

---

## Issue: FINDING-059 - No Validation of Uploaded OpenPGP Key Cryptographic Strength

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The application accepts and stores OpenPGP public keys without validating their cryptographic strength. Keys are parsed and stored with their algorithm type and key length recorded in the database, but no validation is performed to ensure these parameters meet minimum security requirements. This allows weak keys (e.g., RSA 1024-bit or smaller, deprecated DSA keys) to be imported and subsequently used for release artifact signature verification.

### Details
**Affected Files and Lines:**
- `atr/storage/writers/keys.py:109-350` - Key import without strength validation
- `atr/tasks/checks/signature.py:64-131` - Signature verification without strength check

Keys are imported and used without validating they meet minimum cryptographic strength requirements.

### Recommended Remediation
Add validation in `keyring_fingerprint_model()` and `_check_core_logic()`:

```python
# Approved algorithms
APPROVED_ALGORITHMS = {
    pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign,
    pgpy.constants.PubKeyAlgorithm.RSASign,
    pgpy.constants.PubKeyAlgorithm.ECDSA,
    pgpy.constants.PubKeyAlgorithm.EdDSA,
    pgpy.constants.PubKeyAlgorithm.ECDH,
}

# Minimum key sizes
MIN_KEY_SIZES = {
    pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign: 3072,
    pgpy.constants.PubKeyAlgorithm.RSASign: 3072,
    pgpy.constants.PubKeyAlgorithm.ECDSA: 256,
    pgpy.constants.PubKeyAlgorithm.EdDSA: 255,
}

def validate_key_strength(key: pgpy.PGPKey) -> None:
    """Validate key meets minimum cryptographic requirements."""
    if key.key_algorithm not in APPROVED_ALGORITHMS:
        raise ValueError(f"Key algorithm {key.key_algorithm} not approved")
    
    min_size = MIN_KEY_SIZES.get(key.key_algorithm)
    if min_size and key.key_size < min_size:
        raise ValueError(
            f"Key size {key.key_size} below minimum {min_size} "
            f"for algorithm {key.key_algorithm}"
        )
```

Reject keys that do not meet these criteria with a descriptive error message. Filter keys by cryptographic strength before verification.

### Acceptance Criteria
- [ ] Key strength validation implemented
- [ ] Approved algorithms enforced
- [ ] Minimum key sizes enforced
- [ ] Weak keys rejected on import
- [ ] Descriptive error messages
- [ ] Unit test verifying the fix

### References
- Source reports: L2:11.2.3.md, L2:11.6.1.md
- Related findings: FINDING-058
- ASVS sections: 11.2.3, 11.6.1

### Priority
High

---

## Issue: FINDING-060 - OAuth State Parameter Not Bound to User Agent Session (Login CSRF)

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The OAuth state parameter is generated with cryptographic randomness but is not bound to the specific user-agent (browser session) that initiated the flow. Any HTTP client possessing a valid state value can complete the callback, regardless of whether it was the same user agent that initiated the authorization request. This enables Login CSRF attacks where an attacker can trick a victim into completing the attacker's OAuth flow, logging the victim in as the attacker.

### Details
**Affected Files and Lines:**
- `src/asfquart/generics.py:47-93` - OAuth flow without session binding

The state parameter validates CSRF but is not bound to the initiating session, allowing cross-session completion.

### Recommended Remediation
Bind the OAuth state to the user-agent using a short-lived cookie:

```python
# During login initiation
nonce = secrets.token_hex(16)
state = hashlib.sha256(nonce.encode()).hexdigest()

# Store nonce with state
pending_states[state] = {
    'nonce': nonce,
    'created': time.time(),
    'redirect': redirect_to
}

# Set cookie
response = quart.redirect(oauth_url)
response.set_cookie(
    'oauth_nonce',
    nonce,
    max_age=workflow_timeout,
    secure=True,
    httponly=True,
    samesite='Lax'
)

# During callback
cookie_nonce = request.cookies.get('oauth_nonce')
if not cookie_nonce or state_data['nonce'] != cookie_nonce:
    raise ValueError("OAuth state not bound to session")
```

### Acceptance Criteria
- [ ] Nonce generated and stored
- [ ] Cookie set with security flags
- [ ] Cookie validated on callback
- [ ] Session binding enforced
- [ ] Integration test verifies binding
- [ ] Unit test verifying the fix

### References
- Source reports: L2:10.1.2.md, L2:10.2.1.md
- Related findings: FINDING-061, FINDING-062
- ASVS sections: 10.1.2, 10.2.1

### Priority
High

---

## Issue: FINDING-061 - No PKCE Implementation in OAuth Authorization Code Flow

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The OAuth flow uses the state parameter for CSRF protection but does not implement Proof Key for Code Exchange (PKCE). ASVS 10.1.2 specifically names PKCE code_verifier as a client-generated secret that should be transaction-specific and session-bound. Without PKCE, the authorization code itself is the sole bearer credential for obtaining tokens, vulnerable to code interception attacks via Referer header leak, browser history, open redirector, malicious browser extensions, or network-level interception.

### Details
**Affected Files and Lines:**
- `src/asfquart/generics.py:48-101` - OAuth flow without PKCE

The flow lacks PKCE protection, making authorization codes vulnerable to interception.

### Recommended Remediation
Implement PKCE (RFC 7636) if the ASF OAuth service supports it:

```python
# On login initiation
code_verifier = secrets.token_urlsafe(64)
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).rstrip(b'=').decode()

# Store code_verifier in pending_states
pending_states[state]['code_verifier'] = code_verifier

# Include in authorization request
oauth_url = (
    f"{OAUTH_URL_AUTHORIZE}?"
    f"response_type=code&"
    f"client_id={CLIENT_ID}&"
    f"redirect_uri={redirect_uri}&"
    f"state={state}&"
    f"code_challenge={code_challenge}&"
    f"code_challenge_method=S256"
)

# On token exchange
code_verifier = state_data['code_verifier']
token_params = {
    'code': code,
    'code_verifier': code_verifier,
    # ... other params
}
```

### Acceptance Criteria
- [ ] PKCE implementation added
- [ ] code_verifier generated
- [ ] code_challenge computed
- [ ] Challenge included in auth request
- [ ] Verifier included in token exchange
- [ ] Unit test verifying the fix

### References
- Source reports: L2:10.1.2.md, L2:10.2.1.md
- Related findings: FINDING-060, FINDING-062
- ASVS sections: 10.1.2, 10.2.1

### Priority
High

---

## Issue: FINDING-062 - Process-Local OAuth State Storage Breaks Validation in Multi-Instance Deployments

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `pending_states` dictionary is process-local. In a multi-instance or load-balanced deployment, if the OAuth callback routes to a different instance than the one that initiated the flow, the state lookup fails because `pending_states` is not shared across processes. While this fail-safe behavior prevents exploitation, it means that in multi-instance deployments the state validation becomes unreliable, potentially leading to operational workarounds that weaken security.

### Details
**Affected Files and Lines:**
- `src/asfquart/generics.py:31` - Process-local state storage
- `docs/oauth.md` - Missing multi-instance documentation

The process-local storage prevents horizontal scaling and creates operational issues in load-balanced environments.

### Recommended Remediation
Use a shared, TTL-backed store for OAuth state to support multi-instance deployments:

```python
# Recommended approach: Redis-backed state storage
import aioredis

async def store_state(state: str, data: dict, ttl: int) -> None:
    """Store OAuth state in Redis with TTL."""
    redis = await aioredis.create_redis_pool('redis://localhost')
    await redis.setex(f'oauth_state:{state}', ttl, json.dumps(data))
    redis.close()
    await redis.wait_closed()

async def pop_state(state: str) -> dict | None:
    """Atomically get and delete OAuth state."""
    redis = await aioredis.create_redis_pool('redis://localhost')
    
    # Lua script for atomic get-and-delete
    lua_script = """
    local value = redis.call('GET', KEYS[1])
    if value then
        redis.call('DEL', KEYS[1])
    end
    return value
    """
    
    result = await redis.eval(lua_script, keys=[f'oauth_state:{state}'])
    redis.close()
    await redis.wait_closed()
    
    return json.loads(result) if result else None
```

Replace `pending_states[state]` assignments with `await store_state()` calls. Replace `pending_states` lookups with `await pop_state()` calls.

### Acceptance Criteria
- [ ] Shared state storage implemented
- [ ] Redis integration added
- [ ] Atomic operations ensured
- [ ] TTL enforcement maintained
- [ ] Multi-instance support verified
- [ ] Unit test verifying the fix

### References
- Source reports: L2:10.1.2.md, L2:10.2.1.md
- Related findings: FINDING-060, FINDING-061
- ASVS sections: 10.1.2, 10.2.1

### Priority
High

---

## Issue: FINDING-063 - OAuth Token Exchange Bypasses Application's Hardened TLS Context

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The OAuth authorization code exchange creates an `aiohttp.ClientSession` with default SSL settings instead of using the application's hardened TLS context (`create_secure_session()`). While Python 3.10+ defaults include TLS 1.2 minimum, this creates inconsistent security posture for the security-critical OAuth flow that handles session credentials. The documented hardening (TLS 1.2+, CERT_REQUIRED, check_hostname) is not applied to this critical authentication path.

### Details
**Affected Files and Lines:**
- `src/asfquart/generics.py:82-108` - OAuth token exchange without hardened TLS

The OAuth flow uses default TLS settings instead of the application's hardened configuration, creating inconsistency.

### Recommended Remediation
Create an OAuth-specific SSL context matching application security standards:

```python
# Import or duplicate create_secure_ssl_context() pattern
import ssl

def create_oauth_ssl_context() -> ssl.SSLContext:
    """Create hardened SSL context for OAuth."""
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context

# Use in OAuth callback
ssl_context = create_oauth_ssl_context()
connector = aiohttp.TCPConnector(ssl=ssl_context)

async with aiohttp.ClientSession(connector=connector) as session:
    rv = await session.get(OAUTH_URL_CALLBACK % encoded_code)
```

Ensure the context enforces `check_hostname=True`, `verify_mode=ssl.CERT_REQUIRED`, and `minimum_version=ssl.TLSVersion.TLSv1_2`.

### Acceptance Criteria
- [ ] Hardened SSL context created
- [ ] OAuth session uses hardened context
- [ ] TLS 1.2+ enforced
- [ ] Certificate verification enforced
- [ ] Hostname checking enforced
- [ ] Unit test verifying the fix

### References
- Source reports: L2:10.1.2.md, L2:12.3.2.md, L2:12.3.3.md, L2:13.2.3.md
- Related findings: FINDING-064
- ASVS sections: 10.1.2, 12.3.2, 12.3.3, 13.2.3

### Priority
High

---

## Issue: FINDING-064 - Apache Reverse Proxy Disables All TLS Certificate Validation for Backend Connections

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The Apache reverse proxy explicitly disables all TLS certificate validation mechanisms when connecting to backend containers. While TLS encryption is enforced via SSLProxyEngine On and SSLProxyProtocol, the configuration completely bypasses certificate verification using SSLProxyVerify none, SSLProxyCheckPeerCN off, SSLProxyCheckPeerName off, and SSLProxyCheckPeerExpire off. In a container escape or port-hijacking scenario, an attacker could intercept all proxied traffic.

### Details
**Affected Files and Lines:**
- `tooling-vm-ec2-de.apache.org.yaml:91-153` - Proxy configuration with disabled validation

The proxy enforces TLS encryption but disables all certificate validation, creating a man-in-the-middle vulnerability.

### Recommended Remediation
Configure Apache to trust ONLY the specific self-signed certificate generated for the container:

```apache
SSLProxyEngine On
SSLProxyCACertificateFile /var/opt/atr-staging/hypercorn/secrets/cert.pem
SSLProxyVerify require
SSLProxyCheckPeerCN on
SSLProxyCheckPeerName on
```

The `SSLProxyCACertificateFile` directive tells Apache to use the container's specific self-signed cert as the trusted CA certificate. This maintains the self-signed certificate architecture while enforcing validation.

### Acceptance Criteria
- [ ] Certificate validation enabled
- [ ] Specific cert trusted as CA
- [ ] Peer verification enforced
- [ ] CN and name checking enabled
- [ ] Integration test verifies validation
- [ ] Unit test verifying the fix

### References
- Source reports: L2:12.3.2.md, L2:12.3.3.md, L2:12.3.4.md
- Related findings: FINDING-063
- ASVS sections: 12.3.2, 12.3.3, 12.3.4

### Priority
High

---

## Issue: FINDING-065 - Unsanitized Markdown-to-HTML Rendering in Release Checklist Bypasses Auto-Escaping

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The application renders committee-controlled Markdown content as HTML without sanitization in the release checklist feature. The `cmarkgfm.github_flavored_markdown_to_html()` function preserves raw HTML elements embedded in Markdown. By wrapping the output with `markupsafe.Markup()`, the application explicitly marks this content as 'safe,' bypassing Jinja2's auto-escaping protections. Data flows from `project.policy_release_checklist` through template substitution, then cmarkgfm conversion, then markupsafe.Markup() marking as safe, finally rendered unescaped to browser. This allows content spoofing, CSS injection, link injection, and form injection affecting all users viewing the release checklist.

### Details
**Affected Files and Lines:**
- `atr/get/checklist.py:79-80` - Markdown conversion without sanitization

Committee members control the checklist content and can embed arbitrary HTML through Markdown, which is then marked as safe and rendered without escaping.

### Recommended Remediation
**Option A:** Use cmarkgfm's safe mode with `CMARK_OPT_SAFE`.

**Option B (Recommended):** Apply HTML sanitizer (nh3 or bleach) after conversion with allowlist:

```python
import nh3

allowed_tags = {'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'ul', 'ol', 'li', 
                'a', 'code', 'pre', 'em', 'strong', 'blockquote', 'table', 
                'thead', 'tbody', 'tr', 'th', 'td', 'br', 'hr', 
                'input'}  # For checklist checkboxes
allowed_attributes = {
    'a': {'href', 'title'},
    'input': {'type', 'disabled', 'checked'}
}

html = cmarkgfm.github_flavored_markdown_to_html(checklist_markdown)
sanitized_html = nh3.clean(
    html, 
    tags=allowed_tags, 
    attributes=allowed_attributes,
    url_schemes={'https', 'http'}
)
return markupsafe.Markup(sanitized_html)
```

### Acceptance Criteria
- [ ] HTML sanitization implemented
- [ ] Allowed tags whitelist configured
- [ ] Allowed attributes whitelist configured
- [ ] Safe URL schemes enforced
- [ ] Integration test verifies sanitization
- [ ] Unit test verifying the fix

### References
- Source reports: L1:1.2.1.md
- Related findings: FINDING-020, FINDING-209
- ASVS sections: 1.2.1

### Priority
Medium

---

## Issue: FINDING-066 - DOM-based HTML Injection via innerHTML with Server-Rendered Fragments

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The application uses `innerHTML` to inject server-rendered HTML fragments into the DOM in `ongoing-tasks-poll.js` `updatePageContent()` function. While server-side rendering uses htpy (which auto-escapes), the client-side insertion via `innerHTML` creates a cross-boundary trust dependency. If the API endpoint or data flow is compromised, or if future code changes introduce unescaped content, this becomes an XSS vector. Data flows from API endpoint through JSON response containing `checks_summary_html` and `files_table_html` to `element.innerHTML` assignment with no client-side sanitization.

### Details
**Affected Files and Lines:**
- `atr/static/js/src/ongoing-tasks-poll.js:69-74` - innerHTML usage
- `atr/static/js/src/ongoing-tasks-poll.js:109-117` - innerHTML usage
- `atr/templates/check-selected.html` - Server-side rendering
- `atr/blueprints/api.py` - API endpoint

The innerHTML insertion creates a trust boundary where client-side code assumes server-rendered content is safe.

### Recommended Remediation
**Option 1 (Recommended):** Use DOMParser with replaceChildren():

```javascript
function updatePageContent(data) {
    const parser = new DOMParser();
    
    // Parse and insert checks summary
    const checksDoc = parser.parseFromString(data.checks_summary_html, 'text/html');
    checksSummaryContainer.replaceChildren(...checksDoc.body.childNodes);
    
    // Parse and insert files table
    const filesDoc = parser.parseFromString(data.files_table_html, 'text/html');
    filesTableContainer.replaceChildren(...filesDoc.body.childNodes);
}
```

**Option 2:** Use DOMPurify library with allowed tags whitelist.

**Option 3 (Best long-term):** Return structured JSON data instead of pre-rendered HTML fragments and build DOM client-side using safe APIs like `createElement`, `textContent`, and `appendChild`.

### Acceptance Criteria
- [ ] innerHTML replaced with safe DOM API
- [ ] DOMParser or DOMPurify used
- [ ] Server-side rendering still works
- [ ] Integration test verifies safety
- [ ] Unit test verifying the fix

### References
- Source reports: L1:1.2.1.md, L1:1.2.3.md, L2:1.3.3.md
- Related findings: FINDING-020
- ASVS sections: 1.2.1, 1.2.3, 1.3.3

### Priority
Medium

---

## Issue: FINDING-067 - OAuth Authorization Code Parameter Not URL-Encoded in Token Exchange Request

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The OAuth authorization code parameter is not URL-encoded before being interpolated into the token exchange request URL to oauth.apache.org. While `urllib.parse.quote()` is imported and used extensively in the same file for other OAuth parameters, it is not applied to the 'code' parameter. This allows an attacker to inject additional query parameters into the token exchange request. Per RFC 6749 §4.1.2, authorization codes can contain any printable ASCII character including &, =, ?, and #, which enables parameter injection attacks.

### Details
**Affected Files and Lines:**
- `src/asfquart/generics.py:97` - Code parameter without URL encoding

The authorization code is interpolated directly into the URL without encoding, allowing special characters to inject additional parameters.

### Recommended Remediation
Apply `urllib.parse.quote()` to the OAuth code parameter before URL interpolation:

```python
encoded_code = urllib.parse.quote(code, safe='')
rv = await session.get(OAUTH_URL_CALLBACK % encoded_code)
```

Additionally, consider using `create_secure_session()` from `atr/util.py` instead of plain `aiohttp.ClientSession` to enforce TLS 1.2+, explicit certificate verification, hostname checking, and secure cipher suite selection for defense-in-depth.

### Acceptance Criteria
- [ ] Code parameter URL-encoded
- [ ] Parameter injection prevented
- [ ] Hardened TLS session considered
- [ ] Integration test verifies encoding
- [ ] Unit test verifying the fix

### References
- Source reports: L1:1.2.2.md, L2:1.3.6.md
- Related findings: FINDING-068
- ASVS sections: 1.2.2, 1.3.6

### Priority
Medium

---

## Issue: FINDING-068 - OAuth Callback Missing Hardened TLS Configuration

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The OAuth callback endpoint creates a plain `aiohttp.ClientSession` instead of using `create_secure_session()`, missing TLS 1.2+ enforcement, explicit certificate verification, hostname checking, and secure cipher suite selection. This creates a potential man-in-the-middle vulnerability in the OAuth token exchange flow.

### Details
**Affected Files and Lines:**
- `src/asfquart/generics.py:98` - Plain ClientSession without hardened TLS

The OAuth token exchange uses default TLS settings instead of the application's hardened configuration.

### Recommended Remediation
Use `create_secure_session()` for hardened TLS configuration:

```python
async with util.create_secure_session(
    timeout=aiohttp.ClientTimeout(sock_read=15)
) as session:
    rv = await session.get(OAUTH_URL_CALLBACK % encoded_code)
```

### Acceptance Criteria
- [ ] Hardened session used
- [ ] TLS 1.2+ enforced
- [ ] Certificate verification enforced
- [ ] Hostname checking enforced
- [ ] Integration test verifies configuration
- [ ] Unit test verifying the fix

### References
- Source reports: L2:1.3.6.md
- Related findings: FINDING-067
- ASVS sections: 1.3.6

### Priority
Medium

---

## Issue: FINDING-069 - Missing URL Protocol Validation for Third-Party Distribution URLs Rendered in HTML

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
URLs from third-party API responses (NPM, ArtifactHub, PyPI) are rendered as clickable HTML links without protocol validation. The `distribution_web_url()` function extracts URLs directly from API responses and stores them in the database. These URLs are later rendered via `html_tr_a()` as `<a href>` elements without validating the protocol scheme. An attacker could publish a package with a `javascript:` or `data:` URL in the homepage field, which would be stored and later execute in users' browsers when they view the distribution page, resulting in stored XSS. Jinja2 auto-escaping prevents breaking out of HTML attributes but does NOT prevent `javascript:` protocol execution in href attributes.

### Details
**Affected Files and Lines:**
- `atr/shared/distribution.py:161-202` - URL extraction without validation
- `atr/shared/distribution.py:248` - URL rendering
- `atr/get/distribution.py:105` - Distribution display

URLs are extracted from third-party APIs and rendered without protocol validation, allowing dangerous protocols.

### Recommended Remediation
Create a centralized URL protocol validation function and apply it to all third-party URLs:

```python
_SAFE_URL_SCHEMES = frozenset({'http', 'https'})

def validate_url_protocol(url: str) -> str | None:
    """Validate URL has safe protocol scheme."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in _SAFE_URL_SCHEMES:
            return None
        return url
    except Exception:
        return None

# Apply in distribution_web_url() for all cases
web_url = validate_url_protocol(raw_url)
if not web_url:
    return None

# Defense-in-depth at render layer
def html_tr_a(url: str, text: str) -> htm.Element:
    """Render link with protocol validation."""
    safe_url = validate_url_protocol(url)
    if not safe_url:
        return htm.td[text]  # Render as text if unsafe
    return htm.td[htm.a(href=safe_url)[text]]
```

Apply in `distribution_web_url()` for all cases (NPM, ArtifactHub, PyPI). Add defense-in-depth at render layer in `html_tr_a()` to validate URLs again before rendering.

### Acceptance Criteria
- [ ] URL validation function created
- [ ] Validation applied at storage
- [ ] Validation applied at rendering
- [ ] Dangerous protocols rejected
- [ ] Integration test verifies rejection
- [ ] Unit test verifying the fix

### References
- Source reports: L1:1.2.2.md
- Related findings: FINDING-070
- ASVS sections: 1.2.2

### Priority
Medium

---

## Issue: FINDING-070 - Missing URL Protocol Validation for SBOM Supplier URLs

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `supplier_op_from_url()` function in SBOM conformance processing accepts URLs from deps.dev API responses without protocol validation. When processing SBOM documents, the system queries the deps.dev API for Maven package homepage URLs and extracts the URL from the 'HOMEPAGE' link label. The fallback case accepts ANY URL as both the supplier name and URL without validating the protocol scheme. A `javascript:` or `data:` URL from the deps.dev API would be stored in the SBOM supplier URL field. If this data is later rendered in a web context with the URL as a clickable link, it could enable stored XSS.

### Details
**Affected Files and Lines:**
- `atr/sbom/conformance.py:104-115` - supplier_op_from_url without validation
- `atr/sbom/conformance.py:124-132` - URL extraction from API

The function accepts any URL without protocol validation, allowing dangerous protocols to be stored.

### Recommended Remediation
Add protocol validation to `supplier_op_from_url()`:

```python
def supplier_op_from_url(url: str) -> tuple[str, str] | None:
    """Extract supplier from URL with protocol validation."""
    try:
        parsed = urllib.parse.urlparse(url)
        
        # Validate protocol
        if parsed.scheme.lower() not in ('http', 'https'):
            return None
        
        # ... rest of function
    except Exception:
        return None
```

Check `parsed.scheme.lower() in ('http', 'https')` and return None for non-HTTP(S) URLs. This prevents `javascript:`, `data:`, `file:`, and other dangerous protocols from being stored and potentially rendered.

### Acceptance Criteria
- [ ] Protocol validation added
- [ ] Only HTTP(S) URLs accepted
- [ ] Dangerous protocols rejected
- [ ] None returned for invalid URLs
- [ ] Integration test verifies rejection
- [ ] Unit test verifying the fix

### References
- Source reports: L1:1.2.2.md
- Related findings: FINDING-069
- ASVS sections: 1.2.2

### Priority
Medium

---

## Issue: FINDING-071 - SQL Identifier Injection in SQLite Database Wrapper

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The DB class in `asfpy/sqlite.py` constructs SQL statements by directly interpolating table names and dictionary keys (representing column names) into SQL strings via f-strings and %s formatting. While values are correctly parameterized using ? placeholders, identifiers (table names, column names, LIMIT clauses) receive no sanitization, escaping, or allowlist validation. This creates SQL injection vulnerability if table/column names or limit values are derived from user input. No active exploitation path identified in ATR application as it uses SQLAlchemy/SQLModel exclusively.

### Details
**Affected Files and Lines:**
- `asfpy/sqlite.py:66` - delete() with identifier interpolation
- `asfpy/sqlite.py:78` - update() with identifier interpolation
- `asfpy/sqlite.py:94` - insert() with identifier interpolation
- `asfpy/sqlite.py:106` - upsert() with identifier interpolation
- `asfpy/sqlite.py:135` - fetch() with identifier interpolation

Table and column names are interpolated directly into SQL without validation or quoting, creating injection risk.

### Recommended Remediation
Add identifier validation using regex pattern and quote identifiers with double-quotes:

```python
import re

_IDENTIFIER_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

def _validate_identifier(identifier: str) -> str:
    """Validate and quote SQL identifier."""
    if not _IDENTIFIER_PATTERN.match(identifier):
        raise ValueError(f"Invalid SQL identifier: {identifier}")
    return f'"{identifier}"'

# Apply in all methods
def delete(self, table: str, where: dict) -> None:
    """Delete rows with validated identifiers."""
    table = _validate_identifier(table)
    columns = [_validate_identifier(k) for k in where.keys()]
    # ... rest of function
```

Apply `_validate_identifier()` function to all table names, column names in `delete()`, `update()`, `insert()`, `upsert()`, and `fetch()` methods. Parameterize the limit value in `fetch()` method. Fix inconsistent column quoting to use double-quotes throughout.

### Acceptance Criteria
- [ ] Identifier validation function added
- [ ] All table names validated
- [ ] All column names validated
- [ ] Identifiers quoted with double-quotes
- [ ] Limit value parameterized
- [ ] Unit test verifying the fix

### References
- Source reports: L1:1.2.4.md
- Related findings: None
- ASVS sections: 1.2.4

### Priority
Medium

---

## Issue: FINDING-072 - LDAP Filter Injection in Account Lookup Function (Multiple Files)

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
Multiple LDAP account lookup methods construct LDAP search filters by directly interpolating the uid parameter without validation or escaping. In `asfpy/ldapadmin.py`, the `manager.load_account()` method lacks UID validation despite `LDAP_VALID_UID_RE` being defined and used in other methods. In `atr/principal.py`, the `_get_project_memberships()` method uses string interpolation without `escape_filter_chars()`. This creates an inconsistency where the protection control exists but is not applied uniformly. Allows LDAP filter manipulation, information disclosure, potential authentication/authorization bypass, and enumeration attacks via wildcard and partial match queries.

### Details
**Affected Files and Lines:**
- `asfpy/ldapadmin.py:186` - load_account without validation
- `atr/principal.py:142` - _get_project_memberships without escaping

The validation and escaping controls exist but are not applied consistently across all LDAP query construction points.

### Recommended Remediation
Apply defense-in-depth by enforcing validation at the method boundary:

```python
# In asfpy/ldapadmin.py load_account()
if not LDAP_VALID_UID_RE.match(uid):
    raise ValueError(f"Invalid UID format: {uid}")

# In atr/principal.py _get_project_memberships()
from ldap.filter import escape_filter_chars

escaped_uid = escape_filter_chars(asf_uid)
filter_str = f"(&(objectClass=posixGroup)(memberUid={escaped_uid}))"
```

Add `LDAP_VALID_UID_RE` validation to `load_account()` method consistent with other methods in the file. Apply both allowlist validation (Layer 1) and LDAP filter escaping using `ldap.filter.escape_filter_chars()` or `ldap3.utils.conv.escape_filter_chars()` (Layer 2) for defense-in-depth. In `principal.py`, add `escape_filter_chars()` at the point of filter construction despite upstream regex validation.

### Acceptance Criteria
- [ ] UID validation added to load_account()
- [ ] Filter escaping added to _get_project_memberships()
- [ ] Defense-in-depth applied
- [ ] Consistency across LDAP operations
- [ ] Integration test verifies protection
- [ ] Unit test verifying the fix

### References
- Source reports: L1:1.2.4.md, L2:1.2.6.md, L2:1.3.8.md
- Related findings: FINDING-210
- ASVS sections: 1.2.4, 1.2.6, 1.3.8

### Priority
Medium

---

## Issue: FINDING-073 - Missing `--` Separator and Unsafe Argument Order in `sbomqs` Execution

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `sbomqs` command execution places the filename as a positional argument before the `--json` flag without using a `--` separator. This creates a vulnerability where filenames starting with `-` could be interpreted as command-line options rather than file arguments. The vulnerable code executes: `sbomqs score <filename> --json`. A file named `-version.cdx.json` would pass `safe.RelPath` validation (hyphen is allowed) but be interpreted as a flag. While parameterized execution prevents shell injection, the lack of `--` separator allows option injection.

### Details
**Affected Files and Lines:**
- `atr/tasks/sbom.py:157-164` - sbomqs execution without -- separator

The filename argument is placed before flags without a separator, allowing filenames starting with hyphens to inject options.

### Recommended Remediation
Place flags before the filename and add `--` separator:

```python
proc = await asyncio.create_subprocess_exec(
    'sbomqs',
    'score',
    '--json',
    '--',  # Separator
    full_path.name,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
    cwd=full_path.parent
)
```

Additionally, add Pydantic field validator to re-validate `file_path` at deserialization:

```python
@pydantic.field_validator('file_path')
@classmethod
def validate_file_path(cls, v: str) -> str:
    safe.RelPath(v)  # Re-validate
    return v
```

### Acceptance Criteria
- [ ] -- separator added
- [ ] Flags placed before filename
- [ ] Pydantic validator added
- [ ] Option injection prevented
- [ ] Integration test verifies protection
- [ ] Unit test verifying the fix

### References
- Source reports: L1:1.2.5.md
- Related findings: FINDING-211
- ASVS sections: 1.2.5

### Priority
Medium

---

## Issue: FINDING-074 - User Input Used Directly as RegExp Without Escaping in Project Directory Filter

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
User input from the project filter textbox is passed directly to `new RegExp()` without escaping special characters, allowing regex metacharacters to be interpreted as pattern syntax rather than literal characters. This creates a ReDoS vulnerability where patterns like `(a+)+` can cause catastrophic backtracking and browser unresponsiveness. Invalid regex characters (e.g., `[`, `(`) cause unhandled exceptions, breaking the filter functionality entirely. Users expecting literal text search get unexpected wildcard behavior (e.g., `.` matches any character).

### Details
**Affected Files and Lines:**
- `atr/static/js/src/projects-directory.js:25-31` - RegExp without escaping

User input is used directly as a regex pattern without escaping special characters, allowing ReDoS and unexpected behavior.

### Recommended Remediation
Apply escaping to all regex special characters before constructing the RegExp object:

```javascript
const escapedFilter = projectFilter.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&');
const regex = new RegExp(escapedFilter, 'i');
```

**Alternative:** Use `String.includes()` for simple text search instead of regex:

```javascript
const lowerFilter = projectFilter.toLowerCase();
projectRows.forEach(row => {
    const projectName = row.dataset.projectName.toLowerCase();
    row.style.display = projectName.includes(lowerFilter) ? '' : 'none';
});
```

### Acceptance Criteria
- [ ] Regex escaping implemented OR
- [ ] String.includes() used instead
- [ ] ReDoS prevented
- [ ] Invalid characters handled
- [ ] Literal text search works
- [ ] Unit test verifying the fix

### References
- Source reports: L2:1.2.9.md, L2:1.3.3.md
- Related findings: FINDING-212
- ASVS sections: 1.2.9, 1.3.3

### Priority
Medium

---

## Issue: FINDING-075 - Unsandboxed render_string_sync API Allows Arbitrary Jinja2 Template Compilation

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The `render_string_sync` function accepts arbitrary strings and compiles them as Jinja2 templates using a non-sandboxed `jinja2.Environment`. This function is exported as a public API (`render_string`) without input validation, sanitization, or sandboxing, creating a potential Server-Side Template Injection (SSTI) vector if ever called with user-controlled input. While no current code path feeds user-controlled input to this function, its availability represents a latent Remote Code Execution (RCE) risk for future development. The function uses a standard Jinja2 environment (not sandboxed) which would allow full access to Python's object hierarchy, filesystem, and system commands if user input reached it.

### Details
**Affected Files and Lines:**
- `atr/template.py:58-62` - render_string_sync without sandboxing
- `atr/template.py:86` - Public export
- `atr/template.py:44-51` - Non-sandboxed environment

The function is exported publicly without protection against SSTI, creating a latent RCE risk.

### Recommended Remediation
**Priority 1 - Option A (Recommended):** Remove the function entirely if unused, or make it private (`_render_string_sync`) with security warnings if needed internally:

```python
def _render_string_sync(source: str, **context) -> str:
    """INTERNAL ONLY: Render template from string.
    
    WARNING: Never call with user-controlled input - SSTI/RCE risk.
    """
    # ... implementation
```

Remove the public export (`render_string = render_string_sync`).

**Priority 1 - Option B:** Replace `SyncEnvironment` with `SyncSandboxedEnvironment`:

```python
from jinja2.sandbox import SandboxedEnvironment

jinja_env = SandboxedEnvironment(...)
```

**Priority 1 - Option C:** Add runtime validation to reject any source containing Jinja2 expression syntax:

```python
if re.search(r'\{\{|\{%|\{#', source):
    raise ValueError("Template syntax not allowed in render_string")
```

**Priority 2:** Add CI/lint check (pre-commit hook) to flag any new usage of `render_string()`, `render_string_sync()`, or direct calls to `jinja_env.from_string()`.

### Acceptance Criteria
- [ ] Function removed or made private OR
- [ ] Sandboxed environment used OR
- [ ] Template syntax validation added
- [ ] Public export removed
- [ ] CI check added
- [ ] Unit test verifying the fix

### References
- Source reports: L1:1.3.2.md, L2:1.3.7.md
- Related findings: None
- ASVS sections: 1.3.2, 1.3.7

### Priority
Medium

---

## Issue: FINDING-076 - Sequential Template Substitution Allows Variable Injection in Email Templates

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The email template construction in `atr/construct.py` uses sequential `str.replace()` operations without escaping template markers (`{{...}}`) in user-provided content. A committer can inject template variables (e.g., setting revision tag to `{{YOUR_FULL_NAME}}`) that expand using the identity of whoever triggers the email, breaking semantic integrity and allowing identity confusion attacks.

### Details
The vulnerability exists because values from earlier replacements are not sanitized against containing `{{VAR}}` patterns that match later substitution variables. Affected functions include email template construction at lines 93-111, 106-117, 161-196, and 176-188 in `atr/construct.py`. An attacker can inject variables that will be replaced with the announcer's real name or other sensitive context in the final email.

### Recommended Remediation
**Option 1 (Quick Fix):** Implement `_escape_template_vars()` function to escape `{{...}}` patterns in replacement values by replacing `{{` with `{ {` and `}}` with `} }`. Apply this to all non-URL, non-validated replacement values.

**Option 2 (Preferred):** Implement single-pass template substitution using regex pattern matching where all variables are substituted simultaneously via a `_substitute_template()` function that uses `re.compile()` with a pattern matching all variable names at once. This prevents earlier substitutions from affecting later ones.

### Acceptance Criteria
- [ ] Template variable injection is prevented through escaping or single-pass substitution
- [ ] All email template construction paths sanitize user-provided content
- [ ] Unit tests verify that injected `{{VAR}}` patterns in user input are not expanded
- [ ] Integration test confirms revision tags containing template markers do not affect email output

### References
- Source reports: L2:1.3.3.md, L2:1.3.10.md
- Related findings: None
- ASVS sections: 1.3.3, 1.3.10

### Priority
Medium

---

## Issue: FINDING-077 - Form Fields Bypass Safe Type Validation (Multiple Instances)

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Multiple form fields use plain `str` type instead of applying the existing SafeType validation system. Hidden form fields and admin inputs accept arbitrary strings without character allowlists, violating the principle that all user-controllable input should be validated regardless of UI context. This is particularly concerning for hidden form fields which are user-controllable despite being hidden in the UI.

### Details
Affected locations include:
- `atr/shared/ignores.py` lines 61-82: UpdateIgnoreForm.revision_number uses plain str
- `atr/shared/projects.py` line 26: AddProjectForm.committee_key uses plain str
- `atr/admin/__init__.py` various locations: Admin form UIDs lack validators

The codebase has well-designed safe types (e.g., `safe.RevisionNumber`, `safe.CommitteeKey`) but they are not consistently applied.

### Recommended Remediation
Apply safe types consistently:
- UpdateIgnoreForm.revision_number should use `safe.OptionalRevisionNumber`
- AddProjectForm.committee_key should use `safe.CommitteeKey`
- Admin form UIDs should have validators checking `^[-_a-z0-9]+$` pattern with max length 64

### Acceptance Criteria
- [ ] All identified form fields use appropriate SafeType validators
- [ ] Hidden form fields apply the same validation as visible fields
- [ ] Admin form UIDs enforce alphanumeric-dash-underscore pattern
- [ ] Unit tests verify validation is applied to all form fields

### References
- Source reports: L2:1.3.3.md
- Related findings: FINDING-211
- ASVS sections: 1.3.3

### Priority
Medium

---

## Issue: FINDING-078 - No SVG Sanitization Library or Function Exists in Codebase

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The entire codebase contains zero SVG sanitization logic — no library (e.g., bleach, DOMPurify, defusedxml, svg-sanitizer), no tag/attribute allowlist, and no function that strips dangerous SVG elements. If any current or future code path serves user-influenced SVG content to a browser, an attacker could embed `<script>`, `<foreignObject>`, or event handler attributes to achieve XSS.

### Details
The application documents seven defense layers in `input-validation.md`, but none address SVG content sanitization. Jinja2 auto-escaping prevents injection in template variables but does not sanitize SVG files or SVG content embedded in served HTML. If downloads.apache.org or any code path serves SVG as `image/svg+xml` or inline in HTML, XSS is achievable.

### Recommended Remediation
Create an SVG sanitization function using defusedxml or similar library:

1. Implement `sanitize_svg()` function in `atr/svg_sanitize.py`
2. Remove dangerous tags: `script`, `foreignObject`, `iframe`, `object`, `embed`, `set`, `animate`
3. Strip event handler attributes (`on*`)
4. Filter dangerous attribute values (`javascript:`, `data:text/html`)
5. Use SAFE_SVG_TAGS allowlist: `svg`, `g`, `path`, `circle`, `ellipse`, `line`, `polyline`, `polygon`, `rect`, `text`, `tspan`, `defs`, `use`, `symbol`, `clipPath`, `mask`, `pattern`, `linearGradient`, `radialGradient`, `stop`, `title`, `desc`, `metadata`

### Acceptance Criteria
- [ ] SVG sanitization function exists and is tested
- [ ] Dangerous SVG tags and attributes are removed
- [ ] Sanitization is applied wherever SVG content may reach a browser
- [ ] Unit tests verify dangerous SVG elements are stripped

### References
- Source reports: L2:1.3.4.md
- Related findings: FINDING-079
- ASVS sections: 1.3.4

### Priority
Medium

---

## Issue: FINDING-079 - Archive Extraction Does Not Inspect or Sanitize SVG Files

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The archive extraction process extracts ALL file types without SVG inspection. SVG is absent from the detection module's `_EXPECTED` dictionary which covers 18 file extension categories but omits image formats entirely. Authenticated users can upload archives containing malicious `.svg` files which are extracted to disk unmodified. If any download, preview, or serving mechanism exposes these files to browsers, XSS is achievable.

### Details
Affected files:
- `atr/archives.py` lines 28-63, 39-47: Extraction without SVG filtering
- `atr/detection.py` lines 26-49: No SVG in `_EXPECTED` dictionary

The `detection.validate_directory()` function skips SVG files (not in `_EXPECTED`), leaving SVG on disk with full scriptable content. Malicious SVG files in release archives pass all validation undetected.

### Recommended Remediation
1. Add SVG to detection module: Include `.svg` in `_EXPECTED` dictionary with `_SVG_TYPES` set to `{'image/svg+xml'}`
2. Implement `_validate_svg_file()` function in `detection.py` to check SVG files for dangerous scriptable content during `validate_directory()`
3. Use regex patterns to detect:
   - `<script` tags
   - `<foreignObject` tags
   - Event handler attributes (`on*=`)
   - `javascript:` URIs
4. Reject or quarantine SVG files containing these dangerous patterns

### Acceptance Criteria
- [ ] SVG files are recognized in detection module
- [ ] Dangerous SVG content is detected during archive validation
- [ ] Malicious SVG files are rejected or quarantined
- [ ] Unit tests verify dangerous SVG patterns are caught

### References
- Source reports: L2:1.3.4.md
- Related findings: FINDING-078
- ASVS sections: 1.3.4

### Priority
Medium

---

## Issue: FINDING-080 - SMTP Header Injection Vulnerability in Bundled Legacy Library

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `asfpy/messaging.py` module contains a legacy email sending function that constructs email messages using raw string formatting without proper CRLF sanitization. This allows SMTP header injection through multiple parameters including subject, sender, recipient, headers dict, and thread_key. An attacker could inject arbitrary email headers including Bcc, CC, Subject overrides, or Content-Type manipulation via CRLF sequences.

### Details
Affected locations in `asfpy/messaging.py`:
- Lines 130-140: Raw string interpolation for message construction
- Line 95: Subject parameter vulnerable
- Line 120: Headers dict vulnerable
- Line 110: Thread_key vulnerable

Additionally, the module uses assert statements for validation which are disabled with Python's `-O` flag. **Mitigating factor:** This module does not appear to be imported by any ATR application code - the application exclusively uses `atr/mail.py` for email operations.

### Recommended Remediation
**Preferred:** Remove `asfpy/messaging.py` from the repository if it's not needed, or clearly mark it as deprecated/unused.

**Alternative:** If the module must be retained, replace string formatting with Python's `email.message.EmailMessage` API:
- Use `EmailMessage(policy=policy.SMTPUTF8)`
- Use Address objects for From/To headers
- Use proper header assignment that automatically rejects CRLF sequences

Add a linting rule or import check that prevents importing `asfpy.messaging.mail` in any ATR module.

### Acceptance Criteria
- [ ] Legacy messaging module is removed or marked as deprecated
- [ ] If retained, SMTP header injection is prevented through proper API usage
- [ ] Linting rule prevents importing the legacy module
- [ ] Unit tests verify CRLF sequences are rejected

### References
- Source reports: L2:1.3.11.md
- Related findings: None
- ASVS sections: 1.3.11

### Priority
Medium

---

## Issue: FINDING-081 - HTTP Redirects Followed Without Target Domain Validation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `_fetch_keys_from_url` function uses `allow_redirects=True` without validating redirect target domains. If downloads.apache.org were compromised or DNS-hijacked, the application would follow redirects to arbitrary destinations including cloud metadata endpoints (169.254.169.254), internal services, or attacker-controlled servers. Response data from redirect targets is read and stored in database.

### Details
Affected locations:
- `atr/post/keys.py` lines 186-206: Redirect following without validation
- `atr/post/keys.py` lines 207-210: Response data stored
- `scripts/keys_import.py` lines 137-140: Same vulnerability in import script

If downloads.apache.org is compromised, redirects could target internal infrastructure or cloud metadata endpoints, enabling SSRF attacks.

### Recommended Remediation
Implement redirect target validation:

1. Create domain allowlist: `_ALLOWED_KEYS_DOMAINS` with `downloads.apache.org`, `dlcdn.apache.org`, `archive.apache.org`
2. Set `allow_redirects=False`
3. Manually handle redirects with validation
4. Create `_validate_keys_url()` function to check:
   - Scheme (HTTPS only)
   - Hostname (against allowlist)
   - Port (443 only)
5. Only follow redirects after validation passes

### Acceptance Criteria
- [ ] Redirect target validation is implemented
- [ ] Only HTTPS redirects to allowed domains are followed
- [ ] Cloud metadata endpoints cannot be reached via redirect
- [ ] Unit tests verify redirect validation logic

### References
- Source reports: L2:1.3.6.md
- Related findings: None
- ASVS sections: 1.3.6

### Priority
Medium

---

## Issue: FINDING-082 - Thread ID Parameter Lacks Format Validation Before Server-Side Request

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `votes` function accepts `thread_id` as plain str type without format validation or safe type wrapper. No rejection of path traversal sequences (`../../`), fragments (`#`), or query parameters (`?`). While JWT authentication limits attack surface and domain remains hardcoded, lack of validation creates risk of path traversal within lists.apache.org domain or API endpoint manipulation if downstream `util.thread_messages()` doesn't properly validate.

### Details
Affected locations:
- `atr/tabulate.py` lines 131-176: votes function accepts unvalidated thread_id
- `atr/tabulate.py` lines 261-267: thread_id used in server-side request

The thread_id parameter is used to construct URLs for server-side requests to lists.apache.org without format validation, potentially allowing path traversal or endpoint manipulation.

### Recommended Remediation
**Option 1 (Recommended):** Create ThreadId safe type in `atr/models/safe.py` with pattern validation (`^[a-zA-Z0-9]{1,128}$`) to restrict to alphanumeric characters only. Update function signature:

```python
async def votes(committee: sql.Committee | None, thread_id: ThreadId)
```

**Option 2:** Add `_validate_thread_id()` function at entry point to validate format before use.

### Acceptance Criteria
- [ ] thread_id parameter uses safe type or explicit validation
- [ ] Path traversal sequences are rejected
- [ ] Only alphanumeric thread IDs are accepted
- [ ] Unit tests verify validation logic

### References
- Source reports: L2:1.3.6.md
- Related findings: None
- ASVS sections: 1.3.6

### Priority
Medium

---

## Issue: FINDING-083 - Tar Archive Extraction Uses Explicitly Insecure Default Filter

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `extract_member()` method uses `tar_filter='fully_trusted'` as its default parameter value. Python's PEP 706 and official documentation explicitly identify this filter as insecure. The `fully_trusted` filter allows absolute paths, path traversal sequences (`../`), device nodes, symlinks pointing outside extraction directory, and setuid/setgid bits. While mitigating controls exist (pre-extraction validation, quarantine workflow), the insecure default violates the principle of secure defaults.

### Details
Affected location: `atr/tarzip.py` lines 130-154

ASVS 1.5.2 states: "Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input." The `fully_trusted` filter is explicitly documented as insecure by Python.

Mitigating controls:
- Pre-extraction validation in `check_archive_safety()`
- Quarantine workflow with `SecurityConfig`

However, the insecure default creates risk if these controls are bypassed or misconfigured.

### Recommended Remediation
Change the default `tar_filter` parameter from `'fully_trusted'` to `'data'` which is the secure default per PEP 706:

```python
def extract_member(
    self,
    member: tarfile.TarInfo,
    path: str,
    tar_filter: str = 'data',  # Changed from 'fully_trusted'
) -> int:
```

Update the docstring to:
- Document the security implications of each filter option
- Explicitly state that `fully_trusted` should only be used for verified trusted archives
- Add test cases to verify path traversal sequences are sanitized, absolute paths are converted to relative, and external symlinks are blocked or made safe

### Acceptance Criteria
- [ ] Default tar_filter is changed to 'data'
- [ ] Docstring documents security implications
- [ ] Test cases verify secure extraction behavior
- [ ] Path traversal and absolute paths are blocked by default

### References
- Source reports: L2:1.5.2.md
- Related findings: None
- ASVS sections: 1.5.2

### Priority
Medium

---

## Issue: FINDING-084 - TLS Certificate Validation Disabled on LDAP Connection

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The LDAP client explicitly disables TLS certificate verification by calling `set_cert_policy('allow')`. This configuration allows the client to accept any certificate presented by the LDAP server, including self-signed or attacker-controlled certificates. A TODO comment indicates this is a known temporary configuration. An attacker positioned on the network path can intercept the TLS connection, present a self-signed certificate (which the client will accept), intercept authentication credentials (bind DN and password), and modify LDAP query results.

### Details
Affected location: `asfpy/aioldap.py` line 103

This affects all LDAP operations in the ASFQuart OAuth authentication flow. An attacker with network access between the application and LDAP server can:
- Intercept authentication credentials
- Modify LDAP query results (group memberships, user attributes)
- Perform authentication bypass

### Recommended Remediation
Enable proper TLS certificate validation.

**Option 1 (Recommended):** Require valid certificates with system CA trust:
```python
set_cert_policy('demand')
```

**Option 2:** Pin the specific Apache LDAP CA certificate:
```python
TLSSettings(ca_cert_file='/path/to/apache-ldap-ca.crt', verify_mode=ssl.CERT_REQUIRED)
```

**Option 3:** Use system CA bundle:
```python
import certifi
TLSSettings(ca_cert_file=certifi.where(), verify_mode=ssl.CERT_REQUIRED)
```

### Acceptance Criteria
- [ ] TLS certificate validation is enabled
- [ ] Self-signed certificates are rejected
- [ ] System CA trust or pinned CA is used
- [ ] Integration tests verify certificate validation

### References
- Source reports: L2:1.3.8.md
- Related findings: None
- ASVS sections: 1.3.8

### Priority
Medium

---

## Issue: FINDING-085 - Finish-Phase Operations Executable During Any Release Phase

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The finish-phase operations (file movement, directory deletion, RC tag removal) in `atr/post/finish.py` are intended for the RELEASE_PREVIEW phase after vote resolution. While the GET handler correctly enforces `phase == RELEASE_PREVIEW`, the POST handler dispatches directly to operation handlers without phase validation. This allows finish operations to execute during any phase, including RELEASE_CANDIDATE (during active voting).

### Details
Affected locations:
- `atr/post/finish.py` lines 31-42: POST handler dispatches without phase check
- `atr/get/finish.py` line 138: GET handler correctly enforces phase

The POST handler calls `_delete_empty_directory`, `_move_file_to_revision`, `_remove_rc_tags` directly without verifying the release is in RELEASE_PREVIEW phase.

### Recommended Remediation
Add phase validation to the `selected()` POST handler before dispatching to operation handlers. Fetch the release using `session.release()` with `phase=sql.ReleasePhase.RELEASE_PREVIEW` to enforce that finish operations can only execute during the preview phase:

```python
async def selected(session, project_key, version_key, form):
    release = await session.release(
        project_key=project_key,
        version_key=version_key,
        phase=sql.ReleasePhase.RELEASE_PREVIEW
    )
    # ... proceed with operations
```

### Acceptance Criteria
- [ ] Finish operations require RELEASE_PREVIEW phase
- [ ] Attempting finish operations in other phases returns appropriate error
- [ ] Integration tests verify phase enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.3.1.md
- Related findings: FINDING-086, FINDING-023
- ASVS sections: 2.3.1

### Priority
Medium

---

## Issue: FINDING-086 - Draft-Phase File Operations Executable During Any Release Phase

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Four draft-phase file operations (`delete_file`, `hashgen`, `sbomgen`, `quarantine_clear`) in `atr/post/draft.py` create new revisions without validating the release phase. Additionally, the `upload.py::stage()` function uses underscore-prefixed parameter names (`_project_key`, `_version_key`) that bypass the `post.typed` decorator's automatic `check_access()` authorization, allowing file uploads without project access validation. The draft operations call `create_revision_with_quarantine()` which fetches releases without phase filters, enabling operations during any phase including RELEASE_CANDIDATE.

### Details
Affected locations:
- `atr/post/draft.py` lines 92-116: Draft operations without phase validation
- `atr/post/upload.py` lines 109-152: Upload staging bypasses authorization

Draft operations can execute during RELEASE_CANDIDATE phase when they should only be allowed during DRAFT phase. Upload staging bypasses project access checks due to underscore-prefixed parameters.

### Recommended Remediation
**For draft operations:** Add phase validation using `session.release()` with `phase=sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT` before executing file operations:

```python
release = await session.release(
    project_key=project_key,
    version_key=version_key,
    phase=sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
)
```

**For upload staging:** Remove underscore prefixes from `project_key` and `version_key` parameters to enable automatic authorization via `post.typed` decorator. Add explicit phase validation to ensure uploads only occur during writable phases (DRAFT or PREVIEW).

### Acceptance Criteria
- [ ] Draft operations require RELEASE_CANDIDATE_DRAFT phase
- [ ] Upload staging enforces project access authorization
- [ ] Phase validation prevents operations during inappropriate phases
- [ ] Integration tests verify enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.3.1.md
- Related findings: FINDING-085, FINDING-087, FINDING-023
- ASVS sections: 2.3.1

### Priority
Medium

---

## Issue: FINDING-087 - SBOM Operations Bypass Release Phase Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
SBOM (Software Bill of Materials) augmentation and scanning operations in `atr/post/sbom.py` create background tasks that generate new revisions. The `_augment()` and `_scan()` functions fetch releases using `data.release()` without phase validation, allowing SBOM operations during any phase including RELEASE_CANDIDATE (during voting) and RELEASE (after announcement). These background tasks call `create_revision_with_quarantine()` which creates new revisions regardless of current phase.

### Details
Affected locations:
- `atr/post/sbom.py` line 57: `_augment()` fetches release without phase filter
- `atr/post/sbom.py` line 84: `_scan()` fetches release without phase filter

Background tasks can generate new revisions during voting or after release announcement, when compose operations should not be allowed.

### Recommended Remediation
Replace direct database access with `session.release()` which defaults to RELEASE_CANDIDATE_DRAFT phase. This ensures SBOM operations can only execute during the draft phase when compose operations are appropriate:

```python
# In _augment() and _scan() functions:
release = await session.release(
    project_key=args.project_key,
    version_key=args.version_key,
    phase=sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
)
```

Apply this fix to both `_augment()` and `_scan()` functions.

### Acceptance Criteria
- [ ] SBOM operations require RELEASE_CANDIDATE_DRAFT phase
- [ ] Operations during other phases return appropriate error
- [ ] Background tasks respect phase restrictions
- [ ] Integration tests verify phase enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.3.1.md
- Related findings: FINDING-086
- ASVS sections: 2.3.1

### Priority
Medium

---

## Issue: FINDING-088 - Archive Extraction Size Limit Bypass via Metadata File Counter Reset

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The archive extraction functions contain a bug where returning 0 instead of total_extracted when skipping metadata files causes the extraction size counter to reset. This allows attackers to bypass the documented maximum extraction size limit (1GB) by interleaving skipped files between large files. Authenticated users can bypass documented extraction size limits, potentially causing disk exhaustion during SBOM generation or archive processing.

### Details
Affected locations:
- `atr/archives.py` lines 95-98, 100-102, 159-161: Return 0 instead of total_extracted
- `atr/archives.py` lines 180-220: `_tar_archive_extract_member()`
- `atr/archives.py` lines 250-290: `_zip_archive_extract_member()`

The functions return 0 for extracted size when skipping macOS metadata files (`._*` prefix) or device files, instead of returning the accumulated `total_extracted` value. This resets the counter, allowing unlimited extraction by interleaving skipped files.

### Recommended Remediation
Change the return statement from `return 0, extracted_paths` to `return total_extracted, extracted_paths` when skipping metadata files (`._*` prefix) and device files. This preserves the counter across all extraction operations:

```python
# When skipping files:
if should_skip:
    return total_extracted, extracted_paths  # Not 0
```

Change early returns in `_tar_archive_extract_member()` and `_zip_archive_extract_member()` to return `total_extracted` instead of 0 when skipping files.

### Acceptance Criteria
- [ ] Extraction size counter is not reset when skipping files
- [ ] Maximum extraction size limit is enforced correctly
- [ ] Test case verifying interleaved skipped files cannot bypass limit
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.1.1.md, L1:2.2.1.md
- Related findings: None
- ASVS sections: 2.1.1, 2.2.1

### Priority
Medium

---

## Issue: FINDING-089 - API Policy Update Bypasses Form-Level Business Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `PolicyUpdateArgs` Pydantic model used by the API endpoint lacks business validation rules that are present in the corresponding web form models. Missing validations include: min_hours range (72-144 or 0), github_repository_name slash rejection, workflow path prefix checks, and mailto_addresses email format validation. This creates inconsistency where API users bypass validation that web form users receive.

### Details
Affected location: `atr/models/api.py` lines 180-220

API users can submit policy updates that would be rejected through the web form, including:
- Invalid min_hours values outside allowed range
- GitHub repository names with slashes
- Invalid workflow paths
- Malformed email addresses

### Recommended Remediation
Add a Pydantic `model_validator` to `PolicyUpdateArgs` class that enforces all business validation rules present in the form models:

```python
@pydantic.model_validator(mode='after')
def validate_policy_args(self) -> 'PolicyUpdateArgs':
    if self.min_hours is not None:
        if self.min_hours != 0 and not (72 <= self.min_hours <= 144):
            raise ValueError("min_hours must be 0 or between 72-144")
    
    if self.github_repository_name and '/' in self.github_repository_name:
        raise ValueError("github_repository_name cannot contain slashes")
    
    # Add other validations matching form models
    return self
```

### Acceptance Criteria
- [ ] API model enforces same validation as web forms
- [ ] Invalid policy values are rejected via API
- [ ] Test cases verify all validation rules
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.1.md
- Related findings: FINDING-021, FINDING-022
- ASVS sections: 2.2.1

### Priority
Medium

---

## Issue: FINDING-090 - Vote Duration Integer Lacks Range Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `vote_duration` field in `StartVotingForm` and `Initiate` task model accepts any integer without range validation. This allows negative values (creating votes with end times in the past, bypassing minimum voting period) or extremely large values (effectively blocking the release process indefinitely for 114+ years).

### Details
Affected locations:
- `atr/shared/voting.py` lines 45-50: StartVotingForm
- `atr/tasks/vote.py` lines 30-45: Initiate task model

The field is typed as `int` without constraints, allowing:
- Negative values: Creates votes ending in the past
- Extremely large values: Blocks release for years
- Zero: Creates instant vote completion

### Recommended Remediation
Add Pydantic `field_validator` to both `StartVotingForm` and `Initiate` models to enforce minimum of 72 hours and maximum of 336 hours (14 days) for `vote_duration`:

```python
@pydantic.field_validator('vote_duration')
@classmethod
def validate_vote_duration(cls, v: int) -> int:
    if v < 72:
        raise ValueError("Vote duration must be at least 72 hours")
    if v > 336:
        raise ValueError("Vote duration cannot exceed 336 hours (14 days)")
    return v
```

### Acceptance Criteria
- [ ] Vote duration is constrained to 72-336 hours
- [ ] Negative values are rejected
- [ ] Extremely large values are rejected
- [ ] Test cases verify range validation
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.1.md
- Related findings: FINDING-022, FINDING-026
- ASVS sections: 2.2.1

### Priority
Medium

---

## Issue: FINDING-091 - Optional Safe-Type URL Parameters Bypass Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The typed route system skips validation for optional safe-type parameters. When a parameter is typed as `Optional[SafeType]`, the code adds it to `optional_params` and continues without adding it to `validated_params`, causing `validate_params()` to never call the safe type's validation logic. Handlers receive raw strings instead of validated SafeType instances.

### Details
Affected location: `atr/blueprints/common.py` lines 145-152

When a route parameter is typed as `Optional[SafeType]`, the `build_api_path()` function:
1. Detects it as optional
2. Adds to `optional_params` list
3. Skips adding to `validated_params`
4. Never validates the value if present

This means optional safe-type parameters receive no validation, defeating the purpose of safe types.

### Recommended Remediation
Modify `build_api_path()` to still add optional SafeType parameters to `validated_params`, and update `validate_params()` to skip None values while still validating present optional parameters:

```python
# In build_api_path():
if is_optional:
    optional_params.append(param_name)
    # Still add to validated_params if it's a SafeType
    if is_safe_type:
        validated_params[param_name] = safe_type_class

# In validate_params():
for param_name, safe_type_class in validated_params.items():
    value = params.get(param_name)
    if value is None and param_name in optional_params:
        continue  # Skip validation for None optional params
    # Validate present values
    params[param_name] = safe_type_class(value)
```

### Acceptance Criteria
- [ ] Optional SafeType parameters are validated when present
- [ ] None values for optional parameters skip validation
- [ ] Handlers receive validated SafeType instances
- [ ] Test cases verify optional parameter validation
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.1.md
- Related findings: None
- ASVS sections: 2.2.1

### Priority
Medium

---

## Issue: FINDING-092 - UpdateIgnoreForm.revision_number Bypasses Safe Type Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
`UpdateIgnoreForm` uses `revision_number: str | None` while sibling forms (`AddIgnoreForm`, `DeleteIgnoreForm`) use `revision_number: safe.RevisionNumber | None`. This inconsistency means the update operation bypasses character validation, Unicode normalization, and control character blocking provided by the safe type system.

### Details
Affected locations:
- `atr/shared/ignores.py` lines 30-40: UpdateIgnoreForm uses str
- `atr/storage/writers/checks.py` lines 50-80: Storage writer signature

The inconsistency creates a gap where update operations accept unvalidated revision numbers while add/delete operations enforce validation. This violates the principle of consistent validation across CRUD operations.

### Recommended Remediation
Update `UpdateIgnoreForm` to use `safe.OptionalRevisionNumber` type:

```python
class UpdateIgnoreForm(pydantic.BaseModel):
    revision_number: safe.OptionalRevisionNumber  # Changed from str | None
    # ... other fields
```

Update `ignore_update()` storage writer signature to accept `safe.OptionalRevisionNumber`.

Create `OptionalRevisionNumber` type alias if it doesn't exist:
```python
OptionalRevisionNumber = RevisionNumber | None
```

### Acceptance Criteria
- [ ] UpdateIgnoreForm uses safe type for revision_number
- [ ] Validation is consistent across all ignore forms
- [ ] Storage writer signature matches form type
- [ ] Test cases verify validation is applied
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.2.md
- Related findings: FINDING-095
- ASVS sections: 2.2.2

### Priority
Medium

---

## Issue: FINDING-093 - SBOM score_tool Uses previous_release_version in Path Without Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `score_tool()` function uses `args.previous_release_version` to construct file paths for reading previous SBOM data without validating the version format. This could allow path traversal to read SBOM files from other projects if an attacker can modify task queue arguments.

### Details
Affected location: `atr/tasks/sbom.py` lines 140-180

The function constructs paths using unvalidated `previous_release_version`:
```python
previous_path = base_path / args.previous_release_version / "sbom.json"
```

Without validation, an attacker with task queue access could use values like `../../other-project/1.0.0` to read SBOM files from other projects.

### Recommended Remediation
Validate `previous_release_version` using `safe.VersionKey`. Add explicit containment check to verify the resolved path is within the expected project directory:

```python
# Validate version format
validated_version = safe.VersionKey(args.previous_release_version)

# Construct path
previous_path = base_path / str(validated_version) / "sbom.json"

# Verify containment
if not previous_path.resolve().is_relative_to(base_path.resolve()):
    raise ValueError("Path traversal attempt detected")
```

### Acceptance Criteria
- [ ] previous_release_version is validated using safe.VersionKey
- [ ] Path containment is verified before file access
- [ ] Path traversal attempts are rejected
- [ ] Test cases verify validation
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.2.md
- Related findings: FINDING-025, FINDING-094
- ASVS sections: 2.2.2

### Priority
Medium

---

## Issue: FINDING-094 - SBOM Task Functions Use revision_number Without Format Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Four SBOM task functions (`generate_sbom`, `score_tool`, `score_attestation`, `score_osv`) use `args.revision_number` in path construction without validating the format. While `RevisionNumber` safe type exists and is used in forms, task arguments use plain str, allowing directory traversal components like `../` or `.`.

### Details
Affected locations in `atr/tasks/sbom.py`:
- Line 60: `generate_sbom` uses unvalidated revision_number
- Line 150: `score_tool` uses unvalidated revision_number
- Line 210: `score_attestation` uses unvalidated revision_number
- Line 270: `score_osv` uses unvalidated revision_number

All four functions construct file paths using the revision_number without validation, creating path traversal risk.

### Recommended Remediation
Add `safe.RevisionNumber` validation at the start of all 4 affected functions before using `revision_number` in path construction:

```python
# At the start of each function:
validated_revision = safe.RevisionNumber(args.revision_number)
# Use validated_revision in path construction
```

Update Pydantic task argument models to use `safe.RevisionNumber` instead of `str`:

```python
class SBOMTaskArgs(pydantic.BaseModel):
    revision_number: safe.RevisionNumber  # Changed from str
    # ... other fields
```

### Acceptance Criteria
- [ ] All four SBOM task functions validate revision_number
- [ ] Task argument models use safe.RevisionNumber type
- [ ] Path traversal attempts are rejected
- [ ] Test cases verify validation in all functions
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.2.md
- Related findings: FINDING-025, FINDING-093, FINDING-092
- ASVS sections: 2.2.2

### Priority
Medium

---

## Issue: FINDING-095 - Distribution DeleteForm Uses Plain Strings for Fields Validated as Safe Types in Sibling Forms

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Distribution `DeleteForm` uses plain `str` for `identifier` and `version_key` fields, while sibling forms (`AddForm`, `UpdateForm`) use `safe.Alphanumeric` and `safe.VersionKey`. This inconsistency bypasses character validation for delete operations.

### Details
Affected locations:
- `atr/shared/distribution.py` lines 60-70: DeleteForm uses str
- `atr/shared/distribution.py` lines 80-100: AddForm/UpdateForm use safe types

The inconsistency means delete operations accept unvalidated strings while add/update operations enforce validation through safe types. This violates the principle of consistent validation across CRUD operations.

### Recommended Remediation
Update `DeleteForm` to use `safe.Alphanumeric` for `identifier` field and `safe.VersionKey` for `version_key` field to match `AddForm`/`UpdateForm`:

```python
class DeleteForm(pydantic.BaseModel):
    identifier: safe.Alphanumeric  # Changed from str
    version_key: safe.VersionKey   # Changed from str
    # ... other fields
```

Add regression test to verify consistency across CRUD forms.

### Acceptance Criteria
- [ ] DeleteForm uses safe types matching AddForm/UpdateForm
- [ ] Validation is consistent across all distribution forms
- [ ] Test cases verify validation is applied
- [ ] Regression test ensures future consistency
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.2.md
- Related findings: FINDING-092
- ASVS sections: 2.2.2

### Priority
Medium

---

## Issue: FINDING-096 - Revision Number Not Validated Against Release Context

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `selected_revision` endpoint accepts a revision number from the URL path but never validates that the revision actually belongs to the specified release. This violates the contextual consistency principle that `(project_key, version_key, revision_number)` should be validated as a unit. An authenticated committer can query task counts for arbitrary revision numbers, potentially accessing information about revisions they shouldn't have access to.

### Details
Affected location: `atr/get/checks.py` lines 107-162

The endpoint accepts `revision_number` from the URL but only validates that the release exists, not that the revision belongs to that release. This allows querying task information for any revision number regardless of whether it's associated with the specified release.

### Recommended Remediation
Add validation to verify that the revision belongs to the specified release by querying `data.revision(release_key=release.key, number=str(revision_number))` and demanding its existence before proceeding with task operations:

```python
async def selected_revision(session, project_key, version_key, revision_number):
    release = await session.release(project_key, version_key)
    
    # Validate revision belongs to this release
    revision = await data.revision(
        release_key=release.key,
        number=str(revision_number)
    )
    if not revision:
        raise exceptions.NotFound("Revision not found for this release")
    
    # Proceed with task operations
```

### Acceptance Criteria
- [ ] Revision number is validated against release context
- [ ] Invalid revision numbers for a release are rejected
- [ ] Test cases verify contextual validation
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.1.2.md
- Related findings: FINDING-097
- ASVS sections: 2.1.2

### Priority
Medium

---

## Issue: FINDING-097 - Inconsistent Phase Validation Between Related Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `selected` and `selected_revision` endpoints handle related operations (viewing checks for a release), but enforce phase validation inconsistently. The parent endpoint `selected` restricts to `RELEASE_CANDIDATE` phase, while the child endpoint `selected_revision` accepts releases in any phase. This allows users to view revision-specific checks for releases that shouldn't be in checking phase, creating a workflow bypass.

### Details
Affected locations:
- `atr/get/checks.py` line 91: `selected` enforces RELEASE_CANDIDATE phase
- `atr/get/checks.py` line 107: `selected_revision` accepts any phase

This inconsistency allows users to bypass phase restrictions by accessing the revision-specific endpoint instead of the release-level endpoint.

### Recommended Remediation
Either enforce the same phase restriction in `selected_revision` by adding `phase=sql.ReleasePhase.RELEASE_CANDIDATE` parameter to the release query, or explicitly validate the phase and document which phases are allowed for revision-specific operations:

```python
async def selected_revision(session, project_key, version_key, revision_number):
    release = await session.release(
        project_key,
        version_key,
        phase=sql.ReleasePhase.RELEASE_CANDIDATE  # Add phase restriction
    )
    # ... proceed
```

Add documentation table showing operation-to-phase mappings for all check endpoints.

### Acceptance Criteria
- [ ] Phase validation is consistent between related endpoints
- [ ] Documentation describes allowed phases for each operation
- [ ] Test cases verify phase enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.1.2.md
- Related findings: FINDING-096
- ASVS sections: 2.1.2

### Priority
Medium

---

## Issue: FINDING-098 - API Models Lack Cross-Field Contextual Validation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Several API argument models accept related fields but perform no cross-field validation at the model level. This forces callers to rely on undocumented downstream logic to catch inconsistent combined inputs. Examples include: `VoteStartArgs` (email_to not validated against project, vote_duration not validated against policy, revision not validated against release) and `DistributionRecordArgs` (distribution_owner_namespace not validated per platform, no relationship validation between fields).

### Details
Affected location: `atr/models/api.py` lines 100-400

Multiple API models accept related fields without validating their relationships:
- `VoteStartArgs`: No validation that email_to domain is appropriate, vote_duration is positive, or revision belongs to release
- `DistributionRecordArgs`: No validation of distribution_owner_namespace requirements based on platform

This forces validation into downstream code, making it unclear what combinations are valid.

### Recommended Remediation
Add Pydantic `@model_validator` decorators to API models to enforce cross-field rules:

```python
@pydantic.model_validator(mode='after')
def validate_vote_args(self) -> 'VoteStartArgs':
    # Validate vote_duration is positive
    if self.vote_duration <= 0:
        raise ValueError("vote_duration must be positive")
    
    # Validate email_to domain
    if '@' not in self.email_to:
        raise ValueError("email_to must be valid email")
    
    return self

@pydantic.model_validator(mode='after')
def validate_distribution_args(self) -> 'DistributionRecordArgs':
    # Validate distribution_owner_namespace based on platform
    if self.platform == 'maven' and not self.distribution_owner_namespace:
        raise ValueError("Maven distributions require owner namespace")
    
    return self
```

Add comprehensive API documentation describing cross-field validation rules.

### Acceptance Criteria
- [ ] API models enforce cross-field validation rules
- [ ] Invalid field combinations are rejected at model level
- [ ] Documentation describes validation rules
- [ ] Test cases verify cross-field validation
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.1.2.md
- Related findings: FINDING-100
- ASVS sections: 2.1.2

### Priority
Medium

---

## Issue: FINDING-099 - Form Hidden Field Validated Against Wrong Source

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `AddProjectForm` validates the `committee_key` field against itself (from a user-controllable hidden field) rather than cross-validating against the URL parameter used for authorization. User authorized for committee 'infra' via URL can modify hidden field to 'security' before submission. Form validator checks project label starts with 'security-' (passes) but handler creates project under 'infra' committee with 'security-' prefix, bypassing naming conventions.

### Details
Affected locations:
- `atr/shared/projects.py` lines 31-73: Form validates against hidden field
- `atr/post/projects.py` lines 27-42: Handler uses URL parameter

The validator checks that the project label matches the committee_key from the hidden field, but the handler uses the committee_key from the URL for actual authorization and project creation. This mismatch allows naming convention bypass.

### Recommended Remediation
Pass the URL parameter into Pydantic validation context or verify consistency in handler before proceeding:

```python
async def add_project(session, committee_key, project_form):
    # Verify hidden field matches URL parameter
    if project_form.committee_key != str(committee_key):
        raise exceptions.BadRequest("Committee key mismatch")
    
    # Proceed with project creation
```

Alternative: Pass committee_key from URL into Pydantic validation context and validate against that instead of the hidden field.

### Acceptance Criteria
- [ ] Hidden field is validated against URL parameter
- [ ] Mismatched committee keys are rejected
- [ ] Test cases verify cross-validation
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.2.3.md
- Related findings: FINDING-101
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-100 - API Distribution Models Missing Platform/Owner-Namespace Validation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Three API distribution models lack cross-field validation for platform/owner-namespace consistency that exists in the corresponding web form. API clients can submit distribution records with inconsistent platform/owner_namespace combinations (e.g., PyPI with namespace, Maven without) that would be rejected in web forms. No validation that `platform` and `owner_namespace` are consistent.

### Details
Affected locations in `atr/models/api.py`:
- Line 110: `DistributionRecordArgs`
- Line 136: `DistributionRecordFromWorkflowArgs`
- Line 261: `PublisherDistributionRecordArgs`

All three models accept platform and owner_namespace fields without validating their relationship. Web forms enforce this validation but API models don't.

### Recommended Remediation
Add the same validation to all three API models using `@pydantic.model_validator` to check platform/owner_namespace consistency:

```python
@pydantic.model_validator(mode='after')
def validate_platform_namespace(self) -> 'DistributionRecordArgs':
    # Maven requires owner_namespace
    if self.platform == 'maven' and not self.distribution_owner_namespace:
        raise ValueError("Maven distributions require owner namespace")
    
    # PyPI doesn't use owner_namespace
    if self.platform == 'pypi' and self.distribution_owner_namespace:
        raise ValueError("PyPI distributions don't use owner namespace")
    
    return self
```

Apply to all three API models: `DistributionRecordArgs`, `DistributionRecordFromWorkflowArgs`, `PublisherDistributionRecordArgs`.

### Acceptance Criteria
- [ ] All three API models enforce platform/namespace validation
- [ ] Invalid combinations are rejected
- [ ] Validation matches web form behavior
- [ ] Test cases verify validation in all models
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.2.3.md
- Related findings: FINDING-098
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-101 - URL Parameter Not Cross-Validated With Form Project Key

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `EditProjectForm` contains a hidden `project_key` field that is not cross-validated against the URL parameter used for authorization and data retrieval. While the handler correctly uses the URL parameter for authorization and data access, the lack of cross-validation creates potential for confusion if form validators or downstream code reference the form's `project_key` field, assuming it matches the authorized context.

### Details
Affected locations:
- `atr/shared/projects.py` lines 75-119: EditProjectForm with hidden project_key
- `atr/post/projects.py` lines 45-65: Handler uses URL parameter

The form contains a hidden project_key field that could be modified by the user, but the handler uses the URL parameter for actual operations. This creates potential for mismatch between the form's project_key and the authorized context.

### Recommended Remediation
Add cross-validation in the form or handler to verify `form.project_key` matches the URL parameter before proceeding:

```python
async def edit_project(session, project_key, project_form):
    # Verify hidden field matches URL parameter
    if project_form.project_key != str(project_key):
        raise exceptions.BadRequest("Project key mismatch")
    
    # Proceed with project update
```

### Acceptance Criteria
- [ ] Hidden project_key is validated against URL parameter
- [ ] Mismatched project keys are rejected
- [ ] Test cases verify cross-validation
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.2.3.md
- Related findings: FINDING-099
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-102 - Vote Duration Not Validated Against Release Policy

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
When initiating a vote, the submitted `vote_duration_choice` is not validated against the project's release policy `min_hours` requirement. An authorized committee participant could initiate a vote with a 1-hour duration even if the project policy requires a minimum of 72 hours, bypassing ASF voting policy requirements and potentially invalidating the vote.

### Details
Affected locations:
- `atr/storage/writers/vote.py` lines 89-135: Vote creation without policy validation
- `atr/shared/voting.py` lines 20-33: Form without policy validation

The vote writer accepts vote_duration_choice without checking it against the release policy's min_hours setting. This allows votes shorter than governance requirements.

### Recommended Remediation
Validate vote duration against release policy before creating vote task. Check that `vote_duration_choice >= policy.min_hours` and raise `storage.AccessError` if below minimum:

```python
async def start(self, release_key, vote_duration_choice, ...):
    release = await self._get_release(release_key)
    policy = await self._get_policy(release.project_key)
    
    # Validate against policy
    if policy.min_hours and vote_duration_choice < policy.min_hours:
        raise storage.AccessError(
            f"Vote duration {vote_duration_choice}h is less than "
            f"policy minimum {policy.min_hours}h"
        )
    
    # Proceed with vote creation
```

### Acceptance Criteria
- [ ] Vote duration is validated against policy minimum
- [ ] Votes shorter than policy minimum are rejected
- [ ] Test cases verify policy enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.2.3.md
- Related findings: FINDING-026, FINDING-090
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-103 - Upload Session Not Validated Against Project/Version Context

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Upload sessions are not scoped to specific project/version combinations, allowing files staged for one project to be finalized into another if the user has access to both. Files staged for one project/version could be finalized into another project/version, potentially mixing release artifacts or contaminating releases with wrong files.

### Details
Affected locations:
- `atr/post/upload.py` line 107: Stage endpoint doesn't store context
- `atr/post/upload.py` line 39: Finalize endpoint doesn't validate context

The upload session token is used across staging and finalization, but there's no validation that the files being finalized were staged for the same project/version combination.

### Recommended Remediation
Store project/version metadata with the upload session and validate in finalise endpoint. Check that session metadata matches the finalization context before proceeding:

```python
# In stage endpoint:
session_metadata = {
    'project_key': project_key,
    'version_key': version_key,
    'session_id': upload_session
}
# Store metadata with session

# In finalise endpoint:
session_metadata = get_session_metadata(upload_session)
if session_metadata['project_key'] != project_key or \
   session_metadata['version_key'] != version_key:
    raise exceptions.BadRequest("Upload session context mismatch")
```

### Acceptance Criteria
- [ ] Upload sessions are scoped to project/version
- [ ] Cross-project finalization is rejected
- [ ] Session metadata is validated during finalization
- [ ] Test cases verify context validation
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.2.3.md
- Related findings: None
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-104 - Vote Minimum Duration Bypass via Falsy min_hours Value

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The vote outcome calculation uses the Python idiom `min_hours or None`, which converts falsy values (including 0) to None. When a project's min_hours policy is set to 0 (a valid setting to disable minimum duration), it's incorrectly treated as 'no policy', allowing votes to pass immediately without the default 72-hour minimum. This subverts policy intent and allows premature vote resolution.

### Details
Affected location: `atr/tabulate.py` lines 77-84

The code uses `policy_min = min_hours or None`, which treats 0 as falsy and converts it to None. This causes:
- min_hours=0 (explicit "no minimum") → None (treated as "no policy")
- Falls back to default 72-hour minimum instead of respecting the explicit 0 setting

### Recommended Remediation
Replace `min_hours or None` with explicit None check: `if policy_min is not None: min_duration_hours = policy_min`. This ensures 0 is treated as a meaningful value (explicit 'no minimum') rather than being conflated with None (no policy):

```python
# Current (incorrect):
policy_min = min_hours or None

# Fixed:
policy_min = min_hours if min_hours is not None else None

# Or more explicitly:
if min_hours is not None:
    min_duration_hours = min_hours
elif min_hours == 0:
    min_duration_hours = 0  # Explicit no minimum
else:
    min_duration_hours = 72  # Default
```

Add explicit handling for min_hours=0 case in duration calculation.

### Acceptance Criteria
- [ ] min_hours=0 is treated as "no minimum" not "no policy"
- [ ] Explicit None check replaces falsy check
- [ ] Test cases verify 0 vs None behavior
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.3.2.md
- Related findings: FINDING-003
- ASVS sections: 2.3.2

### Priority
Medium

---

## Issue: FINDING-105 - No File Size Limit on Web Upload Staging Endpoint

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The web upload staging endpoint accepts files of arbitrary size without validation. Files are streamed directly to disk in 1 MiB chunks with no cumulative size checking, allowing authenticated users to exhaust staging volume storage. The endpoint writes files completely before any size validation occurs.

### Details
Affected location: `atr/post/upload.py` lines 118-155

The staging endpoint:
1. Accepts file uploads via multipart/form-data
2. Streams content to disk in 1 MiB chunks
3. Has no size limit checking during streaming
4. No cumulative size tracking across multiple uploads

Authenticated users can upload arbitrarily large files, exhausting disk space in the staging volume.

### Recommended Remediation
Add `MAX_UPLOAD_SIZE_BYTES` configuration constant. Track cumulative bytes written during file streaming. Raise `exceptions.PayloadTooLarge` when limit exceeded. Delete partially written files on size limit violation:

```python
MAX_UPLOAD_SIZE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB

async def stage(session, upload_session, file):
    total_bytes = 0
    try:
        async for chunk in file:
            total_bytes += len(chunk)
            if total_bytes > MAX_UPLOAD_SIZE_BYTES:
                raise exceptions.PayloadTooLarge(
                    f"Upload exceeds {MAX_UPLOAD_SIZE_BYTES} byte limit"
                )
            # Write chunk
    except exceptions.PayloadTooLarge:
        # Delete partially written file
        staging_path.unlink(missing_ok=True)
        raise
```

Consider implementing per-release or per-user storage quotas.

### Acceptance Criteria
- [ ] Maximum upload size limit is enforced
- [ ] Limit is checked during streaming, not after
- [ ] Partially written files are cleaned up on limit violation
- [ ] Test cases verify size limit enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.3.2.md
- Related findings: None
- ASVS sections: 2.3.2

### Priority
Medium

---

## Issue: FINDING-106 - Project Creation Race Condition Between Existence Check and Insert

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Project creation uses check-then-create pattern with acknowledged race condition (TODO comment in code). Existence check is performed, then project insert. Concurrent requests could attempt to create the same project between the existence check and insert. Database unique constraint prevents duplication but error handling may not be user-friendly.

### Details
Affected locations in `atr/storage/writers/project.py`:
- Lines 132-165: Project creation with check-then-create pattern
- Lines 135-137: Existence check
- Lines 127-160: Insert operation

The TODO comment at line 135 acknowledges: "This is a race condition, but it's unlikely to be hit in practice." However, concurrent project creation attempts could trigger IntegrityError.

### Recommended Remediation
**Option 1 (Recommended):** Catch IntegrityError - Skip existence check, rely on database constraint, catch IntegrityError and convert to user-friendly AccessError:

```python
try:
    # Skip existence check, attempt insert directly
    await self._insert_project(project_data)
except IntegrityError:
    raise storage.AccessError(f"Project {project_key} already exists")
```

**Option 2:** INSERT ON CONFLICT - Use SQLite INSERT ON CONFLICT DO NOTHING with RETURNING clause to atomically check and insert:

```python
result = await conn.execute(
    "INSERT INTO projects (...) VALUES (...) "
    "ON CONFLICT DO NOTHING RETURNING *"
)
if not result:
    raise storage.AccessError(f"Project {project_key} already exists")
```

**Option 3:** Add `begin_immediate()` before existence check to acquire write lock.

### Acceptance Criteria
- [ ] Race condition is eliminated
- [ ] Concurrent creation attempts are handled gracefully
- [ ] User-friendly error message on conflict
- [ ] Test cases verify concurrent creation handling
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.3.3.md, L2:2.3.4.md
- Related findings: FINDING-030
- ASVS sections: 2.3.3, 2.3.4

### Priority
Medium

---

## Issue: FINDING-107 - GET-Based Logout Permits Cross-Origin Session Destruction

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The OAuth endpoint in `src/asfquart/generics.py` accepts GET requests for logout without CSRF protection or origin validation. When a user requests `/auth?logout` via GET, the application executes `asfquart.session.clear()` (state-changing operation) and returns a Clear-Site-Data header instructing the browser to clear all cookies and storage. An attacker can force logout any authenticated user through image tags, link prefetch, hidden iframes, or cross-origin fetch. While SameSite=Strict prevents the session cookie from being sent cross-origin (95%+ browser coverage), the Clear-Site-Data header is still sent, enabling denial-of-service via forced logout.

### Details
Affected locations:
- `src/asfquart/generics.py` line 29: Route accepts GET
- `src/asfquart/generics.py` lines 56-85: Logout logic without method restriction

This violates ASVS 3.5.3's requirement that state-changing operations use POST/PUT/PATCH/DELETE methods. While Sec-Fetch-Site validation is applied to POST requests, GET requests bypass this entirely.

### Recommended Remediation
**Option 1 (Recommended):** Restrict logout to POST only by checking `if quart.request.method != "POST"` and returning 405 status with `Allow: POST` header before executing session.clear():

```python
elif logout_uri or quart.request.query_string == b"logout":
    if quart.request.method != "POST":
        return quart.Response(
            status=405,
            response="Use POST to logout\n",
            content_type="text/plain; charset=utf-8",
            headers={"Allow": "POST"},
        )
    had_session = bool(await asfquart.session.read())
    asfquart.session.clear()
    response = quart.Response(
        status=200,
        response=f"Logged out. Return to <a href='{base_url}'>front page</a>.\n",
        content_type="text/html; charset=utf-8",
    )
    if had_session:
        response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    return response
```

**Option 2:** Add Sec-Fetch-* validation for GET logout requests to block cross-site requests.

**Option 3:** Require CSRF token for GET logout via query parameter validation.

### Acceptance Criteria
- [ ] Logout requires POST method
- [ ] GET logout requests return 405 Method Not Allowed
- [ ] Cross-origin logout attempts are blocked
- [ ] Test cases verify method restriction
- [ ] Unit test verifying the fix

### References
- Source reports: L1:3.5.1.md, L1:3.5.2.md, L1:3.5.3.md
- Related findings: FINDING-217
- ASVS sections: 3.5.1, 3.5.2, 3.5.3

### Priority
Medium

---

## Issue: FINDING-108 - Form Validation Error Messages Rendered as Unescaped HTML

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `flash_error_summary()` function in `atr/form.py` constructs HTML error messages from Pydantic validation errors and wraps them with `markupsafe.Markup()`, which bypasses Jinja2's auto-escaping. When custom validators like `to_enum()` include user input in error messages, this creates a reflected XSS vulnerability. User input flows through validation error messages without HTML escaping before being inserted into HTML via f-strings, then wrapped with Markup() to bypass template auto-escaping.

### Details
Affected locations:
- `atr/form.py` lines 145-155: flash_error_summary() constructs HTML without escaping
- `atr/form.py` to_enum() function: Reflects user input in error messages
- `atr/templates/macros/flash.html`: Renders unescaped content

The function builds HTML error lists using f-strings with unescaped field_label and msg values, then wraps with Markup() to bypass Jinja2 auto-escaping.

### Recommended Remediation
Use `markupsafe.escape()` to escape both `field_label` and `msg` before HTML insertion in `flash_error_summary()`:

```python
import markupsafe

def flash_error_summary(errors):
    parts = ["<ul>"]
    for error in errors:
        safe_label = markupsafe.escape(field_label)
        safe_msg = markupsafe.escape(msg)
        parts.append(f"<li><strong>{safe_label}</strong>: {safe_msg}</li>")
    parts.append("</ul>")
    return markupsafe.Markup("".join(parts))
```

Also audit all custom Pydantic validators for user input reflection in error messages.

### Acceptance Criteria
- [ ] Error messages are HTML-escaped before rendering
- [ ] XSS via validation error messages is prevented
- [ ] Custom validators don't reflect unescaped user input
- [ ] Test cases verify escaping
- [ ] Unit test verifying the fix

### References
- Source reports: L1:3.2.2.md
- Related findings: FINDING-109
- ASVS sections: 3.2.2

### Priority
Medium

---

## Issue: FINDING-109 - Markdown-to-HTML Rendering Without Explicit Sanitization

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
User-uploaded SBOM files contain vulnerability detail fields that are rendered as markdown and converted to HTML in `atr/get/sbom.py`. The resulting HTML is wrapped with `markupsafe.Markup()`, bypassing htpy's auto-escaping. While cmarkgfm's default behavior suppresses raw HTML, this is an implicit dependency without explicit sanitization. Safety depends entirely on cmarkgfm's default behavior, which could change between versions. Adding CMARK_OPT_UNSAFE in the future would immediately create an XSS vulnerability.

### Details
Affected locations:
- `atr/get/sbom.py` lines 180-190: Markdown rendering without sanitization
- `atr/get/sbom.py` _cdx_to_osv() function: Vulnerability details processed

The code uses `cmarkgfm.github_flavored_markdown_to_html()` and wraps the result with `Markup()`, relying on cmarkgfm's implicit HTML suppression without explicit sanitization layer.

### Recommended Remediation
Add explicit HTML sanitization using nh3 or bleach after cmarkgfm markdown rendering:

```python
import nh3

ALLOWED_TAGS = {"p", "strong", "em", "a", "code", "pre", "ul", "ol", "li", 
                "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "br", "hr",
                "table", "thead", "tbody", "tr", "th", "td", "img", "div", "span"}
ALLOWED_ATTRIBUTES = {
    "a": {"href", "title"},
    "img": {"src", "alt", "title"}
}

raw_html = cmarkgfm.github_flavored_markdown_to_html(vuln.details)
sanitized = nh3.clean(raw_html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)
details = markupsafe.Markup(sanitized)
```

### Acceptance Criteria
- [ ] Explicit HTML sanitization is added after markdown rendering
- [ ] Dangerous HTML tags/attributes are removed
- [ ] Safety doesn't depend on implicit library behavior
- [ ] Test cases verify sanitization
- [ ] Unit test verifying the fix

### References
- Source reports: L1:3.2.2.md
- Related findings: FINDING-108
- ASVS sections: 3.2.2

### Priority
Medium

---

## Issue: FINDING-110 - Missing Global Security Headers on Development Vhost (tooling-vm-ec2-de.apache.org)

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The tooling-vm-ec2-de.apache.org virtual host is an internet-facing server with force_tls: true but lacks global security headers that are present on the release-test.apache.org vhost. Missing headers include: Strict-Transport-Security (HSTS), X-Content-Type-Options, X-Frame-Options, and Referrer-Policy. This creates an inconsistent security posture between development and production environments. Without HSTS, the first HTTP request to the development server is vulnerable to SSL stripping attacks. Without X-Content-Type-Options, MIME-sniffing attacks are possible. Without Referrer-Policy, path information and the internal hostname leak to third parties.

### Details
Affected location: `tooling-vm-ec2-de.apache.org.yaml` lines 120-175

The development vhost configuration has `force_tls: true` but no security headers block, unlike the production vhost which includes comprehensive security headers.

### Recommended Remediation
Add the same security headers block to the tooling-vm-ec2-de.apache.org vhost that exists in release-test.apache.org:

```yaml
tooling-vm-ec2-de.apache.org:
    force_tls: true
    config: |
        # Security Headers (match release-test.apache.org)
        Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-Frame-Options "DENY"
        Header always set Referrer-Policy "same-origin"
```

### Acceptance Criteria
- [ ] Security headers are present on development vhost
- [ ] Headers match production vhost configuration
- [ ] HSTS is enforced on first request
- [ ] Test cases verify header presence
- [ ] Unit test verifying the fix

### References
- Source reports: L1:3.4.1.md, L2:3.4.4.md, L2:3.4.5.md
- Related findings: FINDING-111, FINDING-112, FINDING-216
- ASVS sections: 3.4.1, 3.4.4, 3.4.5

### Priority
Medium

---

## Issue: FINDING-111 - Application Does Not Set Security Headers (HSTS, X-Content-Type-Options, Referrer-Policy)

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The application's `add_security_headers()` after_request handler sets CSP, Permissions-Policy, and X-Permitted-Cross-Domain-Policies directly on responses, but delegates HSTS, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy entirely to the frontend Apache httpd proxy. While the proxy correctly sets these headers for the staging vhost, setting them at the application level as well would provide defense-in-depth against proxy misconfiguration. Impact is minimal given current architecture as backend containers bind to 127.0.0.1 only, external clients cannot bypass the proxy, and the delegation is intentionally documented with audit_guidance comments.

### Details
Affected locations:
- `atr/server.py` lines 445-455: add_security_headers() sets some headers
- `atr/server.py` lines 318-326: Audit guidance comments document delegation

The application sets some security headers but relies on the proxy for others. This creates a gap if the proxy is misconfigured.

### Recommended Remediation
Add the delegated headers directly in the application as well:

```python
@app.after_request
async def add_security_headers(response: quart.Response) -> quart.Response:
    response.headers["Content-Security-Policy"] = csp_header
    response.headers["Permissions-Policy"] = permissions_policy
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    # Add defense-in-depth headers (proxy will override with 'Header always set')
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response
```

Note: The proxy's `Header always set` directive will override the application-level header, so there is no conflict. The application-level header acts as a safety net.

### Acceptance Criteria
- [ ] Application sets all security headers directly
- [ ] Headers provide defense-in-depth against proxy misconfiguration
- [ ] No conflicts with proxy-level headers
- [ ] Test cases verify header presence
- [ ] Unit test verifying the fix

### References
- Source reports: L1:3.4.1.md, L2:3.4.4.md, L2:3.4.5.md
- Related findings: FINDING-110
- ASVS sections: 3.4.1, 3.4.4, 3.4.5

### Priority
Medium

---

## Issue: FINDING-112 - Missing CSP frame-ancestors for Non-Proxied /downloads/ Paths

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The /downloads/ paths on both release-test.apache.org and tooling-vm-ec2-de.apache.org are configured with `ProxyPass !`, meaning they bypass the application entirely and are served directly by Apache. These paths have a Content-Security-Policy header set to 'sandbox' only, without the required 'frame-ancestors' directive. This creates a gap in ASVS 3.4.6 compliance, as these responses rely solely on the obsolete X-Frame-Options: DENY header for framing protection. The 'sandbox' CSP directive restricts page capabilities but does NOT prevent the page from being embedded in a frame.

### Details
Affected locations:
- `tooling-vm-ec2-de.apache.org.yaml` lines 85-93: Downloads directory CSP
- `tooling-vm-ec2-de.apache.org.yaml` lines 149-157: Downloads directory CSP

The application's `_app_setup_security_headers` after_request handler never executes for these paths because they bypass the application with `ProxyPass !`.

### Recommended Remediation
Add 'frame-ancestors 'none'' to the CSP for the downloads directories:

```apache
Header always set Content-Security-Policy "sandbox; frame-ancestors 'none'"
```

Apply the same fix to both the release-test.apache.org and tooling-vm-ec2-de.apache.org /downloads/ Directory blocks. Keep X-Frame-Options for defense-in-depth but do not rely upon it.

### Acceptance Criteria
- [ ] CSP includes frame-ancestors directive for /downloads/ paths
- [ ] Framing is prevented via CSP, not just X-Frame-Options
- [ ] Both vhosts have consistent CSP
- [ ] Test cases verify frame-ancestors enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L2:3.4.6.md
- Related findings: FINDING-216
- ASVS sections: 3.4.6

### Priority
Medium

---

## Issue: FINDING-113 - API Blueprint Lacks Explicit CORS Preflight Enforcement for Session-Authenticated Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The API blueprint explicitly exempts all endpoints from CSRF validation. For the 8 API endpoints that use session cookie authentication (via `common.authenticate()`) rather than JWT Bearer tokens, the only explicit cross-origin protection is SameSite=Strict. While this is currently effective, the application also has an implicit Content-Type enforcement through `quart_schema.validate_request` → `get_json()`, which rejects non-application/json requests. However, this is a side-effect of the validation library, not an explicit security control documented or designed as a security mechanism. If quart_schema or Quart is updated to use `get_json(force=True)` or a more permissive parser, this protection would silently disappear without any security test failure or code review flag.

### Details
Affected locations:
- `atr/blueprints/api.py` lines 145-148: CSRF exemption
- `atr/blueprints/api.py` lines 157-159: before_request hook
- `atr/blueprints/common.py` lines 228-233: authenticate() function
- `atr/api/__init__.py`: Session-authenticated endpoints

The implicit Content-Type enforcement is not documented as a security control and could disappear with library updates.

### Recommended Remediation
**Option 1: Explicit Content-Type Enforcement (Recommended)**

```python
@_BLUEPRINT.before_request
@rate_limiter.rate_limit(500, datetime.timedelta(hours=1))
async def _api_rate_limit() -> None:
    """Set API-wide rate limit and enforce CORS preflight for POST requests."""
    if quart.request.method in ("POST", "PUT", "PATCH", "DELETE"):
        content_type = (quart.request.content_type or "").split(";")[0].strip()
        if content_type not in ("application/json", ""):
            return quart.jsonify({"error": "Content-Type must be application/json"}), 415
```

**Option 2:** Require X-Requested-With header for session-authenticated requests

**Option 3:** Validate request origin for state-changing operations

### Acceptance Criteria
- [ ] Explicit Content-Type enforcement for API requests
- [ ] Non-JSON requests are rejected with 415 status
- [ ] Protection doesn't depend on implicit library behavior
- [ ] Test cases verify Content-Type enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L1:3.5.2.md
- Related findings: None
- ASVS sections: 3.5.2

### Priority
Medium

---

## Issue: FINDING-114 - Open Redirect via Backslash Normalization in OAuth Redirect URI Validation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The OAuth redirect URI validation in the login and logout flows rejects URIs that don't start with '/' or that start with '//', but does not account for the WHATWG URL Standard backslash normalization. Per the spec (§4.4 'relative slash' state), when a URL parser encounters '\' after an initial '/' in a special URL scheme (http/https), it treats '\' identically to '/'. Thus '\' acts as a path separator, and '/\evil.com' is parsed as '//evil.com', a protocol-relative URL pointing to evil.com. The validation passes '/\evil.com' because it starts with '/' and doesn't start with '//', but browsers normalize this to '//evil.com', causing an open redirect.

### Details
Affected locations:
- `src/asfquart/generics.py` lines 48-53: Login redirect validation
- `src/asfquart/generics.py` lines 69-75: Login redirect usage
- `src/asfquart/generics.py` lines 113-119: Logout redirect validation
- `src/asfquart/generics.py` lines 164-172: Logout redirect usage
- `tests/generics.py` lines 53-58: Tests don't cover backslash case

Impact includes post-authentication phishing where users complete OAuth login and are then redirected to an attacker's site mimicking the application.

### Recommended Remediation
Add backslash normalization check to redirect URI validation. Create a helper function `_is_safe_redirect`:

```python
def _is_safe_redirect(uri: str) -> bool:
    """Validate redirect URI is safe (relative, same-origin only)."""
    if not uri.startswith("/"):
        return False
    if uri.startswith("//"):
        return False
    # Block backslash and URL-encoded backslash
    if "\\" in uri or "%5c" in uri.lower() or "%5C" in uri:
        return False
    # Verify no netloc present after parsing
    parsed = urllib.parse.urlsplit(uri)
    if parsed.netloc:
        return False
    return True
```

Add test cases in `tests/generics.py` to verify rejection of '/%5Cevil.com' and '/\evil.com' for both login and logout flows.

### Acceptance Criteria
- [ ] Backslash-based open redirects are blocked
- [ ] URL-encoded backslashes are blocked
- [ ] Test cases verify backslash rejection
- [ ] Both login and logout flows are protected
- [ ] Unit test verifying the fix

### References
- Source reports: L2:3.5.4.md
- Related findings: None
- ASVS sections: 3.5.4

### Priority
Medium

---

## Issue: FINDING-115 - No Evidence of postMessage Origin Validation in Application

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
No frontend JavaScript code was provided for audit. The postMessage API is a client-side browser API that must be validated in JavaScript code. The provided files are exclusively server-side Python (Quart/Flask framework). The template_folder parameter confirms HTML templates exist but were not provided for review. These templates and any associated JavaScript files are where postMessage handlers would reside. If the application uses postMessage without origin validation, an attacker could send crafted messages from a malicious page to manipulate application state, exfiltrate sensitive data, bypass authentication/authorization flows, or execute XSS-equivalent attacks.

### Details
Affected locations (templates not provided in audit):
- `atr/blueprints/admin.py` line 27: template_folder parameter
- `src/asfquart/generics.py`: OAuth templates
- `atr/blueprints/api.py`: API templates
- `atr/api/__init__.py`: API endpoint templates

The audit cannot verify postMessage security without access to frontend JavaScript code.

### Recommended Remediation
The frontend JavaScript codebase must be audited. Any postMessage listener should follow this pattern:

1. Validate origin against explicit allowlist (event.origin check)
2. Validate message syntax (try/catch parsing)
3. Validate expected structure/schema (type/structure checks)
4. Discard untrusted messages (early return)
5. Never use wildcard origins in postMessage() calls

```javascript
window.addEventListener('message', function(event) {
    const TRUSTED_ORIGINS = ['https://your-app.apache.org'];
    if (!TRUSTED_ORIGINS.includes(event.origin)) {
        console.warn('Rejected postMessage from untrusted origin:', event.origin);
        return;
    }
    
    let data;
    try {
        data = JSON.parse(event.data);
    } catch (e) {
        console.error('Invalid postMessage syntax');
        return;
    }
    
    // Validate expected structure
    if (typeof data.action !== 'string' || !isValidAction(data.action)) {
        return;
    }
    
    handleTrustedMessage(data);
});
```

### Acceptance Criteria
- [ ] Frontend JavaScript code is audited for postMessage usage
- [ ] All postMessage listeners validate origin
- [ ] Message structure is validated before processing
- [ ] Wildcard origins are not used
- [ ] Test cases verify origin validation

### References
- Source reports: L2:3.5.5.md
- Related findings: None
- ASVS sections: 3.5.5

### Priority
Medium

---

## Issue: FINDING-116 - No Application-Level HTTPS Enforcement for API Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The application runs behind a reverse proxy (`ProxyFixMiddleware` at line 93-94 of server.py), but has no application-level code to reject or differentiate HTTP requests arriving at API endpoints (/api/*). All HTTP→HTTPS redirect behavior is delegated entirely to the frontend proxy. If the proxy applies a blanket HTTP→HTTPS redirect to all paths (a common default configuration), API clients that erroneously send credentials, JWTs, or sensitive data over HTTP would be silently redirected to HTTPS, masking the data leakage. This violates the core principle of ASVS 4.1.2: API endpoints should fail loudly on HTTP to alert developers of misconfiguration, not silently redirect.

### Details
Affected locations:
- `atr/server.py` lines 91-94: ProxyFixMiddleware configuration
- `atr/blueprints/api.py` lines 124-128: API blueprint
- `atr/server.py` lines 491-502: Server startup

Impact: API clients sending sensitive data (PATs, JWTs, SSH keys, OpenPGP keys) over HTTP would have their credentials exposed in plaintext. A transparent redirect masks this, giving false confidence that the communication was secure.

Affected endpoints include:
- POST /api/jwt/create (sends PAT credentials)
- POST /api/key/add (sends OpenPGP key material)
- POST /api/release/upload (sends release artifacts)
- POST /api/ssh-key/add (sends SSH key material)
- POST /api/distribute/ssh/register (sends SSH key + JWT)

### Recommended Remediation
Add an API-specific before_request hook that rejects non-HTTPS requests:

```python
# atr/blueprints/api.py

@_BLUEPRINT.before_request
async def _enforce_https() -> quart.Response | None:
    """Reject API requests that arrive over plaintext HTTP (ASVS 4.1.2).
    
    User-facing endpoints may redirect HTTP→HTTPS at the proxy level,
    but API endpoints must not silently redirect — they should fail loudly
    so that misconfigured clients are made aware of data leakage.
    """
    if not quart.request.is_secure:
        return quart.jsonify({
            "error": "HTTPS required",
            "detail": "API requests must use HTTPS. Do not rely on HTTP-to-HTTPS redirects.",
        }), 421  # 421 Misdirected Request
```

### Acceptance Criteria
- [ ] API endpoints reject HTTP requests with 421 status
- [ ] HTTPS enforcement is explicit, not proxy-dependent
- [ ] Error message guides developers to fix client configuration
- [ ] Test cases verify HTTP rejection
- [ ] Unit test verifying the fix

### References
- Source reports: L2:4.1.2.md
- Related findings: FINDING-228
- ASVS sections: 4.1.2

### Priority
Medium

---

## Issue: FINDING-117 - Dev Vhost Does Not Sanitize Client-Supplied X-Forwarded-For

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The development vhost uses `RequestHeader add X-Forwarded-For "%{REMOTE_ADDR}s"` which appends a new value without removing client-supplied `X-Forwarded-For` headers. This allows end-users to inject arbitrary IP addresses into the header chain. If `is_dev_environment()` detection changes or if this config is copied to production, the first `X-Forwarded-For` value (attacker-controlled) may influence `remote_addr`, making IP-based rate limiting bypassable for unauthenticated users and causing audit logs to record spoofed IPs.

### Details
Affected locations:
- `tooling-vm-ec2-de.apache.org.yaml` lines 176-178: RequestHeader add (appends)
- `atr/server.py` line 210: ProxyFixMiddleware configuration
- `atr/server.py` lines 384-392: remote_addr usage

The configuration appends to X-Forwarded-For instead of replacing it, allowing client-supplied values to persist.

POC: `curl -k -H "X-Forwarded-For: 10.0.0.1" https://tooling-vm-ec2-de.apache.org/`

### Recommended Remediation
In the tooling-vm-ec2-de.apache.org.yaml dev vhost section, replace `RequestHeader add X-Forwarded-For "%{REMOTE_ADDR}s"` with `RequestHeader unset X-Forwarded-For`. ProxyAddHeaders On (default) will add the correct X-Forwarded-For value:

```yaml
# Instead of:
RequestHeader add X-Forwarded-For "%{REMOTE_ADDR}s"

# Use:
RequestHeader unset X-Forwarded-For
# ProxyAddHeaders On (default) will set correct value
```

### Acceptance Criteria
- [ ] Client-supplied X-Forwarded-For headers are removed
- [ ] Only proxy-set X-Forwarded-For values are trusted
- [ ] IP spoofing via X-Forwarded-For is prevented
- [ ] Test cases verify header sanitization
- [ ] Unit test verifying the fix

### References
- Source reports: L2:4.1.3.md
- Related findings: FINDING-229
- ASVS sections: 4.1.3

### Priority
Medium

---

## Issue: FINDING-118 - No WebSocket Authentication Framework Exists

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The application framework (Quart) natively supports WebSocket endpoints via `@app.websocket()` decorators. However, none of the authentication controls in the codebase are designed to protect WebSocket channels. The `jwtoken.require` decorator and `asfquart.session.read()` function both depend on `quart.request`, which is only available in HTTP request contexts — not WebSocket contexts (where `quart.websocket` is the relevant object). If a developer adds a WebSocket endpoint, there is no reusable security control they could apply, creating a high risk of unauthenticated WebSocket access.

### Details
Affected locations:
- `atr/jwtoken.py` lines 84-101: JWT decorator depends on quart.request
- `atr/jwtoken.py` lines 196-203: JWT verification uses quart.request
- `src/asfquart/session.py` lines 32-87: Session read uses quart.request

None of these authentication mechanisms work in WebSocket contexts where `quart.websocket` is used instead of `quart.request`.

### Recommended Remediation
Create a WebSocket-specific authentication decorator that validates the session during the HTTPS→WebSocket transition:

1. Validate token from query parameter set during HTTPS session, or validate from cookie shared during WS handshake
2. Close connection with code 1008 if authentication fails
3. Validate Origin header to prevent cross-origin WS hijacking
4. Store validated claims in quart.g for use in the handler

Additionally, implement a dedicated WS token issuance endpoint at /api/ws-token that issues short-lived (60s TTL), WS-audience-specific JWTs through authenticated HTTPS endpoints only:

```python
@app.websocket('/ws/endpoint')
async def ws_endpoint():
    # Validate authentication during handshake
    token = quart.websocket.args.get('token')
    if not token or not validate_ws_token(token):
        await quart.websocket.close(1008, "Authentication required")
        return
    
    # Validate Origin header
    origin = quart.websocket.headers.get('Origin')
    if origin not in ALLOWED_ORIGINS:
        await quart.websocket.close(1008, "Invalid origin")
        return
    
    # Store claims in context
    quart.g.ws_claims = decode_ws_token(token)
    
    # Proceed with WebSocket logic
```

### Acceptance Criteria
- [ ] WebSocket authentication framework exists
- [ ] Authentication is validated during WS handshake
- [ ] Origin validation prevents cross-origin WS hijacking
- [ ] Short-lived WS tokens are issued via authenticated endpoint
- [ ] Test cases verify WS authentication
- [ ] Unit test verifying the fix

### References
- Source reports: L2:4.4.4.md
- Related findings: FINDING-230, FINDING-231
- ASVS sections: 4.4.4

### Priority
Medium

---

## Issue: FINDING-119 - Upload Staging Token Lacks Session Management Properties

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `upload_session` parameter functions as a dedicated token for the multi-step upload process. However, this token does not comply with ASVS session management requirements for dedicated tokens used outside standard session management. The token is typed as `unsafe.UnsafeStr` with no guarantee of cryptographic randomness, no user binding verification, no expiration mechanism, no revocation capability, and no scope limitation to specific projects/versions.

### Details
Affected locations:
- `atr/post/upload.py` line 126: stage endpoint accepts upload_session
- `atr/post/upload.py` line 44: finalise endpoint uses upload_session

The token is used to correlate staging and finalization operations but lacks proper session management properties:
- No cryptographic randomness guarantee
- No user binding
- No expiration (sessions persist indefinitely)
- No revocation mechanism
- No scope limitation

### Recommended Remediation
Implement proper session management for upload tokens:

1. Generate tokens server-side using `secrets.token_urlsafe(32)` for 256 bits of entropy
2. Store session metadata in database/cache including:
   - session_id
   - user_id
   - project_key
   - version_key
   - created_at
   - expires_at (24-hour TTL recommended)
3. Validate all session properties in both stage and finalise endpoints:
   - User binding
   - Scope limitation
   - Expiration
4. Implement cleanup task to remove expired sessions and staging directories
5. Provide revocation API for users to invalidate sessions before expiration

```python
# Generate session
upload_session = secrets.token_urlsafe(32)
await store_session_metadata(
    session_id=upload_session,
    user_id=session.uid,
    project_key=project_key,
    version_key=version_key,
    created_at=datetime.utcnow(),
    expires_at=datetime.utcnow() + timedelta(hours=24)
)

# Validate session
session_data = await get_session_metadata(upload_session)
if not session_data or session_data.expires_at < datetime.utcnow():
    raise exceptions.Unauthorized("Invalid or expired upload session")
if session_data.user_id != session.uid:
    raise exceptions.Unauthorized("Upload session belongs to different user")
```

### Acceptance Criteria
- [ ] Upload tokens use cryptographic randomness
- [ ] Session metadata is stored and validated
- [ ] Expired sessions are cleaned up automatically
- [ ] User binding is enforced
- [ ] Scope limitation is enforced
- [ ] Test cases verify session management
- [ ] Unit test verifying the fix

### References
- Source reports: L2:4.4.3.md
- Related findings: FINDING-031
- ASVS sections: 4.4.3

### Priority
Medium

---

## Issue: FINDING-120 - No Cleanup or Aggregate Limit for Upload Staging Directories

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The upload staging mechanism accepts files in multiple stages before finalization. While individual stage requests are bounded by MAX_CONTENT_LENGTH (512 MB), there are no controls on: 1) Aggregate size - total size of all files within a staging directory, 2) File count - number of files per staging session, 3) Cleanup mechanism - abandoned staging directories persist indefinitely, 4) Session lifetime - no expiration for staging sessions. Staging directories are only cleaned during `finalise()` - if this is never called, files remain permanently. This allows authenticated users to stage many files without finalizing, accumulating disk space over time.

### Details
Affected location: `atr/post/upload.py` lines 137-155

Missing controls:
- No aggregate size limit across all staged files
- No file count limit per session
- No cleanup of abandoned staging directories
- No session expiration

### Recommended Remediation
Implement three controls:

**(1) Add aggregate staging limits** - Check current staging directory size and file count before accepting new files:

```python
MAX_STAGING_SIZE = 2 * 1024 * 1024 * 1024  # 2GB
MAX_STAGING_FILES = 50

current_size = sum(f.stat().st_size for f in staging_dir.iterdir())
current_count = len(list(staging_dir.iterdir()))

if current_size + file_size > MAX_STAGING_SIZE:
    raise exceptions.PayloadTooLarge("Staging directory size limit exceeded")
if current_count >= MAX_STAGING_FILES:
    raise exceptions.PayloadTooLarge("Staging file count limit exceeded")
```

**(2) Create periodic cleanup task** - Implement `cleanup_stale_staging()` function in new `atr/tasks/cleanup.py` to remove staging directories older than 24 hours. Run every 6 hours via scheduler.

**(3) Add configuration** - Externalize limits to `atr/config.py` as MAX_STAGING_SIZE, MAX_STAGING_FILES, and STAGING_MAX_AGE_SECONDS.

**(4) Add monitoring** - Create `get_staging_metrics()` to track total staging directories, size, and oldest staging age for operational visibility.

### Acceptance Criteria
- [ ] Aggregate staging size is limited per session
- [ ] File count is limited per session
- [ ] Stale staging directories are cleaned up automatically
- [ ] Limits are configurable
- [ ] Monitoring metrics are available
- [ ] Test cases verify limits
- [ ] Unit test verifying the fix

### References
- Source reports: L1:5.2.1.md
- Related findings: None
- ASVS sections: 5.2.1

### Priority
Medium

---

## Issue: FINDING-121 - In-Memory Hash Function Could Process Unbounded Data

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `compute_sha3_256()` function in `atr/hashes.py` accepts a bytes object and processes it entirely in memory, unlike the five other hash functions that use chunked file I/O. If this function is called with user-uploaded file data (up to 512MB per MAX_CONTENT_LENGTH), it could consume significant memory. Five of six hash functions use chunked processing with _HASH_CHUNK_SIZE (4MB), but this function loads the entire data into memory at once. Impact depends on actual call sites which were not verified in audit scope.

### Details
Affected location: `atr/hashes.py` line 51

The function signature is:
```python
def compute_sha3_256(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()
```

This loads the entire `data` bytes object into memory, unlike other hash functions that read files in chunks.

### Recommended Remediation
Four-step remediation:

**(1) Audit call sites** - Search codebase for all invocations of `compute_sha3_256()` to determine if it's called with user-uploaded data.

**(2) Add size guard** - Implement MAX_IN_MEMORY_SIZE check (10MB) in the function:

```python
MAX_IN_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB

def compute_sha3_256(data: bytes) -> str:
    if len(data) > MAX_IN_MEMORY_SIZE:
        raise ValueError(
            f"Data size {len(data)} exceeds MAX_IN_MEMORY_SIZE {MAX_IN_MEMORY_SIZE}. "
            "Use compute_sha3_256_file() for large data."
        )
    return hashlib.sha3_256(data).hexdigest()
```

**(3) Provide streaming alternative** - Create `compute_sha3_256_file()` that uses chunked reads with _HASH_CHUNK_SIZE (4MB) for memory-safe processing of large files.

**(4) Update call sites** - If any call sites use user-uploaded data, migrate to the streaming version.

### Acceptance Criteria
- [ ] Call sites are audited for user data usage
- [ ] Size guard prevents unbounded memory consumption
- [ ] Streaming alternative exists for large files
- [ ] Call sites using large data are migrated
- [ ] Test cases verify size guard
- [ ] Unit test verifying the fix

### References
- Source reports: L1:5.2.1.md
- Related findings: None
- ASVS sections: 5.2.1

### Priority
Medium

---

## Issue: FINDING-122 - Disallowed File Detection Occurs After Storage, Not At Upload Time

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The DISALLOWED_FILENAMES check runs as a background task after files are already stored in the revision directory. This creates a window where dangerous files (such as .htaccess, .htpasswd, or private keys) exist in storage before being flagged, with no automatic remediation mechanism. The data flow is: User uploads file → stored in staging → finalized into revision → file exists in unfinished/project/version/revision/ directory → LATER background task reports the issue → no automatic remediation occurs.

### Details
Affected locations:
- `atr/tasks/checks/paths.py` lines 181-195: Background check for disallowed filenames
- `atr/post/upload.py`: Upload staging without filename validation
- `atr/analysis.py` lines 57-69: Disallowed filename patterns

The check happens asynchronously after files are already written to disk, creating a window where dangerous files exist in storage.

### Recommended Remediation
Add upload-time blocking in the staging flow:

**(1)** Create `_validate_upload_filename()` function that checks against DISALLOWED_FILENAMES and DISALLOWED_SUFFIXES before saving uploaded files:

```python
def _validate_upload_filename(filename: str) -> None:
    """Validate filename against disallowed patterns before upload."""
    from atr.analysis import DISALLOWED_FILENAMES, DISALLOWED_SUFFIXES
    
    if filename in DISALLOWED_FILENAMES:
        raise exceptions.BadRequest(f"Filename '{filename}' is not allowed")
    
    for suffix in DISALLOWED_SUFFIXES:
        if filename.endswith(suffix):
            raise exceptions.BadRequest(f"File extension '{suffix}' is not allowed")
```

**(2)** Add validation in `atr/storage/writers/revision.py` during `create_revision_with_quarantine()` as defense-in-depth to reject disallowed filenames and extensions before writing files.

### Acceptance Criteria
- [ ] Disallowed filenames are rejected at upload time
- [ ] Files never reach storage if filename is disallowed
- [ ] Defense-in-depth check exists in revision creation
- [ ] Test cases verify upload-time rejection
- [ ] Unit test verifying the fix

### References
- Source reports: L1:5.3.1.md
- Related findings: FINDING-235, FINDING-236
- ASVS sections: 5.3.1

### Priority
Medium

---

## Issue: FINDING-123 - Pre-Extraction Safety Checks Do Not Verify Total Uncompressed Size

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `check_archive_safety()` function runs BEFORE extraction and iterates every archive member with access to member.size attribute, but does not accumulate or validate total uncompressed size against MAX_EXTRACT_SIZE. Total size enforcement is deferred to the extraction phase via exarch SecurityConfig or streaming checks in archives.py. For ZIP files, `zipfile.ZipFile.infolist()` returns all member metadata from the central directory without decompressing any content, making pre-extraction size validation trivially achievable. An attacker could upload a ZIP with 50,000 files of 40 KB each (~2 GB total) that passes safety checks and begins extraction, consuming significant disk I/O and temporary storage before limits are enforced during extraction.

### Details
Affected locations:
- `atr/detection.py` lines 62-75: check_archive_safety() iterates members
- `atr/tasks/quarantine.py` lines 250-265: Calls check_archive_safety()

The function iterates all archive members and accesses member.size but never accumulates total size or validates against MAX_EXTRACT_SIZE.

### Recommended Remediation
Add total uncompressed size validation to `check_archive_safety()` by accumulating member.size during iteration and checking against `config.get().MAX_EXTRACT_SIZE`:

```python
def check_archive_safety(archive_path: Path, max_extract_size: int) -> list[str]:
    """Check archive for safety issues before extraction."""
    errors = []
    total_size = 0
    
    # ... existing iteration code ...
    for member in archive.infolist():
        total_size += member.size
        
        # Check against limit
        if total_size > max_extract_size:
            errors.append(
                f"Total uncompressed size {total_size} exceeds "
                f"MAX_EXTRACT_SIZE {max_extract_size}"
            )
            break  # Stop iteration, already over limit
        
        # ... existing per-member checks ...
    
    return errors
```

This prevents extraction from starting when size limits would be violated.

### Acceptance Criteria
- [ ] Total uncompressed size is validated before extraction starts
- [ ] Archives exceeding size limit are rejected before extraction
- [ ] Validation happens in pre-extraction safety check
- [ ] Test cases verify size limit enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L2:5.2.3.md
- Related findings: FINDING-242
- ASVS sections: 5.2.3

### Priority
Medium

---

## Issue: FINDING-124 - Web Blueprints Lack Blueprint-Level Rate Limiting for LDAP Authentication

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The API blueprint implements blueprint-wide rate limiting via a before_request handler, but the GET, POST, and admin blueprints lack equivalent protection. This is critical because these blueprints support LDAP Basic authentication via the Authorization header, creating an unthrottled credential stuffing vector. LDAP credential brute force via web routes bypasses API rate limiting. Attacker can attempt unlimited password guesses against LDAP accounts (limited only by unverified global rate limit).

### Details
Affected locations:
- `atr/blueprints/get.py`: No blueprint-level rate limiting
- `atr/blueprints/post.py`: No blueprint-level rate limiting
- `atr/blueprints/admin.py`: No blueprint-level rate limiting
- `src/asfquart/session.py` lines 76-85: LDAP authentication without rate limiting

The API blueprint has rate limiting (500 req/hr) but web blueprints that support LDAP authentication do not.

### Recommended Remediation
Add blueprint-level rate limiting to all web blueprints:

```python
# GET blueprint
@_BLUEPRINT.before_request
@rate_limiter.rate_limit(100, datetime.timedelta(minutes=1))
async def _get_rate_limit():
    pass

# POST blueprint
@_BLUEPRINT.before_request
@rate_limiter.rate_limit(100, datetime.timedelta(minutes=1))
async def _post_rate_limit():
    pass

# Admin blueprint
@_BLUEPRINT.before_request
@rate_limiter.rate_limit(30, datetime.timedelta(minutes=1))
async def _admin_rate_limit():
    pass
```

**Alternative:** Explicitly disable LDAP Basic auth in ATR's configuration with `asfquart.ldap.LDAP_SUPPORTED = False`.

### Acceptance Criteria
- [ ] Web blueprints have rate limiting
- [ ] LDAP authentication is rate limited
- [ ] Rate limits are appropriate for each blueprint
- [ ] Test cases verify rate limiting
- [ ] Unit test verifying the fix

### References
- Source reports: L1:6.3.1.md
- Related findings: FINDING-125
- ASVS sections: 6.3.1

### Priority
Medium

---

## Issue: FINDING-125 - LDAP Authentication Has No Application-Level Failed Attempt Tracking

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The LDAP authentication implementation catches authentication failures but does not track them at the application level. The application relies entirely on LDAP server-side controls for brute force protection, with no application-level visibility into failed authentication patterns or ability to implement application-specific lockout policies. Missing controls include: no application-level counter for failed LDAP authentication attempts, no ability to implement application-specific lockout policies, no correlation of failed attempts across different authentication mechanisms (LDAP vs JWT vs SSH), complete reliance on LDAP server-side controls (which may not be configured), and no application-level visibility into failed authentication patterns.

### Details
Affected locations:
- `src/asfquart/ldap.py`: LDAP authentication without attempt tracking
- `src/asfquart/session.py` lines 76-85: Authentication failure handling
- `atr/log.py`: Logging without attempt tracking

The application catches `AuthenticationError` but doesn't track failed attempts per username.

### Recommended Remediation
Add application-level failed attempt tracking to LDAPClient class:

```python
class LDAPClient:
    _MAX_ATTEMPTS = 5
    _LOCKOUT_SECONDS = 900  # 15 minutes
    _failed_attempts: dict[str, list[float]] = {}
    
    def _check_lockout(self, username: str) -> None:
        """Check if user is locked out due to failed attempts."""
        now = time.time()
        attempts = self._failed_attempts.get(username, [])
        
        # Remove old attempts outside lockout window
        recent_attempts = [t for t in attempts if now - t < self._LOCKOUT_SECONDS]
        
        if len(recent_attempts) >= self._MAX_ATTEMPTS:
            raise AuthenticationError(
                f"Account temporarily locked due to {self._MAX_ATTEMPTS} "
                f"failed attempts. Try again in {self._LOCKOUT_SECONDS}s."
            )
        
        self._failed_attempts[username] = recent_attempts
    
    def _record_failure(self, username: str) -> None:
        """Record failed authentication attempt."""
        now = time.time()
        self._failed_attempts.setdefault(username, []).append(now)
    
    async def authenticate(self, username: str, password: str):
        self._check_lockout(username)
        try:
            # Attempt LDAP bind
            await self._bind(username, password)
        except AuthenticationError:
            self._record_failure(username)
            raise
```

### Acceptance Criteria
- [ ] Failed LDAP attempts are tracked at application level
- [ ] Application-level lockout is enforced
- [ ] Lockout threshold and duration are configurable
- [ ] Test cases verify lockout behavior
- [ ] Unit test verifying the fix

### References
- Source reports: L1:6.3.1.md
- Related findings: FINDING-124, FINDING-243
- ASVS sections: 6.3.1

### Priority
Medium

---

## Issue: FINDING-126 - SSH Authentication Pathway Lacks Rate Limiting

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The SSH authentication pathway does not implement rate limiting that is enforced on Web OAuth (100 req/min) and JWT API (500 req/hr) pathways. While workflow SSH keys are high-entropy and short-lived, the lack of rate limiting allows unlimited connection attempts. An attacker can perform unlimited SSH authentication attempts, consuming server resources through connection handling overhead, database queries for key lookups (per attempt), LDAP queries, and log file growth. This is separate from AUTH-RATE-001 as this finding focuses on consistency across authentication pathways per ASVS 6.3.4.

### Details
Affected locations:
- `atr/ssh.py`: SSH server without rate limiting
- `atr/server.py`: No rate limiting for SSH connections

The SSH server accepts unlimited connection attempts without any rate limiting at the application layer.

### Recommended Remediation
Implement connection tracking per IP address in `SSHServer.connection_made()` method:

```python
class SSHServer:
    _connection_timestamps: dict[str, list[float]] = {}
    _MAX_CONNECTIONS_PER_MINUTE = 20
    
    def connection_made(self, transport):
        """Track connections per IP and enforce rate limit."""
        remote_addr = transport.get_extra_info('peername')[0]
        now = time.time()
        
        # Clean old timestamps (older than 60 seconds)
        timestamps = self._connection_timestamps.get(remote_addr, [])
        recent = [t for t in timestamps if now - t < 60]
        
        # Enforce rate limit
        if len(recent) >= self._MAX_CONNECTIONS_PER_MINUTE:
            log.warning('ssh_rate_limit_exceeded', extra={'remote_addr': remote_addr})
            transport.close()
            return
        
        # Record this connection
        recent.append(now)
        self._connection_timestamps[remote_addr] = recent
        
        # Continue with normal connection handling
        super().connection_made(transport)
```

Include logging of rate limit violations.

### Acceptance Criteria
- [ ] SSH connections are rate limited per IP address
- [ ] Rate limit is consistent with other authentication pathways
- [ ] Exceeded rate limits are logged
- [ ] Test cases verify rate limiting
- [ ] Unit test verifying the fix

### References
- Source reports: L2:6.3.4.md
- Related findings: FINDING-004
- ASVS sections: 6.3.4

### Priority
Medium

---

## Issue: FINDING-127 - SSH Authentication Surface Not Covered in Authentication Security Documentation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The SSH server (`atr/ssh.py`) is a significant authentication entry point that accepts public key authentication from GitHub workflow processes. The authentication security documentation does not address this authentication surface at all. Unlimited authentication attempts are possible against SSH server at the application layer. Auditors and operators cannot assess SSH authentication surface protections. GitHub Issue #723 acknowledges this gap but open issues do not substitute for documentation.

### Details
Affected locations:
- `security/ASVS/audit_guidance/authentication-security.md`: No SSH authentication section
- `atr/ssh.py` SSHServer.connection_made, SSHServer.begin_auth, SSHServer.validate_public_key: Undocumented authentication surface

The SSH server is a complete authentication pathway that is not documented in the authentication security documentation.

### Recommended Remediation
Add a dedicated 'SSH Authentication' section to authentication-security.md documenting:

1. **Authentication mechanism:** Public key only, 20-minute TTL
2. **Anti-automation controls:** Key-based authentication, logging
3. **Current limitations:** No connection-level rate limiting tracked in Issue #723, expected to be enforced at network/firewall layer
4. **Monitoring:** Failed SSH authentication attempts

```markdown
## SSH Authentication

The ATR application provides an SSH server for automated release artifact uploads from GitHub Actions workflows.

### Authentication Mechanism
- Public key authentication only (no password authentication)
- Workflow-specific SSH keys with 20-minute TTL
- Keys are generated per-workflow and stored in database
- Authentication validates key against database records

### Anti-Automation Controls
- Key-based authentication prevents brute force password attacks
- All authentication attempts are logged
- Rate limiting is expected at network/firewall layer (Issue #723)

### Current Limitations
- No application-level connection rate limiting (tracked in Issue #723)
- Relies on network/firewall layer for connection throttling

### Monitoring
- Failed SSH authentication attempts are logged
- Connection attempts are tracked for operational visibility
```

### Acceptance Criteria
- [ ] SSH authentication is documented in authentication-security.md
- [ ] Documentation covers authentication mechanism and controls
- [ ] Current limitations are explicitly stated
- [ ] GitHub Issue #723 is referenced
- [ ] Unit test verifying the fix

### References
- Source reports: L1:6.1.1.md
- Related findings: FINDING-004, FINDING-126
- ASVS sections: 6.1.1

### Priority
Medium

---

## Issue: FINDING-128 - Documentation Does Not Address Adaptive Response Mechanisms

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
ASVS 6.1.1 explicitly lists 'adaptive response' as a control that should be documented. The authentication security documentation describes static rate limits but does not document any adaptive or progressive response mechanisms. What is NOT documented: what happens when rate limits are repeatedly hit by the same actor, whether rate limit windows escalate, whether there are alerting or monitoring thresholds, or whether there is automated account protection beyond rate limiting. The documentation stops at 'return 429 with retry_after' with no described escalation or adaptive behavior.

### Details
Affected locations:
- `security/ASVS/audit_guidance/authentication-security.md`: No adaptive response documentation
- `atr/storage/writers/tokens.py` lines 106-130: Static rate limiting only

The documentation describes static rate limits but no adaptive or progressive response mechanisms.

### Recommended Remediation
Document the adaptive response strategy in authentication-security.md. If the project's position is that static rate limits plus OAuth delegation are sufficient, this should be explicitly stated with rationale:

```markdown
## Adaptive Response Strategy

ATR uses a defense-in-depth approach combining static rate limits with OAuth delegation for adaptive response:

### Static Rate Limits
- API endpoints: 500 requests/hour per IP
- Web endpoints: 100 requests/minute per IP
- Admin endpoints: 30 requests/minute per IP

### OAuth Delegation
Password authentication is delegated to ASF OAuth provider which implements:
- Progressive delays on failed attempts
- Account lockout after repeated failures
- CAPTCHA challenges for suspicious patterns
- IP-based reputation scoring

### PAT Security
- PATs are 256-bit cryptographically random tokens
- Brute force is computationally infeasible
- Rate limiting prevents systematic enumeration

### JWT Security
- JWT signing uses server-controlled secrets
- Token expiration limits exposure window
- Revocation mechanisms exist for compromised tokens

### Monitoring Thresholds (Recommended)
While not currently implemented, operators should monitor:
- Rate limit violations per IP (threshold: >10/hour)
- Failed authentication attempts per user (threshold: >5/hour)
- Unusual geographic patterns
- Concurrent session anomalies

### Future Considerations
- Application-level adaptive delays (Issue #XXX)
- Automated IP blocking for persistent abuse (Issue #XXX)
- Integration with ASF-wide abuse detection systems
```

Include recommended monitoring thresholds and future considerations.

### Acceptance Criteria
- [ ] Adaptive response strategy is documented
- [ ] Rationale for current approach is explained
- [ ] Monitoring thresholds are recommended
- [ ] Future considerations are documented
- [ ] Unit test verifying the fix

### References
- Source reports: L1:6.1.1.md
- Related findings: FINDING-245
- ASVS sections: 6.1.1

### Priority
Medium

---

## Issue: FINDING-129 - ldap.is_active() Returns True When LDAP Is Unconfigured (Fail-Open)

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `is_active()` function in `atr/ldap.py` fails open (returns True) when LDAP bind credentials are not configured or invalid. This is a fail-open misconfiguration vulnerability where all account status checks are silently bypassed with no errors or alerts. Banned/disabled users gain full access during LDAP misconfiguration, credential rotation issues, or LDAP server unavailability. This affects all authentication paths that rely on `ldap.is_active()` including web, JWT, and (if fixed) SSH authentication.

### Details
Affected locations:
- `atr/ldap.py` lines 219-226: is_active() fails open
- `atr/ldap.py` get_bind_credentials(): Returns None when unconfigured

The function returns True when LDAP credentials are missing, treating misconfiguration as "all users active" instead of "cannot verify status".

### Recommended Remediation
Modify `is_active()` to fail closed in production mode:

```python
def is_active(username: str) -> bool:
    """Check if LDAP account is active. Fail closed in production."""
    credentials = get_bind_credentials()
    
    if credentials is None:
        # LDAP unconfigured
        if is_production_mode():
            # Fail closed in production
            raise ASFQuartException(
                "LDAP not configured. Cannot verify account status.",
                status=503
            )
        else:
            # Allow in debug mode with warning
            log.warning('ldap_unconfigured_allowing_access', extra={'username': username})
            return True
    
    # Normal LDAP check
    try:
        return _check_ldap_active(username, credentials)
    except LDAPError as e:
        if is_production_mode():
            raise ASFQuartException(
                "LDAP service unavailable. Cannot verify account status.",
                status=503
            )
        else:
            log.warning('ldap_unavailable_allowing_access', extra={'username': username})
            return True
```

Add `validate_ldap_configuration()` startup check that prevents application start if LDAP unconfigured in production.

Implement `check_ldap_health()` monitoring endpoint to alert on LDAP connectivity issues.

Behavior by mode:
- Production: Fail closed with 503 error
- Debug: Allow with warning log
- Test: Check ALLOW_TESTS flag

### Acceptance Criteria
- [ ] is_active() fails closed when LDAP unconfigured in production
- [ ] Startup check prevents running without LDAP in production
- [ ] Debug mode allows with warnings
- [ ] Monitoring endpoint exists for LDAP health
- [ ] Test cases verify fail-closed behavior
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.4.2.md
- Related findings: FINDING-006, FINDING-007
- ASVS sections: 7.4.2

### Priority
Medium

---

## Issue: FINDING-130 - Admin Blueprint post Decorator Bypasses LDAP Active Account Check

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The admin blueprint provides two route decorators: 'typed' decorator which calls `authenticate()` including LDAP active account check, and 'post' decorator which uses `_check_admin_access()` that validates admin status but NOT LDAP account status. The `_check_admin_access()` before_request hook validates that the user has a valid session cookie and is in the admin list, but does not call `ldap.is_active()` to verify the account is still active. Manual code review indicates no current admin routes use the 'post' decorator, making this a latent vulnerability that creates false confidence for future development. If admin routes use the 'post' decorator, deactivated LDAP accounts could continue performing privileged operations for up to 72 hours.

### Details
Affected locations:
- `atr/blueprints/admin.py` lines 23-31: post decorator definition
- `atr/blueprints/admin.py` lines 146-155: _check_admin_access() without LDAP check
- `atr/blueprints/admin.py` lines 87-89: typed decorator calls authenticate()

The `_check_admin_access()` function validates session and admin status but skips LDAP account status verification.

### Recommended Remediation
Update `_check_admin_access()` to call `common.authenticate()` which includes LDAP validation, or deprecate the post decorator entirely.

**Recommended:** Modify `_check_admin_access()` to call `common.authenticate()` instead of directly reading the session:

```python
async def _check_admin_access() -> None:
    """Verify user is authenticated admin with active LDAP account."""
    # Use common.authenticate() which includes LDAP check
    session = await common.authenticate()
    
    # Verify admin status
    if session.uid not in config.get().ADMINS:
        raise exceptions.Forbidden("Admin access required")
```

**Additionally:** Add documentation warning against using post decorator, or remove it entirely if not needed.

### Acceptance Criteria
- [ ] Admin post decorator includes LDAP account status check
- [ ] Deactivated accounts cannot use admin routes
- [ ] Documentation warns against post decorator or it's removed
- [ ] Test cases verify LDAP check for admin routes
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.4.1.md
- Related findings: FINDING-247
- ASVS sections: 7.4.1

### Priority
Medium

---

## Issue: FINDING-131 - No Session Termination After SSH Key Changes

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
When a user adds or removes an SSH key (an authentication factor for the SSH rsync server), no option is presented to terminate other active sessions. SSH keys are authentication factors and their modification should trigger the same session termination option as PAT changes per ASVS 7.4.3. If a user removes a compromised SSH key, SSH access to rsync server is revoked but web UI sessions cannot be terminated, allowing an attacker with stolen web session to re-add SSH keys and regain access.

### Details
Affected locations:
- `atr/post/keys.py` lines 141-155: ssh_add() without session termination option
- `atr/post/keys.py` lines 174-184: _delete_ssh_key() without session termination option

SSH key addition and deletion forms lack "terminate other sessions" option that exists for PAT changes.

### Recommended Remediation
Add 'terminate_other_sessions' boolean field to `AddSSHKeyForm` and `DeleteSSHKeyForm`:

```python
class AddSSHKeyForm(pydantic.BaseModel):
    public_key: str
    terminate_other_sessions: bool = False

class DeleteSSHKeyForm(pydantic.BaseModel):
    fingerprint: str
    terminate_other_sessions: bool = False
```

Update `ssh_add()` and `_delete_ssh_key()` handlers to check this field and call `terminate_all_other_sessions(session.asf_uid, current_session_id)` when checked (requires SESSION-001 fix).

Add checkbox to SSH key forms with appropriate messaging:
- For addition: "Terminate other sessions (recommended if adding key for security reasons)"
- For deletion: "Terminate other sessions (recommended if key was compromised)"

For deletion, show warning if not checked: "SSH key deleted successfully. Consider terminating other sessions if key was compromised."

### Acceptance Criteria
- [ ] SSH key forms include session termination option
- [ ] Session termination is triggered when option is checked
- [ ] Warning is shown if deletion occurs without session termination
- [ ] Test cases verify session termination option
- [ ] Unit test verifying the fix

### References
- Source reports: L2:7.4.3.md
- Related findings: FINDING-005, FINDING-036, FINDING-248
- ASVS sections: 7.4.3

### Priority
Medium

---

## Issue: FINDING-132 - JWT Signing Key Rotation Does Not Invalidate Cookie Sessions

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
When the JWT signing key is rotated via admin panel (a significant security event that invalidates all existing JWTs), cookie-based web sessions are unaffected. While this successfully invalidates all JWTs, it creates an inconsistent security posture where API access via JWTs is revoked but web UI access via cookies continues. If JWT key rotation is performed due to suspected key compromise, attackers with active cookie sessions are not affected by the security response, creating incomplete incident response.

### Details
Affected locations:
- `atr/admin/__init__.py` lines 404-410: rotate_jwt_key_post() doesn't terminate sessions
- `atr/storage/writers/tokens.py` lines 174-179: JWT key rotation logic

JWT key rotation invalidates all JWTs but leaves cookie sessions active.

### Recommended Remediation
Add automatic session termination to `rotate_jwt_key_post()`.

**Recommended Option A:** Terminate all sessions globally including admin:

```python
async def rotate_jwt_key_post():
    # Rotate JWT key
    await write.rotate_jwt_key()
    
    # Terminate all sessions (requires SESSION-001 fix)
    await terminate_all_sessions_globally()
    
    # Redirect to login
    return quart.redirect('/login?message=JWT+key+rotated+and+all+sessions+terminated')
```

**Alternative Option B:** Preserve admin session:

```python
async def rotate_jwt_key_post(session):
    # Rotate JWT key
    await write.rotate_jwt_key()
    
    # Terminate all sessions except current (requires SESSION-001 fix)
    current_session_id = await get_current_session_id()
    await terminate_all_sessions_except(current_session_id)
    
    # Show success message
    flash("JWT signing key rotated and all other sessions terminated successfully.")
    return quart.redirect('/admin')
```

**Recommendation:** Use Option A for maximum security during key rotation events.

### Acceptance Criteria
- [ ] JWT key rotation terminates cookie sessions
- [ ] Security response is complete and consistent
- [ ] Admin is notified of session termination
- [ ] Test cases verify session termination
- [ ] Unit test verifying the fix

### References
- Source reports: L2:7.4.3.md
- Related findings: FINDING-005, FINDING-037, FINDING-133
- ASVS sections: 7.4.3

### Priority
Medium

---

## Issue: FINDING-133 - Web-Issued JWTs Cannot Be Revoked and Survive PAT Deletion

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
JWTs issued through the web UI (`/tokens/jwt`) are not bound to any PAT and remain valid for their full 30-minute TTL regardless of logout or authentication factor changes. Only JWTs with the `atr_th` (PAT hash) claim are validated against the PAT database. The `jwtoken.issue()` function generates a `jti` (JWT ID) claim for all JWTs, but this claim is never checked against any denylist or revocation registry. When `jwtoken.verify()` validates a JWT, it only checks the PAT hash (`atr_th`) if present - web-issued JWTs skip this check entirely. This creates inconsistency: PAT-issued JWTs are immediately revoked when PAT is deleted, but web-issued JWTs continue working for up to 30 minutes, violating ASVS 7.4.1 and 7.4.3 principles of immediate invalidation.

### Details
Affected locations:
- `atr/post/tokens.py` lines 33-41: jwt_post() issues JWT without PAT binding
- `atr/jwtoken.py` lines 42-58: issue() generates jti but no denylist check
- `atr/jwtoken.py` lines 92-126: verify() only checks PAT hash if present

Web-issued JWTs have no revocation mechanism and survive for full 30-minute TTL.

### Recommended Remediation
**Option A (recommended):** Extend the per-user revocation timestamp approach from SESSION-001 to cover JWTs. Update `jwtoken.verify()` to check the user's `sessions_invalid_before` timestamp against the JWT's `iat` (issued at) claim:

```python
def verify(token: str) -> dict:
    claims = jwt.decode(token, signing_key, algorithms=['HS256'])
    
    # Check user's revocation timestamp
    user = get_user(claims['sub'])
    if user.sessions_invalid_before and claims['iat'] < user.sessions_invalid_before:
        raise JWTTokenInvalid("JWT issued before revocation timestamp")
    
    # Existing PAT hash check
    if 'atr_th' in claims:
        # ... existing PAT validation
    
    return claims
```

This provides unified revocation for both web sessions and JWTs using a single database column.

**Option B:** Require all JWTs to be issued through PATs - modify `jwt_post()` to check if user has at least one PAT, raise BadRequest if none exist, bind JWT to first PAT using pat_hash parameter.

**Option C:** Add JTI denylist using Redis for granular JWT revocation.

**Option D (minimal):** Reduce web-issued JWT TTL from 30 minutes to 5 minutes to limit exposure window.

### Acceptance Criteria
- [ ] Web-issued JWTs can be revoked
- [ ] Revocation is immediate or near-immediate
- [ ] Consistency with PAT-issued JWT revocation
- [ ] Test cases verify JWT revocation
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.4.1.md, L2:7.4.3.md
- Related findings: FINDING-005, FINDING-036
- ASVS sections: 7.4.1, 7.4.3

### Priority
Medium

---

## Issue: FINDING-134 - JWT API Authentication Success Not Logged

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `@jwtoken.require()` decorator logs all JWT authentication failures but does not log successful authentications. All exception handlers properly log failures (jwt_token_expired, jwt_signature_invalid, jwt_token_invalid), but when verification succeeds, the code silently sets `quart.g.jwt_claims` without logging. This creates an incomplete audit trail that only captures negative events and prevents reconstruction of successful API access patterns and forensic investigation of compromised accounts.

### Details
Affected locations:
- `atr/jwtoken.py` lines 72-88: require() decorator logs failures only
- `atr/jwtoken.py` lines 89-122: verify() doesn't log success
- `atr/jwtoken.py` lines 124-175: verify_github_oidc() doesn't log success

The decorator has comprehensive failure logging but no success logging, creating incomplete audit trail.

### Recommended Remediation
Add success logging after all exception handlers, before setting `quart.g.jwt_claims`:

```python
# In require() decorator after verify() call:
log.info('jwt_authentication_success', extra={
    'asf_uid': claims.get('sub'),
    'jti': claims.get('jti'),
    'endpoint': quart.request.endpoint,
    'remote_addr': quart.request.remote_addr
})
quart.g.jwt_claims = claims
```

Apply the same pattern to `verify_github_oidc()` function (lines 124-175):

```python
log.info('github_oidc_authentication_success', extra={
    'workflow_repository': claims.get('repository'),
    'workflow_ref': claims.get('ref'),
    'endpoint': quart.request.endpoint
})
```

### Acceptance Criteria
- [ ] Successful JWT authentication is logged
- [ ] Log entries include user identity and endpoint
- [ ] Audit trail is complete for both success and failure
- [ ] Test cases verify success logging
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.2.2.md
- Related findings: FINDING-135, FINDING-136, FINDING-250, FINDING-251
- ASVS sections: 7.2.2

### Priority
Medium

---

## Issue: FINDING-135 - OAuth Authentication Decisions Not Logged

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The OAuth authentication callback handler (`/auth` endpoint) makes critical authentication decisions but does not log any of them. Both successful logins and failures (invalid/expired state, OAuth provider rejection) occur silently. OAuth is the primary web authentication mechanism, making this a significant gap. The code validates state tokens, calls OAuth providers, and creates sessions without any audit trail, preventing detection of state token brute-force, replay attacks, or compromised accounts.

### Details
Affected locations:
- `src/asfquart/generics.py` lines 83-109: OAuth callback without logging
- `src/asfquart/generics.py` lines 52-115: Authentication flow without audit

The OAuth callback performs authentication but never logs success or failure, creating complete gap in audit trail for primary web authentication mechanism.

### Recommended Remediation
Implement an after_request hook to capture OAuth authentication decisions. In `atr/server.py`, add `@app.after_request` handler that checks if `request.path == '/auth'` and logs `oauth_login_success` (status 200 with uid) or `oauth_login_failure` (status 403):

```python
@app.after_request
async def log_oauth_decisions(response: quart.Response) -> quart.Response:
    """Log OAuth authentication decisions for audit trail."""
    if quart.request.path == '/auth':
        if response.status_code == 200:
            # Successful login - extract uid from session
            session_data = await asfquart.session.read()
            log.info('oauth_login_success', extra={
                'asf_uid': session_data.get('uid'),
                'remote_addr': quart.request.remote_addr
            })
        elif response.status_code in (403, 401):
            # Failed login
            log.warning('oauth_login_failure', extra={
                'state_token': quart.request.args.get('state', '')[:8] + '...',  # Truncated
                'remote_addr': quart.request.remote_addr,
                'status': response.status_code
            })
    return response
```

Include `asf_uid` for success cases and failure reason for rejection cases.

### Acceptance Criteria
- [ ] OAuth authentication success is logged
- [ ] OAuth authentication failure is logged
- [ ] Log entries include user identity and remote address
- [ ] Audit trail is complete for OAuth flow
- [ ] Test cases verify OAuth logging
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.2.2.md
- Related findings: FINDING-134, FINDING-136, FINDING-250
- ASVS sections: 7.2.2

### Priority
Medium

---

## Issue: FINDING-136 - Web-Based JWT Issuance Not Audit-Logged

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The web interface allows authenticated users to issue JWTs via POST to `/tokens/jwt`, but this operation is not audit-logged. This creates an inconsistency with the API path (PAT→JWT exchange in `atr/storage/writers/tokens.py:93-127`) which properly logs JWT issuance using `append_to_audit_log()`. The `jwt_post()` function calls `jwtoken.issue()` but never writes to the audit log, preventing reconstruction of web-based JWT generation timeline and detection of compromised web sessions issuing JWTs.

### Details
Affected location: `atr/post/tokens.py` lines 31-39

The web JWT issuance endpoint:
1. Accepts authenticated POST request
2. Issues JWT via `jwtoken.issue()`
3. Returns JWT to user
4. Never logs the issuance

The API path properly logs JWT issuance but web path does not.

### Recommended Remediation
Add audit logging to `jwt_post()` function to match API path behavior. After `jwt_token = jwtoken.issue(session.uid)`, add:

```python
log.info('web_jwt_issued', extra={
    'asf_uid': session.uid,
    'issuance_method': 'web_ui',
    'remote_addr': quart.request.remote_addr,
    'jti': jwt.decode(jwt_token, options={'verify_signature': False})['jti']
})
```

**Alternative:** Use `append_to_audit_log()` infrastructure for consistency with API path (requires access to storage writer):

```python
await write.append_to_audit_log(
    user_uid=session.uid,
    action='jwt_issued',
    details={'method': 'web_ui', 'remote_addr': quart.request.remote_addr}
)
```

### Acceptance Criteria
- [ ] Web JWT issuance is audit-logged
- [ ] Logging is consistent with API path
- [ ] Log entries include user identity and method
- [ ] Test cases verify JWT issuance logging
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.2.2.md
- Related findings: FINDING-134, FINDING-250
- ASVS sections: 7.2.2

### Priority
Medium

---

## Issue: FINDING-137 - Admin Pages Using template.blank() May Lack Logout Button

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Three admin pages use `template.blank()` rendering method whose implementation was not provided in the audit scope, making it unclear whether they include the logout button. If `template.blank()` does not extend `base.html` or include `topnav.html`, authenticated admin users on these pages will have no visible logout mechanism, directly violating ASVS 7.4.4. Users would need to navigate to another page, manually visit `/auth?logout`, or close the browser to terminate their session.

### Details
Affected locations:
- `atr/admin/__init__.py` line 885: tasks_recent uses template.blank()
- `atr/admin/__init__.py` line 1157: _rotate_jwt_key_page uses template.blank()
- `atr/admin/__init__.py` line 1210: _validate_jwt_page uses template.blank()

The `template.blank()` implementation was not provided, making it impossible to verify logout button presence.

### Recommended Remediation
**Option 1:** Ensure `template.blank()` extends base layout by creating `layouts/blank.html` that extends `base.html` and includes topnav:

```html
{% extends "base.html" %}
{% block content %}
    {{ content|safe }}
{% endblock %}
```

**Option 2:** Switch to `template.render()` for these pages to use standard layout with guaranteed logout button presence.

Verify `template.blank()` implementation includes `topnav.html` or refactor affected handlers (`tasks_recent`, `_rotate_jwt_key_page`, `_validate_jwt_page`) to use `template.render()` with proper base layout inheritance.

### Acceptance Criteria
- [ ] Admin pages using template.blank() include logout button
- [ ] Logout button is visible and functional on all admin pages
- [ ] Template inheritance is verified
- [ ] Test cases verify logout button presence
- [ ] Unit test verifying the fix

### References
- Source reports: L2:7.4.4.md
- Related findings: FINDING-138, FINDING-254
- ASVS sections: 7.4.4

### Priority
Medium

---

## Issue: FINDING-138 - Admin Pages Using web.ElementResponse() May Lack Logout Button

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Three admin pages return `web.ElementResponse()` with form HTML elements, but the `web.ElementResponse()` implementation was not provided in audit scope. If `web.ElementResponse` renders only HTML fragments without wrapping them in `base.html`, these pages will lack the topnav navigation and logout button. Authenticated admin users on `keys_check_get`, `keys_regenerate_all_get`, and `delete_test_openpgp_keys_get` pages may have no visible logout mechanism, violating ASVS 7.4.4.

### Details
Affected locations:
- `atr/admin/__init__.py` line 442: keys_check_get returns web.ElementResponse()
- `atr/admin/__init__.py` line 466: keys_regenerate_all_get returns web.ElementResponse()
- `atr/admin/__init__.py` line 392: delete_test_openpgp_keys_get returns web.ElementResponse()

The `web.ElementResponse()` implementation was not provided, making it impossible to verify logout button presence.

### Recommended Remediation
**Option 1:** Modify `web.ElementResponse` class to wrap content in base layout with title parameter, creating `layouts/element-wrapper.html` that extends `base.html`:

```python
class ElementResponse:
    def __init__(self, element, title="Admin"):
        self.element = element
        self.title = title
    
    def render(self):
        # Wrap element in base layout with topnav
        return template.render('layouts/element-wrapper.html', {
            'title': self.title,
            'content': self.element
        })
```

**Option 2:** Switch affected handlers (`keys_check_get`, `keys_regenerate_all_get`, `delete_test_openpgp_keys_get`) to use `template.render()` with `admin/form-page.html` template to ensure logout button presence through base layout inheritance.

### Acceptance Criteria
- [ ] Admin pages using web.ElementResponse() include logout button
- [ ] Logout button is visible and functional on all admin pages
- [ ] Response wrapping is verified
- [ ] Test cases verify logout button presence
- [ ] Unit test verifying the fix

### References
- Source reports: L2:7.4.4.md
- Related findings: FINDING-137, FINDING-254
- ASVS sections: 7.4.4

### Priority
Medium

---

## Issue: FINDING-139 - Inconsistent Defense-in-Depth in Distribution Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
Three distribution POST handlers and one GET handler do not call `session.check_access(project_key)` before accessing project-scoped data. The POST handlers have mitigating storage-layer authorization (`write_as_committee_member()`), but the GET handler (`list_get`) exposes distribution records and workflow task details to any authenticated committer. The inconsistency creates potential for future regression if `check_access` adds security-relevant validation beyond what the storage layer provides.

### Details
Affected locations:
- `atr/get/distribution.py` line 180: list_get() without check_access()
- `atr/get/distribution.py` line 192: record_selected() without check_access()
- `atr/get/distribution.py` line 205: stage_automate_selected() without check_access()
- `atr/post/distribution.py`: POST handlers without check_access()

The GET handler exposes data without authorization check, while POST handlers rely on storage layer.

### Recommended Remediation
Add `await session.check_access(project_key)` at the beginning of all four functions: `list_get()`, `record_selected()`, `stage_automate_selected()`, and `stage_record_selected()`:

```python
async def list_get(session, project_key, version_key):
    # Add authorization check
    await session.check_access(project_key)
    
    # Remove underscore prefix from _session parameter
    # ... existing code
```

Remove underscore prefix from `_session` parameter in `list_get()`. This ensures consistent authorization checks across all distribution endpoints.

### Acceptance Criteria
- [ ] All distribution endpoints call check_access()
- [ ] Authorization is consistent across GET and POST handlers
- [ ] Defense-in-depth is maintained
- [ ] Test cases verify authorization checks
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.2.2.md, L2:8.2.3.md
- Related findings: FINDING-041
- ASVS sections: 8.2.2, 8.2.3

### Priority
Medium

---

## Issue: FINDING-140 - GET Blueprint Lacks Centralized Project-Level Authorization

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The POST blueprint automatically calls `check_access(project_key)` when a `project_key` parameter is detected in the route signature, providing centralized project-level authorization. The GET blueprint has no equivalent mechanism, requiring each GET handler to manually call `session.check_access(project_key)`. This architectural asymmetry creates inconsistency risk — developers adding new GET routes with project parameters may omit the authorization check, and the authorization documentation does not explain this difference.

### Details
Affected locations:
- `atr/blueprints/get.py`: No centralized authorization
- `atr/get/distribution.py`: Manual check_access() calls required
- `atr/get/file.py`: Manual check_access() calls required
- `atr/get/report.py`: Manual check_access() calls required
- `atr/get/checks.py`: Manual check_access() calls required

The POST blueprint provides automatic authorization but GET blueprint requires manual checks, creating inconsistency.

### Recommended Remediation
**Option A (Preferred):** Add automatic authorization to GET Blueprint by detecting `project_key` parameters and calling `check_access()` automatically, mirroring POST blueprint behavior:

```python
# In atr/blueprints/get.py
@_BLUEPRINT.before_request
async def _auto_check_project_access():
    """Automatically check project access for routes with project_key parameter."""
    if 'project_key' in quart.request.view_args:
        session = await common.authenticate()
        project_key = quart.request.view_args['project_key']
        await session.check_access(project_key)
```

**Option B:** Document the requirement in authorization-security.md with explicit guidance that GET endpoints with `project_key` parameters MUST explicitly call `check_access()`. Add linting rule to detect missing checks. Audit all existing GET endpoints with `project_key` parameters. Add integration tests for each endpoint verifying authorization. Add developer documentation to developer-guide.md.

### Acceptance Criteria
- [ ] GET blueprint has centralized authorization or documented requirements
- [ ] Authorization is consistent between GET and POST blueprints
- [ ] Linting or automation prevents missing checks
- [ ] Test cases verify authorization
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.1.1.md
- Related findings: FINDING-141
- ASVS sections: 8.1.1

### Priority
Medium

---

## Issue: FINDING-141 - API Blueprint Lacks Centralized Authentication Hook

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The admin blueprint enforces authentication via a centralized `before_request` hook that verifies admin status for all routes. The API blueprint only implements a rate-limiting hook, requiring each API endpoint to individually apply `@jwtoken.require` decorators. Without centralized enforcement or comprehensive documentation mapping endpoints to authentication requirements, new API endpoints could be added without proper authentication.

### Details
Affected locations:
- `atr/blueprints/api.py`: No centralized authentication hook
- `atr/api/__init__.py`: Individual decorator application required

The API blueprint has no centralized authentication enforcement, relying on developers to remember to apply `@jwtoken.require` decorator to each endpoint.

### Recommended Remediation
**Option A:** Add centralized authentication hook to API blueprint if all API endpoints require auth, performing JWT validation in `before_request` and storing payload in request context:

```python
@_BLUEPRINT.before_request
async def _require_authentication():
    """Require JWT authentication for all API endpoints."""
    # Perform JWT validation
    token = quart.request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return quart.jsonify({"error": "Authentication required"}), 401
    
    try:
        claims = jwtoken.verify(token)
        quart.g.jwt_claims = claims
    except JWTError as e:
        return quart.jsonify({"error": str(e)}), 401
```

**Option B:** Create comprehensive documentation in authorization-security.md with API endpoint authorization matrix including authentication requirements, authorization levels, and rate limits. Add developer checklist for new API endpoints.

**Option C:** Add linting rule to detect API endpoint functions without `@jwtoken.require` decorator. Audit all existing API endpoints for authentication status. Add integration tests verifying authentication for each endpoint.

### Acceptance Criteria
- [ ] API blueprint has centralized authentication or documented requirements
- [ ] Authentication is enforced consistently
- [ ] Linting or automation prevents missing authentication
- [ ] Test cases verify authentication
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.1.1.md
- Related findings: FINDING-140
- ASVS sections: 8.1.1

### Priority
Medium

---

## Issue: FINDING-142 - Worker Task Execution Lacks Function-Level Authorization Re-verification

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
Background tasks verify authorization when queued but do not re-verify permissions when executed by the worker. This creates a Time-of-Check-Time-of-Use (TOCTOU) vulnerability where tasks queued by authorized users continue to execute after their permissions are revoked. Only ban status is checked at execution time, not function-level permissions like admin status or committee membership. Workers check only ban status, not full committee/project membership that may have changed since task was queued.

### Details
Affected locations:
- `atr/worker.py` lines 229-275: _task_process() without permission re-verification
- `atr/worker.py` line 249: Only ban check, no permission check
- `atr/tasks/metadata.py`: METADATA_UPDATE tasks without admin re-verification
- `atr/tasks/*.py`: Project-scoped tasks without committee membership re-verification

Tasks are queued with authorization check but executed without re-verification, creating TOCTOU gap.

### Recommended Remediation
Add function-level permission re-verification in `_task_process()` by creating a new `_verify_task_permissions()` function that checks:

1. Admin status for METADATA_UPDATE tasks
2. Committee membership for project-scoped tasks
3. Full committee/project membership status at execution time

```python
async def _verify_task_permissions(task: sql.Task) -> None:
    """Re-verify permissions at task execution time."""
    user = await data.user(uid=task.user_uid)
    
    # Check if user is banned
    if user.banned:
        raise PermissionError(f"User {task.user_uid} is banned")
    
    # Check admin status for metadata tasks
    if task.type == 'METADATA_UPDATE':
        if task.user_uid not in config.get().ADMINS:
            raise PermissionError(f"User {task.user_uid} is no longer admin")
    
    # Check committee membership for project tasks
    if task.project_key:
        project = await data.project(key=task.project_key)
        if not await user.is_committee_member(project.committee_key):
            raise PermissionError(
                f"User {task.user_uid} is no longer member of "
                f"committee {project.committee_key}"
            )
```

This re-verification should occur after the ban check but before task handler execution, using the storage layer's authorization methods to ensure consistency with creation-time checks. If user no longer has required permissions, fail task with appropriate error.

### Acceptance Criteria
- [ ] Task execution re-verifies permissions
- [ ] Admin status is checked for admin tasks
- [ ] Committee membership is checked for project tasks
- [ ] TOCTOU vulnerability is eliminated
- [ ] Test cases verify permission re-verification
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.2.1.md, L1:8.2.2.md, L1:8.3.1.md
- Related findings: None
- ASVS sections: 8.2.1, 8.2.2, 8.3.1

### Priority
Medium

---

## Issue: FINDING-143 - Information Leakage via Debug Print in SSH Authorization Path

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The SSH read authorization validation function includes a debug `print()` statement that outputs the entire `sql.Release` object to stdout for every SSH read request. This object contains release metadata including phase, version, project key, and potentially sensitive internal data. The output is not structured logging and goes directly to server stdout/logs.

### Details
Affected location: `atr/ssh.py` line 455

The code contains:
```python
print(release)  # Debug output
```

This prints the entire release object for every SSH read operation, leaking internal data to logs.

### Recommended Remediation
**Option A (Preferred):** Remove the debug `print()` statement entirely.

**Option B:** Replace with structured logging using Python logging module at DEBUG level with specific fields (project_key, version, phase, user) rather than full object dump:

```python
log.debug('ssh_read_authorization', extra={
    'project_key': release.project_key,
    'version_key': release.version_key,
    'phase': release.phase,
    'user': asf_uid
})
```

Audit entire codebase for debug `print()` statements. Implement structured logging framework if not already present. Add linting rule to detect `print()` in production code. Document logging standards in developer-guide.md. Review log retention policies for sensitive data.

### Acceptance Criteria
- [ ] Debug print() statement is removed or replaced with structured logging
- [ ] No sensitive data is leaked to logs
- [ ] Linting prevents print() in production code
- [ ] Test cases verify no debug output
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.1.1.md
- Related findings: None
- ASVS sections: 8.1.1

### Priority
Medium

---

## Issue: FINDING-144 - Admin Route Uses Insufficient Authorization Context for Storage Layer

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The admin route for regenerating KEYS files across all committees uses `as_committee_member_outcome()` instead of `as_committee_admin_outcome()`, causing the operation to silently skip committees where the admin is not a PMC member. This undermines the admin's ability to perform security-critical operations across all committees and provides no error indication of incomplete operations. This results in incomplete KEYS file regeneration when an admin (who should have authority over all committees) is not a member of specific committees.

### Details
Affected locations:
- `atr/admin/__init__.py` line 411: Uses as_committee_member_outcome()
- `atr/admin/__init__.py` line 392: delete_test_openpgp_keys_get uses same pattern

The admin route uses committee member authorization instead of admin authorization, causing silent failures for committees where admin is not a member.

### Recommended Remediation
Replace `write.as_committee_member_outcome(committee_key)` with `write.as_committee_admin_outcome(committee_key)` and report authorization failures in the outcomes list instead of silently skipping:

```python
async def keys_regenerate_all_post():
    outcomes = []
    for committee_key in all_committees:
        async with write.as_committee_admin_outcome(committee_key) as outcome:
            # Regenerate KEYS file
            await regenerate_keys_file(committee_key)
            outcome.success = True
        
        # Report outcome (success or authorization failure)
        outcomes.append({
            'committee': committee_key,
            'success': outcome.success,
            'error': outcome.error if not outcome.success else None
        })
    
    return outcomes
```

Add detailed status reporting to indicate which committees were successfully regenerated and which failed. This matches the pattern used in other admin routes like `delete_release_post` at line 180.

### Acceptance Criteria
- [ ] Admin routes use admin authorization context
- [ ] Authorization failures are reported, not silently skipped
- [ ] All committees are processed with clear success/failure status
- [ ] Test cases verify admin authorization
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.2.1.md, L1:8.2.2.md
- Related findings: FINDING-145
- ASVS sections: 8.2.1, 8.2.2

### Priority
Medium

---

## Issue: FINDING-145 - Admin Database Operations Bypass Storage Layer Authorization and Audit

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The admin endpoint for deleting all keys associated with a committee performs direct database operations instead of using the storage layer. This bypasses the storage layer's authorization re-verification and audit logging, creating an inconsistency with other admin operations and violating the centralized audit logging principle. While documentation acknowledges 'you can always import db directly,' the field-level access these operations have is not documented, nor is it clear which operations are audited vs. unaudited. The `delete_committee_keys_post` function directly manipulates `committee.public_signing_keys` via `committee.public_signing_keys.clear()` and deletes orphaned keys without calling `storage.write()`, resulting in no audit log entry.

### Details
Affected locations:
- `atr/admin/__init__.py` line 225: Direct database manipulation
- `atr/admin/__init__.py` lines 208-232: delete_committee_keys_post without storage layer
- `atr/admin/__init__.py` lines 175-190: Similar pattern in other admin operations

The operation directly modifies database without going through storage layer, bypassing authorization and audit logging.

### Recommended Remediation
Create a `delete_all_committee_keys()` method in the `WriteAsCommitteeAdmin` class (`atr/storage/writers/keys.py`) and refactor `delete_committee_keys_post()` to use it via `write.as_committee_admin(committee_key)`:

```python
# In atr/storage/writers/keys.py
class WriteAsCommitteeAdmin:
    async def delete_all_keys(self) -> None:
        """Delete all keys for this committee."""
        committee = await self._get_committee()
        
        # Clear committee keys
        committee.public_signing_keys.clear()
        
        # Delete orphaned keys
        orphaned = await self._get_orphaned_keys()
        for key in orphaned:
            await self._db.delete(key)
        
        # Audit log
        await self._append_audit_log(
            action='committee_keys_deleted',
            details={'committee': self.committee_key}
        )

# In atr/admin/__init__.py
async def delete_committee_keys_post(committee_key):
    async with write.as_committee_admin(committee_key) as ctx:
        await ctx.delete_all_keys()
```

This ensures the operation goes through the storage layer for proper authorization re-verification and audit logging, consistent with other admin operations like `revoke_user_tokens_post`.

Document admin operations with storage layer bypass in authorization-security.md including:
1. Admin Operation Audit Coverage table showing which operations use storage layer and generate audit logs vs. those that don't
2. Field-Level Access for Admin Operations table documenting unrestricted field access when using direct database access
3. Best practice guidance that admin operations should use storage layer when possible for audit logging

### Acceptance Criteria
- [ ] Admin operations use storage layer for authorization and audit
- [ ] Direct database access is eliminated or documented
- [ ] Audit logging is consistent across admin operations
- [ ] Documentation describes audit coverage
- [ ] Test cases verify audit logging
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.2.1.md, L2:8.1.2.md
- Related findings: FINDING-144
- ASVS sections: 8.2.1, 8.1.2

### Priority
Medium

---

## Issue: FINDING-146 - SSH Server Missing LDAP Account Active Status Verification

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The SSH server authenticates users based on SSH keys stored in the database but never verifies that the user's LDAP account is active. This allows disabled accounts to continue accessing the system via SSH, creating a divergence from the web authentication path which properly checks `ldap.is_active()`. SSH read operations have no LDAP check, while write operations rely on a 600s principal cache that may be stale.

### Details
Affected locations:
- `atr/ssh.py` line 206: SSH authentication without LDAP check
- `atr/ssh.py` line 303: Read operations without LDAP check
- `atr/ssh.py` line 345: Write operations with stale cache

The SSH server validates SSH keys but never checks if the associated LDAP account is still active.

### Recommended Remediation
Add LDAP active status check in `_step_02_handle_safely()` immediately after retrieving the `asf_uid` and before processing any commands. Use the same `ldap.is_active()` check that the web path implements in `blueprints/common.py:56-62`:

```python
async def _step_02_handle_safely(self, asf_uid: str, command: str):
    """Handle SSH command with LDAP account verification."""
    # Verify LDAP account is active
    if not await ldap.is_active(asf_uid):
        log.warning('ssh_disabled_account_attempt', extra={'asf_uid': asf_uid})
        raise PermissionDenied(f"Account {asf_uid} is disabled")
    
    # Proceed with command handling
    # ... existing code
```

**Note:** This issue is tracked in GitHub issue #737.

### Acceptance Criteria
- [ ] SSH authentication verifies LDAP account status
- [ ] Disabled accounts cannot access SSH server
- [ ] LDAP check is consistent with web authentication
- [ ] Test cases verify LDAP account verification
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.2.1.md
- Related findings: None
- ASVS sections: 8.2.1

### Priority
Medium

---

## Issue: FINDING-147 - Storage Layer Bypassed for Revision Tag Modification

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `_set_tag()` function allows modification of revision tags through direct database writes instead of routing through the storage layer. While project access is validated via `session.release()`, the operation bypasses storage layer authorization checks and audit logging. Revision tags can be modified without proper authorization validation or audit trail.

### Details
Affected location: `atr/post/revisions.py` lines 67-95

The function:
1. Validates project access via `session.release()`
2. Directly modifies `revision.tag` attribute
3. Commits to database without storage layer
4. No audit log entry

### Recommended Remediation
Route through storage layer with proper authorization. Create `write.revisions.set_tag()` method in storage layer that validates authorization and creates audit log entries:

```python
# In atr/storage/writers/revision.py
class WriteAsCommitteeMember:
    async def set_tag(self, revision_key: str, tag: str | None) -> None:
        """Set revision tag with authorization and audit."""
        revision = await self._get_revision(revision_key)
        
        # Validate authorization
        await self._check_project_access(revision.release.project_key)
        
        # Update tag
        revision.tag = tag
        
        # Audit log
        await self._append_audit_log(
            action='revision_tag_set',
            details={
                'revision': revision_key,
                'tag': tag,
                'previous_tag': revision.tag
            }
        )

# In atr/post/revisions.py
async def _set_tag(session, project_key, version_key, revision_number, tag):
    async with write.as_committee_member(session.uid) as ctx:
        await ctx.set_tag(revision_key, tag)
```

Replace direct database write with storage layer call.

### Acceptance Criteria
- [ ] Revision tag modification uses storage layer
- [ ] Authorization is validated through storage layer
- [ ] Audit log entries are created
- [ ] Test cases verify storage layer usage
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.3.1.md
- Related findings: FINDING-009, FINDING-148
- ASVS sections: 8.3.1

### Priority
Medium

---

## Issue: FINDING-148 - Resource-Committee Validation Control Not Applied Across Storage Writers

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `checks.py` writer implements a validation pattern to ensure a project belongs to the committee the user is acting as a member of. This control is not consistently applied across other writer classes (`distributions.py`, `policy.py`, `release.py`, `revision.py`, `sbom.py`), creating potential for cross-committee authorization bypass if future code changes introduce direct committee-level access.

### Details
Affected locations:
- `atr/storage/writers/distributions.py`: No project-committee validation
- `atr/storage/writers/policy.py`: No project-committee validation
- `atr/storage/writers/release.py`: No project-committee validation
- `atr/storage/writers/revision.py`: No project-committee validation
- `atr/storage/writers/sbom.py`: No project-committee validation

The `checks.py` writer validates that projects belong to the committee context, but other writers don't apply this validation consistently.

### Recommended Remediation
Extract shared validation to base class `WriteAsCommitteeMember._validate_project_in_committee()` and apply in all writer methods accepting project/release keys:

```python
# In atr/storage/writers/base.py
class WriteAsCommitteeMember:
    async def _validate_project_in_committee(self, project_key: str) -> None:
        """Validate that project belongs to this committee."""
        project = await self._get_project(project_key)
        if project.committee_key != self.committee_key:
            raise storage.AccessError(
                f"Project {project_key} does not belong to "
                f"committee {self.committee_key}"
            )

# Apply in all writer methods:
async def some_operation(self, project_key: str, ...):
    await self._validate_project_in_committee(project_key)
    # ... proceed with operation
```

Add validation that project belongs to the committee context in all storage writer methods.

### Acceptance Criteria
- [ ] Project-committee validation is applied consistently
- [ ] Shared validation exists in base class
- [ ] All writers use consistent validation
- [ ] Test cases verify cross-committee access is blocked
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.3.1.md
- Related findings: FINDING-147
- ASVS sections: 8.3.1

### Priority
Medium

---

## Issue: FINDING-149 - Vote Duration Not Validated Against Release Policy Minimum

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `start()` function in the vote writer accepts a `vote_duration_choice` parameter without validating it against the release's configured minimum voting period (`ReleasePolicy.min_hours`). This allows committee participants to initiate votes with durations shorter than governance requirements, potentially completing votes in 1 hour when policy requires 72 hours.

### Details
Affected location: `atr/storage/writers/vote.py` lines 117-167

The function accepts `vote_duration_choice` and creates a vote task without checking if the duration meets the policy minimum. This allows governance policy bypass.

### Recommended Remediation
Add validation against release policy minimum: check if `vote_duration_choice < release_policy.min_hours` and raise `storage.AccessError` if below minimum:

```python
async def start(self, release_key: str, vote_duration_choice: int, ...):
    """Start vote with policy validation."""
    release = await self._get_release(release_key)
    policy = await self._get_policy(release.project_key)
    
    # Validate against policy minimum
    if policy.min_hours and vote_duration_choice < policy.min_hours:
        raise storage.AccessError(
            f"Vote duration {vote_duration_choice}h is less than "
            f"policy minimum {policy.min_hours}h"
        )
    
    # Proceed with vote creation
    # ... existing code
```

### Acceptance Criteria
- [ ] Vote duration is validated against policy minimum
- [ ] Votes shorter than policy minimum are rejected
- [ ] Error message indicates policy requirement
- [ ] Test cases verify policy enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.3.1.md
- Related findings: FINDING-150
- ASVS sections: 8.3.1

### Priority
Medium

---

## Issue: FINDING-150 - API Model Lacks Input Validation Present in Web Form

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The web form for updating vote policy includes a Pydantic validator ensuring `min_hours` is either 0 or between 72-144 hours. The corresponding API model (`PolicyUpdateArgs`) lacks this validation, allowing JWT-authenticated users to bypass constraints via API requests and set invalid policy values like 1-hour minimum voting periods.

### Details
Affected location: `atr/models/api.py` lines 220-244

The `PolicyUpdateArgs` model accepts `min_hours` without validation, while the web form enforces constraints. This allows API users to bypass validation.

### Recommended Remediation
Add identical Pydantic `model_validator` to `PolicyUpdateArgs` that enforces `min_hours` constraints (0 or 72-144) matching the web form validation in `VotePolicyForm`:

```python
@pydantic.model_validator(mode='after')
def validate_min_hours(self) -> 'PolicyUpdateArgs':
    """Validate min_hours matches web form constraints."""
    if self.min_hours is not None:
        if self.min_hours != 0 and not (72 <= self.min_hours <= 144):
            raise ValueError(
                "min_hours must be 0 (no minimum) or between 72-144 hours"
            )
    return self
```

### Acceptance Criteria
- [ ] API model enforces same validation as web form
- [ ] Invalid min_hours values are rejected
- [ ] Validation is consistent across interfaces
- [ ] Test cases verify API validation
- [ ] Unit test verifying the fix

### References
- Source reports: L1:8.3.1.md
- Related findings: FINDING-149, FINDING-151
- ASVS sections: 8.3.1

### Priority
Medium

---

## Issue: FINDING-151 - API Models Accept Client-Submitted Identity Alongside JWT

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Two API models (`DistributeSshRegisterArgs` and `DistributionRecordFromWorkflowArgs`) accept both a JWT token (containing authenticated identity) and a separate `asf_uid` parameter (client-submitted identity). If handlers use the client-submitted `asf_uid` for authorization decisions or audit logging instead of the JWT-derived identity, attackers could impersonate other users by providing a valid JWT for their own account while submitting another user's `asf_uid`.

### Details
The vulnerability exists in `atr/models/api.py` at lines 69-88 and 113-140. These models accept both authentication mechanisms simultaneously, creating ambiguity about which identity should be trusted. This pattern violates the principle that identity should be derived exclusively from cryptographically verified credentials (JWT subject claim) rather than client-supplied parameters.

### Recommended Remediation
Remove the redundant `asf_uid` field from API models and extract identity exclusively from the JWT subject claim. Alternatively, add a Pydantic model validator that enforces `asf_uid` matches the JWT subject:

```python
@pydantic.model_validator(mode='after')
def validate_identity_matches_jwt(self) -> 'DistributeSshRegisterArgs':
    jwt_subject = get_jwt_subject()  # Extract from current request context
    if self.asf_uid != jwt_subject:
        raise ValueError("Client-submitted identity does not match JWT subject")
    return self
```

### Acceptance Criteria
- [ ] `asf_uid` field removed from both API models, with identity extracted from JWT only
- [ ] OR: Pydantic validator added that enforces `asf_uid` matches JWT subject claim
- [ ] All handlers using these models updated to use JWT-derived identity
- [ ] Unit tests verify that mismatched identities are rejected
- [ ] Audit logging uses JWT-derived identity consistently

### References
- Source reports: L1:8.3.1.md
- Related findings: FINDING-150, FINDING-152
- ASVS sections: 8.3.1

### Priority
Medium

---

## Issue: FINDING-152 - Public API Endpoints Expose Internal Implementation Fields

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Public API endpoints (`/tasks/list`, `/checks/list`, `/releases/list`, `/ssh-keys/list`) return full SQL model objects without field-level filtering, exposing internal implementation details to unauthenticated consumers. Fields like `pid`, `task_args`, `error`, `result`, `asf_uid`, `data`, `inputs_hash`, `checker_version`, `cached`, `check_cache_key`, `release_policy_id`, `vote_manual`, `votes`, `github_payload`, `github_nid`, and `github_uid` are exposed. This violates BOPLA (Break Object Parameter or Level Authorization) principles by providing access to object properties that should be internal-only.

### Details
The issue is systemic across multiple endpoints in `atr/api/__init__.py` (lines 783, 1026) and `atr/models/api.py`. SQL models are serialized directly to JSON responses without applying field filtering based on consumer authorization level. Internal fields intended for debugging, caching, and system operations are exposed to the public internet.

### Recommended Remediation
Define public-safe response models that explicitly include only fields appropriate for public consumption:

```python
class TaskPublicView(pydantic.BaseModel):
    id: int
    status: str
    task_type: str
    project_key: str
    version_key: str
    added: datetime
    completed: Optional[datetime]
    # Exclude: pid, task_args, error, result, asf_uid

class CheckResultPublicView(pydantic.BaseModel):
    id: int
    check_name: str
    status: str
    message: Optional[str]
    # Exclude: inputs_hash, checker_version, cached, check_cache_key
```

Apply field filtering by converting SQL models to Safe models before serialization.

### Acceptance Criteria
- [ ] Public-safe response models created for Task, CheckResult, Release, and SSHKey entities
- [ ] All public API endpoints updated to use filtered response models
- [ ] Internal fields no longer exposed in public API responses
- [ ] Unit tests verify field filtering is applied correctly
- [ ] Integration tests confirm public endpoints return only safe fields

### References
- Source reports: L2:8.2.3.md
- Related findings: FINDING-153
- ASVS sections: 8.2.3

### Priority
Medium

---

## Issue: FINDING-153 - Systemic Absence of Authorization-Based Response Differentiation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application has a reader hierarchy (`ReadAsGeneralPublic` → `ReadAsFoundationCommitter`) that provides different methods based on authorization level, but does not provide different field sets for the same resource. All consumers (public, authenticated committer, committee member, admin) receive identical response structures, violating the principle of least privilege at the field level. This means sensitive fields like vote details, policy configurations, and internal cache keys are exposed to all authorization levels equally.

### Details
The issue spans `atr/api/__init__.py` and `atr/storage/readers/`. While the storage layer implements authorization-based method access, the response serialization does not differentiate field visibility. A public user sees the same Release fields as a PMC member, despite the PMC member having legitimate need for additional details like vote status and policy settings.

### Recommended Remediation
Implement tiered response models based on authorization level:

```python
class ReleasePublicView(pydantic.BaseModel):
    """Basic fields for public consumption"""
    project_key: str
    version_key: str
    phase: str
    created: datetime

class ReleaseMemberView(ReleasePublicView):
    """Additional fields for committee members"""
    vote_status: Optional[str]
    policy_details: dict

class ReleaseAdminView(ReleaseMemberView):
    """All fields including internal metadata"""
    cache_keys: dict
    internal_metadata: dict
```

Apply authorization-based selection in endpoints to return appropriate view level based on authenticated user's role.

### Acceptance Criteria
- [ ] Tiered response models defined for Release, CheckResult, and other sensitive entities
- [ ] Endpoints updated to select response model based on user authorization level
- [ ] Public users receive minimal field set
- [ ] Committee members receive appropriate additional fields
- [ ] Admins receive full field set including internal metadata
- [ ] Unit tests verify correct model selection per authorization level

### References
- Source reports: L2:8.2.3.md
- Related findings: FINDING-152
- ASVS sections: 8.2.3

### Priority
Medium

---

## Issue: FINDING-154 - Dynamic Field Assignment Without Explicit Allowlist in Policy Updates

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The policy update function uses dynamic field assignment via `setattr()` loop without an explicit allowlist, creating risk that future model expansions could inadvertently expose additional writable fields. This violates BOPLA protection principles where field-level write access should be explicit, not derived from model structure. Sibling methods (`edit_compose`, `edit_vote`) use explicit field assignment, creating an inconsistency.

### Details
In `atr/storage/writers/policy.py` lines 117-140, the update function iterates over `update.model_fields_set` and applies changes via `setattr()` without checking against an explicit allowlist of editable fields. If the Pydantic model is expanded with new fields in the future, those fields would automatically become editable through this endpoint without explicit security review.

### Recommended Remediation
Define an explicit allowlist and enforce it:

```python
_EDITABLE_POLICY_FIELDS = frozenset({
    'manual_vote',
    'min_hours',
    'github_repository_name',
    'github_workflow_path',
    # Add other intentionally editable fields
})

def edit_policy(self, policy_id: int, update: PolicyUpdate) -> Outcome:
    policy = self._get_policy(policy_id)
    
    # Intersect with allowlist
    requested_fields = update.model_fields_set
    disallowed_fields = requested_fields - _EDITABLE_POLICY_FIELDS
    
    if disallowed_fields:
        return Outcome.err(f"Cannot edit fields: {disallowed_fields}")
    
    for field_name in requested_fields & _EDITABLE_POLICY_FIELDS:
        setattr(policy, field_name, getattr(update, field_name))
```

This ensures field editability is explicitly controlled rather than implicitly derived from the Pydantic model structure.

### Acceptance Criteria
- [ ] `_EDITABLE_POLICY_FIELDS` allowlist defined as frozenset
- [ ] Update function validates requested fields against allowlist
- [ ] Disallowed fields rejected with clear error message
- [ ] Unit tests verify allowlist enforcement
- [ ] Unit tests verify future model additions don't automatically become editable
- [ ] Documentation updated to reflect explicit field control

### References
- Source reports: L2:8.2.3.md
- Related findings: None
- ASVS sections: 8.2.3

### Priority
Medium

---

## Issue: FINDING-155 - Pagination Offset Validation Disabled by Typo

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
A typo in the pagination validation function (`'offest'` instead of `'offset'`) prevents offset boundary enforcement, allowing unbounded pagination that facilitates bulk data extraction beyond intended security design limits. The validation function checks `hasattr(query_args, 'offest')` which will always be False, preventing the offset limit (max 1,000,000) from being enforced. While SQLite handles large offsets reasonably and limit validation is still enforced (max 1000 rows), this represents a defense-in-depth gap allowing unbounded offset values that may cause expensive database queries or resource exhaustion.

### Details
The typo exists in `atr/api/__init__.py` lines 1338-1352. The validation function is called from multiple pagination endpoints (lines 456, 502, 565, 812-824) but never actually validates offset values due to the attribute name mismatch. This means attackers can specify `offset=999999999` and the validation check is bypassed.

### Recommended Remediation
Fix the typo:

```python
# In atr/api/__init__.py, line ~1340
if hasattr(query_args, "offset"):  # Fixed: was "offest"
    if query_args.offset < 0:
        raise base.BadRequest("offset must be >= 0")
    if query_args.offset > 1_000_000:
        raise base.BadRequest("offset must be <= 1,000,000")
```

Add comprehensive testing:

```python
def test_offset_validation_enforced():
    """Verify offset validation works after typo fix"""
    with pytest.raises(base.BadRequest, match="offset must be <= 1,000,000"):
        response = client.get("/api/releases/list?offset=2000000")

def test_offset_validation_negative():
    """Verify negative offsets are rejected"""
    with pytest.raises(base.BadRequest, match="offset must be >= 0"):
        response = client.get("/api/releases/list?offset=-1")
```

Add to code review checklist: "Validate attribute names in `hasattr()` checks match actual model field names"

### Acceptance Criteria
- [ ] Typo fixed: `'offest'` changed to `'offset'`
- [ ] Unit test added verifying offset=2000000 raises BadRequest
- [ ] Unit test added verifying offset=-1 raises BadRequest
- [ ] Integration tests added for each affected endpoint
- [ ] Error message verification tests added
- [ ] Code review checklist updated with hasattr() validation item

### References
- Source reports: L2:8.2.3.md, L2:8.1.2.md
- Related findings: None
- ASVS sections: 8.2.3, 8.1.2

### Priority
Medium

---

## Issue: FINDING-156 - Unvalidated Identity Parameter in Email and Vote Operations

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Committee member methods accept `asf_uid` as a parameter while also having `self.__asf_uid` from the authorization constructor. This creates risk where the storage layer has the correct identity but doesn't enforce it for all operations, potentially allowing email impersonation and authorization bypass. A committee member could invoke methods with another user's `asf_uid`, causing announcement/vote emails to be sent as `{other_user}@apache.org`, recipient lists determined by another user's permissions, and tasks attributed to the wrong user.

### Details
The issue exists in `atr/storage/writers/announce.py` lines 99-183 and `atr/storage/writers/vote.py` lines 87-141 and 252-307. Methods like `send_announcement()` and `send_vote()` accept an `asf_uid` parameter despite having access to the authenticated identity via `self.__asf_uid`. This dual-identity pattern creates confusion about which identity should be used for authorization decisions and audit logging.

### Recommended Remediation
**Option 1 (Preferred):** Remove the `asf_uid` parameter and always use `self.__asf_uid`:

```python
def send_announcement(self, project_key: str, version_key: str, ...) -> Outcome:
    # Use self.__asf_uid instead of accepting parameter
    sender_uid = self.__asf_uid
    sender_email = f"{sender_uid}@apache.org"
    # ... rest of implementation
```

**Option 2:** Add validation assertion:

```python
def send_announcement(self, asf_uid: str, project_key: str, ...) -> Outcome:
    if asf_uid != self.__asf_uid:
        raise AccessError(f"Identity mismatch: {asf_uid} != {self.__asf_uid}")
    # ... rest of implementation
```

This ensures operational identity (for emails, tasks) matches the authenticated identity.

### Acceptance Criteria
- [ ] `asf_uid` parameter removed from announcement and vote methods
- [ ] All method implementations updated to use `self.__asf_uid`
- [ ] OR: Validation assertion added to verify parameter matches authenticated identity
- [ ] Unit tests verify identity mismatch raises AccessError (if using Option 2)
- [ ] Integration tests verify emails are sent with correct sender identity
- [ ] Audit logs verified to contain correct authenticated identity

### References
- Source reports: L2:8.2.3.md
- Related findings: None
- ASVS sections: 8.2.3

### Priority
Medium

---

## Issue: FINDING-157 - Missing Authorization Documentation for Distribution/SSH/Keys/Policy/Project Operations

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The authorization documentation (`atr/docs/authorization-security.md`) comprehensively covers releases, tokens, and check ignores, but lacks documented authorization rules for Distribution Management, SSH/Rsync Access Control, Key Management, Policy Management, Project Management, and Admin Operations. These operations have authorization controls implemented via the storage layer and explicit checks, but without documentation, they cannot be systematically verified during security audits or developer onboarding.

### Details
The missing documentation areas include:
- Distribution Management (automate, record, delete operations)
- SSH/Rsync Access Control (read/write phase restrictions, path validation)
- Key Management (OpenPGP and SSH key operations, committee associations)
- Policy Management (compose/vote/finish settings, workflow configuration)
- Project Management (create, delete, lifecycle operations)
- Admin Operations (beyond token revocation)

Without comprehensive documentation, security reviewers cannot verify complete authorization coverage, and developers may inadvertently introduce authorization gaps.

### Recommended Remediation
Add comprehensive sections to `atr/docs/authorization-security.md`:

1. **Distribution Management Authorization**
   - Document automate, record, delete operations
   - Specify committee member requirements
   - Document phase-based restrictions

2. **SSH/Rsync Access Authorization**
   - Create phase-based access control matrix
   - Document path validation rules
   - Specify read/write restrictions by phase

3. **Key Management Authorization**
   - Document OpenPGP operations (add, remove, associate)
   - Document SSH key operations
   - Specify ownership and committee participation requirements

4. **Policy Management Authorization**
   - Document compose/vote/finish policy updates
   - Specify PMC member requirements

5. **Project Management Authorization**
   - Document create/delete/update operations
   - Specify authorization requirements

6. **Admin Operations Authorization**
   - Complete list of admin-only operations
   - Document admin impersonation controls

Add operation-level authorization matrix to each storage writer module docstring. Create `atr/docs/authorization-matrix.md` with comprehensive endpoint mapping.

### Acceptance Criteria
- [ ] Distribution Management section added to authorization-security.md
- [ ] SSH/Rsync Access section added with phase-based matrix
- [ ] Key Management section added with operation details
- [ ] Policy Management section added
- [ ] Project Management section added
- [ ] Admin Operations section added with complete operation list
- [ ] authorization-matrix.md created with endpoint mapping
- [ ] Storage writer module docstrings updated with authorization details
- [ ] Developer guide updated with authorization examples

### References
- Source reports: L1:8.1.1.md
- Related findings: FINDING-158, FINDING-159, FINDING-160
- ASVS sections: 8.1.1

### Priority
Medium

---

## Issue: FINDING-158 - Phase-Based Authorization Rules Not Consolidated

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Release lifecycle phases govern which operations are permitted, but these phase-based authorization rules are scattered across multiple files (`atr/get/download.py`, `atr/ssh.py`, `atr/storage/writers/release.py`, `atr/get/vote.py`) with no consolidated reference. A developer or auditor must trace through multiple code paths to understand the complete phase access matrix. This makes it difficult to verify complete phase authorization coverage, ensure consistent enforcement, and maintain the authorization model.

### Details
Phase-based rules are implemented in:
- `atr/get/download.py` - download restrictions by phase
- `atr/ssh.py` - SSH access restrictions by phase
- `atr/storage/writers/release.py` - phase transition logic
- `atr/get/vote.py` - voting restrictions by phase
- `atr/post/upload.py` - upload restrictions by phase

Without consolidated documentation, it's unclear whether all operations correctly enforce phase restrictions, and future modifications may introduce inconsistencies.

### Recommended Remediation
Add consolidated phase access matrix to `atr/docs/authorization-security.md`:

```markdown
## Phase-Based Access Control

### Phase Definitions
| Phase | Description | Purpose |
|-------|-------------|---------|
| RELEASE_CANDIDATE_DRAFT | Initial creation | Artifact upload and editing |
| RELEASE_CANDIDATE | Voting phase | Community review and voting |
| RELEASE_PREVIEW | Post-vote preview | Final verification before release |
| RELEASE | Published release | Public distribution |

### Operation Access by Phase Matrix
| Operation | DRAFT | CANDIDATE | PREVIEW | RELEASE | Authorization |
|-----------|-------|-----------|---------|---------|---------------|
| Upload artifacts | ✓ | ✗ | ✗ | ✗ | Project participants |
| SSH write access | ✓ | ✗ | ✗ | ✗ | Project participants |
| SSH read access | ✓ | ✓ | ✓ | ✗ | Project participants |
| Start vote | ✓ | ✗ | ✗ | ✗ | PMC members |
| Cast vote | ✗ | ✓ | ✗ | ✗ | PMC members |
| Resolve vote | ✗ | ✓ | ✗ | ✗ | PMC members |
| Promote to preview | ✗ | ✓ | ✗ | ✗ | PMC members (after vote) |
| Announce release | ✗ | ✗ | ✓ | ✗ | PMC members |
| Download artifacts | ✓ | ✓ | ✓ | ✓ | Public (phase-dependent) |

### Phase Transition Requirements
| Transition | Required Conditions | Authorization |
|------------|---------------------|---------------|
| DRAFT → CANDIDATE | No blocker checks, has files, no ongoing tasks | Project participants |
| CANDIDATE → PREVIEW | Vote resolved successfully, distribution automated | PMC members |
| PREVIEW → RELEASE | Announcement sent | PMC members |
| Any → DRAFT | Cancellation | PMC members or admins |

### Enforcement Locations
- SSH access: `atr/ssh.py` lines 283-323
- Phase transitions: `atr/storage/writers/release.py` lines 180-220
- Vote operations: `atr/storage/writers/vote.py` lines 45-60
- Announcements: `atr/storage/writers/announce.py` lines 83-84
```

Add phase validation helper function to reduce code duplication. Add phase transition audit logging. Create phase transition diagram in documentation.

### Acceptance Criteria
- [ ] Phase access matrix added to authorization-security.md
- [ ] Phase definitions table documented
- [ ] Operation access by phase matrix created
- [ ] Phase transition requirements documented
- [ ] Enforcement locations documented with code references
- [ ] Phase validation helper function created
- [ ] Phase transition audit logging added
- [ ] Phase transition diagram created
- [ ] Phase-based integration tests added for all operations

### References
- Source reports: L1:8.1.1.md
- Related findings: FINDING-157, FINDING-160
- ASVS sections: 8.1.1

### Priority
Medium

---

## Issue: FINDING-159 - Authorization Documentation Lacks Field-Level Write Access Restrictions

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Authorization documentation defines operation-level access (who can start releases, resolve votes, etc.) but does not specify which fields of each entity each role can write, or how field access changes based on resource state. ASVS 8.1.2 explicitly requires documentation of "field-level access restrictions (both read and write) based on consumer permissions and resource attributes." Undocumented field-level rules exist in code including: `Release.phase` (only via state transitions), `Release.vote_resolved` (PMC members only, RELEASE_CANDIDATE phase only), `ReleasePolicy.manual_vote` (PMC members; disallowed for podlings), `ReleasePolicy.min_hours` (PMC members; must be 0 or 72-144), and others.

### Details
The issue spans `atr/docs/authorization-security.md`, `atr/docs/storage-interface.md`, and storage writer modules. While field-level restrictions are implemented in code (e.g., `atr/storage/writers/release.py`, `atr/storage/writers/policy.py`, `atr/storage/writers/checks.py` lines 87-130), they are not documented in a systematic, auditable format.

### Recommended Remediation
Add field-level access matrix to `authorization-security.md`:

```markdown
## Field-Level Write Access Restrictions

### Release Entity
| Field | Writable By | Conditions | Constraints |
|-------|-------------|------------|-------------|
| phase | Project participants, PMC members | Via state transitions only | Must follow transition rules |
| vote_resolved | PMC members | RELEASE_CANDIDATE phase only | Boolean value |
| vote_started | PMC members | DRAFT phase, ready for vote | Timestamp |
| artifacts | Project participants | DRAFT phase only | File uploads |

### ReleasePolicy Entity
| Field | Writable By | Conditions | Constraints |
|-------|-------------|------------|-------------|
| manual_vote | PMC members | Not for podlings | Boolean |
| min_hours | PMC members | - | 0 or 72-144 |
| github_repository_name | PMC members | Valid repository format | String pattern |
| github_workflow_path | PMC members | Valid path format | String pattern |

### CheckResultIgnore Entity
| Field | Writable By | Conditions | Constraints |
|-------|-------------|------------|-------------|
| pattern | PMC members | Valid regex | Regex pattern |
| reason | PMC members | - | Non-empty string |
| asf_uid | System | Ownership transfer on delete | Immutable after creation |

### PublicSigningKey Entity
| Field | Writable By | Conditions | Constraints |
|-------|-------------|------------|-------------|
| key_data | Committee participants | Valid key format | PGP key block |
| committee_id | Committee participants | Member of target committee | Foreign key |
```

Include verification steps: create field-level access matrix document, review all storage writer methods to extract field rules, document ownership transfer behaviors, document immutable fields, cross-reference with operation-level documentation, add to security review checklist.

### Acceptance Criteria
- [ ] Field-level access matrix added for Release entity
- [ ] Field-level access matrix added for ReleasePolicy entity
- [ ] Field-level access matrix added for CheckResultIgnore entity
- [ ] Field-level access matrix added for PublicSigningKey entity
- [ ] Ownership transfer behaviors documented
- [ ] Immutable fields documented
- [ ] Cross-references added to operation-level documentation
- [ ] Security review checklist updated with field-level review items

### References
- Source reports: L2:8.1.2.md
- Related findings: FINDING-157, FINDING-160
- ASVS sections: 8.1.2

### Priority
Medium

---

## Issue: FINDING-160 - State-Dependent Access Rules Not Systematically Documented

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The Release entity has four phases (RELEASE_CANDIDATE_DRAFT, RELEASE_CANDIDATE, RELEASE_PREVIEW, RELEASE) that fundamentally change permitted operations and field modifications. ASVS 8.1.2 explicitly requires documentation of rules that "depend on other attribute values of the relevant data object, such as state or status." While some phase-dependent rules are documented at operation level, systematic field-level state-dependent rules are not documented. Undocumented state-dependent rules include phase transition requirements, SSH access by phase, distribution requirements for transitions, and vote resolution restrictions.

### Details
State-dependent rules are scattered across:
- `atr/storage/writers/announce.py` lines 83-84 (announcement phase requirements)
- `atr/ssh.py` lines 283-323 (SSH access by phase)
- `atr/storage/writers/release.py` lines 180-220 (phase transitions)
- `atr/storage/writers/vote.py` lines 45-60 (vote resolution phase)

Without systematic documentation, developers cannot easily understand the complete state machine and may introduce bugs or security gaps.

### Recommended Remediation
Add state machine documentation to `authorization-security.md`:

```markdown
## State-Dependent Access Rules

### State Transitions
| Current Phase | Allowed Transition | Required Role | Additional Conditions |
|--------------|-------------------|---------------|----------------------|
| DRAFT | → CANDIDATE | Project participants | No blocker checks, has files, no ongoing tasks |
| CANDIDATE | → PREVIEW | PMC members | Vote resolved successfully, distribution automated |
| PREVIEW | → RELEASE | PMC members | Announcement sent to mailing lists |
| Any | → DRAFT | PMC members/admins | Cancellation or rollback |

### Field Access by Phase
| Field | DRAFT | CANDIDATE | PREVIEW | RELEASE | Notes |
|-------|-------|-----------|---------|---------|-------|
| artifacts (write) | ✓ | ✗ | ✗ | ✗ | Upload only in DRAFT |
| vote_resolved (write) | ✗ | ✓ | ✗ | ✗ | PMC members only |
| announcement_sent | ✗ | ✗ | ✓ | ✗ | System-managed |

### Operation Availability by Phase
| Operation | DRAFT | CANDIDATE | PREVIEW | RELEASE | Authorization |
|-----------|-------|-----------|---------|---------|---------------|
| Upload artifacts | ✓ | ✗ | ✗ | ✗ | Project participants |
| Start vote | ✓ | ✗ | ✗ | ✗ | PMC members |
| Cast vote | ✗ | ✓ | ✗ | ✗ | PMC members |
| Resolve vote | ✗ | ✓ | ✗ | ✗ | PMC members |
| Send announcement | ✗ | ✗ | ✓ | ✗ | PMC members |

### SSH/Rsync Access by Phase
| Phase | Read Access | Write Access | Rationale |
|-------|-------------|--------------|-----------|
| DRAFT | ✓ | ✓ | Active development |
| CANDIDATE | ✓ | ✗ | Voting requires immutable artifacts |
| PREVIEW | ✓ | ✗ | Final verification before release |
| RELEASE | ✗ | ✗ | Use distribution channels |

### Distribution State Requirements
- **PREVIEW → RELEASE transition:** Requires announcement sent to appropriate mailing lists
- **Distribution automation:** Must complete before CANDIDATE → PREVIEW transition
```

Add verification steps: create state machine diagram, document preconditions for each transition, create field access matrix by phase, document operation availability by phase, add state machine tests, include in developer onboarding.

### Acceptance Criteria
- [ ] State transition table added to documentation
- [ ] Field access by phase matrix created
- [ ] Operation availability by phase documented
- [ ] SSH/Rsync access by phase documented with rationale
- [ ] Distribution state requirements documented
- [ ] State machine diagram created
- [ ] State machine tests added to verify documented behavior
- [ ] Documentation included in developer onboarding materials

### References
- Source reports: L2:8.1.2.md
- Related findings: FINDING-157, FINDING-158, FINDING-159
- ASVS sections: 8.1.2

### Priority
Medium

---

## Issue: FINDING-161 - Authorization Documentation Lacks Field-Level Read Access Restrictions

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Documentation states "View release information: Allowed for: Everyone" but does not specify which fields are exposed to unauthenticated vs. authenticated users. ASVS 8.1.2 requires documentation of field-level access restrictions for both read and write operations. Code implements different reader classes (`ReadAsGeneralPublic`, `ReadAsFoundationCommitter`) suggesting differentiated read access exists but is not documented. Undocumented field-level read restrictions include: `PersonalAccessToken.token_hash` (never returned), `PersonalAccessToken.token_id/name/created` (owner only), `Release.votes` (access level not specified), `Committee.committee_members` (public via API), `WorkflowStatus.task_args` (public, may contain email addresses), and SSH key fingerprints (public in API).

### Details
The issue spans `atr/docs/authorization-security.md`, `atr/storage/__init__.py` lines 69-85, and various reader modules. While read access differentiation is implemented in code through `ReadAs*` classes, the documentation does not specify which fields are accessible at each authorization level.

### Recommended Remediation
Document field-level read access matrix in `authorization-security.md`:

```markdown
## Field-Level Read Access Restrictions

### Release Files
| Field | Public | Committer | PMC Member | Admin | Rationale |
|-------|--------|-----------|------------|-------|-----------|
| file_path | ✓ | ✓ | ✓ | ✓ | Public verification |
| file_hash | ✓ | ✓ | ✓ | ✓ | Public verification |
| file_size | ✓ | ✓ | ✓ | ✓ | Public information |

**Rationale for public access:** Pre-vote verification requires public access to release artifacts and metadata.

### Personal Access Tokens
| Field | Owner | Other Users | Admin | Notes |
|-------|-------|-------------|-------|-------|
| token_id | ✓ | ✗ | ✓ | Identifier only |
| name | ✓ | ✗ | ✓ | User-defined label |
| token_hash | ✗ | ✗ | ✗ | Never exposed |
| created | ✓ | ✗ | ✓ | Timestamp |

### Committee Data
| Field | Public | Committer | Member | Admin | Notes |
|-------|--------|-----------|--------|-------|-------|
| committee_name | ✓ | ✓ | ✓ | ✓ | Public information |
| committee_members | ✓ | ✓ | ✓ | ✓ | Public via API |
| committee_type | ✓ | ✓ | ✓ | ✓ | Public information |

### Workflow Status
| Field | Public | Committer | Member | Admin | Privacy Concern |
|-------|--------|-----------|--------|-------|-----------------|
| task_type | ✓ | ✓ | ✓ | ✓ | No PII |
| task_args | ✓ | ✓ | ✓ | ✓ | ⚠️ May contain email addresses |
| status | ✓ | ✓ | ✓ | ✓ | No PII |
| error | ✓ | ✓ | ✓ | ✓ | May contain internal paths |

**Privacy Impact:** `task_args` is publicly readable and may contain email addresses. Consider sanitization.
```

Add verification steps: audit all `ReadAs*` classes to extract field-level access, document intentional public access, document sensitive fields never exposed, add privacy impact assessment for publicly readable fields, create checklist for new fields.

### Acceptance Criteria
- [ ] Release Files field-level read access documented
- [ ] Personal Access Tokens field-level read access documented
- [ ] Committee Data field-level read access documented
- [ ] Workflow Status field-level read access documented with privacy notes
- [ ] Rationale provided for intentional public access
- [ ] Privacy impact assessment added for publicly readable fields
- [ ] Checklist created for reviewing new field additions
- [ ] Documentation cross-referenced with ReadAs* class implementations

### References
- Source reports: L2:8.1.2.md
- Related findings: FINDING-152, FINDING-153
- ASVS sections: 8.1.2

### Priority
Medium

---

## Issue: FINDING-162 - ATR JWTs Lack Explicit Token Type Identification

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
ATR JWTs do not include an explicit token type indicator. Neither a `typ` header (e.g., `at+jwt` per RFC 9068) nor a custom `token_type` claim is present. The `verify()` function does not validate any token type field. While no active exploits exist due to robust architectural separation (algorithm, audience, issuer differences), this represents a defense-in-depth gap. If ATR evolves to issue additional JWT types (e.g., refresh tokens, delegation tokens), the absence of an explicit type field would create cross-usage risk within the same issuer context.

### Details
The issue exists in `atr/jwtoken.py` lines 70-83 (token issuance) and 104-137 (token verification). Current tokens contain standard claims (sub, iat, exp, aud, iss) but lack type identification. While existing architectural controls prevent cross-usage with external systems, future expansion of JWT usage within ATR could introduce risks.

### Recommended Remediation
Add explicit token type indicators:

```python
def issue(self, uid: str) -> str:
    """Issue a JWT with explicit type indicators."""
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    claims = {
        "sub": uid,
        "iat": now,
        "exp": now + self.ttl,
        "aud": self.audience,
        "iss": self.issuer,
        "token_type": "atr_api_access",  # Custom claim
    }
    
    # Add typ header per RFC 9068
    return jwt.encode(
        claims,
        self.secret,
        algorithm="HS256",
        headers={"typ": "at+jwt"}
    )

def verify(self, token: str) -> dict:
    """Verify JWT with type validation."""
    try:
        decoded = jwt.decode(
            token,
            self.secret,
            algorithms=["HS256"],
            audience=self.audience,
            issuer=self.issuer,
        )
        
        # Validate token type
        if decoded.get("token_type") != "atr_api_access":
            raise jwt.InvalidTokenError("Invalid token type")
        
        return decoded
    except jwt.InvalidTokenError:
        return {}
```

This future-proofs against token type expansion and improves defense-in-depth.

### Acceptance Criteria
- [ ] `typ: "at+jwt"` header added to issued tokens
- [ ] `token_type: "atr_api_access"` claim added to payload
- [ ] `verify()` function validates both type indicators
- [ ] Unit tests verify type validation enforcement
- [ ] Unit tests verify tokens without type indicators are rejected
- [ ] Documentation updated to describe token type validation

### References
- Source reports: L2:9.2.2.md
- Related findings: None
- ASVS sections: 9.2.2
- CWE: CWE-345

### Priority
Medium

---

## Issue: FINDING-163 - Authorization Code Not URL-Encoded in Token Exchange Request

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
The authorization code received from the OAuth callback is interpolated directly into the token exchange URL without URL encoding (`rv = await session.get(OAUTH_URL_CALLBACK % code)`). If the authorization code contains URL-special characters (&, =, #, %), the request URL would be malformed. An attacker controlling the code parameter could potentially inject additional query parameters (e.g., `code=legit_code&client_id=other_client`), confusing server-side logic or bypassing validation checks. While OAuth authorization codes are typically alphanumeric-only by AS design and the token endpoint should reject invalid codes, this practice violates defensive programming principles and could lead to parameter injection if the AS code format changes.

### Details
The vulnerability exists in `src/asfquart/generics.py` line 109, where the authorization code is directly interpolated into `OAUTH_URL_CALLBACK` (defined at lines 12-14) using Python string formatting without URL encoding.

### Recommended Remediation
Apply URL-encoding to the authorization code before interpolation:

**Option 1 (Simple):**
```python
import urllib.parse

rv = await session.get(OAUTH_URL_CALLBACK % urllib.parse.quote(code, safe=''))
```

**Option 2 (Preferred):**
```python
import urllib.parse

# Parse the callback URL and add code as a proper query parameter
callback_url_base = OAUTH_URL_CALLBACK.split('?')[0]
rv = await session.get(callback_url_base, params={'code': code})
```

This ensures proper encoding regardless of code content and prevents parameter injection attacks.

### Acceptance Criteria
- [ ] Authorization code URL-encoded before interpolation
- [ ] Unit tests verify proper encoding of special characters
- [ ] Unit tests verify parameter injection attempts are prevented
- [ ] Integration tests verify OAuth flow works with encoded codes
- [ ] Code review confirms no other URL interpolation vulnerabilities

### References
- Source reports: L1:10.4.1.md, L1:10.4.2.md, L1:10.4.4.md, L2:10.4.7.md
- Related findings: None
- ASVS sections: 10.4.1, 10.4.2, 10.4.4, 10.4.7
- CWE: CWE-74

### Priority
Medium

---

## Issue: FINDING-164 - Dynamic OAuth Callback URL Constructed from Host Header

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The OAuth `redirect_uri` parameter is dynamically derived from the HTTP Host header (`callback_host = quart.request.host_url.replace('http://', 'https://')`). This violates ASVS 10.4.1 because: (1) The client sends a variable callback URL instead of a fixed, pre-registered one; (2) If the deployment violates the documented `ProxyPreserveHost On` assumption, an attacker controlling the Host header can craft an arbitrary callback URL; (3) If the authorization server uses pattern-based or prefix matching instead of exact string comparison, the authorization code could be redirected to an attacker-controlled domain. This could lead to authorization code theft and account takeover, contingent on AS redirect URI validation strictness and deployment configuration.

### Details
The vulnerability exists in `src/asfquart/generics.py` lines 63-68, where the callback URL is constructed from `quart.request.host_url`. This creates a dynamic redirect URI that varies based on the incoming request's Host header.

### Recommended Remediation
Pre-configure the callback host using an environment variable instead of deriving it from the request:

```python
import os
import urllib.parse

# In configuration
CALLBACK_HOST = os.environ.get('OAUTH_CALLBACK_HOST', 'https://myapp.apache.org')

# Modify setup_oauth() to accept callback_host parameter
def setup_oauth(app, uri: str, callback_host: str):
    @app.route(uri)
    async def oauth_endpoint():
        state = secrets.token_urlsafe(16)
        # Use fixed callback_host instead of request.host_url
        callback_url = urllib.parse.urljoin(callback_host, f'{uri}?state={state}')
        # ... rest of implementation
```

This ensures the callback URL is fixed and can be pre-registered with exact string matching at the Authorization Server.

### Acceptance Criteria
- [ ] `OAUTH_CALLBACK_HOST` environment variable added to configuration
- [ ] `setup_oauth()` modified to accept `callback_host` parameter
- [ ] Callback URL constructed from fixed configuration instead of Host header
- [ ] Unit tests verify callback URL is not affected by Host header
- [ ] Integration tests verify OAuth flow with fixed callback URL
- [ ] Documentation updated with required environment variable
- [ ] Deployment guide updated to emphasize fixed callback URL registration

### References
- Source reports: L1:10.4.1.md
- Related findings: FINDING-273
- ASVS sections: 10.4.1
- CWE: CWE-601

### Priority
Medium

---

## Issue: FINDING-165 - OAuth Client Does Not Request Explicit Scopes (Principle of Least Privilege)

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The OAuth authorization request does not include a `scope` parameter. ATR receives whatever data `oauth.apache.org` returns by default without requesting only the minimum claims needed (e.g., `uid`, `dn`, `fullname`). While scope assignment is the Authorization Server's responsibility, the OAuth client should request only the scopes it needs per the principle of least privilege (OAuth 2.0 Security Best Current Practice §2.4). If `oauth.apache.org` returns more data than ATR needs, it increases the surface area of session data that could be exposed in a session compromise.

### Details
The issue exists in `src/asfquart/generics.py` line 11 (OAUTH_URL_INIT definition) and lines 36-50 (oauth_endpoint implementation). The authorization URL does not include a scope parameter, relying entirely on the Authorization Server's default scope assignment.

### Recommended Remediation
Add explicit scope parameter to the OAuth authorization URL:

```python
OAUTH_URL_INIT = 'https://oauth.apache.org/auth-oidc?state=%s&redirect_uri=%s&scope=openid+uid+dn+fullname'
```

Coordinate with `oauth.apache.org` maintainers to verify:
1. Whether the service supports granular scope parameters
2. What the current client registration assigns
3. Whether client-side scope requests are honored

If not supported, document as accepted risk and ensure AS-side client registration is minimal.

**Alternative if scope parameters are not supported:**
```markdown
# In SECURITY.md or architecture documentation

## OAuth Scope Limitation

**Accepted Risk:** oauth.apache.org does not support client-side scope requests.

**Mitigation:** 
- Client registration at oauth.apache.org configured for minimal scope
- Session data filtered to store only required fields (uid, dn, fullname)
- Periodic review of oauth.apache.org client configuration
```

### Acceptance Criteria
- [ ] Scope parameter added to OAuth authorization URL
- [ ] Coordination completed with oauth.apache.org maintainers
- [ ] Verification that scope requests are honored
- [ ] OR: Accepted risk documented if scope parameters not supported
- [ ] Session data storage verified to include only necessary fields
- [ ] Unit tests verify only expected fields are stored in session
- [ ] Documentation updated with scope requirements

### References
- Source reports: L2:10.4.11.md
- Related findings: FINDING-280, FINDING-281
- ASVS sections: 10.4.11

### Priority
Medium

---

## Issue: FINDING-166 - OAuth Token Exchange Uses Default SSL Context Without Hardened TLS Configuration

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
The OAuth token exchange—a security-critical operation that retrieves user authentication credentials—creates a plain `aiohttp.ClientSession()` without the hardened SSL context used throughout the rest of the application. While `aiohttp`'s default behavior validates certificates and checks hostnames on modern systems, the absence of explicit `minimum_version = TLSv1_2` enforcement means the session may negotiate TLS 1.0/1.1 on systems where these protocols are not disabled at the OpenSSL level. This creates an inconsistency with security controls applied to all other outbound connections (GitHub OIDC, GitHub API, OSV, mailing lists), which all use the centralized `util.create_secure_ssl_context()` factory.

### Details
The vulnerability exists in `src/asfquart/generics.py` lines 76-95, where a default `aiohttp.ClientSession()` is created for the OAuth token exchange without applying the hardened SSL context used elsewhere in the application.

### Recommended Remediation
Replace the default aiohttp.ClientSession() with the existing secure session factory:

**Option 1 (Recommended):**
```python
import aiohttp
from atr import util

ct = aiohttp.ClientTimeout(sock_read=15)
async with util.create_secure_session(timeout=ct) as session:
    rv = await session.get(OAUTH_URL_CALLBACK % code)
```

**Option 2 (If circular dependency exists):**
```python
import ssl
import aiohttp

ct = aiohttp.ClientTimeout(sock_read=15)
ssl_ctx = ssl.create_default_context()
ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
connector = aiohttp.TCPConnector(ssl=ssl_ctx)
async with aiohttp.ClientSession(timeout=ct, connector=connector) as session:
    rv = await session.get(OAUTH_URL_CALLBACK % code)
```

**Option 3 (Minimal):**
Create a local secure session factory with explicit TLS 1.2+ enforcement, CERT_REQUIRED, and check_hostname=True.

### Acceptance Criteria
- [ ] OAuth token exchange uses hardened SSL context
- [ ] TLS 1.2+ minimum version enforced
- [ ] Certificate validation and hostname checking enabled
- [ ] Integration test added to verify OAuth uses hardened SSL context
- [ ] Unit tests verify TLS 1.0/1.1 connections are rejected
- [ ] Code review confirms consistent SSL context usage across application

### References
- Source reports: L1:12.2.1.md, L1:12.2.2.md, L2:12.1.2.md
- Related findings: FINDING-167
- ASVS sections: 12.2.1, 12.2.2, 12.1.2
- CWE: CWE-757

### Priority
Medium

---

## Issue: FINDING-167 - Outbound TLS Connections Do Not Restrict to AEAD-Only Ciphers

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The outbound TLS SSL context creation function (`create_secure_ssl_context()`) does not explicitly restrict cipher suites to AEAD-only algorithms. While the function is documented as creating a "secure SSL context compliant with ASVS 9.1.1 and 9.1.2," it relies on Python's `ssl.create_default_context()` defaults, which include CBC-mode cipher suites. If an outbound connection targets a server that only supports TLS 1.2 with AES-CBC cipher suites, the Python ssl.create_default_context() would negotiate and use the CBC cipher. This creates a gap between hardened inbound TLS configuration (Apache: AEAD-only) and permissive outbound configuration, and does not fully meet ASVS 11.3.2's requirement for "only approved ciphers and modes such as AES with GCM".

### Details
The issue exists in `atr/util.py` lines 254-263 (create_secure_ssl_context function), line 396, and `atr/jwtoken.py` line 152. The function creates a secure SSL context but does not explicitly restrict cipher suites to AEAD-only algorithms.

### Recommended Remediation
Add explicit AEAD-only cipher suite restriction to create_secure_ssl_context():

```python
def create_secure_ssl_context() -> ssl.SSLContext:
    """Create a secure SSL context compliant with ASVS 9.1.1, 9.1.2, and 11.3.2."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # Restrict to AEAD-only cipher suites, matching inbound Apache TLS config
    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    )
    
    return ctx
```

**Alternative (more restrictive):**
If TLS 1.3 is available on target servers, set `ctx.minimum_version = ssl.TLSVersion.TLSv1_3` (TLS 1.3 only uses AEAD ciphers by design).

### Acceptance Criteria
- [ ] AEAD-only cipher suite restriction added to create_secure_ssl_context()
- [ ] Unit tests verify only AEAD cipher suites are negotiated
- [ ] Integration tests verify connections to TLS 1.2 servers use AEAD ciphers
- [ ] Unit tests verify CBC cipher suites are rejected
- [ ] Documentation updated to reflect AEAD-only requirement
- [ ] Code review confirms consistent cipher suite enforcement

### References
- Source reports: L1:11.3.2.md
- Related findings: FINDING-166
- ASVS sections: 11.3.2

### Priority
Medium

---

## Issue: FINDING-168 - Development Virtual Host Missing Comprehensive TLS Hardening Configuration

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The development virtual host (`tooling-vm-ec2-de.apache.org`) is publicly accessible and hosts the ATR development instance. While it has `force_tls: true` for HTTP-to-HTTPS redirection, it lacks the TLS protocol restrictions, cipher suite hardening, HSTS headers, and security headers present in the staging environment configuration (`release-test.apache.org`). This configuration drift creates several risks: legacy TLS versions (1.0/1.1) may be negotiated, weak cipher suites may be accepted, no HSTS protection for first-time visitors, and increased risk of production misconfiguration due to environment differences.

### Details
The issue exists in `tooling-vm-ec2-de.apache.org.yaml` lines 112-170. The staging vhost includes explicit TLS hardening (SSLProtocol, SSLCipherSuite, session security, compression) and security headers (HSTS with 2-year max-age, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) that are completely absent from the dev vhost.

### Recommended Remediation
Apply identical TLS hardening configuration to the development vhost by adding the following directives (matching the staging configuration):

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLProxyProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305
SSLOpenSSLConfCmd Curves X25519:prime256v1:secp384r1
SSLSessionTickets off
SSLCompression off
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Referrer-Policy "same-origin"
```

Verify with:
- `openssl s_client -connect tooling-vm-ec2-de.apache.org:443 -tls1_1` (should fail)
- `curl -I https://tooling-vm-ec2-de.apache.org` (should show HSTS header)

### Acceptance Criteria
- [ ] TLS protocol restrictions added to dev vhost (TLS 1.2+ only)
- [ ] AEAD-only cipher suite configuration added
- [ ] HSTS header added with 2-year max-age
- [ ] X-Content-Type-Options header added
- [ ] X-Frame-Options header added
- [ ] Referrer-Policy header added
- [ ] Verification tests pass (TLS 1.1 rejected, HSTS present)
- [ ] Configuration matches staging environment

### References
- Source reports: L1:12.1.1.md, L1:12.2.1.md, L1:12.2.2.md
- Related findings: None
- ASVS sections: 12.1.1, 12.2.1, 12.2.2
- CWE: CWE-326

### Priority
Medium

---

## Issue: FINDING-169 - Hypercorn Application Server Lacks Explicit TLS Version and Cipher Configuration

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The Hypercorn application server is started without explicit TLS protocol version or cipher suite configuration. While Hypercorn listens only on localhost (127.0.0.1:8443) behind the Apache reverse proxy (significantly mitigating the risk), defense-in-depth requires that internal TLS endpoints also enforce modern protocol versions. Python's default ssl.SSLContext in modern versions (3.10+) generally defaults to TLS 1.2+, but this is implicit behavior that could change with updates or environment differences. The startup scripts (`start-atr.sh` and `start-dev.sh`) lack `--ciphers` flag and TLS version configuration.

### Details
The issue exists in `start-atr.sh` lines 19-22 and `start-dev.sh` lines 19-22. Hypercorn is started without explicit TLS configuration, relying on Python's default SSL context behavior. Additionally, the Apache proxy connection (SSLProxyProtocol -all +TLSv1.2 +TLSv1.3) is only configured on the staging vhost, not the dev vhost.

### Recommended Remediation
Configure Hypercorn's TLS settings explicitly via a configuration file using ssl.SSLContext:

```python
# In a hypercorn config file (e.g., hypercorn_config.py)
import ssl

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
ssl_context.load_cert_chain('secrets/generated/cert.pem', 'secrets/generated/key.pem')
```

Then modify start scripts to use:
```bash
hypercorn --config hypercorn_config.py ...
```

Alternatively, pass explicit TLS parameters in the start script using `--ciphers` flag if supported.

### Acceptance Criteria
- [ ] Hypercorn configuration file created with explicit TLS settings
- [ ] TLS 1.2+ minimum version enforced
- [ ] AEAD-only cipher suites configured
- [ ] Start scripts updated to use configuration file
- [ ] Unit tests verify TLS 1.0/1.1 connections are rejected
- [ ] Integration tests verify internal TLS configuration
- [ ] Documentation updated with TLS configuration requirements

### References
- Source reports: L1:12.1.1.md
- Related findings: FINDING-168
- ASVS sections: 12.1.1

### Priority
Medium

---

## Issue: FINDING-170 - SVN Export Bypasses TLS Certificate Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The SVN export operation uses the `--trust-server-cert-failures` flag with `unknown-ca,cn-mismatch`, which instructs the SVN client to accept certificates signed by unknown/untrusted certificate authorities and certificates where the Common Name doesn't match the hostname. This defeats the authentication component of TLS, reducing it to encryption-only. While the connection is encrypted, there is no cryptographic verification that the server is actually `dist.apache.org`. A network-level attacker could perform MITM and serve malicious artifacts during SVN import.

### Details
The vulnerability exists in `atr/tasks/svn.py` around line 86, where the svn export command includes flags that bypass certificate validation. This violates ASVS 12.2.1's requirement that TLS be used for "all connectivity" with external services (implying proper validation).

### Recommended Remediation
**Option 1 (Recommended):** Remove the `--trust-server-cert-failures` flags entirely from the svn export command. If dist.apache.org uses a publicly trusted certificate (which it should), no special trust configuration is needed.

**Option 2:** If dist.apache.org uses a custom CA, install the ASF CA certificate in the container trust store:
```bash
# In Dockerfile or container initialization
cp asf-ca-cert.crt /usr/local/share/ca-certificates/
update-ca-certificates
```

**Option 3 (Most Secure):** Implement explicit certificate pinning using svn config options:
```bash
svn export https://dist.apache.org/repos/dist/... \
  --config-option servers:global:ssl-authority-files=/path/to/asf-ca-bundle.crt
```

### Acceptance Criteria
- [ ] `--trust-server-cert-failures` flags removed from svn export command
- [ ] OR: ASF CA certificate installed in container trust store
- [ ] OR: Explicit certificate pinning configured
- [ ] Unit tests verify svn export fails with invalid certificates
- [ ] Integration tests verify svn export succeeds with valid certificates
- [ ] Documentation updated with certificate validation approach

### References
- Source reports: L1:12.2.1.md
- Related findings: None
- ASVS sections: 12.2.1
- CWE: CWE-295

### Priority
Medium

---

## Issue: FINDING-171 - HMAC Signer Canonicalization Weakness — Colon Stripping Permits Signature Confusion

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `Signer.sign()` method strips colons from input arguments before joining them with colon delimiters, creating signature collisions. Different logical inputs can produce identical HMAC signatures: `sign('a:b', 'c')` and `sign('ab', 'c')` both produce the same signature because colons are removed (`s.replace(':', '')`) before joining with `:`. This allows an attacker who controls argument values to manipulate colon placement and produce valid signatures for different logical inputs, weakening integrity protection.

### Details
The vulnerability exists in `asfpy/crypto.py` lines 108-112. The canonicalization approach of stripping colons and then joining with colons creates ambiguity where different input combinations produce identical signatures, violating ASVS 11.3.3's requirement for proper authenticated encryption or MAC protection against unauthorized modification.

### Recommended Remediation
Replace colon-stripping canonicalization with length-prefixed encoding to prevent ambiguity:

```python
def sign(self, *argv: str) -> str:
    """Return a URL-safe HMAC-SHA256 signature for the given args."""
    parts = [self.prefix]
    for arg in argv:
        s = str(arg)
        # Length-prefix format: "length:value"
        parts.append(f"{len(s)}:{s}")
    message = "|".join(parts).encode('utf-8')  # Use different separator
    digest = hmac.new(self.key, message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
```

**Alternative:** Use null-byte separators with HMAC-per-field approach:
```python
def sign(self, *argv: str) -> str:
    """Return a URL-safe HMAC-SHA256 signature for the given args."""
    message = '\x00'.join([self.prefix] + [str(arg) for arg in argv])
    digest = hmac.new(self.key, message.encode('utf-8'), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
```

### Acceptance Criteria
- [ ] Canonicalization replaced with length-prefixed encoding or null-byte separators
- [ ] Unit tests verify `sign('a:b', 'c')` ≠ `sign('ab', 'c')`
- [ ] Unit tests verify signature uniqueness for various input combinations
- [ ] Existing signatures remain valid OR migration path documented
- [ ] Code review confirms no other signature collision vulnerabilities

### References
- Source reports: L2:11.3.3.md
- Related findings: FINDING-042
- ASVS sections: 11.3.3
- CWE: CWE-345

### Priority
Medium

---

## Issue: FINDING-172 - PAT Storage Uses Fast Hash (SHA3-256) Instead of Approved KDF

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Personal Access Tokens (PATs) are stored as SHA3-256 hashes instead of using an approved password hashing function per ASVS 11.4.2. SHA3-256 is a general-purpose cryptographic hash function that completes in nanoseconds per hash, enabling high-speed brute-force attacks if the database is compromised. While PATs are generated with 256-bit entropy (via `secrets.token_urlsafe(32)`) which makes brute-force infeasible regardless of hash speed, the fast hash provides no safety net if PAT generation were ever weakened or an implementation bug reduced entropy. Without a computational cost barrier, an attacker with DB access could rapidly crack PATs if entropy is reduced through bugs, configuration errors, or future changes to the token generation mechanism.

### Details
The issue exists in `atr/storage/writers/tokens.py` line 89 and `atr/models/sql.py`. PATs are hashed using SHA3-256 before storage, which provides no computational cost barrier against brute-force attacks.

### Recommended Remediation
Replace SHA3-256 with an approved KDF for PAT storage. Use PBKDF2-HMAC-SHA256 with 600,000 iterations per OWASP guidance:

```python
import hashlib
import secrets

def hash_pat(token: str) -> tuple[str, str]:
    """Hash PAT using PBKDF2-HMAC-SHA256 with 600k iterations."""
    salt = secrets.token_bytes(32)  # 256-bit salt
    digest = hashlib.pbkdf2_hmac('sha256', token.encode('utf-8'), salt, 600_000)
    return digest.hex(), salt.hex()

def verify_pat(token: str, stored_hash: str, stored_salt: str) -> bool:
    """Verify PAT against stored hash."""
    salt = bytes.fromhex(stored_salt)
    digest = hashlib.pbkdf2_hmac('sha256', token.encode('utf-8'), salt, 600_000)
    return secrets.compare_digest(digest.hex(), stored_hash)
```

**Migration Path:**
1. Add `token_hash_version` column to `PersonalAccessToken` model (default `1` for SHA3-256)
2. New PATs use version `2` with PBKDF2
3. On successful PAT→JWT exchange with version `1`, re-hash with version `2` and update
4. After migration period (e.g., 180 days = PAT max lifetime), reject version `1` tokens

### Acceptance Criteria
- [ ] PBKDF2-HMAC-SHA256 with 600k iterations implemented for PAT hashing
- [ ] Salt column added to PersonalAccessToken model
- [ ] Hash version column added for migration tracking
- [ ] New PATs hashed with PBKDF2
- [ ] Migration path implemented for existing SHA3-256 hashes
- [ ] Unit tests verify PBKDF2 hashing and verification
- [ ] Performance tests verify acceptable hash computation time
- [ ] Documentation updated with KDF details and migration timeline

### References
- Source reports: L2:11.4.2.md
- Related findings: None
- ASVS sections: 11.4.2
- CWE: CWE-916

### Priority
Medium

---

## Issue: FINDING-173 - `Clear-Site-Data` Header Missing on Implicit Session Termination

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The application implements the `Clear-Site-Data` HTTP response header on explicit logout (`/auth?logout`) but fails to send this header when sessions are terminated implicitly through inactivity timeout (7 days), absolute session maximum (72 hours), or account deactivation. This creates a gap where authenticated content remains cached in the browser after implicit session termination. On shared computers, subsequent users could potentially view cached authenticated content via browser back button, cache inspection tools, or browser developer tools.

### Details
The issue exists in `src/asfquart/session.py` lines 52-56, `atr/blueprints/common.py` lines 27-30, and `atr/server.py` lines 337-363. When sessions are terminated implicitly, the browser retains cached authenticated HTML pages, browser storage, and HTTP cache entries with authenticated content.

### Recommended Remediation
**Option A — Add `Clear-Site-Data` to Error Responses (Explicit):**
Modify authenticate() function in atr/blueprints/common.py to include Clear-Site-Data header on 401 responses:

```python
async def authenticate(session_type: Type[web.Session]) -> web.Session:
    session = await asfquart.session.read()
    if not session:
        response = quart.Response("Unauthorized", status=401)
        response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
        raise quart.exceptions.Unauthorized(response=response)
    # ... rest of implementation
```

**Option B — Add `after_request` Hook (Recommended — Centralized):**
Add an after_request hook in atr/server.py that automatically adds Clear-Site-Data header to all 401 responses:

```python
@app.after_request
async def add_clear_site_data_on_session_termination(response):
    if response.status_code == 401:
        response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    return response
```

### Acceptance Criteria
- [ ] Clear-Site-Data header added to 401 responses for implicit session termination
- [ ] Unit tests verify header is present on inactivity timeout
- [ ] Unit tests verify header is present on absolute session expiration
- [ ] Unit tests verify header is present on account deactivation
- [ ] Integration tests verify browser cache is cleared on implicit termination
- [ ] Manual testing confirms cached content is not accessible after session expiration

### References
- Source reports: L1:14.3.1.md
- Related findings: None
- ASVS sections: 14.3.1

### Priority
Medium

---

## Issue: FINDING-174 - No Client-Side Fallback for Offline Session Cleanup

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
ASVS 14.3.1 explicitly requires that the client-side should also be able to clear up if the server connection is not available when the session is terminated. The application contains no JavaScript mechanism that detects session termination when the server is unreachable, clears authenticated data from client storage on browser/tab close, or provides periodic session validity checks with client-side cleanup. In offline scenarios: browser/tab closure without logout results in cached pages persisting indefinitely, session expires while user is offline with no client-side cleanup, network failure during session leaves authenticated content in browser cache, and on shared computers subsequent users can access cached authenticated content.

### Details
The issue is application-wide, affecting `atr/static/js/` and `atr/static/ts/`. No client-side session watchdog or cleanup mechanism exists to handle offline session termination scenarios.

### Recommended Remediation
Implement a comprehensive client-side session watchdog script (`atr/static/js/session-watchdog.js`):

```javascript
(function() {
    'use strict';
    
    const SESSION_CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes
    
    function clearAuthenticatedData() {
        // Remove authenticated DOM elements
        document.querySelectorAll('[data-authenticated]').forEach(el => el.remove());
        
        // Clear sessionStorage
        sessionStorage.clear();
        
        // Redirect to login
        window.location.href = '/auth';
    }
    
    async function checkSessionValidity() {
        try {
            const response = await fetch('/auth', {
                method: 'HEAD',
                cache: 'no-store'
            });
            
            if (response.status === 401) {
                clearAuthenticatedData();
            }
        } catch (error) {
            // Network error - clear data as precaution
            console.warn('Session check failed, clearing authenticated data');
            clearAuthenticatedData();
        }
    }
    
    // Periodic session validity checks
    setInterval(checkSessionValidity, SESSION_CHECK_INTERVAL);
    
    // Clear data when page becomes hidden
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
            clearAuthenticatedData();
        }
    });
    
    // Clear data when page is unloaded
    window.addEventListener('pagehide', clearAuthenticatedData);
    
    // Initial check on page load
    checkSessionValidity();
})();
```

Include this script on all authenticated page templates:
```html
<script src='/static/js/session-watchdog.js' defer></script>
```

### Acceptance Criteria
- [ ] Session watchdog script created with periodic validity checks
- [ ] clearAuthenticatedData() function implemented
- [ ] visibilitychange event listener added
- [ ] pagehide event listener added
- [ ] Initial session check on page load implemented
- [ ] Script included on all authenticated page templates
- [ ] Unit tests verify session validity checks
- [ ] Integration tests verify offline cleanup behavior
- [ ] Manual testing confirms data cleared when offline

### References
- Source reports: L1:14.3.1.md
- Related findings: None
- ASVS sections: 14.3.1

### Priority
Medium

---

## Issue: FINDING-175 - Admin /admin/env Exposes All Environment Variables Without Debug Gating or Redaction

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `/admin/env` endpoint exposes all environment variables without checking if debug mode is enabled and without redacting sensitive values. While admin authentication is required, this is a debugging feature that should only be available in debug mode. Common secrets exposed include LDAP_BIND_PASSWORD, GITHUB_TOKEN, SVN_TOKEN, PUBSUB_PASSWORD, etc. The sibling 'configuration' route demonstrates correct pattern by redacting sensitive patterns.

### Details
The issue exists in `atr/admin/__init__.py`. The endpoint returns all environment variables without any filtering or redaction, exposing sensitive credentials to administrators even in production environments.

### Recommended Remediation
Add debug mode check and sensitive pattern redaction:

```python
@admin.get
async def env(session: web.Admin) -> web.QuartResponse:
    _require_debug_and_allow_tests()  # Add this check
    
    # Redact sensitive patterns
    SENSITIVE_PATTERNS = ['PASSWORD', 'TOKEN', 'SECRET', 'KEY', 'CREDENTIAL', 'AUTH']
    
    env_data = {}
    for key, value in os.environ.items():
        if any(pattern in key.upper() for pattern in SENSITIVE_PATTERNS):
            env_data[key] = '***REDACTED***'
        else:
            env_data[key] = value
    
    return await render("admin/env.html", env=env_data)
```

### Acceptance Criteria
- [ ] `_require_debug_and_allow_tests()` call added at function start
- [ ] Sensitive pattern redaction implemented
- [ ] Unit tests verify endpoint returns 404 in production mode
- [ ] Unit tests verify sensitive values are redacted
- [ ] Integration tests verify debug mode requirement
- [ ] Documentation updated with debug mode requirement

### References
- Source reports: L2:13.4.2.md, L2:13.4.5.md, L2:14.2.4.md
- Related findings: FINDING-178, FINDING-288, FINDING-182
- ASVS sections: 13.4.2, 13.4.5, 14.2.4

### Priority
Medium

---

## Issue: FINDING-176 - Test Endpoints Accessible in Production Without ALLOW_TESTS Check

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Three test endpoints (`test_empty`, `test_multiple`, `test_single`) are publicly accessible without checking the ALLOW_TESTS configuration flag. In the same file, three other test routes (`test_login`, `test_merge`, `test_vote`) correctly implement the protection by returning 404 when ALLOW_TESTS is False. This inconsistency creates a gap where debug/test features remain accessible in production. No authentication is required for these endpoints.

### Details
The issue exists in `atr/get/test.py` at lines 44, 117, and 141. These three endpoints do not check the ALLOW_TESTS configuration flag before executing, while sibling endpoints in the same file correctly implement this protection.

### Recommended Remediation
Add ALLOW_TESTS check at the beginning of each affected function:

```python
@test.get
async def test_empty(session: web.Public) -> web.QuartResponse:
    if not config.get().ALLOW_TESTS:
        return quart.abort(404)
    # ... rest of implementation

@test.get
async def test_multiple(session: web.Public) -> web.QuartResponse:
    if not config.get().ALLOW_TESTS:
        return quart.abort(404)
    # ... rest of implementation

@test.get
async def test_single(session: web.Public) -> web.QuartResponse:
    if not config.get().ALLOW_TESTS:
        return quart.abort(404)
    # ... rest of implementation
```

### Acceptance Criteria
- [ ] ALLOW_TESTS check added to test_empty function
- [ ] ALLOW_TESTS check added to test_multiple function
- [ ] ALLOW_TESTS check added to test_single function
- [ ] Unit tests verify endpoints return 404 when ALLOW_TESTS is False
- [ ] Unit tests verify endpoints work when ALLOW_TESTS is True
- [ ] Integration tests verify production behavior

### References
- Source reports: L2:13.4.2.md
- Related findings: None
- ASVS sections: 13.4.2

### Priority
Medium

---

## Issue: FINDING-177 - Unauthenticated /api/tasks/list Endpoint Exposes Internal Error Details

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `/api/tasks/list` endpoint is publicly accessible without authentication and returns task records including the 'error' field. When tasks fail in the worker process, exception messages are stored directly in this field via `str(e)`. These error messages can contain internal file paths, function names, configuration details, and other implementation information. Task types, arguments, project names, version keys, and user identifiers are also exposed.

### Details
The issue exists in `atr/api/__init__.py` lines 810-835 (endpoint definition) and `atr/worker.py` lines 232-235 (error storage). The endpoint returns full task objects including detailed error messages without any authentication or sanitization.

### Recommended Remediation
**Option 1 (Recommended):** Add authentication requirement:

```python
@api.get
@jwtoken.require  # Add this decorator
async def tasks_list(
    session: web.Public,  # Change to web.Committer
    # ... rest of parameters
) -> list[sql.WorkflowStatus]:
    # ... implementation
```

**Option 2:** Sanitize error field in response for non-admin users:

```python
@api.get
async def tasks_list(
    session: web.Public,
    # ... rest of parameters
) -> list[dict]:
    tasks = # ... fetch tasks
    
    # Sanitize for non-admin users
    is_admin = isinstance(session, web.Admin)
    
    result = []
    for task in tasks:
        task_dict = task.dict()
        if not is_admin and task_dict.get('error'):
            task_dict['error'] = 'Task failed (details hidden)'
        result.append(task_dict)
    
    return result
```

### Acceptance Criteria
- [ ] Authentication added to /api/tasks/list endpoint
- [ ] OR: Error field sanitization implemented for non-admin users
- [ ] Unit tests verify unauthenticated requests are rejected (Option 1)
- [ ] Unit tests verify error details are hidden from non-admins (Option 2)
- [ ] Integration tests verify endpoint security
- [ ] Documentation updated with authentication requirements

### References
- Source reports: L2:13.4.2.md
- Related findings: FINDING-289
- ASVS sections: 13.4.2

### Priority
Medium

---

## Issue: FINDING-178 - JWT Error Response Leaks Token Claim Content

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
When JWT token validation fails due to an invalid 'sub' claim type, the error message includes the raw claim value using `repr()` and Python type information. This leaks the internal structure of JWT claims and confirms implementation details to attackers, aiding in crafting targeted attacks. Error reveals Python class names and internal type handling.

### Details
The issue exists in `atr/api/__init__.py` lines 1080-1085. When JWT validation encounters an invalid subject claim type, the error message includes the raw claim value and type information using Python's `repr()` function.

### Recommended Remediation
Replace detailed error message with generic response:

```python
# In atr/api/__init__.py, around line 1083
# Replace:
# raise base.ASFQuartException(
#     f"Invalid or missing token subject: {repr(claims.get('sub'))}",
#     errorcode=401
# )

# With:
raise base.ASFQuartException(
    'Invalid or missing token subject',
    errorcode=401
)
```

Do not reveal claim content or type information in error messages.

### Acceptance Criteria
- [ ] Error message replaced with generic message
- [ ] No claim content included in error responses
- [ ] No type information included in error responses
- [ ] Unit tests verify generic error messages
- [ ] Integration tests verify no information leakage
- [ ] Code review confirms no other JWT error leakage

### References
- Source reports: L2:13.4.2.md
- Related findings: FINDING-289
- ASVS sections: 13.4.2

### Priority
Medium

---

## Issue: FINDING-179 - User Directory Listing Enabled Without Security Hardening

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The user directory `/~sbp/` is configured with directory listing enabled (`+Indexes`) but lacks critical security hardening measures that are present in the `/downloads/` directory blocks on the same vhost. Missing controls include: no `-ExecCGI` option, no `SetHandler none`, no `X-Content-Type-Options: nosniff`, no `Content-Security-Policy: sandbox`, no `Cross-Origin-Resource-Policy`, and `+FollowSymLinks` without restrictions could expose files outside `/home/sbp/www/`.

### Details
The issue exists in `tooling-vm-ec2-de.apache.org.yaml`. The `/~sbp/` directory configuration lacks the security hardening that is properly applied to `/downloads/` directory blocks, creating an inconsistent security posture.

### Recommended Remediation
Apply the same security hardening as the `/downloads/` directory blocks:

```yaml
<Directory /home/sbp/www/>
    Options +Indexes +FollowSymLinks -ExecCGI
    Require all granted
    IndexOptions FancyIndexing NameWidth=* FoldersFirst ScanHTMLTitles DescriptionWidth=*
    DefaultType text/plain
    Header always set X-Content-Type-Options "nosniff"
    Header always set Content-Security-Policy "sandbox"
    Header always set Referrer-Policy "no-referrer"
    Header always set X-Frame-Options "DENY"
    Header always set Cross-Origin-Resource-Policy "same-origin"
    SetHandler none
</Directory>
```

### Acceptance Criteria
- [ ] `-ExecCGI` option added to Directory configuration
- [ ] `SetHandler none` directive added
- [ ] X-Content-Type-Options header added
- [ ] Content-Security-Policy sandbox header added
- [ ] Referrer-Policy header added
- [ ] X-Frame-Options header added
- [ ] Cross-Origin-Resource-Policy header added
- [ ] Configuration matches /downloads/ security hardening
- [ ] Manual testing confirms headers are present

### References
- Source reports: L2:13.4.3.md
- Related findings: FINDING-180
- ASVS sections: 13.4.3

### Priority
Medium

---

## Issue: FINDING-180 - Development Vhost Missing Vhost-Level Security Headers for Directly Served Content

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The development vhost `tooling-vm-ec2-de.apache.org` lacks vhost-level security headers that are properly configured on the production `release-test.apache.org` vhost. While individual directory blocks like `/downloads/` have their own security headers, directly served content outside these blocks (such as `/~sbp/`) lacks HSTS, framing protection, MIME sniffing prevention, and referrer leakage controls. Missing headers: HSTS (downgrade attacks possible), X-Frame-Options (clickjacking vulnerability), X-Content-Type-Options (MIME sniffing attacks possible), Referrer-Policy (information leakage through referrer headers).

### Details
The issue exists in `tooling-vm-ec2-de.apache.org.yaml`. The vhost configuration lacks vhost-level security headers, meaning directly served content outside specific directory blocks is unprotected. Proxied content receives headers from the backend application, but directly served paths are unprotected.

### Recommended Remediation
Add vhost-level security headers to the `tooling-vm-ec2-de.apache.org` vhost:

```yaml
# Security Headers
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Referrer-Policy "same-origin"
```

Place these directives at the vhost level so they apply to all content, with directory-specific overrides where needed.

### Acceptance Criteria
- [ ] HSTS header added at vhost level
- [ ] X-Content-Type-Options header added at vhost level
- [ ] X-Frame-Options header added at vhost level
- [ ] Referrer-Policy header added at vhost level
- [ ] Manual testing confirms headers present on directly served content
- [ ] Manual testing confirms headers present on /~sbp/ directory
- [ ] Configuration matches production vhost security posture

### References
- Source reports: L2:13.4.3.md
- Related findings: FINDING-179
- ASVS sections: 13.4.3

### Priority
Medium

---

## Issue: FINDING-181 - HTTP TRACE Method Not Disabled at Apache Reverse Proxy

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The Apache httpd reverse proxy configuration does not include the `TraceEnable Off` directive. Apache httpd enables TRACE by default. Critically, Apache handles TRACE requests natively—it echoes back the full HTTP request including all headers—and does not proxy TRACE to the backend application, regardless of ProxyPass rules. Sensitive headers (session cookies, Authorization tokens) are reflected back in TRACE responses, enabling Cross-Site Tracing (XST) attacks when combined with other vulnerabilities. Even though modern browsers block JavaScript TRACE requests, non-browser API clients and automated tools can still exploit this.

### Details
The issue exists in `tooling-vm-ec2-de.apache.org.yaml` lines 76-155 and 156-230. The Apache configuration lacks the `TraceEnable Off` directive at both the vhost level and globally, leaving the TRACE method enabled by default.

### Recommended Remediation
Add `TraceEnable Off` to the Apache configuration at the vhost level or globally:

**Option 1 (Vhost-level):**
```yaml
# In tooling-vm-ec2-de.apache.org.yaml
vhosts:
  - servername: tooling-vm-ec2-de.apache.org
    TraceEnable: 'Off'  # Add this directive
    # ... rest of configuration
```

**Option 2 (Global via Puppet/Hiera):**
```yaml
apache::trace_enable: 'Off'
```

Verify with:
```bash
curl -X TRACE https://tooling-vm-ec2-de.apache.org/
# Should return 405 Method Not Allowed
```

### Acceptance Criteria
- [ ] `TraceEnable Off` directive added to Apache configuration
- [ ] Unit tests verify TRACE method returns 405
- [ ] Integration tests verify TRACE is disabled on all vhosts
- [ ] Manual testing confirms TRACE requests are rejected
- [ ] Documentation updated with TRACE method configuration

### References
- Source reports: L2:13.4.4.md
- Related findings: FINDING-295
- ASVS sections: 13.4.4

### Priority
Medium

---

## Issue: FINDING-182 - Internal Documentation Publicly Exposed

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `/docs/*` endpoints serve internal developer documentation without any authentication requirements. The `web.Public` session type explicitly marks these routes as accessible to unauthenticated users. Documentation includes sensitive information such as OAuth state storage details, architectural weaknesses (multi-instance deployment state lookup failures), permission hierarchy bypass methods, filesystem layouts, configuration variable names, and audit logging mechanisms. Path traversal protection is present and correct, but no authentication check exists.

### Details
The issue exists in `atr/get/docs.py` lines 57 and 62. Both the `index` and `page` functions use `web.Public` session type, allowing unauthenticated access. Sensitive documentation files include `docs/oauth.md` and `docs/storage-interface.md`.

### Recommended Remediation
**Option A (Recommended):** Require authentication by changing session type:

```python
@docs.get
async def index(session: web.Committer) -> web.QuartResponse:  # Changed from web.Public
    # ... implementation

@docs.get
async def page(session: web.Committer, name: safe.RelPath) -> web.QuartResponse:  # Changed from web.Public
    # ... implementation
```

**Option B:** Separate public from internal docs:
- Serve only from `docs/public/` directory for unauthenticated users
- Move sensitive docs to `docs/internal/` requiring authentication

**Option C:** Gate behind production mode:
```python
@docs.get
async def page(session: web.Public, name: safe.RelPath) -> web.QuartResponse:
    if config.get().PRODUCTION_MODE:
        return quart.abort(404)
    # ... rest of implementation
```

**Option D:** Implement allowlist of permitted public documentation files with authentication requirement for others.

### Acceptance Criteria
- [ ] Authentication required for /docs/* endpoints
- [ ] OR: Public/internal documentation separated
- [ ] OR: Production mode gating implemented
- [ ] Unit tests verify unauthenticated access is rejected
- [ ] Unit tests verify authenticated access works
- [ ] Integration tests verify documentation security
- [ ] Documentation updated with access requirements

### References
- Source reports: L2:13.4.5.md
- Related findings: None
- ASVS sections: 13.4.5

### Priority
Medium

---

## Issue: FINDING-183 - Swagger UI and OpenAPI Specification Publicly Accessible

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The Swagger UI (`/api/docs`) and OpenAPI specification (`/api/openapi.json`) are publicly accessible without authentication. While the custom `ApiOnlyOpenAPIProvider` filters admin routes from the specification, the complete API surface for public endpoints is exposed. The `@quart_schema.hide` decorator only hides routes from the OpenAPI spec itself but does NOT restrict access to the endpoints. This exposes complete API surface enumeration, JWT vs unprotected endpoint mapping, request/response data models, parameter types and validation rules, and internal naming conventions.

### Details
The issue exists in `atr/server.py`, `atr/blueprints/api.py`, and `atr/templates/about.html` line 51. Blueprint-level protection only applies rate limiting with no authentication check.

### Recommended Remediation
**If NOT intended to be public:** Add authentication check to both `/api/docs` and `/api/openapi.json` endpoints:

```python
@app.before_request
async def protect_api_docs():
    if quart.request.path in ('/api/docs', '/api/openapi.json'):
        session = await asfquart.session.read()
        if not session:
            return quart.abort(404)  # Hide existence from unauthenticated users
```

**If intentionally public:** 
- Document this decision in configuration or security documentation
- Consider serving a minimal public version and full version behind auth
- Ensure the OpenAPI spec doesn't leak internal implementation details

### Acceptance Criteria
- [ ] Authentication added to /api/docs endpoint
- [ ] Authentication added to /api/openapi.json endpoint
- [ ] Unit tests verify unauthenticated access is rejected
- [ ] Unit tests verify authenticated access works
- [ ] OR: Decision to keep public documented with rationale
- [ ] OR: Minimal public spec created with full spec behind auth
- [ ] Documentation updated with API documentation access policy

### References
- Source reports: L2:13.4.5.md
- Related findings: None
- ASVS sections: 13.4.5

### Priority
Medium

---

## Issue: FINDING-184 - Key Management Endpoints Lack Cache-Control Headers

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Endpoints displaying user SSH and OpenPGP keys lack cache-control headers. While public keys are less sensitive than private keys, they are authentication-related material tied to specific users. Cached responses could expose which keys belong to which users. For shared/misconfigured caching infrastructure, could serve user A's keys to user B.

### Details
The issue exists in `atr/get/keys.py` affecting the `keys()`, `details()`, and `export()` functions. These endpoints return user-specific key information without anti-caching headers.

### Recommended Remediation
This issue is covered by the global fix in FINDING-046 (API_SCM_CLIENT-026), which adds cache-control headers to all authenticated endpoints. Specific implementation:

```python
@keys.get
async def keys(session: web.Committer) -> web.QuartResponse:
    # ... implementation
    response = await render("keys/keys.html", ...)
    response.headers['Cache-Control'] = 'no-store'
    return response

@keys.get
async def details(session: web.Committer, key_id: int) -> web.QuartResponse:
    # ... implementation
    response = await render("keys/details.html", ...)
    response.headers['Cache-Control'] = 'no-store'
    return response

@keys.get
async def export(session: web.Committer) -> web.QuartResponse:
    # ... implementation
    response = web.TextResponse(...)
    response.headers['Cache-Control'] = 'no-store'
    return response
```

### Acceptance Criteria
- [ ] Cache-Control: no-store header added to keys() endpoint
- [ ] Cache-Control: no-store header added to details() endpoint
- [ ] Cache-Control: no-store header added to export() endpoint
- [ ] Unit tests verify cache-control headers are present
- [ ] Integration tests verify no caching occurs
- [ ] Manual testing confirms headers in responses

### References
- Source reports: L2:14.2.2.md
- Related findings: FINDING-046
- ASVS sections: 14.2.2
- CWE: CWE-524

### Priority
Medium

---

## Issue: FINDING-185 - Session Cache Persists Sensitive Data Indefinitely Without TTL

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The session cache mechanism stores user authorization data (admin privileges, committee memberships, MFA status) in a persistent JSON file without TTL or automatic purging. Stale data persists indefinitely after role changes or account deactivation. The cache stores `isRoot` (admin privilege status), `isChair` (PMC chair status), `isMember` (ASF membership status), `pmcs/projects` (authorization data), and `mfa` (MFA enrollment status). No mechanism exists to automatically invalidate stale data.

### Details
The issue exists in `atr/post/user.py` lines 40-57 and `atr/util.py` (session_cache_read() and session_cache_write() functions). Authorization data is cached to disk without expiration timestamps or cleanup mechanisms.

### Recommended Remediation
Add TTL metadata and purge expired entries:

```python
import time

def session_cache_write(uid: str, data: dict):
    """Write session cache with TTL metadata."""
    cache_entry = {
        'data': data,
        'cached_at': time.time(),
        'expires_at': time.time() + (24 * 60 * 60)  # 24 hour TTL
    }
    # ... write cache_entry to disk

def session_cache_read(uid: str) -> dict:
    """Read session cache with expiration check."""
    cache_entry = # ... read from disk
    
    if cache_entry and cache_entry.get('expires_at', 0) > time.time():
        return cache_entry['data']
    else:
        # Expired or missing - return None to force refresh
        return None

def purge_expired_cache_entries():
    """Periodic cleanup of expired cache entries."""
    cache_dir = # ... get cache directory
    current_time = time.time()
    
    for cache_file in cache_dir.glob('*.json'):
        cache_entry = # ... read cache file
        if cache_entry.get('expires_at', 0) < current_time:
            cache_file.unlink()  # Delete expired entry

# Schedule periodic cleanup
# In atr/server.py or worker initialization:
asyncio.create_task(periodic_cache_cleanup())
```

### Acceptance Criteria
- [ ] TTL metadata added to cache entries (cached_at, expires_at)
- [ ] session_cache_read() checks expiration before returning data
- [ ] Periodic cleanup task implemented to purge expired entries
- [ ] Unit tests verify expired entries are not returned
- [ ] Unit tests verify cleanup removes expired entries
- [ ] Integration tests verify cache expiration behavior
- [ ] Documentation updated with cache TTL policy

### References
- Source reports: L2:14.2.2.md, L2:14.2.4.md
- Related findings: FINDING-297, FINDING-302
- ASVS sections: 14.2.2, 14.2.4
- CWE: CWE-524

### Priority
Medium

---

## Issue: FINDING-186 - WorkflowSSHKey Entries Not Purged After Expiration

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Workflow SSH keys are temporary credentials valid for 20 minutes. The WorkflowSSHKey table includes an `expires` field that is checked during authentication but never used to purge expired entries from the database. Without auto-purging, the database accumulates expired key material that could be exposed through database compromise or admin data browser. This violates the requirement to "securely purge data after use".

### Details
The issue exists in `atr/storage/writers/ssh.py` lines 82-86 and the `atr/models/sql.py` WorkflowSSHKey model. Expired keys remain in the database indefinitely despite being functionally invalid.

### Recommended Remediation
Add periodic cleanup task to delete expired WorkflowSSHKey entries:

```python
# In atr/storage/writers/ssh.py or atr/tasks/cleanup.py
async def purge_expired_workflow_ssh_keys():
    """Delete expired WorkflowSSHKey entries from database."""
    from datetime import datetime, timezone
    from atr.models import sql
    from atr.storage import db
    
    now = datetime.now(timezone.utc)
    
    async with db.session() as session:
        result = await session.execute(
            sql.delete(sql.WorkflowSSHKey).where(
                sql.WorkflowSSHKey.expires < now
            )
        )
        await session.commit()
        
        deleted_count = result.rowcount
        if deleted_count > 0:
            log.info(f"Purged {deleted_count} expired workflow SSH keys")

# Schedule in task worker or add to before_serving hook
# In atr/server.py:
@app.before_serving
async def schedule_cleanup_tasks():
    async def periodic_cleanup():
        while True:
            await asyncio.sleep(5 * 60)  # Run every 5 minutes
            await purge_expired_workflow_ssh_keys()
    
    asyncio.create_task(periodic_cleanup())
```

### Acceptance Criteria
- [ ] Periodic cleanup task implemented for expired WorkflowSSHKey entries
- [ ] Task scheduled to run every 5 minutes
- [ ] Unit tests verify expired keys are deleted
- [ ] Unit tests verify non-expired keys are retained
- [ ] Integration tests verify cleanup task execution
- [ ] Logging added for cleanup operations
- [ ] Documentation updated with cleanup policy

### References
- Source reports: L2:14.2.2.md
- Related findings: None
- ASVS sections: 14.2.2
- CWE: CWE-459

### Priority
Medium

---

## Issue: FINDING-187 - Full Email Content Logged at INFO Level

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Complete email messages—including headers (sender, recipient), subject, and full body text—are logged at INFO level. Email bodies contain vote details, release candidate information, user full names, and mailing list addresses. When structured logs are forwarded to centralized logging platforms (common in production environments), sensitive communication content reaches infrastructure that may be managed by different teams with broader access, stored in third-party logging services (CloudWatch, Datadog, Splunk, ELK), subject to different retention and access policies, or potentially exposed through log analysis tools or SIEM systems.

### Details
The issue exists in `atr/mail.py` lines 58 and 84. Full email content including body text is logged at INFO level, which is typically forwarded to centralized logging systems.

### Recommended Remediation
Replace full email content logging with metadata-only logging:

```python
# In atr/mail.py, replace lines 58 and 84

# Instead of:
# log.info("Sending email", msg=msg_data)

# Use:
log.info(
    "Sending email",
    recipient=msg_data.email_recipient,
    subject=msg_data.subject,
    message_id=msg_data.message_id,
    body_length=len(msg_data.body)
)

# Alternative with domain-only logging:
log.info(
    "Sending email",
    recipient_domain=msg_data.email_recipient.split('@')[1],
    subject_prefix=msg_data.subject.split(':')[0] if ':' in msg_data.subject else msg_data.subject[:20],
    body_length=len(msg_data.body),
    message_id=msg_data.message_id
)
```

Do NOT log the body content at INFO level. If full content logging is needed for debugging, use DEBUG level and ensure DEBUG logs are not forwarded to centralized systems in production.

### Acceptance Criteria
- [ ] Full email body logging removed from INFO level
- [ ] Metadata-only logging implemented (recipient, subject, message_id)
- [ ] Unit tests verify body content is not in log output
- [ ] Integration tests verify logging behavior
- [ ] Documentation updated with logging policy
- [ ] Production logging configuration verified to not forward DEBUG logs

### References
- Source reports: L2:14.2.3.md, L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.3, 14.2.4
- CWE: CWE-532

### Priority
Medium

---

## Issue: FINDING-188 - Audit Log Integrity Bug — Missing f-string Prefix

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Missing 'f' prefix on audit log reason string causes literal string to be logged instead of interpolated values, compromising audit trail integrity. The audit trail for directory deletion during release promotion does not contain actual user identity or release details, compromising forensic investigation capability. Actual log output shows literal `'{self.__asf_uid}'` instead of actual username.

### Details
The issue exists in `atr/storage/writers/announce.py` line 170. The audit log reason string is missing the 'f' prefix, causing variable names to be logged as literal strings instead of their values.

### Recommended Remediation
Add f-string prefix to the reason parameter:

```python
# In atr/storage/writers/announce.py, line 170
# Change:
reason="user {self.__asf_uid} is releasing {project_key} {version_key} {preview_revision_number}",

# To:
reason=f"user {self.__asf_uid} is releasing {project_key} {version_key} {preview_revision_number}",
```

### Acceptance Criteria
- [ ] f-string prefix added to audit log reason string
- [ ] Unit tests verify actual values are logged (not literal strings)
- [ ] Integration tests verify audit log contains correct user identity
- [ ] Code review confirms no other missing f-string prefixes in audit logs
- [ ] Existing audit logs reviewed for similar issues

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Medium

---

## Issue: FINDING-189 - HMAC Integrity Verification Function Broken

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The HMAC verification function compares base64-encoded bytes with raw decoded bytes, causing all valid signatures to be rejected. The 'expected' value is a base64-encoded ASCII string while 'given_bytes' is raw decoded bytes, causing comparison to always return False. Any code relying on `Signer.verify()` will always reject valid signatures, causing either Denial of Service or security bypass depending on how the calling code handles verification failures.

### Details
The issue exists in `asfpy/crypto.py` line 87. The verification function decodes the given signature to bytes but compares it with the base64-encoded expected signature string, resulting in a type mismatch that always returns False.

### Recommended Remediation
Compare base64 strings directly instead of mixing types:

```python
def verify(self, *args: str, given: str) -> bool:
    """Verify HMAC signature matches expected value.
    
    Args:
        *args: Arguments to sign (same as used in sign())
        given: The signature to verify (base64-encoded string)
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        expected = self.sign(*args)  # Keep as base64 string
        return hmac.compare_digest(expected, given)
    except (base64.binascii.Error, ValueError):
        return False
```

### Acceptance Criteria
- [ ] Verification function fixed to compare base64 strings directly
- [ ] Unit tests verify valid signatures are accepted
- [ ] Unit tests verify invalid signatures are rejected
- [ ] Unit tests verify type handling is correct
- [ ] Integration tests verify HMAC verification works end-to-end
- [ ] Code review confirms no other type comparison issues

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Medium

---

## Issue: FINDING-190 - GPG Process Debug Output Stored in Publicly Accessible Check Results

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
GPG stderr output is stored in check results that are accessible via unauthenticated API endpoint (`GET /api/checks/list/<project>/<version>`), exposing internal system paths and configuration details. Example exposed data includes temporary keyring paths (`/tmp/tmpXYZ/pubring.kbx`), trust database state, and server-side error diagnostics.

### Details
The issue exists in `atr/tasks/checks/signature.py` lines 126-142. GPG stderr output is captured and stored in the `debug_info` field of check results, which are then returned via the public API without sanitization.

### Recommended Remediation
**Option 1 (Recommended):** Remove stderr from stored results:

```python
# In atr/tasks/checks/signature.py, around line 135
if hasattr(verified, "stderr") and verified.stderr:
    # Log for debugging but don't store in public results
    log.debug(f"GPG stderr for {signature_path}: {verified.stderr}")
    # Do NOT add to debug_info

# Remove the line that adds stderr to debug_info
```

**Option 2:** Sanitize paths before storing:

```python
import re

if hasattr(verified, "stderr") and verified.stderr:
    # Sanitize paths in stderr before storing
    sanitized = re.sub(r'/[^\s:]+', '<path>', verified.stderr)
    debug_info["stderr_sanitized"] = sanitized
```

### Acceptance Criteria
- [ ] GPG stderr removed from check results OR sanitized
- [ ] Unit tests verify stderr is not in check results
- [ ] OR: Unit tests verify paths are sanitized in stderr
- [ ] Integration tests verify public API does not expose internal paths
- [ ] Manual testing confirms no path disclosure via API
- [ ] Code review confirms no other debug output leakage

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Medium

---

## Issue: FINDING-191 - API /user/info Returns Authorization Data Without Anti-Caching Headers

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `/api/user/info` endpoint returns the authenticated user's project participation and committee memberships without anti-caching headers. The endpoint returns `participant_of` and `member_of` lists that reveal organizational access levels. User's project memberships and committee participation could be cached, revealing organizational access levels and potentially facilitating social engineering attacks.

### Details
The issue exists in `atr/api/__init__.py` lines 1008-1020. The endpoint returns sensitive authorization information without setting cache-control headers to prevent caching.

### Recommended Remediation
Change return type to include response object with cache-control header:

```python
@api.get
@jwtoken.require
async def user_info(session: web.Session) -> tuple[quart.Response, int]:
    """Return user information with anti-caching headers."""
    user_data = {
        'uid': session.uid,
        'fullname': session.fullname,
        'participant_of': session.participant_of,
        'member_of': session.member_of,
        # ... other fields
    }
    
    response = quart.jsonify(user_data)
    response.headers['Cache-Control'] = 'no-store'
    return response, 200
```

### Acceptance Criteria
- [ ] Cache-Control: no-store header added to /api/user/info endpoint
- [ ] Return type changed to tuple[quart.Response, int]
- [ ] Unit tests verify cache-control header is present
- [ ] Integration tests verify no caching occurs
- [ ] Manual testing confirms header in responses

### References
- Source reports: L2:14.3.2.md
- Related findings: FINDING-011
- ASVS sections: 14.3.2

### Priority
Medium

---

## Issue: FINDING-192 - Session Cookie Contains PII and Authorization Data in Readable (Signed-But-Not-Encrypted) Format

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Quart's default SecureCookieSessionInterface serializes session data as JSON, optionally compresses it, base64-encodes it, and HMAC-signs it using the application secret_key. The payload is signed but not encrypted—the base64-encoded data can be decoded by anyone with access to the raw cookie value. The session cookie stores the complete user profile from the OAuth provider without field filtering, including: `uid`, `dn` (LDAP Distinguished Name), `fullname` (PII), `email` (PII), `isMember/isChair/isRoot` (authorization flags), `pmcs` (committee memberships), `projects` (project memberships), `mfa` (security configuration), and `metadata.admin` (admin impersonation identity). ASVS 14.3.3 permits session tokens in cookies but not other sensitive data.

### Details
The issue exists in `src/asfquart/generics.py` lines 81-82, `src/asfquart/session.py` lines 86-96, and `atr/admin/__init__.py` lines 130-157. The session cookie is the session state, containing PII and authorization details in a signed-but-readable format.

### Recommended Remediation
**Option A (Preferred):** Implement server-side sessions using a server-side session store:

```python
# Use quart-session with Redis or database backend
from quart_session import Session

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis_client
Session(app)

# Only session ID is stored in cookie, data is server-side
```

**Option B:** Encrypt the session cookie payload:

```python
from cryptography.fernet import Fernet

class EncryptedSessionInterface(SecureCookieSessionInterface):
    def __init__(self, encryption_key: bytes):
        self.fernet = Fernet(encryption_key)
        super().__init__()
    
    def save_session(self, app, session, response):
        # Encrypt before signing
        serialized = self.get_signing_serializer(app).dumps(dict(session))
        encrypted = self.fernet.encrypt(serialized.encode())
        # ... set cookie with encrypted data
```

**Option C (Minimum):** Allowlist session fields to store only essential data:

```python
# Store only uid, cts, uts in cookie
# Perform authorization lookups server-side on each request using uid
ALLOWED_SESSION_FIELDS = {'uid', 'cts', 'uts'}

def write_session(session_data: dict):
    filtered_data = {k: v for k, v in session_data.items() if k in ALLOWED_SESSION_FIELDS}
    # Store filtered_data in cookie
```

### Acceptance Criteria
- [ ] Server-side session store implemented OR session encryption added OR field allowlist implemented
- [ ] PII and authorization data no longer readable in cookie
- [ ] Unit tests verify cookie content is not readable
- [ ] Unit tests verify session functionality works with new approach
- [ ] Integration tests verify authentication and authorization work
- [ ] Performance impact assessed and acceptable
- [ ] Documentation updated with session storage approach

### References
- Source reports: L2:14.3.3.md
- Related findings: FINDING-305
- ASVS sections: 14.3.3

### Priority
Medium

---

## Issue: FINDING-193 - OSV Vulnerability Scanning Has No HTTP Timeout

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The OSV vulnerability scanning functionality makes external HTTP requests to `api.osv.dev` without specifying timeouts. The codebase provides a `create_secure_session()` utility that accepts an optional `timeout` parameter, but OSV scanning does not use it. This can cause worker processes to hang if the OSV API is slow or unresponsive, leading to worker starvation and task failures. Worker process isolation and worker manager 300s timeout backstop provide some protection but are coarse-grained.

### Details
The issue exists in `atr/sbom/osv.py` in the `scan_bundle()`, `_fetch_vulnerabilities_for_batch()`, and `_fetch_vulnerability_details()` functions. HTTP requests are made without explicit timeout configuration.

### Recommended Remediation
Apply timeout to session creation:

```python
import aiohttp
from atr import util

_OSV_REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=60, connect=10)

async def scan_bundle(...):
    async with util.create_secure_session(timeout=_OSV_REQUEST_TIMEOUT) as session:
        # ... make requests with session

async def _fetch_vulnerabilities_for_batch(...):
    async with util.create_secure_session(timeout=_OSV_REQUEST_TIMEOUT) as session:
        # ... make requests with session

async def _fetch_vulnerability_details(...):
    async with util.create_secure_session(timeout=_OSV_REQUEST_TIMEOUT) as session:
        # ... make requests with session
```

Apply same fix to:
- Distribution platform checks (`atr/shared/distribution.py`)
- Apache metadata sources (`atr/datasources/apache.py`)
- GitHub API (`atr/tasks/gha.py`)
- Thread messages (`atr/util.py`)

### Acceptance Criteria
- [ ] Timeout added to OSV scanning HTTP requests
- [ ] Timeout added to distribution platform checks
- [ ] Timeout added to Apache metadata sources
- [ ] Timeout added to GitHub API requests
- [ ] Timeout added to thread message fetching
- [ ] Unit tests verify timeout enforcement
- [ ] Integration tests verify graceful timeout handling
- [ ] Worker process monitoring confirms no hangs

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-052, FINDING-195, FINDING-056, FINDING-204
- ASVS sections: 15.1.3
- CWE: CWE-400

### Priority
Medium

---

## Issue: FINDING-194 - Unbounded Response Sizes on Multiple List Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Multiple endpoints return unbounded result sets without pagination or limits. Affected endpoints include: (1) `/api/checks/list/<project>/<version>` which may return thousands of check results for releases with large archives, (2) `/api/release/paths/<project>/<version>` which collects all file paths in memory before returning, (3) `/admin/data/<model>` which loads all database records, and (4) `/admin/consistency` which walks entire filesystem. Code comments acknowledge the issue ('TODO: We should perhaps paginate this') but it remains unaddressed.

### Details
The issue exists in:
- `atr/api/__init__.py` checks_list() function
- `atr/api/__init__.py` release_paths() function
- `atr/admin/__init__.py` _data_browse() function
- `atr/admin/__init__.py` consistency() function

### Recommended Remediation
Add pagination to API endpoints using query parameters (limit/offset):

```python
# For checks_list() and release_paths()
_MAX_RESULTS = 100

@api.get
async def checks_list(
    session: web.Public,
    project_key: safe.ProjectKey,
    version_key: safe.VersionKey,
    limit: int = _MAX_RESULTS,
    offset: int = 0
) -> dict:
    # Validate pagination parameters (after fixing typo in FINDING-155)
    _pagination_args_validate(limit, offset)
    
    # Apply limit and offset to query
    checks = # ... query with .limit(limit).offset(offset)
    
    total_count = # ... count query without limit/offset
    
    return {
        'checks': checks,
        'total': total_count,
        'limit': limit,
        'offset': offset
    }

# For admin endpoints
_MAX_BROWSE_RECORDS = 500

@admin.get
async def _data_browse(
    session: web.Admin,
    model: str,
    page: int = 1
) -> web.QuartResponse:
    limit = _MAX_BROWSE_RECORDS
    offset = (page - 1) * limit
    
    records = # ... query with .limit(limit).offset(offset)
    total_count = # ... count query
    
    return await render("admin/data_browse.html",
                       records=records,
                       total=total_count,
                       page=page,
                       total_pages=(total_count + limit - 1) // limit)
```

### Acceptance Criteria
- [ ] Pagination added to /api/checks/list endpoint
- [ ] Pagination added to /api/release/paths endpoint
- [ ] Pagination added to /admin/data/<model> endpoint
- [ ] Page size limits enforced on all endpoints
- [ ] Total count included in paginated responses
- [ ] Unit tests verify pagination works correctly
- [ ] Unit tests verify page size limits are enforced
- [ ] Integration tests verify large result sets are paginated
- [ ] Documentation updated with pagination parameters

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-012, FINDING-052, FINDING-207
- ASVS sections: 15.1.3
- CWE: CWE-770

### Priority
Medium

---

## Issue: FINDING-195 - Thread Message Fetching Without Timeout or Concurrency Limit

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The thread message fetching functionality retrieves email messages from Apache mailing list archives without applying HTTP timeouts or limiting concurrent requests. For threads with hundreds of messages, this creates hundreds of simultaneous HTTP requests with no semaphore control. Each request can hang indefinitely without timeouts, causing connection exhaustion and potential rate limiting by the remote server.

### Details
The issue exists in `atr/util.py` in the `thread_messages()` and `get_urls_as_completed()` functions. Message fetching is unbounded in both concurrency and timeout.

### Recommended Remediation
Apply timeout, message count limit, and concurrency control:

```python
import asyncio
import aiohttp

_THREAD_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10)
_MAX_THREAD_MESSAGES = 200
_FETCH_CONCURRENCY = 20

async def thread_messages(thread_url: str) -> list[dict]:
    """Fetch thread messages with limits."""
    message_urls = # ... extract message URLs
    
    # Limit message count
    if len(message_urls) > _MAX_THREAD_MESSAGES:
        log.warning(f"Thread has {len(message_urls)} messages, limiting to {_MAX_THREAD_MESSAGES}")
        message_urls = message_urls[:_MAX_THREAD_MESSAGES]
    
    # Fetch with concurrency limit and timeout
    messages = await get_urls_as_completed(
        message_urls,
        timeout=_THREAD_TIMEOUT,
        max_concurrent=_FETCH_CONCURRENCY
    )
    
    return messages

async def get_urls_as_completed(
    urls: list[str],
    timeout: aiohttp.ClientTimeout,
    max_concurrent: int
) -> list[dict]:
    """Fetch URLs with concurrency control."""
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def fetch_with_semaphore(url: str):
        async with semaphore:
            async with util.create_secure_session(timeout=timeout) as session:
                return await session.get(url)
    
    tasks = [fetch_with_semaphore(url) for url in urls]
    return await asyncio.gather(*tasks, return_exceptions=True)
```

### Acceptance Criteria
- [ ] HTTP timeout added to thread message fetching
- [ ] Message count limit enforced (_MAX_THREAD_MESSAGES)
- [ ] Concurrency control added with semaphore
- [ ] Unit tests verify timeout enforcement
- [ ] Unit tests verify message count limit
- [ ] Unit tests verify concurrency limit
- [ ] Integration tests verify thread fetching with limits
- [ ] Performance tests verify acceptable behavior with large threads

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-193, FINDING-052
- ASVS sections: 15.1.3
- CWE: CWE-400

### Priority
Medium

---

## Issue: FINDING-196 - ZIP Download Streaming Without Size or Time Guards

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The ZIP download endpoint streams an archive of all files in a release directory without checking total size, file count, or imposing streaming timeouts. For releases with many large files (50,000 files, 20 GB total), this causes extended resource consumption during ZIP generation and transfer, potentially holding server resources for hours on slow client connections. Authentication and rate limiting provide some protection.

### Details
The issue exists in `atr/get/download.py` in the `zip_selected()` function. ZIP streaming is unbounded in both file count and total size.

### Recommended Remediation
Add resource limits before streaming:

```python
_MAX_ZIP_FILES = 10000
_MAX_ZIP_TOTAL_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB

@download.get
async def zip_selected(
    session: web.Committer,
    project_key: safe.ProjectKey,
    version_key: safe.VersionKey
) -> web.QuartResponse:
    """Stream ZIP archive with resource limits."""
    
    # Collect files and track size
    files_to_zip = []
    total_size = 0
    
    for file_path in release_directory.iterdir():
        if len(files_to_zip) >= _MAX_ZIP_FILES:
            return quart.Response(
                f"Release contains more than {_MAX_ZIP_FILES} files. "
                f"Please download individual files or contact support.",
                status=413
            )
        
        file_size = file_path.stat().st_size
        total_size += file_size
        
        if total_size > _MAX_ZIP_TOTAL_BYTES:
            return quart.Response(
                f"Release total size exceeds {_MAX_ZIP_TOTAL_BYTES // (1024**3)} GB. "
                f"Please download individual files or contact support.",
                status=413
            )
        
        files_to_zip.append(file_path)
    
    # Log metrics for monitoring
    log.info(
        "Starting ZIP download",
        project=project_key,
        version=version_key,
        file_count=len(files_to_zip),
        total_size=total_size
    )
    
    # Stream ZIP with collected files
    return await stream_zip(files_to_zip)
```

**Alternative approach for very large releases:**
Provide manifest file with individual download links instead of ZIP streaming:

```python
if len(files_to_zip) > _MAX_ZIP_FILES or total_size > _MAX_ZIP_TOTAL_BYTES:
    # Generate manifest with download links
    manifest = generate_download_manifest(files_to_zip)
    return web.TextResponse(manifest, mimetype='text/plain')
```

### Acceptance Criteria
- [ ] File count limit enforced (_MAX_ZIP_FILES)
- [ ] Total size limit enforced (_MAX_ZIP_TOTAL_BYTES)
- [ ] 413 status returned with helpful message when limits exceeded
- [ ] Metrics logged for monitoring (file count, total size)
- [ ] Unit tests verify limits are enforced
- [ ] Integration tests verify large releases handled correctly
- [ ] OR: Manifest-based approach implemented for large releases
- [ ] Documentation updated with ZIP download limits

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-052
- ASVS sections: 15.1.3
- CWE: CWE-770

### Priority
Medium

---

## Issue: FINDING-197 - Unbounded Distribution Status Check Loop

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The distribution status check task queries all pending distributions and processes them sequentially without batch size limits. If many distributions are pending (e.g., 500 due to temporary external service outage), the task attempts to process every one, potentially exceeding the 300s worker timeout. This leaves distributions in inconsistent state when the worker is killed mid-processing, with some updated and others remaining pending.

### Details
The issue exists in `atr/tasks/distribution.py` in the `status_check()` function. The task queries all pending distributions and processes them without batch limits.

### Recommended Remediation
Implement batch processing:

```python
_BATCH_SIZE = 20

async def status_check():
    """Check distribution status with batch processing."""
    # Query only a batch of pending distributions
    pending_distributions = # ... query with .limit(_BATCH_SIZE)
    
    total_pending = # ... count query without limit
    
    log.info(
        "Processing distribution status checks",
        batch_size=len(pending_distributions),
        total_pending=total_pending
    )
    
    for distribution in pending_distributions:
        # Process distribution
        await check_and_update_status(distribution)
    
    if total_pending > _BATCH_SIZE:
        log.info(
            f"Processed {_BATCH_SIZE} of {total_pending} pending distributions. "
            f"Remaining distributions will be processed in subsequent runs."
        )
```

This prevents worker timeout and ensures consistent state. The task will be rescheduled to process remaining distributions in subsequent runs.

### Acceptance Criteria
- [ ] Batch size limit implemented (_BATCH_SIZE = 20)
- [ ] LIMIT clause added to database query
- [ ] Progress logging added indicating batch processing
- [ ] Unit tests verify batch size is enforced
- [ ] Unit tests verify remaining items are left for next run
- [ ] Integration tests verify batch processing behavior
- [ ] Worker timeout monitoring confirms no timeouts occur

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-193, FINDING-052
- ASVS sections: 15.1.3
- CWE: CWE-834

### Priority
Medium

---

## Issue: FINDING-198 - No Documented Risk-Based Remediation Timeframes for Vulnerable Components

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The application implements comprehensive vulnerability detection infrastructure (OSV scanning, pip-audit pre-commit hooks, SBOM quality scoring, severity mapping) but lacks documented policy defining risk-based remediation timeframes that differentiate by severity (Critical/High/Medium/Low with corresponding SLAs). Vulnerabilities are detected and reported only—there is no documented policy defining risk-based remediation timeframes. This is fundamentally a documentation gap rather than a technical deficiency.

### Details
The issue exists in `SECURITY.md`, `atr/sbom/osv.py`, and `atr/tasks/sbom.py` lines 280-350. While technical infrastructure exists for vulnerability detection, no documented policy exists for remediation timeframes based on severity.

### Recommended Remediation
Create a documented remediation policy in `docs/dependency-remediation-policy.md` or add section to `SECURITY.md`:

```markdown
## Dependency Vulnerability Remediation Policy

### Risk-Based Remediation Timeframes

| Severity | CVSS Score Range | Remediation SLA | Notes |
|----------|------------------|-----------------|-------|
| Critical | 9.0 - 10.0 | 48 hours | Emergency patching process available |
| High | 7.0 - 8.9 | 7 days | Prioritized in sprint planning |
| Medium | 4.0 - 6.9 | 30 days | Scheduled in regular maintenance |
| Low | 0.1 - 3.9 | 90 days | Addressed during dependency updates |

### Emergency Override Process

For Critical vulnerabilities, the emergency patching process bypasses the normal 14-day Dependabot cooldown:

1. Security team reviews vulnerability details
2. If confirmed exploitable, emergency PR created immediately
3. Expedited review and deployment process initiated
4. Post-incident review conducted within 7 days

### High-Risk Dependencies

The following dependencies receive enhanced monitoring due to their security-critical nature:

- **cryptography**: Used for TLS, HMAC, JWT signing
- **aiohttp**: Handles all outbound HTTPS connections
- **jinja2**: Template rendering (XSS risk)
- **sqlalchemy**: Database operations (SQL injection risk)
- **pyjwt**: JWT validation (authentication bypass risk)

### Enforcement Mechanisms

1. **Automated Detection**: OSV scanning in CI/CD pipeline
2. **Pre-commit Hooks**: pip-audit blocks commits with vulnerable dependencies
3. **SBOM Quality Scoring**: Tracks vulnerability remediation progress
4. **Regular Audits**: Monthly review of open vulnerability reports
```

Total effort: ~1 day for documentation creation and team review.

### Acceptance Criteria
- [ ] Remediation policy document created
- [ ] Risk-based SLA table defined with severity levels
- [ ] Emergency override process documented
- [ ] High-risk dependencies identified and documented
- [ ] Enforcement mechanisms documented
- [ ] Policy reviewed and approved by security team
- [ ] Policy published in project documentation
- [ ] Team trained on remediation policy

### References
- Source reports: L1:15.1.1.md
- Related findings: FINDING-306, FINDING-307
- ASVS sections: 15.1.1

### Priority
Medium

---

## Issue: FINDING-199 - No Documented Update Timeframe for npm/Frontend Dependencies

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The npm/frontend dependency ecosystem lacks documented update timeframes and automated freshness enforcement, creating an asymmetric policy where Python dependencies have a 30-day documented timeframe but npm dependencies have none. While vulnerability scanning exists via npm audit, there is no mechanism to prevent deployment of stale but non-vulnerable versions. The `bootstrap/context/bump.sh` script implements a 14-day cooldown that prevents TOO-NEW versions but has no check for TOO-OLD versions.

### Details
The issue exists in `bootstrap/source/package.json` line 3 and `bootstrap/context/bump.sh` lines 14-16. No documented update timeframe exists for npm dependencies, and no automated enforcement prevents deployment of outdated versions.

### Recommended Remediation
1. **Add npm to Dependabot** (`.github/dependabot.yml`):

```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/bootstrap/source"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    # Match existing bump.sh cooldown
    ignore:
      - dependency-name: "*"
        update-types: ["version-update:semver-major", "version-update:semver-minor"]
        # Allow updates only after 14 days
```

2. **Add npm freshness check** (`scripts/check_npm_dependencies_updated.py`):

```python
#!/usr/bin/env python3
"""Check that npm dependencies are not stale."""
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

MAX_AGE_DAYS = 60

package_lock = Path("bootstrap/source/package-lock.json")
if not package_lock.exists():
    print("ERROR: package-lock.json not found")
    sys.exit(1)

last_modified = datetime.fromtimestamp(package_lock.stat().st_mtime)
age_days = (datetime.now() - last_modified).days

if age_days > MAX_AGE_DAYS:
    print(f"ERROR: package-lock.json is {age_days} days old (max {MAX_AGE_DAYS})")
    sys.exit(1)

print(f"OK: package-lock.json is {age_days} days old")
```

3. **Document policy in DEPENDENCIES.md**:

```markdown
## npm Dependency Update Policy

### Update Frequency
- npm dependencies must be updated at least every 60 days
- Dependabot runs weekly and creates PRs for outdated packages
- 14-day cooldown period enforced to match bump.sh behavior

### Freshness Enforcement
- Pre-commit hook checks package-lock.json age
- CI pipeline fails if dependencies exceed 60-day maximum age
- Manual override available for documented exceptions
```

### Acceptance Criteria
- [ ] Dependabot configuration added for npm ecosystem
- [ ] Weekly schedule configured with 14-day cooldown
- [ ] Freshness check script created (check_npm_dependencies_updated.py)
- [ ] Pre-commit hook added to run freshness check
- [ ] CI pipeline updated to enforce freshness check
- [ ] DEPENDENCIES.md updated with npm update policy
- [ ] 60-day maximum age documented and enforced
- [ ] Team trained on npm dependency update process

### References
- Source reports: L1:15.2.1.md
- Related findings: None
- ASVS sections: 15.2.1

### Priority
Medium

---

## Issue: FINDING-200 - No Update Timeframe or Monitoring for Dockerfile-Installed External Tools

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Five external tools are installed in the Docker image with pinned versions but no documented update timeframes, automated monitoring, or consistent integrity verification. These tools include syft 1.38.2, parlay 0.9.0, sbomqs 1.1.0, cyclonedx-cli 0.29.1, and Apache RAT 0.18. These tools process untrusted user input (SBOM files, release archives), making vulnerability exposure particularly concerning. Apache RAT has proper SHA512 verification, but syft and cyclonedx-cli are installed via curl without hash verification.

### Details
The issue exists in `Dockerfile.alpine` lines 45-71 (tool installations), 62-64 (syft installation), and 71 (cyclonedx-cli installation). External tools are installed with pinned versions but no update monitoring or consistent integrity verification.

### Recommended Remediation
1. **Add CI check for Dockerfile tool versions** (`scripts/check_dockerfile_tool_versions.py`):

```python
#!/usr/bin/env python3
"""Check that Dockerfile tool versions are not stale."""
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
import requests

MAX_AGE_DAYS = 90

TOOLS = {
    'SYFT_VERSION': 'anchore/syft',
    'PARLAY_VERSION': 'snyk/parlay',
    'SBOMQS_VERSION': 'interlynk-io/sbomqs',
    'CDXCLI_VERSION': 'CycloneDX/cyclonedx-cli',
}

def check_tool_age(tool_name: str, repo: str, current_version: str) -> bool:
    """Check if tool version is within acceptable age."""
    # Query GitHub API for release date
    url = f"https://api.github.com/repos/{repo}/releases/tags/v{current_version}"
    response = requests.get(url)
    
    if response.status_code != 200:
        print(f"WARNING: Could not check {tool_name} version age")
        return True  # Don't fail on API errors
    
    release_date = datetime.fromisoformat(response.json()['published_at'].replace('Z', '+00:00'))
    age_days = (datetime.now(timezone.utc) - release_date).days
    
    if age_days > MAX_AGE_DAYS:
        print(f"ERROR: {tool_name} {current_version} is {age_days} days old (max {MAX_AGE_DAYS})")
        return False
    
    print(f"OK: {tool_name} {current_version} is {age_days} days old")
    return True

# Parse Dockerfile and check each tool
dockerfile = Path("Dockerfile.alpine").read_text()
all_ok = True

for env_var, repo in TOOLS.items():
    match = re.search(rf'ENV {env_var}="?([^"\s]+)"?', dockerfile)
    if match:
        version = match.group(1)
        if not check_tool_age(env_var, repo, version):
            all_ok = False

sys.exit(0 if all_ok else 1)
```

2. **Add hash verification for curl-installed tools** (in Dockerfile.alpine):

```dockerfile
# Add ENV variables for hashes
ENV SYFT_SHA256="<hash>"
ENV CDXCLI_SHA256="<hash>"

# Verify syft download
RUN curl -sSfL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" -o /tmp/syft.tar.gz && \
    echo "${SYFT_SHA256}  /tmp/syft.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft && \
    rm /tmp/syft.tar.gz

# Verify cyclonedx-cli download
RUN curl -L "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v${CDXCLI_VERSION}/cyclonedx-linux-musl-x64" -o /usr/local/bin/cyclonedx && \
    echo "${CDXCLI_SHA256}  /usr/local/bin/cyclonedx" | sha256sum -c - && \
    chmod +x /usr/local/bin/cyclonedx
```

3. **Document policy in DEPENDENCIES.md**:

```markdown
## External Tool Update Policy

### Update Frequency
- External tools in Dockerfile must be updated at least every 90 days
- CI check enforces maximum age of 90 days
- All tools must have SHA256 or SHA512 hash verification

### Monitored Tools
- syft (SBOM generation)
- parlay (SBOM analysis)
- sbomqs (SBOM quality scoring)
- cyclonedx-cli (SBOM format conversion)
- Apache RAT (license analysis)

### Hash Verification
All tools installed via curl must include hash verification:
- Obtain hash from official release page
- Store hash in ENV variable
- Verify hash before installation
```

### Acceptance Criteria
- [ ] CI check script created (check_dockerfile_tool_versions.py)
- [ ] Script integrated into .github/workflows/analyze.yml
- [ ] Hash verification added for syft
- [ ] Hash verification added for cyclonedx-cli
- [ ] 90-day maximum age enforced
- [ ] DEPENDENCIES.md updated with external tool policy
- [ ] Hashes documented and verified
- [ ] CI pipeline fails if tools are stale

### References
- Source reports: L1:15.2.1.md
- Related findings: FINDING-201, FINDING-202
- ASVS sections: 15.2.1

### Priority
Medium

---

## Issue: FINDING-201 - Binary Tool Downloaded Without Integrity Verification (CycloneDX CLI)

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The CycloneDX CLI binary is downloaded from GitHub without any hash or signature verification. The code includes an explicit `# TODO: Check hash` comment acknowledging this gap. A compromised GitHub release or MITM attack could inject a malicious binary into the build. If the CycloneDX CLI binary is tampered with at the source, ATR would incorporate a potentially malicious binary into its Docker image that processes SBOM data.

### Details
The issue exists in `Dockerfile.alpine` lines 45-48. The CycloneDX CLI is downloaded via curl without hash verification, despite a TODO comment indicating this is a known gap.

### Recommended Remediation
Add SHA256 hash verification for CycloneDX CLI download:

```dockerfile
# Add ENV variable for hash
ENV CDXCLI_VERSION=0.29.1
ENV CDXCLI_SHA256="<obtain from official release page>"

# Download and verify
RUN curl -L "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v${CDXCLI_VERSION}/cyclonedx-linux-musl-x64" -o /usr/local/bin/cyclonedx && \
    echo "${CDXCLI_SHA256}  /usr/local/bin/cyclonedx" | sha256sum -c - && \
    chmod +x /usr/local/bin/cyclonedx
```

To obtain the hash:
1. Visit the official GitHub release page
2. Download the binary manually
3. Calculate hash: `sha256sum cyclonedx-linux-musl-x64`
4. Add hash to Dockerfile ENV variable

### Acceptance Criteria
- [ ] CDXCLI_SHA256 ENV variable added to Dockerfile
- [ ] Hash verification added to curl download command
- [ ] Hash obtained from official GitHub release
- [ ] Build fails if hash verification fails
- [ ] Unit tests verify hash verification (if applicable)
- [ ] Documentation updated with hash verification requirement
- [ ] TODO comment removed

### References
- Source reports: L2:15.1.2.md
- Related findings: FINDING-200, FINDING-202
- ASVS sections: 15.1.2

### Priority
Medium

---

## Issue: FINDING-202 - Syft Installed via Unverified Remote Script Execution

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Syft is installed by piping a remote shell script from GitHub directly into `sh`. While HTTPS and version pinning in the URL provide some protection, the script itself could be modified (e.g., via GitHub account compromise) without detection. The previous approach using `go install` (commented out) would have leveraged Go module checksums for integrity. Syft is the primary tool for generating SBOMs from release artifacts. A compromised syft binary could generate falsified SBOMs that hide vulnerable components.

### Details
The issue exists in `Dockerfile.alpine` lines 37-39. Syft is installed via `curl | sh` pattern without hash verification of the installation script or resulting binary.

### Recommended Remediation
Replace `curl | sh` pattern with direct binary download and hash verification:

```dockerfile
# Add ENV variable for hash
ENV SYFT_VERSION=1.38.2
ENV SYFT_SHA256="<obtain from official release page>"

# Download tarball directly with hash verification
RUN curl -sSfL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" -o /tmp/syft.tar.gz && \
    echo "${SYFT_SHA256}  /tmp/syft.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft && \
    rm /tmp/syft.tar.gz
```

**Alternative:** Restore `go install` approach which provides Go module checksum verification:

```dockerfile
RUN go install github.com/anchore/syft/cmd/syft@v${SYFT_VERSION}
```

This approach leverages Go's built-in integrity verification via module checksums.

### Acceptance Criteria
- [ ] `curl | sh` pattern removed
- [ ] Direct binary download with hash verification implemented
- [ ] OR: `go install` approach restored with module checksum verification
- [ ] SYFT_SHA256 ENV variable added (if using direct download)
- [ ] Hash obtained from official GitHub release
- [ ] Build fails if hash verification fails
- [ ] Unit tests verify hash verification (if applicable)
- [ ] Documentation updated with installation method

### References
- Source reports: L2:15.1.2.md
- Related findings: FINDING-200, FINDING-201
- ASVS sections: 15.1.2

### Priority
Medium

---

## Issue: FINDING-203 - No Formal SBOM for ATR's Own Third-Party Dependencies

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
While ATR provides comprehensive SBOM generation, validation, and management tooling for projects it serves, ATR does not maintain a formal SBOM (CycloneDX or SPDX format) for its own third-party dependencies. The `pip-audit.requirements` file serves as an informal inventory with exact versions, and `uv.lock` pins resolved versions, but neither constitutes a standard-format SBOM. Without a formal SBOM, automated supply chain analysis tools cannot consume ATR's dependency information in a standardized way.

### Details
The issue exists project-wide—no SBOM artifact is generated or published for ATR's own dependencies. While dependency information exists in multiple formats (requirements files, lock files), none conform to SBOM standards (CycloneDX or SPDX).

### Recommended Remediation
Add SBOM generation to CI workflow:

```yaml
# In .github/workflows/analyze.yml or new workflow
name: Generate SBOM

on:
  push:
    branches: [main]
  release:
    types: [published]

jobs:
  generate-sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install uv
        run: pip install uv
      
      - name: Generate CycloneDX SBOM
        run: |
          uv run --frozen cyclonedx-py environment \
            --output-format json \
            --outfile sbom.cdx.json
      
      - name: Upload SBOM as artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.cdx.json
      
      - name: Attach SBOM to release
        if: github.event_name == 'release'
        uses: actions/upload-release-asset@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          upload_url: ${{ github.event.release.upload_url }}
          asset_path: sbom.cdx.json
          asset_name: sbom.cdx.json
          asset_content_type: application/json
```

Add Makefile target for local generation:

```makefile
.PHONY: sbom
sbom:
	uv run --frozen cyclonedx-py environment \
		--output-format json \
		--outfile sbom.cdx.json
	@echo "SBOM generated: sbom.cdx.json"
```

### Acceptance Criteria
- [ ] CI workflow added to generate SBOM
- [ ] SBOM generated on push to main branch
- [ ] SBOM attached to GitHub releases
- [ ] SBOM uploaded as build artifact
- [ ] Makefile target added for local SBOM generation
- [ ] SBOM format validated (CycloneDX JSON)
- [ ] Documentation updated with SBOM generation instructions
- [ ] SBOM includes all Python dependencies from uv.lock

### References
- Source reports: L2:15.1.2.md
- Related findings: None
- ASVS sections: 15.1.2

### Priority
Medium

---

## Issue: FINDING-204 - OSV API Unbounded Pagination and Detail Fetching

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The OSV API pagination implementation has no maximum page limit, and vulnerability detail fetching has no concurrency bounds. Components with hundreds of vulnerabilities cause hundreds of sequential HTTP requests, consuming worker resources for extended periods. The pagination while loop has no iteration limit, and unique vulnerability detail fetching has no total count or individual timeout limits.

### Details
The issue exists in `atr/sbom/osv.py` lines 227-246 (pagination loop) and 268-283 (detail fetching). Unbounded loops and sequential requests can cause worker resource exhaustion.

### Recommended Remediation
Add limits to pagination and detail fetching:

```python
import asyncio

_MAX_PAGINATION_PAGES = 20
_MAX_VULNERABILITIES_PER_COMPONENT = 500
_MAX_VULNERABILITY_DETAILS = 200
_VULNERABILITY_DETAIL_TIMEOUT = 10  # seconds per detail fetch

async def _fetch_vulnerabilities_for_batch(...):
    """Fetch vulnerabilities with pagination limits."""
    page_count = 0
    vulnerability_count = 0
    
    while page_token:
        page_count += 1
        if page_count > _MAX_PAGINATION_PAGES:
            log.warning(
                f"Reached maximum pagination pages ({_MAX_PAGINATION_PAGES}), "
                f"stopping pagination for component"
            )
            break
        
        # Fetch page
        vulnerabilities = # ... fetch from OSV API
        vulnerability_count += len(vulnerabilities)
        
        if vulnerability_count > _MAX_VULNERABILITIES_PER_COMPONENT:
            log.warning(
                f"Component has more than {_MAX_VULNERABILITIES_PER_COMPONENT} vulnerabilities, "
                f"truncating results"
            )
            break
        
        # Process vulnerabilities
        # ...

async def _fetch_vulnerability_details(...):
    """Fetch vulnerability details with limits and timeouts."""
    # Truncate unique_ids if too many
    if len(unique_ids) > _MAX_VULNERABILITY_DETAILS:
        log.warning(
            f"Truncating vulnerability detail fetching from {len(unique_ids)} "
            f"to {_MAX_VULNERABILITY_DETAILS}"
        )
        unique_ids = list(unique_ids)[:_MAX_VULNERABILITY_DETAILS]
    
    # Fetch with timeout per detail
    async def fetch_with_timeout(vuln_id: str):
        try:
            return await asyncio.wait_for(
                _fetch_single_vulnerability(vuln_id),
                timeout=_VULNERABILITY_DETAIL_TIMEOUT
            )
        except asyncio.TimeoutError:
            log.warning(f"Timeout fetching vulnerability {vuln_id}")
            return None
    
    tasks = [fetch_with_timeout(vid) for vid in unique_ids]
    return await asyncio.gather(*tasks, return_exceptions=True)
```

### Acceptance Criteria
- [ ] Maximum pagination pages limit added (_MAX_PAGINATION_PAGES)
- [ ] Maximum vulnerabilities per component limit added (_MAX_VULNERABILITIES_PER_COMPONENT)
- [ ] Maximum vulnerability details limit added (_MAX_VULNERABILITY_DETAILS)
- [ ] Individual timeout added for detail fetching (_VULNERABILITY_DETAIL_TIMEOUT)
- [ ] Warning logs added when limits are reached
- [ ] Unit tests verify limits are enforced
- [ ] Integration tests verify OSV scanning with limits
- [ ] Worker timeout monitoring confirms no hangs

### References
- Source reports: L2:15.2.2.md
- Related findings: FINDING-193
- ASVS sections: 15.2.2

### Priority
Medium

---

## Issue: FINDING-205 - SSH Server Lacks Connection and Idle Timeouts

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The SSH server configuration lacks keepalive and idle timeout settings. Authenticated connections can remain idle indefinitely, exhausting the server's connection capacity over time. No automatic cleanup of stale connections exists.

### Details
The issue exists in `atr/ssh.py` line 181, where `asyncssh.create_server()` is called without keepalive or timeout parameters.

### Recommended Remediation
Add keepalive and timeout parameters to SSH server creation:

```python
# In atr/ssh.py, line 181
server = await asyncssh.create_server(
    # ... existing parameters
    keepalive_interval=30,  # Send keepalive every 30 seconds
    keepalive_count_max=3,  # Close after 3 missed keepalives (90s total)
)
```

This sends keepalive every 30 seconds and closes connections after 3 missed keepalives (90 seconds total idle time).

**Optional:** Add configuration options for flexibility:

```python
# In configuration
SSH_KEEPALIVE_INTERVAL = int(os.environ.get('SSH_KEEPALIVE_INTERVAL', '30'))
SSH_KEEPALIVE_COUNT_MAX = int(os.environ.get('SSH_KEEPALIVE_COUNT_MAX', '3'))

# In SSH server creation
server = await asyncssh.create_server(
    # ... existing parameters
    keepalive_interval=SSH_KEEPALIVE_INTERVAL,
    keepalive_count_max=SSH_KEEPALIVE_COUNT_MAX,
)
```

### Acceptance Criteria
- [ ] keepalive_interval parameter added (30 seconds)
- [ ] keepalive_count_max parameter added (3 attempts)
- [ ] Configuration options added for flexibility (optional)
- [ ] Unit tests verify idle connections are closed
- [ ] Integration tests verify SSH keepalive behavior
- [ ] Documentation updated with timeout settings
- [ ] Manual testing confirms stale connections are cleaned up

### References
- Source reports: L2:15.2.2.md
- Related findings: FINDING-050
- ASVS sections: 15.2.2

### Priority
Medium

---

## Issue: FINDING-206 - SBOM Conformance External HTTP Requests Without Explicit Timeout

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
SBOM conformance checking makes N sequential HTTP requests to `api.deps.dev` with only aiohttp's default 300-second timeout. No explicit timeout or request count limit is configured. SBOMs with 50 components result in 50 sequential API calls, each waiting up to 300s.

### Details
The issue exists in `atr/sbom/conformance.py` lines 30-120. HTTP requests to deps.dev API are made without explicit timeout configuration or request count limits.

### Recommended Remediation
Add timeout and request count limits:

```python
import aiohttp

_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=10)
_MAX_SUPPLIER_LOOKUPS = 50

async def check_conformance(sbom: dict) -> dict:
    """Check SBOM conformance with limits."""
    components = sbom.get('components', [])
    
    # Limit supplier lookups
    if len(components) > _MAX_SUPPLIER_LOOKUPS:
        log.warning(
            f"SBOM has {len(components)} components, "
            f"limiting supplier lookups to {_MAX_SUPPLIER_LOOKUPS}"
        )
        components = components[:_MAX_SUPPLIER_LOOKUPS]
    
    async with util.create_secure_session(timeout=_HTTP_TIMEOUT) as session:
        for component in components:
            try:
                # Lookup with timeout
                supplier_info = await session.get(
                    f"https://api.deps.dev/v3alpha/purl/{component['purl']}"
                )
            except asyncio.TimeoutError:
                log.warning(f"Timeout looking up supplier for {component['purl']}")
                continue
            
            # Process supplier info
            # ...
```

### Acceptance Criteria
- [ ] HTTP timeout added (_HTTP_TIMEOUT = 10 seconds)
- [ ] Request count limit added (_MAX_SUPPLIER_LOOKUPS = 50)
- [ ] Timeout applied to all deps.dev API requests
- [ ] Warning logged when limits are reached
- [ ] Unit tests verify timeout enforcement
- [ ] Unit tests verify request count limit
- [ ] Integration tests verify conformance checking with limits
- [ ] Worker timeout monitoring confirms no hangs

### References
- Source reports: L2:15.2.2.md
- Related findings: FINDING-193
- ASVS sections: 15.2.2

### Priority
Medium

---

## Issue: FINDING-207 - Admin Data Browser Loads All Records Without Pagination

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The administrative data browser executes `.all()` queries without pagination. For models like CheckResult and Task that can have millions of rows, this loads all records into memory, causing excessive database I/O and memory consumption.

### Details
The issue exists in `atr/admin/__init__.py` lines 500-530. The data browser function queries all records without applying pagination limits.

### Recommended Remediation
Add pagination to data browser queries:

```python
BROWSE_PAGE_SIZE = 100

@admin.get
async def _data_browse(
    session: web.Admin,
    model: str,
    page: int = 1
) -> web.QuartResponse:
    """Browse database records with pagination."""
    # Get model class
    model_class = # ... resolve model from name
    
    # Calculate offset
    limit = BROWSE_PAGE_SIZE
    offset = (page - 1) * limit
    
    # Fetch page of records
    async with db.session() as db_session:
        # Count total records
        total_count = await db_session.scalar(
            sql.select(sql.func.count()).select_from(model_class)
        )
        
        # Fetch page
        result = await db_session.execute(
            sql.select(model_class)
            .limit(limit)
            .offset(offset)
        )
        records = result.scalars().all()
    
    # Calculate pagination info
    total_pages = (total_count + limit - 1) // limit
    
    return await render(
        "admin/data_browse.html",
        model=model,
        records=records,
        page=page,
        total_pages=total_pages,
        total_count=total_count,
        page_size=limit
    )
```

Update template to include pagination controls:

```html
<!-- In admin/data_browse.html -->
<nav>
  <ul class="pagination">
    {% if page > 1 %}
    <li><a href="?page={{ page - 1 }}">Previous</a></li>
    {% endif %}
    
    <li>Page {{ page }} of {{ total_pages }}</li>
    
    {% if page < total_pages %}
    <li><a href="?page={{ page + 1 }}">Next</a></li>
    {% endif %}
  </ul>
</nav>
```

### Acceptance Criteria
- [ ] BROWSE_PAGE_SIZE constant added (100 records per page)
- [ ] Pagination implemented with LIMIT and OFFSET
- [ ] Total count query added for pagination UI
- [ ] Page parameter added to endpoint
- [ ] Template updated with pagination controls
- [ ] Unit tests verify pagination works correctly
- [ ] Integration tests verify large datasets are paginated
- [ ] Performance tests confirm acceptable query times

### References
- Source reports: L2:15.2.2.md
- Related findings: FINDING-194
- ASVS sections: 15.2.2

### Priority
Medium

---

## Issue: FINDING-208 - Unbounded PGP Key Block Processing in Bulk Operations

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The bulk PGP key processing function has no limit on the number of key blocks processed per request. Each block triggers CPU-intensive PGP parsing operations. Attackers can submit 1000+ key blocks in a single request, monopolizing workers until CPU limit kills the process.

### Details
The issue exists in `atr/storage/writers/keys.py` line 388. The bulk key processing function accepts an unbounded list of key blocks without enforcing a maximum count.

### Recommended Remediation
Add maximum key block count limit:

```python
_MAX_KEY_BLOCKS_PER_REQUEST = 100

def add_bulk_public_keys(self, key_blocks: list[str], committee_id: int) -> Outcome:
    """Add multiple public keys with count limit."""
    # Check key block count
    if len(key_blocks) > _MAX_KEY_BLOCKS_PER_REQUEST:
        return Outcome.err(
            f"Cannot process more than {_MAX_KEY_BLOCKS_PER_REQUEST} key blocks "
            f"in a single request. Received {len(key_blocks)} blocks."
        )
    
    # Process key blocks
    results = []
    for key_block in key_blocks:
        result = self.add_public_key(key_block, committee_id)
        results.append(result)
    
    return Outcome.ok(results)
```

This aligns with the single-block enforcement in `FoundationCommitter.__ensure_one()` and prevents resource exhaustion.

### Acceptance Criteria
- [ ] _MAX_KEY_BLOCKS_PER_REQUEST constant added (100 blocks)
- [ ] Key block count check added to bulk processing function
- [ ] Error returned with helpful message when limit exceeded
- [ ] Unit tests verify limit is enforced
- [ ] Unit tests verify processing works within limit
- [ ] Integration tests verify bulk key processing with limits
- [ ] Documentation updated with bulk processing limits

### References
- Source reports: L2:15.2.2.md
- Related findings: None
- ASVS sections: 15.2.2

### Priority
Medium

---

## Issue: FINDING-209 - Implicit Reliance on cmarkgfm Default Safe Behavior Without Explicit Configuration

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application correctly uses cmarkgfm with safe defaults, but the safety is implicit rather than explicit. This creates maintenance risks: no code comment documenting the security requirement, no explicit options=0 parameter (relies on library default), no unit test verifying raw HTML suppression, and future developers could add options=cmarkgfm.Options.CMARK_OPT_UNSAFE without recognizing security implications. While currently secure, this represents a code quality and defense-in-depth gap.

### Details
The issue exists in `atr/get/checklist.py` line 55 and `scripts/gfm_to_html.py` line 35. While cmarkgfm is used correctly, the security-critical safe behavior is not explicitly enforced or documented.

### Recommended Remediation
**Immediate (Priority 1):** Add unit tests to verify cmarkgfm suppresses raw HTML:

```python
def test_cmarkgfm_suppresses_raw_html():
    """Verify cmarkgfm default behavior suppresses raw HTML."""
    markdown = "<script>alert('XSS')</script>\n\nNormal text"
    html = cmarkgfm.github_flavored_markdown_to_html(markdown)
    
    # Should NOT contain script tag
    assert '<script>' not in html
    assert 'alert' not in html
    
    # Should contain escaped or removed HTML
    assert 'Normal text' in html

def test_cmarkgfm_suppresses_javascript_urls():
    """Verify cmarkgfm suppresses javascript: URLs."""
    markdown = "[Click me](javascript:alert('XSS'))"
    html = cmarkgfm.github_flavored_markdown_to_html(markdown)
    
    # Should NOT contain javascript: URL
    assert 'javascript:' not in html.lower()

def test_cmarkgfm_suppresses_data_urls():
    """Verify cmarkgfm suppresses data: URLs."""
    markdown = "![Image](data:text/html,<script>alert('XSS')</script>)"
    html = cmarkgfm.github_flavored_markdown_to_html(markdown)
    
    # Should NOT contain data: URL
    assert 'data:' not in html.lower()
```

**Short-term (Priority 2):** Make security requirement explicit:

```python
# In atr/get/checklist.py and scripts/gfm_to_html.py

# Security: ASVS 1.3.5 - Explicit safe options
# cmarkgfm defaults to options=0 (safe mode) which:
# - Suppresses raw HTML tags
# - Blocks javascript: URLs
# - Blocks data: URLs
_SAFE_CMARKGFM_OPTIONS = 0

html = cmarkgfm.github_flavored_markdown_to_html(
    markdown,
    options=_SAFE_CMARKGFM_OPTIONS
)
```

**Long-term:** Pin cmarkgfm version with comment:

```
# In requirements.txt
cmarkgfm==2024.1.14  # Pinned: verified safe behavior per ASVS 1.3.5
```

### Acceptance Criteria
- [ ] Unit tests added to verify raw HTML suppression
- [ ] Unit tests added to verify JavaScript URL blocking
- [ ] Unit tests added to verify data URL blocking
- [ ] _SAFE_CMARKGFM_OPTIONS constant added with security comment
- [ ] Explicit options parameter passed to cmarkgfm calls
- [ ] cmarkgfm version pinned in requirements.txt with comment
- [ ] Code review confirms explicit security configuration

### References
- Source reports: L2:1.3.5.md
- Related findings: FINDING-020, FINDING-065
- ASVS sections: 1.3.5
- CWE: CWE-1188

### Priority
Low

---

## Issue: FINDING-210 - LDAP Filter Construction via String Interpolation Without escape_filter_chars() in _get_project_memberships

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `_get_project_memberships()` method constructs LDAP filters using string interpolation without applying `ldap3.utils.conv.escape_filter_chars()`. While the `Committer.__init__()` method validates the user parameter with a strict regex (`^[-_a-z0-9]+$`), this creates a coupling where the filter safety depends entirely on upstream validation rather than proper output encoding at the point of use. If the regex at line 51 were ever modified to allow additional characters, LDAP injection would become possible because `escape_filter_chars()` is not called.

### Details
The issue exists in `atr/principal.py` line 142 (filter construction) and lines 34-35 (upstream validation). While currently protected by input validation, defense-in-depth requires output encoding at the point of use.

### Recommended Remediation
Apply defense-in-depth by adding `escape_filter_chars()` at the point of filter construction:

```python
from ldap3.utils import conv

def _get_project_memberships(self) -> tuple[set[str], set[str]]:
    """Get project memberships with LDAP filter escaping."""
    # Defense-in-depth: escape even though input is validated
    escaped_user = conv.escape_filter_chars(self.user)
    
    result = ldap_search.search(
        ldap_server=self.ldap_server,
        ldap_query=ldap_filter % (escaped_user,),
        # ... rest of parameters
    )
    # ... rest of implementation
```

This ensures filter safety is maintained even if upstream validation changes in the future.

### Acceptance Criteria
- [ ] escape_filter_chars() added to filter construction
- [ ] Unit tests verify escaping is applied
- [ ] Unit tests verify special characters are properly escaped
- [ ] Code review confirms defense-in-depth approach
- [ ] Documentation updated with LDAP filter escaping requirement

### References
- Source reports: L2:1.2.6.md
- Related findings: FINDING-072
- ASVS sections: 1.2.6
- CWE: CWE-90

### Priority
Low

---

## Issue: FINDING-211 - Task Argument Models Lack Safe Type Re-Validation at Deserialization

**Labels:** bug, security, priority:low, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
Task argument models (`FileArgs`, `ScoreArgs`) accept validated inputs from web routes but do not re-apply safe type validation when deserializing in worker processes. The web layer validates inputs through `safe.ProjectKey`, `safe.VersionKey`, `safe.RelPath`, then serializes to plain strings for the task queue. Worker processes deserialize these as plain string types without re-validation through the safe type system. While `project_key`, `version_key`, and `revision_number` are re-validated within function bodies, `file_path` is NOT re-validated.

### Details
The issue exists in `atr/tasks/sbom.py` lines 39-43 (FileArgs and ScoreArgs models). Task arguments cross a trust boundary (web process → task queue → worker process) without re-validation at deserialization.

### Recommended Remediation
Add Pydantic model validator to re-validate all fields through safe types at deserialization:

```python
import pydantic
from atr.models import safe

class FileArgs(pydantic.BaseModel):
    project_key: str
    version_key: str
    revision_number: int
    file_path: str
    
    @pydantic.model_validator(mode='after')
    def validate_safe_types(self) -> 'FileArgs':
        """Re-validate all fields through safe types at deserialization."""
        # Validate each field - raises ValueError if invalid
        safe.ProjectKey(self.project_key)
        safe.VersionKey(self.version_key)
        safe.RevisionNumber(self.revision_number)
        safe.RelPath(self.file_path)
        
        return self

class ScoreArgs(pydantic.BaseModel):
    project_key: str
    version_key: str
    revision_number: int
    file_path: str
    
    @pydantic.model_validator(mode='after')
    def validate_safe_types(self) -> 'ScoreArgs':
        """Re-validate all fields through safe types at deserialization."""
        safe.ProjectKey(self.project_key)
        safe.VersionKey(self.version_key)
        safe.RevisionNumber(self.revision_number)
        safe.RelPath(self.file_path)
        
        return self
```

Apply similar validation to other task argument models throughout the codebase.

### Acceptance Criteria
- [ ] Pydantic model validator added to FileArgs
- [ ] Pydantic model validator added to ScoreArgs
- [ ] All fields validated through safe types at deserialization
- [ ] Unit tests verify validation is applied at deserialization
- [ ] Unit tests verify invalid values raise ValueError
- [ ] Code review confirms other task argument models are similarly protected
- [ ] Integration tests verify task argument validation

### References
- Source reports: L1:1.2.5.md, L2:1.3.3.md
- Related findings: FINDING-073
- ASVS sections: 1.2.5, 1.3.3
- CWE: CWE-20

### Priority
Low

---

## Issue: FINDING-212 - Regex Escaping Applied Only as Fallback in Committee Directory Filter

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The committee directory filter applies regex escaping only as a fallback when the initial unescaped regex construction fails. Valid but malicious regex patterns (e.g., ReDoS patterns like `(a+)+`) pass through the primary path without escaping. Syntactically invalid patterns are correctly caught and escaped, but valid malicious patterns are not. This creates a ReDoS vulnerability for valid-but-pathological regex patterns that can cause catastrophic backtracking and browser unresponsiveness.

### Details
The issue exists in `atr/static/js/src/committee-directory.js` lines 36-50. The try-catch block only escapes patterns that fail regex construction, allowing valid-but-malicious patterns through.

### Recommended Remediation
Always escape first for literal matching:

```javascript
// In atr/static/js/src/committee-directory.js

function filterProjects() {
    const projectFilter = document.getElementById('project-filter').value;
    
    // Always escape for literal matching (no regex interpretation)
    const escapedFilter = projectFilter.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&');
    
    // Create regex with escaped pattern
    const regex = new RegExp(escapedFilter, 'i');
    
    // Apply filter to project cards
    // ... rest of implementation
}
```

**For advanced use cases with explicit regex mode:**

```javascript
// Add checkbox for regex mode
<label>
    <input type="checkbox" id="regex-mode"> Use regex pattern
</label>

function filterProjects() {
    const projectFilter = document.getElementById('project-filter').value;
    const regexMode = document.getElementById('regex-mode').checked;
    
    let regex;
    if (regexMode) {
        // Explicit regex mode - validate pattern only when requested
        try {
            regex = new RegExp(projectFilter, 'i');
        } catch (e) {
            // Show error to user
            console.warn('Invalid regex pattern:', e);
            return;
        }
    } else {
        // Default: literal matching with escaping
        const escapedFilter = projectFilter.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&');
        regex = new RegExp(escapedFilter, 'i');
    }
    
    // Apply filter
    // ... rest of implementation
}
```

### Acceptance Criteria
- [ ] Regex escaping applied before regex construction (not as fallback)
- [ ] OR: Explicit regex mode checkbox added with user opt-in
- [ ] Unit tests verify ReDoS patterns are escaped
- [ ] Unit tests verify literal matching works correctly
- [ ] Manual testing confirms filter behavior is correct
- [ ] Performance tests verify no ReDoS vulnerability

### References
- Source reports: L2:1.2.9.md
- Related findings: FINDING-074
- ASVS sections: 1.2.9
- CWE: CWE-1333

### Priority
Low

---

## Issue: FINDING-213 - VersionKey Safe Type Missing Documented Business Rules

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `safe.VersionKey` type used for API URL parameter validation is missing two business rules that are documented and enforced in the web form validation function `version_key_error()`. This creates an inconsistency where version keys accepted via the API would be rejected via web forms. The missing rules are: (1) must not be the literal string 'version', and (2) must not contain consecutive special characters (+, ., -).

### Details
The issue exists in `atr/util.py` lines 81-87 (web form validation) and `atr/models/safe.py` lines 95-105 (safe type validation). The safe type has a TODO comment acknowledging the missing validation.

### Recommended Remediation
Add the missing validation rules to `safe.VersionKey._additional_validations()`:

```python
class VersionKey(str):
    """Version key with complete business rule validation."""
    
    @classmethod
    def _additional_validations(cls, value: str):
        """Apply business rules beyond basic format validation."""
        # Rule 1: Reject literal string 'version' (case-insensitive)
        if value.lower() == 'version':
            raise ValueError("Version key cannot be the literal string 'version'")
        
        # Rule 2: Reject consecutive special characters
        if re.search(r'[+.-]{2,}', value):
            raise ValueError("Version key cannot contain consecutive special characters (+, ., -)")
        
        # Existing validations
        # ...
```

Remove the TODO comment and duplicate rules from `version_key_error()` in `atr/util.py`:

```python
def version_key_error(version_key: str) -> str | None:
    """Validate version key using safe type."""
    try:
        safe.VersionKey(version_key)
        return None
    except ValueError as e:
        return str(e)
```

### Acceptance Criteria
- [ ] Literal 'version' string rejection added to safe.VersionKey
- [ ] Consecutive special character rejection added to safe.VersionKey
- [ ] TODO comment removed from safe.VersionKey
- [ ] version_key_error() simplified to use safe.VersionKey
- [ ] Unit tests verify 'version' string is rejected
- [ ] Unit tests verify consecutive special characters are rejected
- [ ] Integration tests verify API and web form validation are consistent

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Low

---

## Issue: FINDING-214 - Vote Casting POST Endpoint Relies on Indirect Phase Check

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The vote casting POST handler in `atr/post/vote.py` validates that a vote thread exists but does not explicitly check that the release is in RELEASE_CANDIDATE phase. If a vote thread exists from a previous voting round and the release was moved back to RELEASE_CANDIDATE_DRAFT (after a failed vote), the stale thread would still exist while the release is no longer in the voting phase. The handler relies on the indirect check that `send_user_vote()` validates vote thread existence, but this doesn't prevent votes on stale threads.

### Details
The issue exists in `atr/post/vote.py` and `atr/shared/vote.py`. The vote casting handler does not explicitly validate the release phase before accepting votes.

### Recommended Remediation
Add explicit phase validation in `selected_post()` before processing votes:

```python
@vote.typed
async def selected_post(
    session: web.Committer,
    project_key: safe.ProjectKey,
    version_key: safe.VersionKey,
    form: form.VoteForm
) -> web.QuartResponse:
    """Cast vote with explicit phase validation."""
    # Fetch release
    release = # ... fetch from database
    
    # Explicit phase check for defense-in-depth
    if release.phase != sql.ReleasePhase.RELEASE_CANDIDATE:
        return await render(
            "vote/error.html",
            error="Voting is only allowed for releases in RELEASE_CANDIDATE phase"
        )
    
    # Validate vote thread exists
    if not release.vote_thread_url:
        return await render(
            "vote/error.html",
            error="No active vote thread for this release"
        )
    
    # Process vote
    # ... rest of implementation
```

This provides defense in depth beyond the vote thread existence check.

### Acceptance Criteria
- [ ] Explicit phase validation added to vote casting handler
- [ ] Error message returned when release is not in RELEASE_CANDIDATE phase
- [ ] Unit tests verify votes are rejected for non-CANDIDATE phases
- [ ] Unit tests verify votes are accepted for RELEASE_CANDIDATE phase
- [ ] Integration tests verify vote casting phase validation
- [ ] Manual testing confirms stale vote threads cannot be used

### References
- Source reports: L1:2.3.1.md
- Related findings: None
- ASVS sections: 2.3.1
- CWE: CWE-841

### Priority
Low

---

## Issue: FINDING-215 - Documentation Missing Cross-Entity Business Logic Validation Rules

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `input-validation.md` documentation defines data integrity validation rules in `validate.py`, but does not document significant cross-entity contextual validation rules implemented in `atr/db/interaction.py` and other modules. ASVS 2.1.2 explicitly requires documentation to define how logical and contextual consistency is validated. Undocumented rules include vote readiness cross-checks, trusted publishing phase matching, email recipient domain validation, and repository/workflow validation.

### Details
The issue exists in `atr/docs/input-validation.md` (missing documentation) and implementation in `atr/db/interaction.py` lines 220-260, 310-340, 410-440, and `atr/mail.py` lines 115-125.

### Recommended Remediation
Add a 'Business Logic Validation' section to `input-validation.md`:

```markdown
## Business Logic Validation

### Cross-Entity Contextual Validation

Beyond field-level validation, ATR enforces business rules that span multiple entities and depend on system state.

#### Vote Initiation Requirements

**Function:** `release_ready_for_vote()` in `atr/db/interaction.py`

**Rules:**
- Release must be in RELEASE_CANDIDATE_DRAFT phase
- No blocker-severity check failures
- At least one artifact file present
- No ongoing background tasks
- Vote thread must not already exist

**Enforcement:** Called before starting vote via `/vote/start` endpoint

#### Trusted Publishing Validation

**Function:** `trusted_jwt_for_dist()` and `_trusted_project()` in `atr/db/interaction.py`

**Rules:**
- GitHub JWT subject must match configured repository
- Workflow path must match configured path
- Release must be in RELEASE_PREVIEW phase
- Distribution record must exist for the release

**Enforcement:** Called during GitHub Actions trusted publishing workflow

#### Email Recipient Domain Validation

**Function:** `_validate_recipient()` in `atr/mail.py`

**Rules:**
- Recipient email must end with `@apache.org` or configured allowed domains
- Prevents email to arbitrary external addresses
- Applied to announcement and vote emails

**Enforcement:** Called before sending any email

#### Repository/Workflow Validation

**Function:** Policy validation in `atr/storage/writers/policy.py`

**Rules:**
- GitHub repository name must match pattern: `apache/{project_name}`
- Workflow path must be within `.github/workflows/`
- Workflow file must exist in repository

**Enforcement:** Applied when updating release policy configuration

### Contextual Consistency Examples

| Validation Rule | Entities Involved | Enforcement Location |
|----------------|-------------------|---------------------|
| Vote readiness | Release, CheckResult, WorkflowStatus | `release_ready_for_vote()` |
| Trusted publishing | Release, Distribution, GitHub JWT | `trusted_jwt_for_dist()` |
| Email recipients | EmailMessage, Configuration | `_validate_recipient()` |
| Phase transitions | Release, WorkflowStatus, CheckResult | `atr/storage/writers/release.py` |
| Distribution automation | Release, Distribution, Policy | `atr/storage/writers/announce.py` |

### Additional Business Rules

- **Rate Limiting:** API endpoints enforce per-user rate limits (documented in `atr/blueprints/api.py`)
- **Archive Extraction:** Maximum file count, size, and depth limits (documented in `atr/tasks/checks/`)
- **Voting Business Rules:** Quorum requirements, vote resolution logic (documented in `atr/shared/vote.py`)
- **Session Lifecycle:** Inactivity timeout (7 days), absolute maximum (72 hours) (documented in `src/asfquart/session.py`)
- **Trusted Publishing:** JWT validation, phase matching (documented in `atr/db/interaction.py`)
- **Distribution Retry Logic:** Exponential backoff, maximum attempts (documented in `atr/tasks/distribution.py`)
```

### Acceptance Criteria
- [ ] Business Logic Validation section added to input-validation.md
- [ ] Vote initiation requirements documented
- [ ] Trusted publishing validation rules documented
- [ ] Email recipient domain validation documented
- [ ] Repository/workflow validation documented
- [ ] Contextual consistency table created
- [ ] Additional business rules documented
- [ ] Cross-references added to implementation files
- [ ] Documentation reviewed and approved

### References
- Source reports: L2:2.1.2.md, L2:2.1.3.md
- Related findings: None
- ASVS sections: 2.1.2, 2.1.3
- CWE: CWE-1059

### Priority
Low

---

## Issue: FINDING-216 - Missing All Framing Protection for /~sbp/ on Dev VM

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `/~sbp/` path on the development VM (`tooling-vm-ec2-de.apache.org`) is configured to serve content directly from a user's home directory without any framing protection headers. Neither 'frame-ancestors' in CSP nor X-Frame-Options is set, leaving the content completely unprotected against iframe embedding. The path uses `ProxyPass /~sbp/ !` so requests are NOT proxied to the application, and Apache serves content directly from `/home/sbp/www/` with no CSP header set and no X-Frame-Options set. Limited practical impact as this is a developer directory on a development VM only.

### Details
The issue exists in `tooling-vm-ec2-de.apache.org.yaml` lines 161-168. The `/~sbp/` directory configuration lacks any framing protection headers.

### Recommended Remediation
Add comprehensive security headers to the `/~sbp/` Directory block:

```yaml
<Directory /home/sbp/www/>
    Options +Indexes +FollowSymLinks -ExecCGI
    Require all granted
    IndexOptions FancyIndexing NameWidth=* FoldersFirst ScanHTMLTitles DescriptionWidth=*
    DefaultType text/plain
    Header always set Content-Security-Policy "frame-ancestors 'none'"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "no-referrer"
    Header always set Cross-Origin-Resource-Policy "same-origin"
    SetHandler none
</Directory>
```

### Acceptance Criteria
- [ ] Content-Security-Policy with frame-ancestors 'none' added
- [ ] X-Frame-Options: DENY header added
- [ ] X-Content-Type-Options: nosniff header added
- [ ] Referrer-Policy: no-referrer header added
- [ ] Cross-Origin-Resource-Policy: same-origin header added
- [ ] SetHandler none directive added
- [ ] Manual testing confirms headers are present
- [ ] Manual testing confirms iframe embedding is blocked

### References
- Source reports: L2:3.4.6.md, L2:3.4.4.md, L2:3.4.5.md
- Related findings: FINDING-110, FINDING-112
- ASVS sections: 3.4.6, 3.4.4, 3.4.5
- CWE: CWE-1021

### Priority
Low

---

## Issue: FINDING-217 - Sec-Fetch-Site Validation Permits Absent Header and Same-Site Requests

**Labels:** bug, security, priority:low, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
The Sec-Fetch-Site validation explicitly allows None (header absent) in the OAuth endpoint and global validation, necessary for backward compatibility with older browsers and non-browser clients. However, ASVS 3.5.3 calls for strict validation. The global validation also permits 'same-site' requests, meaning other `*.apache.org` subdomains could make state-changing requests. For browser-only endpoints like OAuth, stricter validation could be applied when any Sec-Fetch header is present (indicating a modern browser). Allowing None creates a narrow window where attackers can deliberately omit headers to bypass this specific check, though other controls still apply (CSRF tokens, OAuth state parameter, authentication). Impact is limited due to layered defenses.

### Details
The issue exists in `src/asfquart/generics.py` line 33 (OAuth endpoint) and `atr/server.py` lines 360-374 (global validation). Sec-Fetch-Site validation allows None and 'same-site' values.

### Recommended Remediation
For browser-only endpoints, apply comprehensive validation when any Sec-Fetch header is present:

```python
def _validate_sec_fetch_for_browser(headers):
    """Strict validation when Sec-Fetch headers indicate a modern browser."""
    has_sec_fetch = any([
        headers.get("Sec-Fetch-Site"),
        headers.get("Sec-Fetch-Mode"),
        headers.get("Sec-Fetch-Dest")
    ])
    
    if not has_sec_fetch:
        # Legacy browser or non-browser client - allow but log
        log.info("Request without Sec-Fetch headers (legacy client)")
        return True
    
    # Modern browser detected - enforce strict validation
    site = headers.get("Sec-Fetch-Site")
    mode = headers.get("Sec-Fetch-Mode")
    dest = headers.get("Sec-Fetch-Dest")
    
    if site not in ("same-origin", "none"):
        return False
    if mode not in ("navigate", "same-origin"):
        return False
    if dest not in ("document", "empty"):
        return False
    
    return True

# Apply to OAuth endpoint
@app.route('/auth')
async def oauth_endpoint():
    if not _validate_sec_fetch_for_browser(quart.request.headers):
        return quart.abort(403)
    # ... rest of implementation
```

For global validation, consider tightening to block 'same-site' for non-GET requests, or document the trust model for `apache.org` subdomains.

Add test cases to verify rejection of deliberately omitted headers in modern browser contexts.

### Acceptance Criteria
- [ ] Strict Sec-Fetch validation added for browser-only endpoints
- [ ] Legacy client detection added (absence of all Sec-Fetch headers)
- [ ] Modern browser validation enforces strict rules
- [ ] Unit tests verify strict validation for modern browsers
- [ ] Unit tests verify legacy clients are allowed
- [ ] Unit tests verify deliberately omitted headers are rejected
- [ ] OR: same-site blocking added for non-GET requests
- [ ] OR: trust model for apache.org subdomains documented

### References
- Source reports: L1:3.5.3.md, L2:3.5.4.md
- Related findings: FINDING-107
- ASVS sections: 3.5.3, 3.5.4
- CWE: CWE-352

### Priority
Low

---

## Issue: FINDING-218 - Inconsistent CSRF Enforcement Pattern on Admin POST Endpoints

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Five admin POST endpoints use the `@admin.post()` decorator without form parameters, relying solely on global CSRFProtect middleware for CSRF validation. Nine other admin endpoints use `@admin.typed` with form parameters, providing both global and form-level CSRF validation. This creates an inconsistent defense posture. If CSRFProtect were accidentally disabled or misconfigured (e.g., blueprint-wide exemption applied incorrectly), these 5 endpoints would lack application-level CSRF validation, while the 9 `@admin.typed` endpoints would retain form-level protection. Currently protected by global CSRFProtect middleware, SameSite=Strict cookies, and Sec-Fetch header validation.

### Details
The issue exists in `atr/admin/__init__.py` at lines 299, 316, 338, 399, and 429. These five endpoints use `@admin.post()` without form parameters. The blueprint configuration is in `atr/blueprints/admin.py` lines 22-30.

### Recommended Remediation
Convert all 5 affected endpoints to `@admin.typed` with `form.Empty` parameter to add form-level CSRF validation consistent with the 9 other admin endpoints:

```python
@admin.typed
async def endpoint(
    session: web.Committer,
    _endpoint_name: Literal["endpoint/path"],
    _form: form.Empty
) -> web.QuartResponse:
    """Endpoint with form-level CSRF validation."""
    # endpoint logic
    # ...
```

Apply to:
- Line 299: project creation endpoint
- Line 316: project deletion endpoint
- Line 338: configuration update endpoint
- Line 399: cache invalidation endpoint
- Line 429: consistency check endpoint

This addresses the developer's own TODO comment in the code asking why the form is missing.

### Acceptance Criteria
- [ ] All 5 endpoints converted to @admin.typed
- [ ] form.Empty parameter added to each endpoint
- [ ] Unit tests verify CSRF validation is applied
- [ ] Unit tests verify CSRF token validation fails without valid token
- [ ] Integration tests verify endpoint security
- [ ] TODO comment removed from code
- [ ] Code review confirms consistent CSRF enforcement

### References
- Source reports: L1:3.5.1.md
- Related findings: None
- ASVS sections: 3.5.1
- CWE: CWE-352

### Priority
Low

---

## Issue: FINDING-219 - Sec-Fetch-Mode Validation Not Applied to GET Requests on API Endpoints

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `validate_sec_fetch_headers()` middleware explicitly excludes GET, HEAD, and OPTIONS requests from Sec-Fetch-* validation. While POST/PUT/DELETE requests are validated to prevent cross-site mutations and API navigation, GET requests to `/api/*` endpoints can be directly navigated to in the browser. Browser address bar navigation to API endpoints succeeds with JSON rendered in browser tab instead of being rejected for programmatic-only access.

### Details
The issue exists in `atr/server.py` around line 517, where the validation middleware excludes GET requests. API endpoints in `atr/api/__init__.py` and blueprint configuration in `atr/blueprints/api.py` do not have endpoint-specific Sec-Fetch validation.

### Recommended Remediation
Implement Sec-Fetch-Dest validation for API endpoints on all HTTP methods including GET:

```python
# In atr/server.py, add API-specific validation
@app.before_request
async def validate_api_sec_fetch():
    """Validate Sec-Fetch-Dest for API endpoints to prevent browser navigation."""
    if quart.request.path.startswith('/api/'):
        sec_fetch_dest = quart.request.headers.get('Sec-Fetch-Dest')
        
        # Block browser navigation contexts
        if sec_fetch_dest in ('document', 'iframe', 'embed', 'object'):
            raise quart.exceptions.Forbidden(
                'API must be accessed programmatically'
            )
        
        # Allow programmatic access
        # Sec-Fetch-Dest will be 'empty', 'fetch', or 'xmlhttprequest'
        # or None for clients that don't send Sec-Fetch headers
```

This blocks browser navigation (address bar, bookmarks, links) while allowing programmatic access via fetch(), XMLHttpRequest, or non-browser clients.

### Acceptance Criteria
- [ ] Sec-Fetch-Dest validation added for /api/* endpoints
- [ ] Browser navigation contexts blocked (document, iframe, embed, object)
- [ ] Programmatic access allowed (empty, fetch, xmlhttprequest)
- [ ] Non-browser clients allowed (no Sec-Fetch-Dest header)
- [ ] Unit tests verify browser navigation is blocked
- [ ] Unit tests verify programmatic access works
- [ ] Integration tests verify API security
- [ ] Manual testing confirms address bar navigation is blocked

### References
- Source reports: L1:3.2.1.md
- Related findings: None
- ASVS sections: 3.2.1
- CWE: CWE-346

### Priority
Low

---

## Issue: FINDING-220 - ZipResponse Does Not Enforce Content-Disposition: attachment

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The ZipResponse class in `atr/web.py` does not automatically enforce `Content-Disposition: attachment` header, relying on callers to provide it. This is a defense-in-depth gap - ASVS 3.2.1 explicitly recommends the attachment disposition for downloadable content to prevent browser rendering and unintended content interpretation.

### Details
The issue exists in `atr/web.py` around lines 218-226. The ZipResponse class does not automatically set the Content-Disposition header.

### Recommended Remediation
Enforce Content-Disposition: attachment in ZipResponse constructor as defense-in-depth:

**Option 1 (Add if missing):**
```python
class ZipResponse:
    def __init__(self, filename: str = "archive.zip", **kwargs):
        """Create ZIP response with Content-Disposition: attachment."""
        # Ensure Content-Disposition is set
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        
        if 'Content-Disposition' not in kwargs['headers']:
            kwargs['headers']['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # ... rest of initialization
```

**Option 2 (Always enforce):**
```python
class ZipResponse:
    def __init__(self, filename: str = "archive.zip", **kwargs):
        """Create ZIP response with enforced Content-Disposition: attachment."""
        # Always set Content-Disposition (override caller if provided)
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        
        kwargs['headers']['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # ... rest of initialization
```

### Acceptance Criteria
- [ ] Content-Disposition: attachment header enforced in ZipResponse
- [ ] Filename parameter added to constructor
- [ ] Unit tests verify header is present
- [ ] Unit tests verify filename is properly escaped
- [ ] Integration tests verify ZIP downloads have attachment disposition
- [ ] Code review confirms defense-in-depth approach

### References
- Source reports: L1:3.2.1.md
- Related findings: FINDING-221
- ASVS sections: 3.2.1
- CWE: CWE-430

### Priority
Low

---

## Issue: FINDING-221 - ShellResponse Serves Executable Content Without Content-Disposition: attachment

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The ShellResponse class serves `text/x-shellscript` content without `Content-Disposition: attachment` header. While an `audit_guidance` comment indicates this is an intentional design decision with multiple compensating controls, ASVS 3.2.1 best practices recommend attachment header for executable content as defense-in-depth. Practical risk is negligible due to CSP, X-Content-Type-Options, and explicit Content-Type headers.

### Details
The issue exists in `atr/web.py` around lines 209-211. An audit_guidance comment already exists indicating this is an intentional design decision with compensating controls.

### Recommended Remediation
**Option 1 (Add filename parameter and always set attachment):**
```python
class ShellResponse:
    def __init__(self, content: str, filename: str = "script.sh", **kwargs):
        """Create shell script response with Content-Disposition: attachment."""
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        
        kwargs['headers']['Content-Disposition'] = f'attachment; filename="{filename}"'
        kwargs['headers']['Content-Type'] = 'text/x-shellscript'
        
        # ... rest of initialization
```

**Option 2 (Add as_attachment flag):**
```python
class ShellResponse:
    def __init__(self, content: str, filename: str = "script.sh", as_attachment: bool = True, **kwargs):
        """Create shell script response with optional attachment disposition."""
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        
        if as_attachment:
            kwargs['headers']['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        kwargs['headers']['Content-Type'] = 'text/x-shellscript'
        
        # ... rest of initialization
```

**Option 3 (Risk acceptance with updated audit_guidance):**
```python
# audit_guidance: ASVS 3.2.1 LOW-003 reviewed 2024-01-15
# Content-Disposition: attachment intentionally not set for shell scripts
# Compensating controls:
# - CSP default-src 'self' prevents inline execution
# - X-Content-Type-Options: nosniff prevents MIME sniffing
# - Explicit Content-Type: text/x-shellscript
# - Browsers do not execute text/x-shellscript inline
# Risk accepted: Negligible due to multiple defense layers
```

### Acceptance Criteria
- [ ] Content-Disposition: attachment added (Option 1 or 2)
- [ ] OR: Risk acceptance documented with updated audit_guidance (Option 3)
- [ ] Unit tests verify header behavior
- [ ] Integration tests verify shell script responses
- [ ] Code review confirms defense-in-depth approach
- [ ] Documentation updated with design decision

### References
- Source reports: L1:3.2.1.md
- Related findings: FINDING-220
- ASVS sections: 3.2.1
- CWE: CWE-430

### Priority
Low

---

## Issue: FINDING-222 - innerHTML Read Used Where textContent Is Appropriate

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The filter function in `projects-directory.js` reads `.innerHTML` instead of `.textContent` to extract the project name for filtering. Since `.card-title` contains an `<a>` tag, this causes the filter to match against HTML attributes (href, class) rather than just the visible project name. This is a functional bug rather than a direct XSS risk since it's a read operation, but demonstrates incorrect API usage.

### Details
The issue exists in `atr/static/js/src/projects-directory.js` line 26. The code reads innerHTML when it should read textContent for filtering purposes.

### Recommended Remediation
Replace innerHTML read with textContent:

```javascript
// In atr/static/js/src/projects-directory.js, line 26
// Change:
// const name = nameElement.innerHTML;

// To:
const name = nameElement.textContent;
```

This correctly reads only visible text as done in `committee-directory.js`.

### Acceptance Criteria
- [ ] innerHTML replaced with textContent
- [ ] Unit tests verify filter matches only visible text
- [ ] Unit tests verify filter does not match HTML attributes
- [ ] Manual testing confirms filter behavior is correct
- [ ] Code review confirms consistent API usage across JavaScript files

### References
- Source reports: L1:3.2.2.md
- Related findings: None
- ASVS sections: 3.2.2
- CWE: CWE-79

### Priority
Low

---

## Issue: FINDING-223 - innerHTML Usage with Static Content (Defense-in-Depth)

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `createWarningDiv()` function in `vote-body-duration.js` uses innerHTML to set static, developer-controlled HTML content. While not currently vulnerable (no user-controllable data), this pattern creates maintenance risk if future modifications introduce dynamic content. This is NOT an ASVS 3.2.2 violation because the content IS intended to be rendered as HTML (contains `<strong>`, `<br>`, `<button>` elements by design), but represents a defense-in-depth opportunity.

### Details
The issue exists in `atr/static/js/src/vote-body-duration.js` lines 24-26. The function uses innerHTML with static HTML content.

### Recommended Remediation
Refactor to use createElement and textContent/appendChild pattern for defense-in-depth and maintainability:

```javascript
function createWarningDiv() {
    const div = document.createElement('div');
    div.className = 'alert alert-warning';
    
    const strong = document.createElement('strong');
    strong.textContent = 'Warning: ';
    div.appendChild(strong);
    
    div.appendChild(document.createTextNode('Vote duration is less than 72 hours. '));
    
    const br = document.createElement('br');
    div.appendChild(br);
    
    div.appendChild(document.createTextNode('This may not allow sufficient time for community review.'));
    
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'btn-close';
    button.setAttribute('data-bs-dismiss', 'alert');
    button.setAttribute('aria-label', 'Close');
    div.appendChild(button);
    
    return div;
}
```

This approach is more verbose but eliminates any risk of future XSS if the function is modified to accept dynamic content.

### Acceptance Criteria
- [ ] innerHTML replaced with createElement/textContent pattern
- [ ] Unit tests verify warning div is created correctly
- [ ] Unit tests verify no XSS vulnerability if modified with dynamic content
- [ ] Manual testing confirms warning display is correct
- [ ] Code review confirms defense-in-depth approach

### References
- Source reports: L1:3.2.2.md
- Related findings: None
- ASVS sections: 3.2.2
- CWE: CWE-79

### Priority
Low

---

## Issue: FINDING-224 - style-src 'unsafe-inline' Weakens CSP Protection Against CSS Injection

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `style-src` directive includes `'unsafe-inline'`, which allows any inline `<style>` elements or style attributes to be applied. If an HTML injection vulnerability exists elsewhere in the application, an attacker could inject arbitrary CSS via inline styles. CSS injection can enable data exfiltration through attribute selectors or visual UI redress attacks. While the overall policy uses an allowlist approach ('self'), the style-src directive effectively allows ALL inline styles. However, the primary purpose of preventing malicious JavaScript execution is met since `script-src 'self'` does NOT include 'unsafe-inline'. The practical exploitability is very low since `default-src 'self'` and `connect-src 'self'` would block external URL loads in CSS-based exfiltration attempts.

### Details
The issue exists in `atr/server.py` line 463. The CSP policy includes `style-src 'self' 'unsafe-inline'`.

### Recommended Remediation
Replace 'unsafe-inline' with CSS nonces or hashes where feasible:

**Option 1 (CSS nonces):**
```python
@app.before_request
async def add_csp_nonce():
    """Generate CSP nonce for inline styles."""
    quart.g.csp_nonce = secrets.token_urlsafe(16)

@app.after_request
async def set_csp_with_nonce(response):
    """Set CSP with style nonce."""
    nonce = quart.g.get('csp_nonce', '')
    csp = (
        f"default-src 'self'; "
        f"script-src 'self'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        # ... rest of CSP
    )
    response.headers['Content-Security-Policy'] = csp
    return response

# In templates, add nonce to inline styles:
<style nonce="{{ g.csp_nonce }}">
    /* inline styles */
</style>
```

**Option 2 (Extract to external stylesheet):**
If Bootstrap requires inline styles, consider using a build process to extract them to external stylesheets.

**Option 3 (Accept risk with documentation):**
If 'unsafe-inline' must remain, document the accepted risk:

```python
# In atr/server.py
# audit_guidance: ASVS 3.4.3 LOW-001 reviewed 2024-01-15
# style-src 'unsafe-inline' required for Bootstrap inline styles
# Compensating controls:
# - default-src 'self' and connect-src 'self' block external URL loads
# - No HTML injection vulnerabilities identified in audit
# - CSS injection risk limited to visual UI redress (no data exfiltration)
# Risk accepted: Low exploitability due to defense-in-depth controls
```

### Acceptance Criteria
- [ ] 'unsafe-inline' replaced with nonces or hashes (Option 1)
- [ ] OR: Inline styles extracted to external stylesheet (Option 2)
- [ ] OR: Risk acceptance documented with audit_guidance (Option 3)
- [ ] Unit tests verify CSP policy
- [ ] Integration tests verify inline styles work with nonces
- [ ] Manual testing confirms UI rendering is correct
- [ ] Code review confirms defense-in-depth approach

### References
- Source reports: L2:3.4.3.md
- Related findings: None
- ASVS sections: 3.4.3
- CWE: CWE-79

### Priority
Low

---

## Issue: FINDING-225 - Unverifiable Session Cookie Write in atr.util

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `util.write_quart_session_cookie()` function is called during the request lifecycle but its source code is not included in the audit scope. If this function uses `response.set_cookie()` directly rather than `quart.session`, it must explicitly pass `httponly=True` to maintain compliance. If it writes to `quart.session`, the framework-level `SESSION_COOKIE_HTTPONLY` config is automatically applied. If `write_quart_session_cookie` bypasses Quart's session framework and does not set HttpOnly, the session cookie would be accessible to client-side JavaScript, enabling session hijacking via XSS.

### Details
The issue exists in `atr/server.py` lines 316-319 (function call) and `atr/util.py` (function implementation - unknown line, not in audit scope).

### Recommended Remediation
Verify that `atr/util.py::write_quart_session_cookie()` either:

**Option A (Preferred):** Uses `quart.session` (inherits HttpOnly from config):
```python
async def write_quart_session_cookie(session_data: dict):
    """Write session data using Quart's session framework."""
    # This inherits SESSION_COOKIE_HTTPONLY=True from config
    quart.session[cookie_id] = session_data
```

**Option B:** If using `response.set_cookie()` directly, explicitly sets `httponly=True`:
```python
async def write_quart_session_cookie(response: quart.Response, session_data: dict):
    """Write session cookie with explicit HttpOnly flag."""
    response.set_cookie(
        key='session',
        value=serialize_session(session_data),
        httponly=True,  # Explicit HttpOnly
        secure=True,    # HTTPS only
        samesite='Strict',  # CSRF protection
        path='/',
        max_age=SESSION_MAX_AGE
    )
```

### Acceptance Criteria
- [ ] Source code of write_quart_session_cookie() reviewed
- [ ] Function uses quart.session OR explicitly sets httponly=True
- [ ] Unit tests verify HttpOnly flag is set
- [ ] Integration tests verify session cookie has HttpOnly attribute
- [ ] Manual testing confirms cookie is not accessible to JavaScript
- [ ] Documentation updated with session cookie implementation details

### References
- Source reports: L2:3.3.4.md
- Related findings: None
- ASVS sections: 3.3.4
- CWE: CWE-1004

### Priority
Low

---

## Issue: FINDING-226 - Text Response Classes Rely on Implicit Charset from Werkzeug

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Three custom response classes (TextResponse, ElementResponse, ShellResponse) in `atr/web.py` specify only the mimetype parameter without explicitly including the charset. These classes rely on Werkzeug's `get_content_type()` method to automatically append `; charset=utf-8` to all text/* mimetypes. While this produces correct headers at runtime, it creates a dependency on framework implementation details rather than explicit application control.

### Details
The affected response classes are located at:
- `atr/web.py` line ~195 (TextResponse)
- `atr/web.py` line ~202 (ElementResponse)
- `atr/web.py` line ~207 (ShellResponse)

All three classes pass `mimetype` parameter to the parent Response class without explicit charset specification, relying on implicit framework behavior to append `; charset=utf-8`.

### Recommended Remediation
Replace the `mimetype` parameter with explicit `content_type` including charset in all three response classes:

```python
class TextResponse(quart.Response):
    def __init__(self, text: str, status: int = 200) -> None:
        super().__init__(text, status=status, content_type="text/plain; charset=utf-8")

class ElementResponse(quart.Response):
    def __init__(self, element: htm.Element, status: int = 200) -> None:
        super().__init__(str(element), status=status, content_type="text/html; charset=utf-8")

class ShellResponse(quart.Response):
    def __init__(self, text: str, status: int = 200) -> None:
        super().__init__(text, status=status, content_type="text/x-shellscript; charset=utf-8")
```

Effort: Low (3 one-line changes). Risk: None (zero runtime behavior change).

### Acceptance Criteria
- [ ] All three response classes explicitly specify `content_type` with charset
- [ ] Existing functionality remains unchanged (no runtime behavior change)
- [ ] Unit tests verify correct Content-Type headers are set

### References
- Source reports: L1:4.1.1.md
- Related findings: None
- ASVS sections: 4.1.1

### Priority
Low

---

## Issue: FINDING-227 - Library-Level WSS Enforcement Not Independently Verifiable

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The application validates that the URL starts with `https://` before passing it to `asfpy.pubsub.listen()`. However, the actual TLS enforcement depends on the `asfpy.pubsub` library's implementation. If the library internally downgrades, redirects, or fails to verify TLS certificates, the application-level check would provide false confidence. This is an observation about defense-in-depth rather than an exploitable vulnerability.

### Details
In `atr/svn/pubsub.py` at line 78, the URL validation checks for `https://` prefix but does not verify that the underlying library enforces TLS correctly. The `asfpy.pubsub` library is published by the Apache Software Foundation and is expected to properly handle HTTPS URLs with TLS, but this is not independently verified within the application code.

### Recommended Remediation
Consider adding an explicit assertion or documentation that the `asfpy.pubsub` library enforces TLS for `https://` URLs. Optionally, pin or audit the library version.

Example: Add explicit verification comment:
```python
# SECURITY: asfpy.pubsub.listen() uses aiohttp internally, which enforces TLS 
# for https:// URLs. Verified in asfpy v X.Y.Z.
```

Or add runtime validation of the library's SSL behavior.

### Acceptance Criteria
- [ ] Documentation added confirming TLS enforcement by asfpy.pubsub library
- [ ] Library version pinned in requirements
- [ ] Unit test verifying the fix (if runtime validation added)

### References
- Source reports: L1:4.4.1.md
- Related findings: None
- ASVS sections: 4.4.1

### Priority
Low

---

## Issue: FINDING-228 - HSTS Not Applied at Application Level

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The Strict-Transport-Security header is documented as being applied by the frontend proxy, not by the application itself. While this is a valid deployment pattern, if the proxy is misconfigured or replaced, HSTS protection silently disappears. The application's `add_security_headers` function adds several headers directly but omits HSTS, creating no defense-in-depth at the application layer.

### Details
In `atr/server.py` at lines 491-502, the `add_security_headers` function adds multiple security headers but does not include Strict-Transport-Security. The application relies on proxy configuration (lines 93-94) to apply HSTS headers. If the proxy configuration changes and HSTS is removed, browsers could make initial HTTP requests, leaking data.

This is a lower severity issue because HSTS is documented as being applied at proxy level and ProxyFixMiddleware is correctly configured.

### Recommended Remediation
Add HSTS at the application level as defense-in-depth (duplicate headers are harmless and the most restrictive wins):

```python
# atr/server.py, in add_security_headers
if quart.request.is_secure:
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
```

### Acceptance Criteria
- [ ] HSTS header added at application level for HTTPS requests
- [ ] Proxy-level HSTS configuration remains in place
- [ ] Unit test verifying HSTS header presence on secure requests

### References
- Source reports: L2:4.1.2.md
- Related findings: FINDING-116
- ASVS sections: 4.1.2

### Priority
Low

---

## Issue: FINDING-229 - Neither Vhost Sanitizes X-Forwarded-Host

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
Neither the staging nor the dev vhost includes directives to sanitize `X-Forwarded-Host` or `X-Forwarded-Server` headers. This allows end-users to inject arbitrary values for these headers, which could potentially influence host-based logic if the middleware or application code processes them. Currently low impact due to middleware not processing this header, but represents a defense-in-depth gap.

### Details
The Apache configuration in `tooling-vm-ec2-de.apache.org.yaml` does not unset `X-Forwarded-Host` or `X-Forwarded-Server` headers. If middleware is changed or updated to process `X-Forwarded-Host`, the OAuth callback URL generation in `asfquart/generics.py` (lines 39-43) and the URL validation in `atr/web.py` (line 230 and lines 100-105) could be affected.

POC: `curl -k -H "X-Forwarded-Host: evil.example.com" https://release-test.apache.org/auth?login`

### Recommended Remediation
Add `RequestHeader unset X-Forwarded-Host` and `RequestHeader unset X-Forwarded-Server` to BOTH vhosts in `tooling-vm-ec2-de.apache.org.yaml`, before the ProxyPass directives.

### Acceptance Criteria
- [ ] Both vhosts unset X-Forwarded-Host header
- [ ] Both vhosts unset X-Forwarded-Server header
- [ ] Integration test verifying headers are not passed through
- [ ] Unit test verifying the fix

### References
- Source reports: L2:4.1.3.md
- Related findings: FINDING-117
- ASVS sections: 4.1.3

### Priority
Low

---

## Issue: FINDING-230 - No WebSocket Origin Validation Framework Exists

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The application does not implement any WebSocket Origin header validation mechanism. While no WebSocket endpoints currently exist, the underlying framework (Quart + Hypercorn) supports WebSocket connections natively and does not disable them by default. Future risk is HIGH if WebSocket is added without controls. Potential vulnerabilities include Cross-Site WebSocket Hijacking (CSWSH), data exfiltration, unauthorized actions, and session hijacking.

### Details
Gap Analysis:
1. No WebSocket endpoints defined - Zero @app.websocket() decorators across 122 analyzed files
2. No Origin validation framework - No reusable middleware, decorator, or configuration for validating WebSocket Origin headers
3. WebSocket not explicitly disabled - Hypercorn will accept WebSocket upgrade requests by default
4. HTTP security controls don't transfer - The existing Sec-Fetch-Site CSRF protection (in `src/asfquart/generics.py` lines 30, 128) only applies to HTTP POST requests, not WebSocket handshakes

Current impact is minimal as no WebSocket endpoints exist.

### Recommended Remediation
Three options provided:

**Option 1 (Recommended):** Implement reusable WebSocket Origin validation decorator. Create `src/asfquart/websocket.py` with `validate_websocket_origin` decorator that checks Origin header against ALLOWED_ORIGINS set (e.g., https://trusted-releases.apache.org, https://whimsy.apache.org). Reject connections without Origin header or with disallowed origins using `quart.websocket.reject(403)`.

**Option 2:** Disable WebSocket at reverse proxy level if not planned. Use Apache httpd.conf with RewriteEngine to block WebSocket upgrade requests.

**Option 3:** Configure Hypercorn WebSocket security options including --websocket-max-size and --websocket-ping-interval flags.

Implementation steps:
1. Immediate - Document WebSocket security policy in SECURITY.md
2. Short-term - Implement validation decorator and add to code review checklist
3. Long-term - If WebSocket never planned, implement proxy-level block

### Acceptance Criteria
- [ ] WebSocket security policy documented
- [ ] Origin validation framework implemented OR WebSocket explicitly disabled
- [ ] Unit tests for validation logic (if implementing validation)
- [ ] Integration tests verifying WebSocket security

### References
- Source reports: L2:4.4.2.md
- Related findings: FINDING-118, FINDING-231
- ASVS sections: 4.4.2

### Priority
Low

---

## Issue: FINDING-231 - No Origin Header Validation Infrastructure for WebSocket

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
WebSocket connections are vulnerable to Cross-Site WebSocket Hijacking (CSWSH) attacks where an attacker's page initiates a WebSocket connection to the target application. The browser sends cookies with the WS upgrade request, potentially authenticating the attacker's connection. No Origin header validation exists anywhere in the codebase that could be applied to WebSocket handshakes.

### Details
Grep across all files shows zero references to Origin header validation. `src/asfquart/generics.py` checks Sec-Fetch-Site (line 37) but only for HTTP POST CSRF, not WebSocket upgrades. The application lacks infrastructure to validate the Origin header during WebSocket handshake, which is the primary defense against CSWSH attacks.

### Recommended Remediation
Include Origin validation in the WebSocket authentication framework. Create an `_ALLOWED_ORIGINS` set containing allowed origins (e.g., https://{APP_HOST}), implement an `_is_allowed_origin()` function to validate the Origin header, and integrate this validation into the require_websocket decorator. The decorator should close the connection with code 1008 if the Origin header does not match allowed origins.

### Acceptance Criteria
- [ ] ALLOWED_ORIGINS configuration added
- [ ] Origin validation function implemented
- [ ] WebSocket decorator enforces Origin validation
- [ ] Unit tests for Origin validation logic
- [ ] Integration tests verifying CSWSH protection

### References
- Source reports: L2:4.4.4.md
- Related findings: FINDING-230, FINDING-118
- ASVS sections: 4.4.4

### Priority
Low

---

## Issue: FINDING-232 - Inconsistent Session Context in Token Operations

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The `_add_token` and `_delete_token` functions in `atr/post/tokens.py` handle `session` parameter passing to `storage.write()` inconsistently. The `_add_token` function does not explicitly pass the session parameter while `_delete_token` does. While this is likely functionally correct due to request context resolution, the inconsistency reduces code clarity and defense-in-depth.

### Details
In `atr/post/tokens.py`:
- Lines 54-74: `_add_token()` calls `storage.write()` without explicit session parameter
- Lines 77-85: `_delete_token()` calls `storage.write(session)` with explicit session parameter

The inconsistency creates maintenance risk and could fail silently if context resolution changes.

### Recommended Remediation
Update `_add_token()` to explicitly pass `session` parameter to `storage.write(session)` for consistency with `_delete_token()` and the established pattern throughout the codebase. Establish and enforce consistent pattern across codebase — always explicitly pass `session` to `storage.write()`.

### Acceptance Criteria
- [ ] `_add_token()` explicitly passes session parameter
- [ ] Consistent pattern applied across all storage.write() calls
- [ ] Unit test verifying correct session context usage

### References
- Source reports: L2:4.4.3.md
- Related findings: None
- ASVS sections: 4.4.3

### Priority
Low

---

## Issue: FINDING-233 - No Client-Side File Size Validation Before Upload

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The client-side upload interface does not validate file sizes before initiating uploads. Users can select and attempt to upload files exceeding server limits. The browser uploads the entire file before receiving a 413 error from the server, wasting bandwidth and time for both client and server. Additionally, there is no upper bound on the number of files that can be selected and uploaded simultaneously. This is NOT a security issue as server-side MAX_CONTENT_LENGTH enforces the limit correctly - it is purely a user experience and efficiency concern.

### Details
In `atr/static/js/src/upload-progress.js`:
- Line 123: File upload initiated without size validation
- Line 89: No file count validation

The server-side validation is correct, but client-side pre-validation would improve UX and efficiency.

### Recommended Remediation
Add client-side validation in `handleFormSubmit()` function:
1. Define constants matching server configuration - MAX_FILE_SIZE (512MB) and MAX_FILE_COUNT (50)
2. Validate file count - Check files.length against MAX_FILE_COUNT and alert user if exceeded
3. Validate individual file sizes - Filter files where file.size > MAX_FILE_SIZE and display detailed alert listing oversized files with names and sizes
4. Add real-time validation on file input change event to provide immediate feedback as users select files
5. Display helpful summary showing total file count and size

NOTE: This is a UX improvement only - server-side validation must remain as the security control.

### Acceptance Criteria
- [ ] Client-side file size validation implemented
- [ ] Client-side file count validation implemented
- [ ] User receives clear feedback before upload attempt
- [ ] Server-side validation remains unchanged
- [ ] Unit test verifying client-side validation logic

### References
- Source reports: L1:5.2.1.md
- Related findings: None
- ASVS sections: 5.2.1

### Priority
Low

---

## Issue: FINDING-234 - KEYS File Web Upload Lacks Extension Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The KEYS file web upload endpoint in `atr/post/keys.py` accepts file uploads without validating the file extension. While the file content IS validated by PGP parsing (rejecting non-PGP content), the absence of extension checking violates ASVS 5.2.2's explicit requirement to 'check if the file extension matches an expected file extension.' The upload handler processes files with any extension (including potentially confusing extensions like .exe) as long as they contain valid PGP key data.

### Details
In `atr/post/keys.py` at lines 284-305, the `_upload_file_keys()` function processes uploaded files without verifying the file extension. No verification is performed that the uploaded file has an expected extension such as .asc, .gpg, .key, .pub, .txt, or no extension.

### Recommended Remediation
Add file extension validation before content processing. Validate that the uploaded file has an expected extension from the allowlist: {"", ".asc", ".gpg", ".key", ".pub", ".txt"}.

```python
async def _upload_file_keys(upload_file_form: shared.keys.UploadFileForm) -> str:
    if upload_file_form.key is None:
        await quart.flash("No KEYS file uploaded", "error")
        return await shared.keys.render_upload_page(error=True)

    # Validate file extension
    filename = upload_file_form.key.filename or ""
    allowed_extensions = {"", ".asc", ".gpg", ".key", ".pub", ".txt"}
    ext = pathlib.PurePath(filename).suffix.lower()
    
    if ext not in allowed_extensions:
        await quart.flash(
            f"Unexpected file extension '{ext}'. "
            f"Expected a PGP key file ({', '.join(sorted(allowed_extensions))}).",
            "error"
        )
        return await shared.keys.render_upload_page(error=True)

    keys_content = await asyncio.to_thread(upload_file_form.key.read)
    keys_text = keys_content.decode("utf-8", errors="replace")
    await _process_keys(keys_text)
```

### Acceptance Criteria
- [ ] File extension validation implemented before content processing
- [ ] Only allowed extensions accepted
- [ ] Clear error messages for invalid extensions
- [ ] Unit test verifying extension validation

### References
- Source reports: L1:5.2.2.md
- Related findings: None
- ASVS sections: 5.2.2

### Priority
Low

---

## Issue: FINDING-235 - Defense-in-Depth — Missing AllowOverride None in Apache Downloads Directory

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The Apache configuration for the /downloads/ directory does not explicitly set `AllowOverride None`, relying instead on Apache 2.4's default behavior. While the default is secure, explicit configuration provides defense-in-depth and prevents potential misconfiguration. In the unlikely scenario where AllowOverride is changed from default, uploaded .htaccess files could override `SetHandler none` and enable script execution.

### Details
In `tooling-vm-ec2-de.apache.org.yaml` at lines 49-62 and 105-117, the <Directory> blocks for the downloads directory do not explicitly set `AllowOverride None`. This creates a defense-in-depth gap if Apache's default configuration is changed or overridden.

### Recommended Remediation
Make the security configuration explicit by adding 'AllowOverride None' to both Apache <Directory> blocks in the YAML configuration for the downloads directory.

### Acceptance Criteria
- [ ] AllowOverride None added to both <Directory> blocks
- [ ] Apache configuration reloaded successfully
- [ ] Integration test verifying .htaccess files are ignored
- [ ] Unit test verifying the fix

### References
- Source reports: L1:5.3.1.md
- Related findings: FINDING-122, FINDING-236
- ASVS sections: 5.3.1

### Priority
Low

---

## Issue: FINDING-236 - Defense-in-Depth — Incomplete Web Server Configuration File Blocking

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `safe.RelPath` validation blocks SCM directories but not web server configuration files. The DISALLOWED_SUFFIXES only contains .key, missing common executable extensions. The `validate_directory()` function allows files with unrecognized suffixes, including .htaccess. Files like .htaccess pass validation because they have no recognized suffix and are allowed through. If combined with FINDING-235 (missing AllowOverride None) and a misconfigured Apache, this could enable server-side code execution.

### Details
In `atr/models/safe.py` at lines 97-134, the validation logic:
- Blocks SCM directories (.git, .svn, etc.)
- Only disallows .key file extension
- Does not check for web server configuration files (.htaccess, .htpasswd, web.config)
- Does not check for executable extensions (.php, .cgi, .pl, .py, .rb, .jsp, .asp, .aspx, .exe, .bat, .cmd, .ps1, .sh)

The validation is also used in `atr/analysis.py` (lines 72-76) and `atr/detection.py` (lines 135-147).

### Recommended Remediation
Update `safe.RelPath` disallowed names to include .htaccess, .htpasswd, and web.config. Expand DISALLOWED_SUFFIXES to include executable extensions (.php, .cgi, .pl, .py, .rb, .jsp, .asp, .aspx, .exe, .bat, .cmd, .ps1, .sh). Add explicit check in `validate_directory()` to reject web server configuration files.

### Acceptance Criteria
- [ ] Web server configuration files blocked by validation
- [ ] Executable extensions blocked by validation
- [ ] Explicit check in validate_directory() implemented
- [ ] Unit tests verifying all blocked file types are rejected

### References
- Source reports: L1:5.3.1.md
- Related findings: FINDING-122, FINDING-235
- ASVS sections: 5.3.1

### Priority
Low

---

## Issue: FINDING-237 - Missing resolve() + is_relative_to() Defense-in-Depth in File Serving Endpoints

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
File serving endpoints rely solely on `safe.RelPath` validation without the secondary `resolve()` + `is_relative_to()` containment check that is consistently applied in write operations. This creates an asymmetry in defense-in-depth between read and write operations. While the primary control (safe.RelPath) is comprehensive and blocks absolute paths, .., dotfiles, and SCM directories, the lack of secondary runtime path containment verification creates an inconsistency with write operations.

### Details
In `atr/get/download.py` at line ~162 and `atr/get/file.py` at line ~126, file serving operations use `safe.RelPath` validation but do not perform the additional `resolve()` + `is_relative_to()` containment check that is consistently applied in write operations throughout the codebase.

### Recommended Remediation
Add `resolve()` + `is_relative_to()` containment check before file operations:

```python
resolved = await asyncio.to_thread(full_path.resolve)
base_resolved = await asyncio.to_thread(base_dir.resolve)
if not resolved.is_relative_to(base_resolved):
    raise base.ASFQuartException('Path traversal detected', errorcode=400)
```

Apply similar fix to both `_download_or_list()` and `selected_path()` functions.

### Acceptance Criteria
- [ ] Containment check added to all file serving endpoints
- [ ] Path traversal attempts are rejected
- [ ] Legitimate file access continues to work
- [ ] Unit tests verifying containment validation

### References
- Source reports: L1:5.3.2.md
- Related findings: None
- ASVS sections: 5.3.2

### Priority
Low

---

## Issue: FINDING-238 - SBOM Task Handlers Use Unvalidated Path Strings from Database

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
SBOM task handlers accept path arguments as plain strings without re-validation at the worker boundary. While all current code paths creating these tasks validate inputs through `safe.RelPath` before storage, the worker process does not re-apply validation when deserializing task arguments from the database. The FileArgs model accepts file_path as plain str without validation. This creates a defense-in-depth gap at the web server/worker boundary.

### Details
In `atr/tasks/sbom.py`:
- Lines ~85-92: Task handler accepts unvalidated file_path
- Line ~120: Path used without re-validation
- Line ~170: Path used without re-validation
- Line ~200: Path used without re-validation

The FileArgs model accepts file_path as plain str without validation, creating risk if task arguments are tampered with between storage and execution.

### Recommended Remediation
Add Pydantic field validators to FileArgs model:

```python
@pydantic.field_validator('file_path')
@classmethod
def validate_file_path(cls, v: str) -> str:
    safe.RelPath(v)
    return v
```

Apply similar validators for project_key, version_key, and revision_number. Alternatively, add usage-point validation with containment check in each handler function.

### Acceptance Criteria
- [ ] Field validators added to FileArgs model
- [ ] All path fields validated at worker boundary
- [ ] Existing functionality preserved
- [ ] Unit tests verifying validation at worker boundary

### References
- Source reports: L1:5.3.2.md
- Related findings: FINDING-239
- ASVS sections: 5.3.2

### Priority
Low

---

## Issue: FINDING-239 - CycloneDX Generation Handler Uses Unvalidated Absolute Paths

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The CycloneDX generation task handler accepts absolute paths as plain strings without validation at the worker boundary. While paths are constructed from validated inputs and resolved at task creation time, the worker does not verify that deserialized paths remain within expected directories. The GenerateCycloneDX model accepts artifact_path and output_path as absolute path strings without validation, allowing arbitrary file read (via extraction) and write operations if task arguments are tampered with.

### Details
In `atr/tasks/sbom.py` at lines ~260-340, the `_generate_cyclonedx_core()` function accepts absolute paths without containment validation. The GenerateCycloneDX model accepts both artifact_path and output_path as strings without verifying they remain within the unfinished_dir boundaries.

### Recommended Remediation
Add containment validation in `_generate_cyclonedx_core()`:

```python
unfinished_dir = paths.get_unfinished_dir().resolve()
resolved_artifact = pathlib.Path(artifact_path).resolve()
resolved_output = pathlib.Path(output_path).resolve()

if not resolved_artifact.is_relative_to(unfinished_dir):
    raise SBOMGenerationError(...)
if not resolved_output.is_relative_to(unfinished_dir):
    raise SBOMGenerationError(...)
```

Verify files exist and are regular files before operations.

### Acceptance Criteria
- [ ] Containment validation added to CycloneDX generation handler
- [ ] Path traversal attempts are rejected
- [ ] Legitimate SBOM generation continues to work
- [ ] Unit tests verifying containment validation

### References
- Source reports: L1:5.3.2.md
- Related findings: FINDING-238
- ASVS sections: 5.3.2

### Priority
Low

---

## Issue: FINDING-240 - Unvalidated file_name Parameter in Path Construction Utility

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `revision_path_for_file()` utility function in `atr/paths.py` accepts an unvalidated `file_name: str` parameter and directly appends it to a path. While no current callers pass user-controlled input, the function signature does not indicate that validation is the caller's responsibility, creating a latent security risk. If future code passes user input as file_name (e.g., ../../etc/passwd), path traversal would occur without any validation.

### Details
In `atr/paths.py` at line ~101, the `revision_path_for_file()` function accepts a plain string file_name parameter and directly appends it to the path without validation. The function signature does not communicate that validation is required by the caller.

### Recommended Remediation
Change function signature to accept `safe.RelPath` instead of str:

```python
def revision_path_for_file(
    project_key: safe.ProjectKey,
    version_key: safe.VersionKey,
    revision: safe.RevisionNumber,
    file_name: safe.RelPath
) -> pathlib.Path:
    return base_path_for_revision(project_key, version_key, revision) / file_name.as_path()
```

Update all callers to pass `safe.RelPath` instances.

### Acceptance Criteria
- [ ] Function signature updated to require safe.RelPath
- [ ] All callers updated to pass safe.RelPath instances
- [ ] Type checking enforces safe parameter usage
- [ ] Unit tests verifying path validation

### References
- Source reports: L1:5.3.2.md
- Related findings: None
- ASVS sections: 5.3.2

### Priority
Low

---

## Issue: FINDING-241 - SVN PubSub Path Construction Missing Traversal Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The SVN PubSub handler constructs local filesystem paths from repository paths provided in commit notifications without explicit path traversal validation. While SVN itself prevents .. in repository paths and the PubSub connection is authenticated, a defense-in-depth check is missing. If PubSub infrastructure is compromised or SVN path validation is bypassed, arbitrary svn update commands could be executed outside the intended working copy directory.

### Details
In `atr/svn/pubsub.py` at lines ~97-108, the PubSub handler constructs local paths from repository paths without containment validation. The handler trusts that repository paths from PubSub are safe, but does not verify the constructed local path remains within working_copy_root.

### Recommended Remediation
Add containment validation after path construction:

```python
local_path = (self.working_copy_root / relative_part).resolve()
if not local_path.is_relative_to(self.working_copy_root.resolve()):
    log.warning(
        f'PubSub path escapes working copy root',
        extra={'repo_path': repo_path, 'local_path': str(local_path)}
    )
    continue
```

Add try/except around `svn.update()` with error logging.

### Acceptance Criteria
- [ ] Containment validation added to PubSub handler
- [ ] Path traversal attempts are logged and rejected
- [ ] Legitimate SVN updates continue to work
- [ ] Unit tests verifying containment validation

### References
- Source reports: L1:5.3.2.md
- Related findings: None
- ASVS sections: 5.3.2

### Priority
Low

---

## Issue: FINDING-242 - total_size() Function Defined But Never Called Before Extraction

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The `total_size()` function in `atr/archives.py` (lines 77-85) computes total uncompressed size of an archive by iterating all members and reading through all file content via `fileobj.read(chunk_size)`, performing decompression without writing to disk. This function exists as a utility that could serve as a pre-extraction check, but no code in the codebase calls it before `extract()` or any other extraction operation. Its mere existence may create false confidence that pre-extraction size checking is implemented.

### Details
The `total_size()` function is defined but never called. While it could provide pre-extraction size validation, its presence without usage creates a false sense of security that size checks are being performed.

### Recommended Remediation
Either call `total_size()` before `extract()` at every call site to provide pre-extraction size validation, or integrate size checking directly into the pre-extraction safety check (as recommended in FINDING-123) and remove or deprecate this unused function to reduce confusion and false confidence.

### Acceptance Criteria
- [ ] total_size() either called before all extract() operations OR removed
- [ ] If implemented, size limits enforced before extraction
- [ ] If removed, no false confidence in unused code
- [ ] Unit tests verifying size validation (if implemented)

### References
- Source reports: L2:5.2.3.md
- Related findings: FINDING-123
- ASVS sections: 5.2.3

### Priority
Low

---

## Issue: FINDING-243 - Authentication Failure Logging Is Passive — No Blocking Integration

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `failed_authentication()` function in `atr/log.py` is called from multiple locations when authentication fails. While logging is valuable for monitoring, the function is purely passive and does not integrate with any blocking mechanism. Failed authentication attempts are logged for post-hoc analysis only. Cannot trigger real-time protective actions (e.g., temporary IP blocking, account lockout). Security monitoring requires manual log analysis or external SIEM integration. No automated response to brute force patterns.

### Details
In `atr/log.py` at lines ~108-112, the `failed_authentication()` function logs failures but takes no protective action. The function is called from:
- `atr/jwtoken.py`
- `atr/ssh.py`
- `atr/storage/writers/tokens.py`

All calls are passive logging only, with no integration to rate limiting or blocking mechanisms.

### Recommended Remediation
Integrate failure logging with an active blocking mechanism. Modify `failed_authentication()` to:
1. Accept an identifier parameter (IP, username, etc.)
2. Increment a failure counter for that identifier
3. Check if threshold is exceeded
4. Trigger temporary block or rate limit escalation if threshold exceeded

### Acceptance Criteria
- [ ] Failed authentication triggers protective actions
- [ ] Threshold-based blocking or rate limit escalation implemented
- [ ] Legitimate users not locked out by false positives
- [ ] Unit tests verifying blocking logic

### References
- Source reports: L1:6.3.1.md
- Related findings: FINDING-004, FINDING-125
- ASVS sections: 6.3.1

### Priority
Low

---

## Issue: FINDING-244 - Inconsistent Rate Limiting Across GitHub OIDC Endpoints

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
Five trusted publisher endpoints lack endpoint-specific rate limiting (distribution_record_from_workflow, publisher_distribution_record, publisher_release_announce, publisher_vote_resolve, update_distribution_task_status) while two similar endpoints have 10/hour rate limits (distribute_ssh_register, publisher_ssh_register). All endpoints are subject to global rate limiting (100/min, 1000/hr), but this inconsistency creates an uneven security posture. An attacker with a valid GitHub OIDC token could make unlimited calls to the unprotected endpoints subject only to global rate limits.

### Details
In `atr/api/__init__.py`, the following endpoints lack endpoint-specific rate limits:
- publisher_vote_resolve
- publisher_release_announce
- publisher_distribution_record
- distribution_record_from_workflow
- update_distribution_task_status

While `distribute_ssh_register` and `publisher_ssh_register` have `@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))`.

### Recommended Remediation
Apply consistent rate limiting (`@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))`) to all GitHub OIDC endpoints: publisher_vote_resolve, publisher_release_announce, publisher_distribution_record, distribution_record_from_workflow, and update_distribution_task_status.

### Acceptance Criteria
- [ ] All GitHub OIDC endpoints have consistent rate limiting
- [ ] Rate limits are enforced correctly
- [ ] Legitimate automation is not impacted
- [ ] Unit tests verifying rate limit enforcement

### References
- Source reports: L2:6.1.3.md
- Related findings: None
- ASVS sections: 6.1.3

### Priority
Low

---

## Issue: FINDING-245 - Documentation Does Not Describe Failed Authentication Monitoring and Alerting

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
While the code includes authentication failure logging (log.warning, log.failed_authentication with structured metadata), the documentation does not describe how these logs are monitored, what alerting thresholds exist, or how operators should respond to attack patterns. Operations teams cannot determine proper monitoring configuration from documentation alone. Security events may go undetected without documented alerting thresholds and incident response procedures are unclear.

### Details
The file `security/ASVS/audit_guidance/authentication-security.md` does not document monitoring and alerting procedures. Authentication failure logging exists in `atr/storage/writers/tokens.py` at lines 105-116, but operational guidance is missing.

### Recommended Remediation
Add a 'Monitoring and Detection' section to `authentication-security.md` documenting:
- Authentication failure logging with structured metadata (reason, asf_uid, remote_addr, timestamp)
- Log locations
- Recommended monitoring thresholds:
  - Sustained rate limit violations >10 HTTP 429 from single IP in 1 hour
  - Failed PAT validations >5 for single user in 1 hour
  - Account status failures
  - SSH authentication failures >20 from single IP in 10 minutes
- Incident response procedures for sustained authentication failures

### Acceptance Criteria
- [ ] Monitoring section added to documentation
- [ ] Alerting thresholds documented
- [ ] Incident response procedures documented
- [ ] Log locations and formats documented

### References
- Source reports: L1:6.1.1.md
- Related findings: FINDING-128
- ASVS sections: 6.1.1

### Priority
Low

---

## Issue: FINDING-246 - JWT TTL Documentation Inconsistency

**Labels:** bug, security, priority:low, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
The documentation claims JWT tokens have a 90-minute validity period, while the actual implementation enforces a 30-minute TTL. This creates a discrepancy between documented and actual security behavior. Documentation-based security decisions may be based on incorrect TTL assumptions. While the actual TTL (30 minutes) is more secure than documented, the inconsistency erodes trust in documentation accuracy, could lead to confusion during incident response, may cause operational issues if teams plan around 90-minute windows, and creates audit trail inconsistencies.

### Details
In `atr/docs/authentication-security.md`, multiple locations reference 90-minute JWT validity. However, in `atr/jwtoken.py` at line 47, the implementation uses `_ATR_JWT_TTL = 30 * 60` (30 minutes).

### Recommended Remediation
Update documentation to reflect actual implementation: In `atr/docs/authentication-security.md`, update to: * **Validity**: 30 minutes from creation. Search all documentation files for "90 min" or "90 minutes" references to JWT and update all occurrences to "30 min" or "30 minutes". Add a documentation review step to CI/CD that validates security-critical parameters match code constants. Consider extracting TTL values from code comments/docstrings to ensure single source of truth.

### Acceptance Criteria
- [ ] All documentation references updated to 30 minutes
- [ ] No references to 90 minutes remain
- [ ] Documentation review added to CI/CD
- [ ] Single source of truth established for TTL values

### References
- Source reports: L1:6.3.1.md, L1:6.4.1.md, L2:6.3.4.md
- Related findings: None
- ASVS sections: 6.3.1, 6.4.1, 6.3.4

### Priority
Low

---

## Issue: FINDING-247 - Utility Function get_asf_id_or_die() Bypasses LDAP Account Status Check

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `get_asf_id_or_die()` utility function in `atr/util.py` validates session existence but does not verify LDAP account status using `ldap.is_active()`. This function may be used in various parts of the codebase without proper authentication checks, creating a potential bypass vector for utility functions.

### Details
The `get_asf_id_or_die()` utility function provides a convenient way to extract the ASF ID from the session, but it does not perform the same LDAP account status validation that the main authentication flow performs. If this function is used in contexts where `authenticate()` has not been called, disabled accounts could potentially access functionality.

### Recommended Remediation
Update `get_asf_id_or_die()` to include LDAP account status validation by calling `ldap.is_active()`. Alternatively, ensure this utility function is only used in contexts where `authenticate()` has already been called. Add documentation clarifying the security properties of this function and when it should be used.

### Acceptance Criteria
- [ ] LDAP account status validation added OR usage contexts documented
- [ ] Function documentation clarifies security properties
- [ ] Unit tests verify account status checking

### References
- Source reports: L1:7.4.1.md
- Related findings: FINDING-130
- ASVS sections: 7.4.1

### Priority
Low

---

## Issue: FINDING-248 - No Session Termination After OpenPGP Key Changes

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
When a user removes an OpenPGP key, no option is presented to terminate other active sessions. While OpenPGP keys are primarily for signing/encryption rather than authentication, their management should still offer session termination for consistency with other authentication factor changes per ASVS 7.4.3. This is a completeness issue rather than a critical security gap, as OpenPGP keys are not directly used for authentication in this application.

### Details
In `atr/post/keys.py` at lines 161-171, the `_delete_openpgp_key()` handler removes keys but does not offer session termination. This is inconsistent with other authentication factor changes that do provide this option.

### Recommended Remediation
Add 'terminate_other_sessions' boolean field to DeleteOpenPGPKeyForm for consistency. Update `_delete_openpgp_key()` handler to check this field and call `terminate_all_other_sessions(session.asf_uid, current_session_id)` when checked (requires FINDING-005 fix). Add checkbox to OpenPGP key deletion form with message: 'Also terminate all other active sessions'. Update success message based on checkbox selection.

### Acceptance Criteria
- [ ] terminate_other_sessions field added to form
- [ ] Handler checks field and terminates sessions when requested
- [ ] UI checkbox added to key deletion form
- [ ] Unit tests verify session termination logic

### References
- Source reports: L2:7.4.3.md
- Related findings: FINDING-005, FINDING-131
- ASVS sections: 7.4.3

### Priority
Low

---

## Issue: FINDING-249 - No "Revoke All Tokens for ALL Users" Global Capability

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The admin can revoke PATs for a single user at a time via `revoke_all_user_tokens()`. In a security incident affecting all users (e.g., PAT hash algorithm weakness), there's no single action to revoke all PATs for all users. The JWT key rotation covers JWTs but PATs themselves remain valid (and could be exchanged for new JWTs after key rotation). In a mass security incident, admin must individually revoke tokens for each user shown on the revoke page, which is slow and error-prone.

### Details
In `atr/storage/writers/tokens.py` at line 163, the `revoke_all_user_tokens()` function only handles single-user revocation. No global revocation capability exists in `atr/admin/__init__.py`.

### Recommended Remediation
Add a `revoke_all_tokens_globally()` method to `atr/storage/writers/tokens.py` that queries all PersonalAccessToken records, deletes them, and logs the global revocation to audit. Add a corresponding admin route (RevokeAllTokensGloballyForm and revoke_all_tokens_globally_post) to `atr/admin/__init__.py` with confirmation string 'REVOKE ALL TOKENS' and strong warning message about impact.

### Acceptance Criteria
- [ ] Global revocation method implemented
- [ ] Admin route with strong confirmation added
- [ ] Audit logging for global revocation
- [ ] Unit tests verify global revocation logic

### References
- Source reports: L2:7.4.5.md
- Related findings: FINDING-037, FINDING-132
- ASVS sections: 7.4.5

### Priority
Low

---

## Issue: FINDING-250 - PAT Creation Not Audit-Logged (Inconsistency)

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
PAT creation (`add_token()` in `atr/storage/writers/tokens.py:48-71`) sends an email notification to the user but does not write an entry to the audit log. This creates an inconsistency with PAT deletion and JWT issuance operations, which are properly audit-logged using `append_to_audit_log()`. While email notification provides user-level audit trail, the audit log should contain complete PAT lifecycle events for forensic purposes.

### Details
Token deletion properly calls `append_to_audit_log()` with action='token_deleted', but token creation only sends email without audit logging. This creates an incomplete audit trail for PAT lifecycle management.

### Recommended Remediation
Add audit logging to match deletion behavior. After `await self.__data.commit()` and before sending email, add:

```python
self.__write_as.append_to_audit_log(
    asf_uid=self.__asf_uid,
    token_id=pat.id,
    action='token_created',
    label=label,
    expires=expires.isoformat()
)
```

### Acceptance Criteria
- [ ] PAT creation logged to audit log
- [ ] Audit log entry includes all relevant metadata
- [ ] Consistent with PAT deletion logging
- [ ] Unit tests verify audit logging

### References
- Source reports: L1:7.2.2.md
- Related findings: FINDING-134, FINDING-136
- ASVS sections: 7.2.2

### Priority
Low

---

## Issue: FINDING-251 - SSH Authentication Success Not Logged

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The SSH authentication handler (`SSHServer.validate_public_key` in `atr/ssh.py`) logs some failure cases but does not log successful authentications or missing workflow key lookups. The function properly logs invalid usernames (public_key_invalid) and expired keys (public_key_expired), and sets authentication context with `log.set_asf_uid()`, but when workflow key is not found in database or authentication succeeds, no log entry is created. This creates an incomplete audit trail for automated GitHub workflow authentication.

### Details
In `atr/ssh.py` at lines 97-122, the `validate_public_key()` method logs failures but not successes or missing key scenarios.

### Recommended Remediation
Add logging for both success and missing key scenarios. When workflow_key is None, add:

```python
log.failed_authentication('workflow_key_not_found', extra={'fingerprint': fingerprint})
```

Before return True at end of function, add:

```python
log.info('ssh_auth_success', extra={
    'username': username,
    'fingerprint': fingerprint,
    'asf_uid': self._github_asf_uid
})
```

### Acceptance Criteria
- [ ] SSH authentication success logged
- [ ] Missing workflow key logged as failure
- [ ] Complete audit trail for SSH authentication
- [ ] Unit tests verify logging

### References
- Source reports: L1:7.2.2.md
- Related findings: FINDING-134
- ASVS sections: 7.2.2

### Priority
Low

---

## Issue: FINDING-252 - Unverified JWT Claims Used for Post-Verification Authorization Checks

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The JWT verification function performs two decodes of the same token: an unverified decode and a verified decode. Post-verification authorization checks (LDAP status, type validation) reference the unverified `claims_unsafe['sub']` instead of the verified `claims['sub']`. While not currently exploitable due to execution order (verified decode happens before usage), this violates defense-in-depth principles and could become vulnerable if future PyJWT vulnerabilities produce divergent payloads between verified/unverified decodes.

### Details
In `atr/jwtoken.py` at lines 115-147, the `verify()` function performs both unverified and verified JWT decodes. Security-relevant operations (LDAP account status check, subject type validation) use claims from the unverified decode instead of the verified decode.

### Recommended Remediation
Use verified claims consistently throughout the function. Replace all references to `claims_unsafe['sub']` with `claims['sub']` after the verified decode. Keep unverified decode only for logging purposes if needed.

### Acceptance Criteria
- [ ] All security checks use verified claims
- [ ] Unverified decode only used for pre-verification logging
- [ ] Defense-in-depth principle maintained
- [ ] Unit tests verify correct claim usage

### References
- Source reports: L1:7.2.1.md
- Related findings: None
- ASVS sections: 7.2.1

### Priority
Low

---

## Issue: FINDING-253 - PAT Validation Exceptions Return HTTP 500 Instead of 401

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Failed PAT validation raises `ASFQuartException` without specifying errorcode, defaulting to HTTP 500 (Internal Server Error) instead of 401 (Unauthorized). This affects three validation points: invalid PAT hash, user mismatch, and expired PAT. While verification still occurs correctly on the backend, API consumers and monitoring systems misinterpret authentication failures as server errors.

### Details
In `atr/jwtoken.py` at lines 134-143, PAT validation failures raise exceptions without specifying errorcode=401, resulting in HTTP 500 responses for authentication failures.

### Recommended Remediation
Add errorcode=401 to all PAT validation exceptions:

```python
raise ASFQuartException('Personal Access Token invalid', errorcode=401)  # for hash mismatch and user mismatch
raise ASFQuartException('Personal Access Token expired', errorcode=401)  # for expiration
```

### Acceptance Criteria
- [ ] All PAT validation failures return HTTP 401
- [ ] API consumers receive correct error codes
- [ ] Monitoring systems correctly identify authentication failures
- [ ] Unit tests verify error codes

### References
- Source reports: L1:7.2.1.md
- Related findings: None
- ASVS sections: 7.2.1

### Priority
Low

---

## Issue: FINDING-254 - Admin Plain-Text Endpoints Lack Logout Functionality

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
Six admin diagnostic endpoints (configuration, consistency, env, keys_check_post, keys_regenerate_all_post, logs) return text/plain responses with no HTML structure and therefore no logout button. Authenticated admins viewing these pages must use browser back button, navigate to another URL, or manually visit /auth?logout to terminate sessions. Impact is limited as these are diagnostic endpoints for technically sophisticated admin users, sessions still have timeout enforcement, and the admin user base is small.

### Details
In `atr/admin/__init__.py`, the following endpoints return plain text without logout functionality:
- Line 206: configuration
- Line 250: consistency
- Line 430: env
- Line 453: keys_check_post
- Line 490: keys_regenerate_all_post
- Line 588: logs

### Recommended Remediation
**Option 1 (Recommended for compliance):** Wrap text output in HTML using `template.render()` with `admin/text-display.html` that extends `base.html`, displaying content in `<pre>` tags while maintaining logout button access.

**Option 2 (Alternative):** Accept as documented limitation and add to documentation that admin diagnostic endpoints return plain text for machine readability without logout buttons, instructing users to use browser navigation or visit /auth?logout directly.

### Acceptance Criteria
- [ ] Either HTML wrapper added OR limitation documented
- [ ] Logout functionality accessible from all admin pages (if Option 1)
- [ ] Documentation updated (if Option 2)
- [ ] Unit tests verify logout accessibility

### References
- Source reports: L2:7.4.4.md
- Related findings: FINDING-137, FINDING-138
- ASVS sections: 7.4.4

### Priority
Low

---

## Issue: FINDING-255 - No Comprehensive Endpoint-to-Authorization Mapping

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
While authorization rules are well-defined by operation category (releases, tokens, etc.), there is no comprehensive mapping of HTTP endpoints to their specific authorization requirements. This makes it difficult to verify complete authorization coverage during audits, understand authorization requirements when reviewing routes, ensure consistent authorization across similar endpoints, and onboard new developers to the authorization model. Authorization documentation is organized by operation type rather than by HTTP endpoint.

### Details
The file `atr/docs/authorization-matrix.md` does not exist. Authorization documentation is scattered across operation-specific documents, making it difficult to get a complete view of endpoint-level authorization requirements.

### Recommended Remediation
Create `atr/docs/authorization-matrix.md` with comprehensive mapping of all HTTP endpoints to authentication and authorization requirements. Include sections for:
- Web Endpoints (public, authenticated, admin)
- API Endpoints (token management, release management, trusted publisher operations, public API)
- SSH/Rsync Endpoints

For each endpoint document:
- HTTP method
- Path
- Authentication requirements
- Authorization checks
- Additional validation
- Rate limits
- Phase restrictions

Include authorization legend explaining authorization levels. Document enforcement layers and mechanisms. List known gaps with references to security findings. Generate authorization matrix as part of CI/CD pipeline to keep synchronized with code.

### Acceptance Criteria
- [ ] Comprehensive authorization matrix created
- [ ] All endpoints documented with authorization requirements
- [ ] CI/CD integration for keeping matrix synchronized
- [ ] Documentation reviewed and approved

### References
- Source reports: L1:8.1.1.md
- Related findings: FINDING-157
- ASVS sections: 8.1.1

### Priority
Low

---

## Issue: FINDING-256 - Asymmetric Authorization Enforcement Between Read and Write Paths

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The storage layer's Write class validates that asf_uid is not None before granting foundation committer access. The Read class lacks this check, creating asymmetry in authorization enforcement between read and write operations.

### Details
In `atr/storage/__init__.py` at line 89, the Read class's `as_foundation_committer_outcome()` method does not validate that asf_uid is not None, while the corresponding Write class method does perform this validation.

### Recommended Remediation
Add asf_uid validation to `Read.as_foundation_committer_outcome()` matching the check in `Write.as_foundation_committer_outcome()`. Ensure consistent authorization validation across read and write paths.

### Acceptance Criteria
- [ ] Read class validates asf_uid is not None
- [ ] Consistent authorization validation between read and write
- [ ] Unit tests verify validation in both paths

### References
- Source reports: L1:8.3.1.md
- Related findings: None
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-257 - Vote Policy Validation Gaps

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Vote policy validation has multiple gaps: (1) Does not verify binding vote requirements are set appropriately in relation to total vote requirements, which could allow configurations where binding votes exceed total votes. (2) Vote recording does not verify that vote duration has elapsed before allowing vote completion, relying on application logic rather than enforcing at storage layer.

### Details
In `atr/storage/writers/vote.py`, vote policy validation does not ensure min_binding_votes <= min_total_votes when both are configured. Additionally, temporal validation to verify vote duration has elapsed is missing at the storage layer.

### Recommended Remediation
Add validation ensuring min_binding_votes <= min_total_votes when both are configured. Add temporal validation in storage layer to verify vote duration has elapsed before accepting vote completion.

### Acceptance Criteria
- [ ] Vote policy validation enforces binding vs total vote relationship
- [ ] Temporal validation added at storage layer
- [ ] Invalid vote configurations rejected
- [ ] Unit tests verify all validation logic

### References
- Source reports: L1:8.3.1.md
- Related findings: FINDING-149, FINDING-150
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-258 - Project Deletion Missing Additional Authorization Checks

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Project deletion in storage writer accepts deletion requests without additional validation that project has no active releases or ongoing votes that should prevent deletion.

### Details
In `atr/storage/writers/project.py`, the project deletion logic does not check for blocking conditions such as active releases, ongoing votes, or other dependencies that should prevent deletion.

### Recommended Remediation
Add validation checks before project deletion to ensure no active releases, ongoing votes, or other blocking conditions exist.

### Acceptance Criteria
- [ ] Project deletion validates no active releases exist
- [ ] Project deletion validates no ongoing votes exist
- [ ] Clear error messages for blocked deletions
- [ ] Unit tests verify validation logic

### References
- Source reports: L1:8.3.1.md
- Related findings: None
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-259 - Distribution Writer Missing Fine-Grained Permission Checks

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Distribution automation operations accept parameters without fine-grained validation of user permissions for specific distribution operations beyond committee membership.

### Details
In `atr/storage/writers/distributions.py`, distribution operations only validate basic committee membership without checking specific permissions for individual distribution operations.

### Recommended Remediation
Add specific permission checks for distribution operations beyond basic committee membership validation.

### Acceptance Criteria
- [ ] Fine-grained permission checks implemented
- [ ] Each distribution operation validates specific permissions
- [ ] Unauthorized operations rejected
- [ ] Unit tests verify permission checks

### References
- Source reports: L1:8.3.1.md
- Related findings: FINDING-148
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-260 - API Models Lack Enum Validation for Phase Parameter

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
API models accept plain string for phase parameter (compose/vote/finish/published) rather than using Literal type enum, allowing invalid phase values that should be rejected at validation layer.

### Details
In `atr/models/api.py`, the phase parameter is defined as plain `str` rather than using `Literal['compose', 'vote', 'finish', 'published']` to enforce valid values at the validation layer.

### Recommended Remediation
Replace `phase: str` with `phase: Literal['compose', 'vote', 'finish', 'published']` in API models to enforce valid phase values at validation layer.

### Acceptance Criteria
- [ ] Phase parameter uses Literal type enum
- [ ] Invalid phase values rejected at validation layer
- [ ] Clear error messages for invalid phases
- [ ] Unit tests verify validation

### References
- Source reports: L1:8.3.1.md
- Related findings: FINDING-150
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-261 - Audit Log Access Pattern Not Consistently Applied

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Audit logging through `storage.AccessAs.append_to_audit_log()` is consistently used for storage layer operations, but some direct database operations bypass this logging mechanism.

### Details
In `atr/post/keys.py` (lines 76-115) and `atr/post/revisions.py` (lines 67-95), some operations perform direct database writes that bypass the audit logging mechanism provided by the storage layer.

### Recommended Remediation
Ensure all authorization-sensitive operations route through storage layer to leverage consistent audit logging. Eliminate direct database writes that bypass audit trail.

### Acceptance Criteria
- [ ] All operations use storage layer for audit logging
- [ ] No direct database writes bypass audit trail
- [ ] Complete audit trail for all sensitive operations
- [ ] Unit tests verify audit logging

### References
- Source reports: L1:8.3.1.md
- Related findings: FINDING-009, FINDING-147, FINDING-145
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-262 - Vote Tabulation Authorization Check Commented Out

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The vote tabulation endpoint has JWT authentication enabled but the identity extraction is commented out (`asf_uid = _jwt_asf_uid()` is commented), and the operation uses the lowest privilege level (`as_general_public()`). While ASF voting is transparent, the consumer's identity is not bound to the operation and there's no check that the consumer has any relationship to the project.

### Details
In `atr/api/__init__.py` at lines 1255-1290, the vote tabulation endpoint has commented-out identity extraction and uses `as_general_public()` instead of verifying the user has a relationship to the project.

### Recommended Remediation
Uncomment the identity extraction line (`asf_uid = _jwt_asf_uid()`). Use the authenticated identity in the storage write context (`storage.write(asf_uid)`). Verify the user has a relationship to the project by checking committee participant status (`write.as_committee_participant(release.project.committee_key)`) before allowing vote tabulation operations.

### Acceptance Criteria
- [ ] Identity extraction uncommented
- [ ] Authenticated identity used in storage context
- [ ] Committee participant status verified
- [ ] Unit tests verify authorization checks

### References
- Source reports: L2:8.2.3.md
- Related findings: None
- ASVS sections: 8.2.3

### Priority
Low

---

## Issue: FINDING-263 - Unverified JWT Subject Claim Used for Logging Before Signature Verification

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `verify()` function in `atr/jwtoken.py` performs an unverified JWT decode to extract the 'sub' claim for logging context (`log.set_asf_uid()`) before the verified signature check completes. This allows an attacker to inject arbitrary usernames into authentication failure log entries. The unverified decode happens first with verify_signature=False, then the sub claim is used for logging, and only afterward does signature verification occur. This creates a TOCTOU (Time-of-check Time-of-use) race condition where unverified data is used before verification completes.

### Details
In `atr/jwtoken.py` at lines 108-112, the function performs unverified decode and uses the sub claim for logging before signature verification is complete.

### Recommended Remediation
Refactor the `verify()` function to perform verified JWT decode first before using any claims data. Move the `jwt.decode()` call with signature verification to the beginning of the function, then extract the sub claim from the verified claims dictionary for logging. Alternative: If logging is needed for failed attempts, only log unverified claims in exception handlers with clear warnings that the subject is unverified.

### Acceptance Criteria
- [ ] Verified decode performed before using claims
- [ ] No unverified claims used for security decisions
- [ ] Logging uses verified claims only
- [ ] Unit tests verify correct decode order

### References
- Source reports: L1:9.1.1.md
- Related findings: FINDING-268
- ASVS sections: 9.1.1

### Priority
Low

---

## Issue: FINDING-264 - Bearer Token Logged to stdout When No Token Handler Registered

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
When no PAT (Personal Access Token) handler is registered (which is the case for ATR), the `session.read()` function prints raw bearer tokens to stdout for debugging purposes. This function is called in before_request hooks for every incoming request with an Authorization header. The vulnerable code prints the full token value when app.token_handler is not registered. While the token IS validated separately by @jwtoken.require before authorization decisions, the raw credential is exposed in application logs/stdout.

### Details
In `src/asfquart/session.py` at line 76, a print() statement outputs raw bearer tokens when no token handler is registered.

### Recommended Remediation
Remove or redact the debug print() statement that logs raw bearer tokens. Replace with proper logging that does not include the token value:

```python
logging.getLogger(__name__).debug('No PAT handler registered for bearer token authentication')
```

Alternative: Log only token metadata such as a truncated preview (first 10 chars + '...'). Best practice: Remove debug code entirely in production.

### Acceptance Criteria
- [ ] Raw bearer tokens no longer logged
- [ ] Proper logging without token values implemented
- [ ] Debug code removed from production paths
- [ ] Unit tests verify no token leakage

### References
- Source reports: L1:9.1.1.md
- Related findings: None
- ASVS sections: 9.1.1

### Priority
Low

---

## Issue: FINDING-265 - Documentation-Code TTL Discrepancy

**Labels:** bug, security, priority:low, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
Documentation states JWT validity is "90 minutes" but code defines `_ATR_JWT_TTL = 30 * 60` (30 minutes), creating a discrepancy between expected and actual token lifetime. This can lead to operational confusion, incorrect security assumptions in dependent systems, and unnecessary support requests when tokens expire earlier than documented. The documentation inconsistency appears in multiple sections of authentication-security.md.

### Details
In `atr/jwtoken.py` at line 42, the TTL is defined as 30 minutes. However, `atr/docs/authentication-security.md` documents it as 90 minutes in multiple locations.

### Recommended Remediation
**Option 1 (Recommended):** Update documentation to match code:
```markdown
* **Validity**: 30 minutes from creation
```

**Option 2:** If 90 minutes is the intended policy, update code:
```python
_ATR_JWT_TTL: Final[int] = 90 * 60  # 90 minutes
```

Verification: Review and align all documentation references to token lifetime, including API documentation, user guides, and inline code comments.

### Acceptance Criteria
- [ ] Documentation and code TTL values match
- [ ] All documentation references updated
- [ ] Single source of truth established
- [ ] Unit tests verify TTL enforcement

### References
- Source reports: L1:9.1.2.md, L2:9.2.2.md
- Related findings: None
- ASVS sections: 9.1.2, 9.2.2

### Priority
Low

---

## Issue: FINDING-266 - Incomplete Dangerous Header Blocking — Missing x5c and Related X.509 Headers

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The dangerous header check blocks jku, x5u, and jwk headers but does not include x5c (X.509 certificate chain), x5t (X.509 certificate SHA-1 thumbprint), or x5t#S256 (X.509 certificate SHA-256 thumbprint). While ASVS 9.1.3 explicitly names jku, x5u, and jwk, the use of 'such as' indicates these are illustrative examples, not an exhaustive list. This creates a defense-in-depth gap that could become exploitable if the JWT library is upgraded and changes behavior regarding header processing, the code is refactored to derive keys from headers in some scenarios, a different decode path is introduced that doesn't explicitly provide keys, or a developer copies this validation pattern to another context where keys aren't explicitly provided.

### Details
In `atr/jwtoken.py` at lines 142-145, the dangerous_headers set only includes {"jku", "x5u", "jwk"} and is missing X.509-related headers. Currently not exploitable because the code provides the signing key explicitly to jwt.decode() via the signing_key.key parameter, and PyJWT does not extract keys from x5c headers when a key is provided directly.

### Recommended Remediation
Update line 143 in atr/jwtoken.py to include all X.509-related headers:

```python
dangerous_headers = {"jku", "x5u", "jwk", "x5c", "x5t", "x5t#S256"}
```

This completes the dangerous header blocking control and protects against future code or library changes. Effort: Trivial (1 line change).

### Acceptance Criteria
- [ ] All X.509-related headers blocked
- [ ] Defense-in-depth protection complete
- [ ] Unit tests verify all dangerous headers rejected

### References
- Source reports: L1:9.1.3.md
- Related findings: None
- ASVS sections: 9.1.3

### Priority
Low

---

## Issue: FINDING-267 - `nbf` Claim Not Enforced as Required in ATR JWT Verification

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `verify()` function uses PyJWT's `require` option to mandate the presence of specific claims but omits `nbf` from the required list. While PyJWT's default behavior (`verify_nbf=True`) does verify the `nbf` claim when present, it does not enforce that the claim must exist in the token. The vulnerability is not practically exploitable because ATR uses HS256 symmetric signing with a secret key, and attackers cannot forge valid tokens without the signing key. All legitimate ATR-issued tokens include `nbf`. This is a defense-in-depth gap rather than an exploitable vulnerability.

### Details
In `atr/jwtoken.py` at lines 107-115, the `jwt.decode()` call includes a `require` list that does not include "nbf".

### Recommended Remediation
Add `"nbf"` to the required claims list in the `jwt.decode()` call:

```python
# atr/jwtoken.py, line 113
claims = jwt.decode(
    token,
    jwt_secret_key,
    algorithms=[_ALGORITHM],
    issuer=_ATR_JWT_ISSUER,
    audience=_ATR_JWT_AUDIENCE,
    options={"require": ["sub", "iss", "aud", "iat", "nbf", "exp", "jti"]},
    #                                            ^^^^ ADDED
)
```

Validation steps:
1. All existing tests pass (tokens already include `nbf`)
2. Add negative test: token without `nbf` is rejected
3. Confirm error message indicates missing required claim

### Acceptance Criteria
- [ ] nbf claim added to required list
- [ ] Tokens without nbf claim are rejected
- [ ] All existing tests pass
- [ ] Negative test added for missing nbf

### References
- Source reports: L1:9.2.1.md
- Related findings: None
- ASVS sections: 9.2.1

### Priority
Low

---

## Issue: FINDING-268 - Post-Verification Security Checks Use Unverified Token Claims

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The `verify()` function performs two JWT decode operations: one unverified (for logging) and one verified (for security). However, security-relevant operations (LDAP account status check via `ldap.is_active()`, subject type validation via `isinstance()`) use claims from the unverified decode instead of the verified decode. While not currently exploitable (both decode operations process the same token bytes), this violates the principle that security decisions must use verified data and creates future refactoring risk.

### Details
In `atr/jwtoken.py` at lines 104-137, security-relevant operations at lines 118-123 use `claims_unsafe['sub']` instead of `claims['sub']` after the verified decode.

### Recommended Remediation
Change lines 118-123 to use `asf_uid = claims.get("sub")` (from verified claims) instead of extracting from `claims_unsafe`. Keep unverified decode only for pre-verification logging purposes. This ensures all security-relevant operations (LDAP lookups, type checks) use cryptographically verified data.

### Acceptance Criteria
- [ ] All security checks use verified claims
- [ ] Unverified decode only used for logging
- [ ] Defense-in-depth principle maintained
- [ ] Unit tests verify correct claim usage

### References
- Source reports: L2:9.2.2.md
- Related findings: FINDING-263
- ASVS sections: 9.2.2

### Priority
Low

---

## Issue: FINDING-269 - JWT Audience Values Contain 'test' Identifier

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
Both audience constants contain 'test' in their names (`_ATR_JWT_AUDIENCE = "atr-api-pat-test-v1"` and `_GITHUB_OIDC_AUDIENCE = "atr-test-v1"`), which may indicate development/testing configuration carried over to production deployment. While the audience values are functionally secure (distinct from each other, correctly validated), the naming suggests incomplete production configuration and could cause operational confusion about the token's intended deployment context.

### Details
In `atr/jwtoken.py` at lines 23-24, both JWT audience constants contain 'test' identifiers that suggest development/testing configuration.

### Recommended Remediation
Update audience values to production-appropriate URIs:
- `_ATR_JWT_AUDIENCE = "https://release.apache.org/api/v1"`
- `_GITHUB_OIDC_AUDIENCE = "https://release.apache.org/trusted-publisher/v1"`

Alternatively, use environment-specific configuration with `APP_HOST` variable. Remove 'test' identifiers for clarity and operational confidence.

### Acceptance Criteria
- [ ] Audience values updated to production-appropriate URIs
- [ ] No 'test' identifiers in production configuration
- [ ] Environment-specific configuration if applicable
- [ ] Unit tests verify audience validation

### References
- Source reports: L2:9.2.2.md
- Related findings: None
- ASVS sections: 9.2.2

### Priority
Low

---

## Issue: FINDING-270 - GitHub OIDC `require` List Missing `aud`, `iss`, and `sub` Claims (Defense-in-Depth)

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The GitHub OIDC token verification function does not include "aud", "iss", or "sub" in the explicit `require` list within the `options` parameter, despite validating these claims via the `audience` and `issuer` parameters. PyJWT's `audience` and `issuer` parameters do enforce validation of the `aud` and `iss` claims respectively, so this is not currently exploitable. Additionally, the TrustedPublisherPayload Pydantic model defines aud: str as a required field, providing a second validation layer. However, the explicit `require` list serves as defense-in-depth and makes the security intent unambiguous.

### Details
In `atr/jwtoken.py` at line 158 and lines 165-170, the GitHub OIDC verification does not include "aud", "iss", or "sub" in the explicit require list. If a future PyJWT update changed the implicit enforcement behavior, or if the `audience`/`issuer` parameters were accidentally removed during code maintenance, the explicit `require` list would catch the gap. This creates an inconsistency with the ATR JWT verification path which explicitly requires all critical claims.

### Recommended Remediation
Add "aud", "iss", and "sub" to the explicit `require` list for consistency with ATR's own JWT verification pattern and defense-in-depth:

```python
payload = jwt.decode(
    token,
    key=signing_key.key,
    algorithms=["RS256"],
    audience=_GITHUB_OIDC_AUDIENCE,
    issuer=_GITHUB_OIDC_ISSUER,
    options={"require": ["exp", "iat", "aud", "iss", "sub"]},
)
```

### Acceptance Criteria
- [ ] aud, iss, and sub added to require list
- [ ] Consistent with ATR JWT verification pattern
- [ ] Defense-in-depth protection complete
- [ ] Unit tests verify all required claims

### References
- Source reports: L2:9.2.3.md, L2:9.2.4.md
- Related findings: None
- ASVS sections: 9.2.3, 9.2.4

### Priority
Low

---

## Issue: FINDING-271 - JWT TTL Documentation Discrepancy (30 Minutes Actual vs 90 Minutes Documented)

**Labels:** bug, security, priority:low, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
The JWT time-to-live (TTL) is hardcoded as 30 minutes (1,800 seconds) in `atr/jwtoken.py` line 40-43 (`_ATR_JWT_TTL = 30 * 60`), but the authentication security documentation claims 90 minutes. The code implements the more restrictive value, so there is no security weakness. However, this discrepancy could cause confusion during security reviews, incorrect threat modeling assumptions, misleading incident response procedures, and compliance documentation errors.

### Details
In `atr/jwtoken.py` at lines 40-43, the TTL is 30 minutes. In `atr/docs/authentication-security.md`, it is documented as 90 minutes.

### Recommended Remediation
Update `atr/docs/authentication-security.md` to change 'Validity: 90 minutes from creation' to 'Validity: 30 minutes from creation' to align documentation with code implementation. Keep the 30-minute TTL in code (more secure) rather than increasing to 90 minutes. The shorter lifetime reduces the exposure window for compromised tokens.

### Acceptance Criteria
- [ ] Documentation updated to 30 minutes
- [ ] All references to 90 minutes removed
- [ ] Single source of truth established
- [ ] Unit tests verify TTL enforcement

### References
- Source reports: L1:10.4.2.md, L1:10.4.3.md, L2:10.4.8.md
- Related findings: None
- ASVS sections: 10.4.2, 10.4.3, 10.4.8

### Priority
Low

---

## Issue: FINDING-272 - Process-Local OAuth State Storage Fails in Multi-Instance Deployments

**Labels:** bug, security, priority:low, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
OAuth state parameters are stored in a process-local dictionary (`pending_states = {}`) rather than shared storage. In multi-instance or load-balanced deployments, if the OAuth callback request is routed to a different instance than the one that initiated the flow, the state lookup will fail, causing authentication denial. This is an availability concern rather than a security vulnerability. The issue is documented in `docs/oauth.md` and tracked in GitHub issue infrastructure-asfquart#52.

### Details
In `src/asfquart/generics.py` at lines 38-40, OAuth state is stored in a process-local dictionary. This works for single-instance deployments but fails in multi-instance scenarios.

### Recommended Remediation
For production multi-instance deployments:

**Option 1 (preferred):** Use shared state store (e.g., Redis) with TTL-based expiry:
```python
redis_client.setex(f'oauth_state:{state}', workflow_timeout, json.dumps(state_data))
```

**Option 2:** Configure session-affinity (sticky sessions) at load balancer based on session cookie.

**Option 3:** Continue single-instance deployment if scale requirements allow.

### Acceptance Criteria
- [ ] Multi-instance OAuth flows work correctly OR deployment remains single-instance
- [ ] State storage solution documented
- [ ] Unit tests verify state persistence across instances (if applicable)

### References
- Source reports: L1:10.4.2.md, L1:10.4.4.md, L2:10.4.7.md
- Related findings: None
- ASVS sections: 10.4.2, 10.4.4, 10.4.7

### Priority
Low

---

## Issue: FINDING-273 - Redirect URI Validation Lacks Newline/Control Character Filtering

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The redirect URI validation only checks the prefix (starts with `/`, not `//`). A value like `/dashboard\r\nX-Injected: true` passes validation but contains CRLF characters. This value is later placed directly into a Refresh response header. Mitigating Factor: Modern Werkzeug (≥2.3) rejects header values containing \r, \n, or \x00, raising a ValueError. The `HeaderValue` class in `web.py` (lines 153-175) demonstrates the project's awareness of this issue, yet it is not applied in the OAuth flow. If the Werkzeug version is downgraded or the framework-level check is bypassed, HTTP response header injection becomes possible.

### Details
In `src/asfquart/generics.py` at lines 55-62, 117-122, and 73-80, redirect URI validation does not filter control characters. While Werkzeug provides protection, application-level validation should be defense-in-depth.

### Recommended Remediation
Add control character validation to redirect URI validation function:

```python
import re
_INVALID_REDIRECT_CHARS = re.compile(r'[\x00-\x1f\x7f]')

def _validate_redirect_uri(uri: str) -> bool:
    if not uri.startswith('/') or uri.startswith('//'):
        return False
    if _INVALID_REDIRECT_CHARS.search(uri):
        return False
    return True
```

Apply this validation consistently to all redirect URI parameters in login, logout, and OAuth callback flows.

### Acceptance Criteria
- [ ] Control character validation added
- [ ] All redirect URI parameters validated
- [ ] CRLF injection attempts blocked
- [ ] Unit tests verify validation

### References
- Source reports: L1:10.4.1.md
- Related findings: FINDING-164
- ASVS sections: 10.4.1

### Priority
Low

---

## Issue: FINDING-274 - OAuth State Timeout (15 Minutes) Exceeds Authorization Code Best Practice Window

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The OAuth `workflow_timeout` parameter is configured at 900 seconds (15 minutes). While this controls the state parameter timeout and NOT the authorization code lifetime itself, it creates a 15-minute window during which ATR will accept an OAuth callback. ASVS 10.4.3 recommends authorization codes should not live longer than 10 minutes for L1/L2 applications. The actual authorization code lifetime is enforced server-side by `oauth.apache.org`, not by ATR. This is informational because ATR cannot control the authorization code lifetime directly, but aligning the state window with best practices would improve security posture.

### Details
In `src/asfquart/generics.py` at line 16 and line 95, the workflow_timeout is set to 900 seconds (15 minutes), exceeding the 10-minute recommendation.

### Recommended Remediation
Consider reducing `workflow_timeout` to 600 seconds (10 minutes) to align ATR's state window with ASVS guidance:

```python
def setup_oauth(app, uri=DEFAULT_OAUTH_URI, workflow_timeout: int = 600):
```

Additionally, coordinate with the ASF OAuth service team to confirm the actual authorization code lifetime enforced by `oauth.apache.org` and document any variance from ASVS 10.4.3 recommendations as an accepted architectural risk.

### Acceptance Criteria
- [ ] workflow_timeout reduced to 10 minutes OR risk acceptance documented
- [ ] Coordination with ASF OAuth service team
- [ ] Documentation updated with actual authorization code lifetime
- [ ] Unit tests verify timeout enforcement

### References
- Source reports: L1:10.4.3.md
- Related findings: FINDING-278
- ASVS sections: 10.4.3

### Priority
Low

---

## Issue: FINDING-275 - Pagination Offset Validation Never Executes Due to Typo

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The pagination validation function contains a typo in the attribute name check: `if hasattr(query_args, 'offest'):` instead of `'offset'`. This causes offset validation to be silently skipped for all paginated API endpoints. Attackers can force expensive database queries with very large offset values. Impact is limited by: (1) Correct limit validation (max 1000), (2) Public data only (no authorization bypass), (3) Database query optimizer handling. This is a resource exhaustion risk rather than a data breach risk.

### Details
In `atr/api/__init__.py` at line 710, the hasattr check uses 'offest' instead of 'offset', preventing offset validation from executing.

### Recommended Remediation
Fix the typo: Change `if hasattr(query_args, 'offest'):` to `if hasattr(query_args, 'offset'):` on line 710 of `atr/api/__init__.py`. Add unit tests to verify offset validation:
1. Test maximum offset enforcement (>1000000 rejected)
2. Test negative offset rejection
3. Test valid offset acceptance

Add integration test to prevent regression.

### Acceptance Criteria
- [ ] Typo fixed in attribute name check
- [ ] Offset validation executes correctly
- [ ] Unit tests verify offset validation
- [ ] Integration test prevents regression

### References
- Source reports: L1:10.4.5.md
- Related findings: None
- ASVS sections: 10.4.5

### Priority
Low

---

## Issue: FINDING-276 - No Expiry Cleanup for Stale OAuth State Entries (Memory Leak)

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
Expired state entries are only cleaned up when specifically looked up during a callback. If a user initiates an OAuth flow but never completes the callback, the state entry remains in the dictionary indefinitely until process restart, causing gradual memory growth. With ~200 bytes per entry, 1000 abandoned flows would leak ~200 KB. This is a resource leak rather than a security vulnerability, but could impact long-running processes in high-traffic scenarios.

### Details
In `src/asfquart/generics.py` at line 40 and lines 87-93, expired state entries are only cleaned up on lookup, not proactively.

### Recommended Remediation
Implement periodic cleanup mechanism.

**Option 1:** Add async background task that runs every 5 minutes to clean expired states:
```python
async def _cleanup_expired_states():
    current_time = time.time()
    expired = [s for s, d in pending_states.items() if d['timestamp'] < (current_time - workflow_timeout)]
    for state in expired:
        pending_states.pop(state, None)
```

**Option 2:** Probabilistic cleanup on each request (e.g., 10% of requests trigger cleanup).

**Option 3:** Migrate to Redis with automatic TTL-based expiry.

### Acceptance Criteria
- [ ] Periodic cleanup mechanism implemented
- [ ] Memory leak eliminated
- [ ] Long-running processes maintain stable memory usage
- [ ] Unit tests verify cleanup logic

### References
- Source reports: L2:10.4.7.md
- Related findings: FINDING-272
- ASVS sections: 10.4.7

### Priority
Low

---

## Issue: FINDING-277 - ASFQuart Session Absolute Expiration Disabled by Default

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
ASFQuart's `MAX_SESSION_AGE` configuration defaults to 0, which disables absolute session lifetime enforcement at the framework level. The session implementation includes a sliding inactivity timeout (7 days default) where `uts` (update timestamp) is refreshed on every access, and a creation timestamp `cts` that is set once. Without explicit configuration, a session accessed at least once every 7 days could persist indefinitely from ASFQuart's perspective. This is mitigated by ATR's additional enforcement via `ABSOLUTE_SESSION_MAX_SECONDS` (72 hours default) in a `before_request` hook in `server.py`, but framework-level protection would provide defense-in-depth.

### Details
In `src/asfquart/session.py`:
- Line 45: MAX_SESSION_AGE defaults to 0
- Lines 51-52: Creation timestamp (cts) set once
- Line 56: Update timestamp (uts) refreshed on access
- Line 99: No absolute expiration check at framework level

### Recommended Remediation
Configure ASFQuart session absolute expiration for defense-in-depth: Add `app.cfg['MAX_SESSION_AGE'] = 72 * 3600` (72 hours) to application configuration. This provides framework-level enforcement independent of application hooks, ensures expiration even if `before_request` hook fails or is bypassed, and aligns with ATR's documented `ABSOLUTE_SESSION_MAX_SECONDS` policy.

### Acceptance Criteria
- [ ] MAX_SESSION_AGE configured at framework level
- [ ] Framework-level expiration enforced
- [ ] Defense-in-depth protection complete
- [ ] Unit tests verify absolute expiration

### References
- Source reports: L2:10.4.8.md
- Related findings: None
- ASVS sections: 10.4.8

### Priority
Low

---

## Issue: FINDING-278 - Admin Bulk Token Revocation Does Not Notify Affected User

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
When an admin revokes all tokens for a user via the `/admin/revoke-user-tokens` endpoint, the affected user receives no email notification. This is inconsistent with the individual token deletion flow, which does send notifications. When an admin revokes all tokens (e.g., due to suspected compromise), the affected user is not notified, delaying their awareness that action was taken on their account. This is particularly important in incident response scenarios. The audit log captures the event, but the user must proactively check to discover the revocation.

### Details
In `atr/storage/writers/tokens.py` at lines 170-186, the `revoke_all_user_tokens()` function does not send email notification to the affected user.

### Recommended Remediation
Add email notification to the affected user in the `revoke_all_user_tokens()` function. Send notification email to `{target_asf_uid}@apache.org` with subject 'ATR - All API Tokens Revoked' informing them that an administrator has revoked all their tokens and to contact ASF security if unexpected. Include the count of revoked tokens. Send after audit log write for proper sequencing.

### Acceptance Criteria
- [ ] Email notification sent to affected user
- [ ] Notification includes token count
- [ ] Audit log written before email
- [ ] Unit tests verify notification logic

### References
- Source reports: L2:10.4.9.md
- Related findings: FINDING-279
- ASVS sections: 10.4.9

### Priority
Low

---

## Issue: FINDING-279 - Web-Issued JWTs Lack PAT Binding and Cannot Be Individually Revoked

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
JWTs issued through the web UI 'Generate JWT' button don't include the `atr_th` (PAT hash) claim. This means they cannot be individually revoked via PAT deletion and remain valid for their full 30-minute TTL even if an admin revokes all of a user's PATs. If an admin revokes all PATs for a user (e.g., due to suspected compromise), web-issued JWTs remain valid for up to 30 minutes. The only way to immediately invalidate them is JWT signing key rotation, which invalidates ALL JWTs for ALL users.

### Details
In `atr/post/tokens.py` at lines 34-41, web-issued JWTs are created without PAT binding. In `atr/jwtoken.py` at lines 116-128, verification checks for PAT binding but web-issued tokens don't have it.

Mitigating controls:
- 30-minute TTL limits exposure window
- LDAP check rejects JWTs for disabled accounts
- Admin can rotate JWT signing key for immediate global invalidation
- JWT generation is rate-limited to 10 requests per hour

### Recommended Remediation
This is an acceptable architectural trade-off given the mitigations. If stronger revocation is needed in the future, consider:

**Option 1** - Bind web-issued JWTs to a PAT by creating an ephemeral PAT for JWT binding in `jwt_post()` and passing its hash to `jwtoken.issue()`.

**Option 2** - Add server-side JWT tracking (blocklist) by storing JWT IDs in Redis/database for revoked tokens and checking the blocklist during verification.

**Short-term:** Add documentation note about the 30-minute window for non-PAT-bound JWTs in `atr/docs/authentication-security.md`.

### Acceptance Criteria
- [ ] Documentation updated with 30-minute revocation window
- [ ] Risk acceptance documented OR stronger revocation implemented
- [ ] Unit tests verify revocation behavior

### References
- Source reports: L2:10.4.9.md
- Related findings: FINDING-278, FINDING-280
- ASVS sections: 10.4.9

### Priority
Low

---

## Issue: FINDING-280 - ATR JWTs Have No Scope Claims — All API Access is Uniform

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
ATR's JWTs contain no `scope` or permission claims. A JWT obtained for any purpose grants identical bearer access to every JWT-protected endpoint (upload releases, delete releases, modify policies, manage keys, etc.). While RBAC in the storage layer enforces authorization per-operation, the token itself carries no scope restriction. This violates the principle that tokens should carry only the required permissions. If a JWT is compromised (e.g., leaked in logs, intercepted, stolen from client storage), the attacker has full API access as that user for the token's lifetime (30 minutes), rather than access limited to the operation the token was intended for.

### Details
In `atr/jwtoken.py`:
- Lines 65-78: JWT issuance does not include scope claims
- Lines 109-133: JWT verification does not check scopes
- Lines 188-207: GitHub OIDC tokens also lack scope claims

In `atr/storage/writers/tokens.py` at lines 95-122, PAT creation does not include scope configuration.

### Recommended Remediation
Add `scopes` parameter to `issue()` function and include scope claim in JWT payload using RFC 8693 format: `payload['scope'] = ' '.join(scopes)`. Validate scopes in `require()` decorator to enforce token-level scope restrictions. Update API endpoints to use scope-restricted decorators like `@jwtoken.require('release:write')`. Design scope claim structure (e.g., `release:read`, `release:write`, `key:manage`, `policy:write`). Example validation: `token_scopes = set(claims.get('scope', '').split())`.

### Acceptance Criteria
- [ ] Scope claims added to JWT payload
- [ ] Scope validation in require() decorator
- [ ] API endpoints use scope-restricted decorators
- [ ] Unit tests verify scope enforcement

### References
- Source reports: L2:10.4.11.md
- Related findings: FINDING-165, FINDING-281, FINDING-279
- ASVS sections: 10.4.11

### Priority
Low

---

## Issue: FINDING-281 - PATs Have No Scope Limitation

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
Personal Access Tokens (180-day validity) have no scope or permission restriction. Any PAT can be exchanged for a JWT that grants full API access. There is no mechanism to create a PAT limited to specific operations (e.g., read-only, upload-only, ci-only). A long-lived credential (180 days) with full permissions increases the blast radius of credential compromise compared to a scope-limited token. If a CI/CD PAT is compromised, the attacker has full API access rather than just upload permissions.

### Details
In `atr/storage/writers/tokens.py`:
- Lines 67-74: PAT creation does not include scopes
- Lines 95-122: JWT issuance from PAT does not propagate scopes

In `atr/storage/readers/tokens.py` at lines 28-40, PAT reading does not include scope information.

### Recommended Remediation
Add `scopes` field to `PersonalAccessToken` model to store space-separated scope list (e.g., 'release:write release:read'). Update `add_token()` to accept optional `scopes` parameter:

```python
async def add_token(self, token_hash: str, created: datetime.datetime, expires: datetime.datetime, label: str | None, scopes: list[str] | None = None)
```

Propagate scopes to JWT in `issue_jwt()` by parsing scopes from PAT and passing to `jwtoken.issue()`. Allow users to specify scopes when creating PATs via UI/API.

### Acceptance Criteria
- [ ] Scopes field added to PAT model
- [ ] PAT creation accepts scope parameter
- [ ] Scopes propagated to issued JWTs
- [ ] UI/API allows scope specification
- [ ] Unit tests verify scope propagation

### References
- Source reports: L2:10.4.11.md
- Related findings: FINDING-165, FINDING-280
- ASVS sections: 10.4.11

### Priority
Low

---

## Issue: FINDING-282 - Session Cookies Signed But Not Encrypted — Documentation Claims Encryption

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
Documentation in `docs/sessions.md` incorrectly states that session cookies are 'encrypted to ensure authenticity', when they are actually only cryptographically signed using `itsdangerous.URLSafeTimedSerializer`. Session contents are base64-encoded and readable to anyone possessing the cookie. While HMAC signing protects integrity and prevents tampering (satisfying ASVS 11.3.3 integrity requirements), session data is not confidential. This documentation mismatch could lead developers to store sensitive data in sessions under false assumptions of confidentiality.

### Details
In `docs/sessions.md` at line 2, the documentation claims encryption. In `src/asfquart/base.py` at lines 118-137 and `src/asfquart/session.py`, the implementation uses signing (not encryption), which provides authentication and integrity but not confidentiality.

### Recommended Remediation
**Option 1 (Recommended):** Update documentation to accurately describe the security model:

```markdown
## Session Security

OAuth user sessions are **cryptographically signed** using HMAC-SHA256 to ensure integrity and authenticity. Session data is transmitted over HTTPS and protected with HttpOnly, Secure, and SameSite=Strict flags to prevent JavaScript access and CSRF attacks.

**Important:** Session contents are base64-encoded but not encrypted. Do not store highly sensitive data (e.g., raw passwords, financial data, PII beyond what's necessary for authentication) in sessions. Only store:
- User identifier (UID)
- Authentication status
- Session metadata (creation time, expiration)
- Non-sensitive user attributes (display name, email for ASF members)
```

**Option 2 (Alternative):** Implement encrypted sessions using Fernet or server-side session storage:
```python
from cryptography.fernet import Fernet
# Use Fernet for encrypted+authenticated sessions
# OR use server-side storage (Redis/database) with only session ID in cookie
```

### Acceptance Criteria
- [ ] Documentation accurately describes session security
- [ ] Developers understand session data is not encrypted
- [ ] Sensitive data guidelines documented
- [ ] Unit tests verify session security properties

### References
- Source reports: L2:11.3.3.md
- Related findings: None
- ASVS sections: 11.3.3

### Priority
Low

---

## Issue: FINDING-283 - Server Does Not Enforce Cipher Suite Preference Order

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The Apache TLS configuration uses `SSLHonorCipherOrder off`, which allows the client to choose the cipher suite from the server's offered list. ASVS 12.1.2 states cipher suites should have 'the strongest cipher suites set as preferred.' With client-side preference, a client could select a 128-bit AES cipher over a 256-bit cipher, or a DHE fallback over ECDHE. However, the practical security impact is minimal because all listed cipher suites provide forward secrecy (meeting L3 requirements), all use AEAD modes (AES-GCM or ChaCha20-Poly1305), no weak or legacy ciphers are present in the suite, and this matches Mozilla's current 'Intermediate' configuration guidance.

### Details
In `tooling-vm-ec2-de.apache.org.yaml` and `atr/docs/tls-security-configuration.md`, the configuration uses `SSLHonorCipherOrder off`. The documentation explicitly justifies this choice for mobile device optimization (ChaCha20 selection). This finding reflects a strict reading of the ASVS requirement rather than a practical security concern.

### Recommended Remediation
If strict ASVS L2 compliance is required, enable server cipher preference with strongest ciphers first:

```apache
SSLHonorCipherOrder on
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256
```

**Note:** Mozilla's current 'Intermediate' configuration (used by millions of sites) also uses `SSLHonorCipherOrder off`. The current configuration represents industry best practice. If you choose to enable server preference, verify mobile client compatibility (ChaCha20 performance). Consider accepting this as a documented exception with business justification: 'Client preference enabled to optimize mobile performance per Mozilla Intermediate profile.'

### Acceptance Criteria
- [ ] Server cipher preference enabled OR risk acceptance documented
- [ ] Mobile client compatibility verified (if enabling server preference)
- [ ] Documentation updated with justification
- [ ] Unit tests verify cipher suite configuration

### References
- Source reports: L2:12.1.2.md
- Related findings: None
- ASVS sections: 12.1.2

### Priority
Low

---

## Issue: FINDING-284 - Missing .dockerignore for Build Context Optimization

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The builder stage uses `COPY . .` (line 23), which sends the entire build context — including `.git` and `.svn` directories — to the Docker daemon and into the builder layer. While the multi-stage selective copy ensures these do not reach the final image, a `.dockerignore` file would provide additional defense-in-depth benefits. This does NOT constitute an ASVS 13.4.1 violation, as the final deployed image does not contain source control metadata. However, larger build contexts slow down builds (especially in CI/CD), builder images if accidentally pushed contain full source history, intermediate layers consume more storage, and the builder stage has unnecessary files that could be leveraged in supply chain attacks.

### Details
In `Dockerfile.alpine` at line 23, `COPY . .` includes all files. No `.dockerignore` file exists to exclude unnecessary files from build context.

### Recommended Remediation
**Option 1: Add .dockerignore (Recommended for most cases)**

Create `.dockerignore` in repository root with exclusions for .git, .svn, Python artifacts, IDE files, etc.

**⚠️ Important:** The current build requires `.git` for `make generate-version`. If `.git` is excluded via `.dockerignore`, version generation will fail.

**Option 2: Pass Version as Build Argument (Recommended for CI/CD)**

Modify Dockerfile.alpine to accept APP_VERSION as build argument:
```dockerfile
ARG APP_VERSION=dev
RUN apk add --no-cache make patch  # git removed
RUN echo "APP_VERSION='${APP_VERSION}'\" > atr/version.py
```

Build command:
```bash
docker build --build-arg APP_VERSION=$(git describe --tags) -t atr .
```

**Option 3: Hybrid Approach**

Use .dockerignore but add exception for version generation using BuildKit mount:
```dockerfile
RUN --mount=type=bind,source=.git,target=/tmp/git \
    git --git-dir=/tmp/git describe --tags > /tmp/version.txt && \
    echo "APP_VERSION='$(cat /tmp/version.txt)'\" > atr/version.py
```

### Acceptance Criteria
- [ ] .dockerignore created OR version passed as build arg
- [ ] Build context size reduced
- [ ] Version generation continues to work
- [ ] Unit tests verify build process

### References
- Source reports: L1:13.4.1.md
- Related findings: None
- ASVS sections: 13.4.1

### Priority
Low

---

## Issue: FINDING-285 - OAuth Authorization Code Sent in URL Query String to Token Endpoint

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The OAuth authorization code is transmitted to the ASF token endpoint via a GET request with the code as a URL query parameter, rather than in an HTTP POST body as recommended by RFC 6749 Section 4.1.3 and OAuth 2.0 Security Best Current Practice (RFC 9700). During the OAuth login flow, after the user authenticates at oauth.apache.org and is redirected back to ATR, the authorization code is received from the OAuth redirect and then placed in the URL query string of a GET request to https://oauth.apache.org/token-oidc?code=AUTHORIZATION_CODE.

### Details
In `atr/server.py` at line 67, `src/asfquart/generics.py` at line 14, and `src/asfquart/generics.py` at line 94, the authorization code is transmitted via GET query parameter.

This means the authorization code (a credential) appears in the URL and will be recorded in access logs on oauth.apache.org, any intermediate proxy/load balancer logs, and network monitoring tools performing TLS inspection.

Multiple mitigating factors reduce the risk:
1. Server-to-server back-channel communication not exposed to browser
2. HTTPS transport security
3. Single-use token with 900s expiration
4. Referrer-Policy headers prevent leakage
5. ATR request logs exclude query strings

### Recommended Remediation
**Option 1 (Recommended if supported):** Switch to POST method for token exchange. Replace GET request with POST request sending the authorization code in the request body using application/x-www-form-urlencoded format with grant_type=authorization_code and code parameter. Contact ASF OAuth service maintainers to confirm POST support.

**Option 2 (If POST not supported):** Document the accepted risk with inline code comments explaining that the OAuth authorization code is sent via GET query parameter due to upstream ASF OAuth endpoint constraint, and note the mitigating factors: server-to-server HTTPS communication, single-use codes with 900s expiration, immediate exchange, and query string exclusion from request logs.

### Acceptance Criteria
- [ ] POST method used for token exchange OR risk acceptance documented
- [ ] Code comments explain implementation choice
- [ ] Unit tests verify token exchange security

### References
- Source reports: L1:14.2.1.md
- Related findings: None
- ASVS sections: 14.2.1

### Priority
Low

---

## Issue: FINDING-286 - JWT DOM Auto-Clear Lacks Page Lifecycle Event Handlers

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The JWT display functionality on `/tokens` implements a 60-second auto-clear timer, which is a good security practice. However, it lacks page lifecycle event handlers that would provide defense-in-depth by clearing the JWT when: user switches tabs (visibilitychange), page enters back-forward cache (pagehide), or user navigates away before timer expires. The JWT cleanup relies solely on the 60-second timer. If the page is stored in the browser's back-forward cache (bfcache), the timer may not fire when the user navigates back, and the JWT could persist in the DOM.

### Details
In `atr/static/ts/create-a-jwt.ts` at lines 28-50, the JWT display only implements a 60-second timer without page lifecycle event handlers.

JWT tokens displayed on /tokens page could persist in DOM if user navigates away before 60-second timer expires, page enters browser's back-forward cache, and user returns via back button.

### Recommended Remediation
Add to `atr/static/ts/create-a-jwt.ts`:
1. `clearJwtDisplay()` function to clear output, outputContainer, and both timeoutObj and intervalObj
2. visibilitychange event listener to call `clearJwtDisplay()` when document.visibilityState becomes 'hidden'
3. pagehide event listener to call `clearJwtDisplay()` when page is being unloaded or cached
4. pageshow event listener to call `clearJwtDisplay()` when page is restored from bfcache (event.persisted === true)

### Acceptance Criteria
- [ ] Page lifecycle event handlers added
- [ ] JWT cleared on tab switch
- [ ] JWT cleared on navigation
- [ ] JWT cleared on bfcache restore
- [ ] Unit tests verify cleanup logic

### References
- Source reports: L1:14.3.1.md
- Related findings: None
- ASVS sections: 14.3.1

### Priority
Low

---

## Issue: FINDING-287 - No `Cache-Control: no-store` on Authenticated Responses

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Authenticated pages are not served with `Cache-Control: no-store`, meaning browsers may cache the full HTML response to disk. Even when `Clear-Site-Data` is sent on logout, the browser could have already persisted pages to disk cache before the logout occurred. `Cache-Control: no-store` provides defense-in-depth by preventing authenticated content from being written to cache in the first place, making the `Clear-Site-Data` header more effective.

### Details
In `atr/server.py` at lines 403-413, the `add_security_headers` function does not add Cache-Control headers for authenticated responses.

This reduces effectiveness of `Clear-Site-Data` implementation, since: browser cache clearing behavior varies across implementations, some browsers may not fully honor `Clear-Site-Data` for disk cache, and authenticated content may be written to disk before logout occurs.

### Recommended Remediation
Modify `add_security_headers` function in `atr/server.py` to add Cache-Control headers for authenticated responses: Check if user is authenticated by reading the session; if authenticated and the request path is not /auth or /static/*, add the following headers:
- `Cache-Control: no-store, no-cache, must-revalidate`
- `Pragma: no-cache` (for HTTP/1.0 compatibility)
- `Expires: 0` (for proxies)

Alternative more aggressive approach: Apply to all non-static content regardless of authentication status.

### Acceptance Criteria
- [ ] Cache-Control headers added for authenticated responses
- [ ] Authenticated content not cached to disk
- [ ] Clear-Site-Data effectiveness improved
- [ ] Unit tests verify header presence

### References
- Source reports: L1:14.3.1.md
- Related findings: FINDING-044, FINDING-045, FINDING-175, FINDING-176, FINDING-177
- ASVS sections: 14.3.1

### Priority
Low

---

## Issue: FINDING-288 - Admin Debug Test Route /admin/raise-error Available in Production

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The /admin/raise-error route is explicitly a test route designed to deliberately trigger error handling for debugging purposes. While it requires admin authentication, it lacks the `_require_debug_and_allow_tests()` check that other debug routes use, making it accessible in production environments. Can be used to probe error handling behavior and verify whether tracebacks are leaked.

### Details
In `atr/admin/__init__.py`, the raise_error function does not call `_require_debug_and_allow_tests()` before deliberately raising an exception.

### Recommended Remediation
Add `_require_debug_and_allow_tests()` call at the beginning of the raise_error function.

### Acceptance Criteria
- [ ] Debug check added to raise_error function
- [ ] Route not accessible in production
- [ ] Unit tests verify debug mode requirement

### References
- Source reports: L2:13.4.2.md, L2:13.4.5.md
- Related findings: FINDING-175, FINDING-290
- ASVS sections: 13.4.2, 13.4.5

### Priority
Low

---

## Issue: FINDING-289 - API Error Responses Leak Internal Error Details

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
When unhandled exceptions occur in API endpoints, the error handlers return str(error) directly to the client. For unexpected exceptions, this can expose internal file paths, SQL fragments, class names, and system state information that aids attackers in understanding the application internals. Tracebacks are suppressed but raw exception messages are still returned.

### Details
In `atr/server.py` and `atr/blueprints/api.py`, error handlers return raw exception messages to clients.

### Recommended Remediation
In `_handle_generic_exception`, log full error details but only return detailed errors when `is_dev_environment()` is True. Return generic 'Internal server error' message in production.

### Acceptance Criteria
- [ ] Detailed errors only in development mode
- [ ] Generic errors in production
- [ ] Full error details logged server-side
- [ ] Unit tests verify error handling

### References
- Source reports: L2:13.4.2.md
- Related findings: FINDING-177, FINDING-178
- ASVS sections: 13.4.2

### Priority
Low

---

## Issue: FINDING-290 - Admin Database Browser Available in Production Without Debug Check

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The /admin/data routes provide a database browser interface that exposes raw database records including SSH keys, task details, and full entity data. While admin authentication is required, this is a development/debugging feature that should be gated by debug mode to prevent production access. Reveals internal data structures and relationships.

### Details
In `atr/admin/__init__.py`, the data and data_model functions do not call `_require_debug_and_allow_tests()`.

### Recommended Remediation
Add `_require_debug_and_allow_tests()` call to both data and data_model functions.

### Acceptance Criteria
- [ ] Debug check added to database browser routes
- [ ] Routes not accessible in production
- [ ] Unit tests verify debug mode requirement

### References
- Source reports: L2:13.4.2.md
- Related findings: FINDING-175, FINDING-288
- ASVS sections: 13.4.2

### Priority
Low

---

## Issue: FINDING-291 - Task Arguments Logged at INFO Level in Production

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
Task arguments are logged at INFO level, which is active in production. These arguments may contain sensitive information such as project keys, version identifiers, user identifiers, and other operational data. If logs are compromised or inadvertently exposed, this information increases the attack surface.

### Details
In `atr/worker.py` at line 193 and line 207, task arguments are logged at INFO level.

### Recommended Remediation
Change `log.info()` to `log.debug()` for task argument logging, or log only non-sensitive fields (task_id, task_type) at INFO level.

### Acceptance Criteria
- [ ] Sensitive task arguments logged at DEBUG level only
- [ ] INFO level logs contain only non-sensitive metadata
- [ ] Unit tests verify logging levels

### References
- Source reports: L2:13.4.2.md
- Related findings: FINDING-292
- ASVS sections: 13.4.2

### Priority
Low

---

## Issue: FINDING-292 - Database Connection URL Logged at Startup

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
During database initialization, the absolute database file path and migrations directory are logged at INFO level. This reveals filesystem layout information that could aid attackers in understanding the deployment structure if logs are exposed.

### Details
In `atr/db/__init__.py` at lines 640-645, Alembic URL and script_location are logged at INFO level.

### Recommended Remediation
Change `log.info()` to `log.debug()` for Alembic URL and script_location logging.

### Acceptance Criteria
- [ ] Database paths logged at DEBUG level only
- [ ] INFO level logs do not reveal filesystem layout
- [ ] Unit tests verify logging levels

### References
- Source reports: L2:13.4.2.md
- Related findings: FINDING-291
- ASVS sections: 13.4.2

### Priority
Low

---

## Issue: FINDING-293 - Pagination Offset Validation Bypassed Due to Typo

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
A typo in the attribute name check ('offest' instead of 'offset') prevents the offset validation from ever executing. This allows users to pass arbitrarily large offset values, potentially causing resource exhaustion or performance degradation. The hasattr check uses wrong attribute name.

### Details
In `atr/api/__init__.py` at lines 1095-1110, the hasattr check uses 'offest' instead of 'offset'.

### Recommended Remediation
Fix typo: change `hasattr(query_args, 'offest')` to `hasattr(query_args, 'offset')`

### Acceptance Criteria
- [ ] Typo fixed in attribute name check
- [ ] Offset validation executes correctly
- [ ] Unit tests verify offset validation
- [ ] Integration test prevents regression

### References
- Source reports: L2:13.4.2.md, L2:14.2.4.md
- Related findings: None
- ASVS sections: 13.4.2, 14.2.4

### Priority
Low

---

## Issue: FINDING-294 - No Explicit Directory Listing Prevention on Docroot

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
Neither vhost configuration includes an explicit `<Directory>` block for the docroot `/x1/dist/` with `Options -Indexes`. If the global Apache configuration does not explicitly set `Options -Indexes` (the Apache default is `Options All` which includes `Indexes`), and if any URL path is not matched by the `ProxyPass` rules or Alias directives, the docroot could expose a directory listing. Current proxy rules cover `/` (proxied to backend) and `/downloads/` (aliased), minimizing practical risk. However, defense-in-depth dictates explicitly disabling indexes on the docroot.

### Details
In `tooling-vm-ec2-de.apache.org.yaml`, no explicit directory block exists for the docroot with Options -Indexes.

### Recommended Remediation
Add an explicit directory block for the docroot:

```yaml
<Directory /x1/dist/>
    Options -Indexes +FollowSymLinks
    Require all denied
</Directory>
```

### Acceptance Criteria
- [ ] Directory block added for docroot
- [ ] Directory listing explicitly disabled
- [ ] Defense-in-depth protection complete
- [ ] Unit tests verify no directory listing

### References
- Source reports: L2:13.4.3.md
- Related findings: None
- ASVS sections: 13.4.3

### Priority
Low

---

## Issue: FINDING-295 - No Application-Level TRACE Method Rejection

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The application has a `before_request` hook that validates Sec-Fetch-Mode and Sec-Fetch-Site for non-GET/HEAD/OPTIONS requests, but it does not explicitly reject the TRACE method. While Quart's routing returns 405 for routes not registered with TRACE, a defense-in-depth approach should explicitly block TRACE at the application level in case the reverse proxy is misconfigured or bypassed. This is a defense-in-depth gap. Low risk since Quart's routing would return 405 for TRACE on registered routes and direct access to Hypercorn ports (4443/8443) is bound to 127.0.0.1, limiting exposure.

### Details
In `atr/server.py` at line 527, the before_request hook does not explicitly reject TRACE method.

### Recommended Remediation
Add an explicit TRACE rejection in the `before_request` hook within `_app_setup_security_headers()` in atr/server.py:

```python
@app.before_request
async def block_trace_method() -> None:
    if quart.request.method == "TRACE":
        raise base.ASFQuartException("TRACE method not allowed", errorcode=405)
```

### Acceptance Criteria
- [ ] TRACE method explicitly rejected at application level
- [ ] Defense-in-depth protection complete
- [ ] Unit tests verify TRACE rejection

### References
- Source reports: L2:13.4.4.md
- Related findings: FINDING-181
- ASVS sections: 13.4.4

### Priority
Low

---

## Issue: FINDING-296 - Principal Authorization Cache Lacks Purge for Inactive Users

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The authorization cache stores committee and project memberships for authenticated users. While entries are refreshed when outdated (600-second TTL), entries for inactive users are never removed, causing unbounded memory growth. While this is committee/project membership metadata (not credentials), ASVS 14.2.2 requires cached data be 'securely purged after use'. If user's committee memberships change or account deactivated, stale data remains until process restart.

### Details
In `atr/principal.py` at lines 172-182, the authorization cache refreshes entries but never removes stale entries for inactive users.

### Recommended Remediation
Add eviction mechanism for stale entries by removing entries not refreshed within 2x TTL. Call periodically from admins_refresh_loop or dedicated background task.

### Acceptance Criteria
- [ ] Eviction mechanism for stale entries implemented
- [ ] Memory growth bounded
- [ ] Inactive user entries removed
- [ ] Unit tests verify eviction logic

### References
- Source reports: L2:14.2.2.md
- Related findings: None
- ASVS sections: 14.2.2

### Priority
Low

---

## Issue: FINDING-297 - In-Memory Log Buffer Retains Query Parameters with Sensitive Data

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
When query logging is enabled, SQL queries are compiled with literal_binds=True, expanding parameter values into the query string. These queries are stored in an in-memory log buffer that may contain token hashes, fingerprints, and user identifiers. Token hashes, fingerprints, user identifiers appear in query strings and are stored in in-memory log buffer (capped at 100 entries, no sensitive-value scrubbing). Exposed via GET /admin/logs when debug+test enabled. Lower severity due to limited exposure, but violates principle of not caching sensitive data.

### Details
In `atr/log.py` at line ~16 and `atr/db/__init__.py` in the Query.log_query() method, queries are logged with literal parameter values.

### Recommended Remediation
**Option 1:** Never use literal_binds for logging - log query structure without parameter values.

**Option 2:** Apply Cache-Control to logs endpoint (covered by global fix).

### Acceptance Criteria
- [ ] Sensitive data not included in logged queries
- [ ] Query structure logged without parameter values
- [ ] Unit tests verify no sensitive data in logs

### References
- Source reports: L2:14.2.2.md
- Related findings: FINDING-046
- ASVS sections: 14.2.2

### Priority
Low

---

## Issue: FINDING-298 - Session Cache File Written Without Restrictive Permissions

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The session cache file containing user authorization data is written without explicit restrictive permissions, inheriting default umask (typically 0o644, world-readable). user_session_cache.json containing all users' cached session data (roles, admin status, committee memberships) may be readable by other processes/users on same system. The atomic_write_file() function does not call os.chmod() - file inherits umask permissions.

### Details
In `atr/util.py`, the atomic_write_file() function does not set restrictive permissions on written files.

### Recommended Remediation
Set restrictive permissions (0o600) after write in session_cache_write() or enhance atomic_write_file() with mode parameter.

### Acceptance Criteria
- [ ] Session cache file written with 0o600 permissions
- [ ] Only application user can read cache file
- [ ] Unit tests verify file permissions

### References
- Source reports: L2:14.2.2.md
- Related findings: FINDING-185
- ASVS sections: 14.2.2

### Priority
Low

---

## Issue: FINDING-299 - JWT Claims Including User Identity Logged at DEBUG Level

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
JWT claims including user identity (sub), JWT ID (jti), timestamps (iat, exp), and potentially PAT hash (atr_th) are logged in their entirety at DEBUG level. At DEBUG level, this is less likely to be enabled in production, but DEBUG logging is commonly enabled during troubleshooting. User identity and token identifiers enter the log stream, and if logs are forwarded to external aggregation services, this data leaves application control. PAT hash (atr_th) could potentially be used to correlate token usage across systems.

### Details
In `atr/jwtoken.py` at line 116, full JWT claims are logged at DEBUG level.

### Recommended Remediation
Replace full claims dump with selective logging. Log only essential information for debugging:

```python
log.debug("JWT verified successfully",
    subject=claims.get("sub"),
    jti=claims.get("jti")[:8] + "..." if claims.get("jti") else None,
    expires_in=claims.get("exp") - int(time.time()) if claims.get("exp") else None
)
```

Truncate sensitive identifiers and avoid logging the full claims dictionary.

### Acceptance Criteria
- [ ] Full claims dictionary not logged
- [ ] Only essential information logged
- [ ] Sensitive identifiers truncated
- [ ] Unit tests verify logging content

### References
- Source reports: L2:14.2.3.md, L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.3, 14.2.4

### Priority
Low

---

## Issue: FINDING-300 - User Identity Data Sent to External GitHub API

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2

**Description:**

### Summary
The asf_uid (Apache Software Foundation user identifier) is transmitted to GitHub's API as a workflow input parameter for GitHub Actions workflow dispatch events. Once transmitted, the ASF UID is stored on GitHub/Microsoft infrastructure, subject to GitHub's data retention policies (not Apache's), visible to anyone with read access to the apache/tooling-actions repository, potentially logged in GitHub's internal systems, and subject to GitHub's privacy policy and terms of service. This represents data leaving Apache's direct control and entering third-party infrastructure.

### Details
In `atr/tasks/gha.py` at lines 119-155, the asf_uid is sent to GitHub API as a workflow input parameter.

Mitigating factors include: ASF UIDs are already semi-public information visible in commits and mailing lists; apache/tooling-actions is an Apache-controlled repository; GitHub has a formal organizational relationship with ASF; user identity is required for audit traceability of release actions; only ASF committers can trigger workflows; and no additional PII is sent.

### Recommended Remediation
Two options:

**Option 1: Pseudonymization** - Create a pseudonymous dispatch reference using hash of asf_uid:unique_id:workflow, store mapping internally for audit purposes, and send only the pseudonymous reference to GitHub.

**Option 2: Risk Acceptance with Documentation** - Document this as an accepted data sharing arrangement in a Data Privacy Impact Assessment (DPIA), noting that ASF UID is semi-public, GitHub has organizational relationship with ASF, required for audit logs, and limited to authenticated committers.

Option 2 (risk acceptance) is recommended given the mitigating factors and legitimate audit requirements.

### Acceptance Criteria
- [ ] Risk acceptance documented in DPIA OR pseudonymization implemented
- [ ] Data sharing arrangement documented
- [ ] Audit requirements satisfied
- [ ] Unit tests verify implementation

### References
- Source reports: L2:14.2.3.md
- Related findings: None
- ASVS sections: 14.2.3

### Priority
Low

---

## Issue: FINDING-301 - JWT TTL Documentation Mismatch

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The authentication security documentation incorrectly states that JWT TTL is 90 minutes, while the actual implementation in `atr/jwtoken.py` uses 30 minutes (`_ATR_JWT_TTL = 30 * 60`). This documentation mismatch causes operational confusion as users may expect longer session duration than actually provided, potentially leading to unexpected authentication failures and support overhead.

### Details
The JWT time-to-live constant is set to 30 minutes in the implementation:
- **File:** `atr/jwtoken.py` - defines `_ATR_JWT_TTL = 30 * 60`
- **File:** `atr/docs/authentication-security.md` - incorrectly documents 90 minutes

This discrepancy between documented and actual behavior violates configuration management best practices and can lead to user confusion when sessions expire earlier than documented.

### Recommended Remediation
Update the documentation in `authentication-security.md` to reflect the actual implementation:

```markdown
- **JWT TTL:** 30 minutes (short-lived, refresh via re-authentication)
```

Alternatively, if 90 minutes is the intended behavior, update the code constant to match the documentation.

### Acceptance Criteria
- [ ] Documentation in `authentication-security.md` accurately reflects the JWT TTL value in code
- [ ] Verify no other documentation references the incorrect 90-minute value
- [ ] Add a comment in `jwtoken.py` referencing the documentation location

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Low

---

## Issue: FINDING-302 - Expired Personal Access Tokens Not Automatically Purged

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Expired Personal Access Tokens (PATs) are properly rejected during authentication but are never deleted from the database. This causes unbounded database growth as expired credentials accumulate indefinitely, wasting storage and potentially exposing expired credentials longer than necessary.

### Details
The token authentication mechanism in `atr/storage/writers/tokens.py` validates token expiration at authentication time but lacks a cleanup mechanism for expired tokens. Over time, this will result in:
- Unbounded growth of the tokens table
- Unnecessary storage costs
- Increased backup sizes
- Potential compliance issues with data retention policies
- Longer query times as the table grows

### Recommended Remediation
Implement a recurring cleanup task that purges expired tokens older than a retention period (e.g., 30 days):

```python
def purge_expired_tokens(retention_days=30):
    """Remove expired tokens older than retention_days."""
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    # DELETE FROM tokens WHERE expires_at < cutoff AND expires_at < NOW()
```

Schedule this task to run daily via cron, Celery beat, or similar scheduling mechanism.

### Acceptance Criteria
- [ ] Implement automated cleanup task that deletes expired tokens older than 30 days
- [ ] Schedule cleanup task to run at least daily
- [ ] Add logging for cleanup operations (number of tokens purged)
- [ ] Document the cleanup policy in the security documentation
- [ ] Unit test verifying the cleanup logic correctly identifies and removes only expired tokens

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Low

---

## Issue: FINDING-303 - Debug print() Bypasses Structured Logging

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The file `atr/sbom/osv.py` at line 110 uses `print(vulns)` for debug output, bypassing the application's structured logging framework. This produces unstructured output that cannot be filtered, routed, or managed through the logging configuration, reducing log manageability and potentially exposing information through uncontrolled output channels.

### Details
The use of `print()` statements in production code:
- Bypasses logging level controls (cannot be disabled in production)
- Outputs to stdout instead of configured log handlers
- Produces unstructured text instead of structured log entries
- Cannot be filtered or routed by logging infrastructure
- May expose information in contexts where stdout is captured differently than logs

**Affected file:** `atr/sbom/osv.py`, line 110

This inconsistency with the application's structured logging approach reduces operational visibility and control.

### Recommended Remediation
Replace the `print()` statement with structured logging:

```python
log.debug("Loaded vulnerabilities from bundle", count=len(vulns))
```

If detailed vulnerability information is needed for debugging, use:

```python
log.debug("Loaded vulnerabilities from bundle", count=len(vulns), vulns=vulns)
```

### Acceptance Criteria
- [ ] Replace `print(vulns)` with structured logging call
- [ ] Verify log output includes vulnerability count
- [ ] Confirm logging respects configured log levels
- [ ] Search codebase for other `print()` statements and remediate
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Low

---

## Issue: FINDING-304 - Environment Variables Logged in Exception Handler

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The GitHub clone failure exception handler in `atr/tasks/checks/compare.py` (lines 159-170) logs seven environment variables including potentially sensitive configuration values. This causes unnecessary exposure of environment configuration in error logs, which may be collected by log aggregation systems, stored in less-secure locations, or accessible to personnel who should not see configuration details.

### Details
When a GitHub clone operation fails, the exception handler logs the full values of environment variables such as:
- `GIT_AUTHOR_NAME`
- `GIT_AUTHOR_EMAIL`
- `GIT_COMMITTER_NAME`
- `GIT_COMMITTER_EMAIL`
- And potentially others related to Git configuration

While these specific variables may not be highly sensitive, logging full environment variable values establishes a pattern that could lead to accidentally logging secrets if the code is copied or modified. Additionally, email addresses and configuration details may have privacy implications.

**Affected file:** `atr/tasks/checks/compare.py`, lines 159-170

### Recommended Remediation
Log only presence indicators instead of actual values:

```python
log.exception(
    "Failed to clone GitHub repo",
    repo_url=repo_url,
    git_identity_configured=bool(os.environ.get("GIT_AUTHOR_NAME")),
    git_email_configured=bool(os.environ.get("GIT_AUTHOR_EMAIL")),
)
```

This provides sufficient debugging information (whether configuration exists) without exposing the actual values in logs.

### Acceptance Criteria
- [ ] Modify exception handler to log presence indicators instead of values
- [ ] Verify logs still provide sufficient debugging information
- [ ] Review other exception handlers for similar patterns
- [ ] Document logging best practices for environment variables
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Low

---

## Issue: FINDING-305 - Client-Side JWT Display TypeScript Not Available for Complete Audit

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `/tokens` page loads a TypeScript module named 'create-a-jwt' that handles JWT generation and display, but the TypeScript source was not included in the audit scope. Without this code, it cannot be verified whether the JWT is improperly stored in browser storage (localStorage, sessionStorage, or IndexedDB), which would violate ASVS 14.3.3 since JWTs are bearer credentials. This represents an audit coverage gap rather than a confirmed vulnerability.

### Details
The tokens page (`atr/get/tokens.py`, lines 55-80) implements a JWT display workflow:
1. User requests JWT generation via AJAX
2. TypeScript module 'create-a-jwt' handles the request
3. JWT is displayed in DOM element `#jwt-output`
4. A countdown timer manages the display period

**Unverifiable security properties:**
- Whether JWT is stored in localStorage, sessionStorage, or IndexedDB during display
- Whether JWT is reliably cleared from DOM and memory after countdown
- Whether AJAX response is cached in browser storage
- Whether JWT is properly cleaned up on page navigation
- Whether the countdown timer reliably clears the JWT after 30 minutes

If the TypeScript stores the JWT in browser storage, it would violate ASVS 14.3.3 requirements for bearer credential handling.

**Affected file:** `atr/get/tokens.py`, lines 55-80

### Recommended Remediation
1. **Include TypeScript in audit scope:** Add the 'create-a-jwt' TypeScript module to the repository and audit to verify:
   - No JWT storage in localStorage/sessionStorage/IndexedDB
   - JWT is only held in DOM/memory
   - Proper cleanup on page navigation

2. **Implement explicit cleanup handlers:**
```typescript
window.addEventListener('beforeunload', () => {
    // Clear JWT from DOM
    document.getElementById('jwt-output').textContent = '';
    // Clear any in-memory references
});
```

3. **Consider memory-only approaches:** Use Blob URLs that can be explicitly revoked, or keep JWT only in JavaScript closure scope

4. **Verify countdown timer:** Ensure the 30-minute countdown reliably clears the JWT and cannot be bypassed

### Acceptance Criteria
- [ ] TypeScript source code 'create-a-jwt' is added to repository
- [ ] Code review confirms no browser storage usage for JWT
- [ ] Explicit cleanup handlers are implemented for page navigation
- [ ] Countdown timer behavior is verified and tested
- [ ] Browser developer tools testing confirms no JWT persistence
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.3.3.md
- Related findings: FINDING-192
- ASVS sections: 14.3.3

### Priority
Low

---

## Issue: FINDING-306 - General Library Update Timeframe Is Enforced but Undocumented as Policy

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The application enforces a 30-day maximum dependency age through code (`_MAX_AGE_DAYS=30` in `scripts/check_when_dependencies_updated.py`) with pre-commit enforcement, but this policy is not documented in application documentation as required by ASVS 15.1.1. New team members must read code to understand the policy, and the pre-commit hook incorrectly references 'ASVS 15.2.1' instead of '15.1.1'. There is no documented rationale for the 30-day value.

### Details
**Current enforcement mechanism:**
- Script reads `exclude-newer` timestamp from `uv.lock`
- Fails build if dependencies exceed 30 days old
- Verified on every commit via pre-commit hook

**Issues identified:**
1. Policy exists only in code (`scripts/check_when_dependencies_updated.py`, lines 30-31)
2. No documented rationale for 30-day value
3. Pre-commit hook description references wrong ASVS section (`.pre-commit-config.yaml`, lines 148-153)
4. No centralized policy document for team reference

ASVS 15.1.1 requires dependency management policies to be defined in application documentation, not just enforced in code.

**Affected files:**
- `scripts/check_when_dependencies_updated.py`, lines 30-31
- `.pre-commit-config.yaml`, lines 148-153

### Recommended Remediation
1. **Create policy documentation:** Add documented reference in `SECURITY.md` or `docs/dependency-remediation-policy.md`:

```markdown
## Dependency Update Policy

### General Library Updates (ASVS 15.1.1)
- **Maximum age:** 30 days
- **Rationale:** Balance between stability and security freshness
- **Enforcement:** Automated pre-commit hook checks `exclude-newer` timestamp
- **Verification:** Every commit triggers dependency age validation
```

2. **Fix ASVS reference:** Correct `.pre-commit-config.yaml` line 150 from 'ASVS 15.2.1' to 'ASVS 15.1.1'

3. **Add code comments:** Reference policy document in `scripts/check_when_dependencies_updated.py`:
```python
# Enforces 30-day maximum dependency age per dependency-remediation-policy.md
_MAX_AGE_DAYS = 30
```

**Estimated effort:** ~1 hour

### Acceptance Criteria
- [ ] Policy document created in `SECURITY.md` or `docs/dependency-remediation-policy.md`
- [ ] Document explains 30-day value and rationale
- [ ] Document describes enforcement mechanism
- [ ] ASVS reference corrected in `.pre-commit-config.yaml`
- [ ] Code comments added referencing policy document
- [ ] Unit test verifying the fix

### References
- Source reports: L1:15.1.1.md
- Related findings: FINDING-198
- ASVS sections: 15.1.1

### Priority
Low

---

## Issue: FINDING-307 - Dependabot Cooldown May Delay Critical Vulnerability Patches

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Dependabot applies a uniform 7-day cooldown period regardless of vulnerability severity, with updates running only weekly on Monday. If a critical RCE vulnerability is disclosed in a dependency (e.g., cryptography) on Tuesday, Dependabot will wait until the following Monday (6 days), then potentially wait another 7 days if cooldown is active, creating a potential exposure window of up to 14 days for critical vulnerabilities. There is no documented override process for bypassing the cooldown in emergency situations.

### Details
**Current Dependabot configuration:**
- Updates run weekly on Monday
- 7-day cooldown after any update
- No differentiation for vulnerability severity
- No documented emergency override process

**Worst-case scenario:**
1. Critical vulnerability (CVSS ≥9.0) disclosed Tuesday after weekly run
2. Wait until following Monday: 6 days
3. If cooldown active from previous update: additional 7 days
4. **Total potential exposure:** up to 14 days

This delay violates the spirit of ASVS 15.1.1, which requires timely remediation of known vulnerabilities.

**Affected file:** `.github/dependabot.yml`, lines 8-15

### Recommended Remediation
1. **Document emergency override process** for critical vulnerabilities (CVSS ≥9.0):
   - Immediate assessment within 4 hours of disclosure
   - Manual PR creation bypassing Dependabot
   - Expedited testing protocol
   - Deployment within 48 hours

2. **Add to remediation policy document:**
```markdown
## Critical Vulnerability Override Process
- **Trigger:** CVSS ≥9.0 in production dependency
- **Assessment:** Within 4 hours
- **Response:** Manual PR bypassing Dependabot cooldown
- **Testing:** Expedited test suite (core functionality only)
- **Deployment:** Within 48 hours of disclosure
```

3. **Optional enhancements:**
   - Add second Dependabot configuration for security-only updates with no cooldown (requires GitHub Advanced Security)
   - Implement automated critical CVE monitoring GitHub Action (runs every 6 hours, creates emergency issues)

**Estimated effort:** 1-5 hours depending on optional enhancements

### Acceptance Criteria
- [ ] Emergency override process documented in remediation policy
- [ ] Process includes specific timelines (4-hour assessment, 48-hour deployment)
- [ ] Manual PR creation procedure documented
- [ ] Team trained on override process
- [ ] Optional: Automated CVE monitoring implemented
- [ ] Unit test verifying the fix

### References
- Source reports: L1:15.1.1.md
- Related findings: FINDING-198
- ASVS sections: 15.1.1

### Priority
Low

---

## Issue: FINDING-308 - Pre-Release (Release Candidate) Dependency Used in Production

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The application uses a release candidate version (ldap3==2.10.2rc3) in production without documented justification or special monitoring procedures. Release candidate versions have uncertain security patch processes and may not receive updates through standard channels, making the 30-day freshness policy less meaningful. If a vulnerability is discovered, the fix may be released in stable 2.9.x branch but not backported to 2.10.x RC branch, creating unclear upgrade paths.

### Details
**Current situation:**
- Production dependency: `ldap3==2.10.2rc3` (release candidate)
- Latest stable release: `ldap3==2.9.1`
- No documented justification for using RC version
- No special monitoring procedures for RC dependencies

**Security concerns:**
1. RC versions may not receive security patches through standard channels
2. Vulnerability fixes might be released only in stable branches
3. Unclear upgrade path if security issue found in RC version
4. 30-day freshness policy less meaningful for RC versions (no regular releases)
5. No established process for monitoring RC security status

**Affected file:** `pip-audit.requirements`, line 148

### Recommended Remediation
**Option A — Use stable version (preferred):**
1. Test application functionality with `ldap3==2.9.1`
2. If no regressions, prefer stable over RC
3. Update `pip-audit.requirements` to use stable version

**Option B — Document justification and establish monitoring:**
1. Create `DEPENDENCIES.md` with section for Pre-Release Dependencies:
```markdown
## Pre-Release Dependencies

### ldap3==2.10.2rc3
- **Reason:** [Document specific feature or bug fix required]
- **Stable alternative tested:** 2.9.1 [results]
- **Monitoring:** Weekly manual checks of releases
- **Security advisories:** Subscribed to ldap3 security notifications
- **Upgrade target:** Migrate to stable 2.10.x within 7 days of release
```

2. Establish explicit monitoring procedures:
   - Weekly manual checks of ldap3 releases
   - Subscribe to security advisories
   - Document remediation timeline

**Option C — Automated RC version monitoring:**
Implement `scripts/check_prerelease_deps.py`:
```python
def check_prerelease_versions():
    """Detect pre-release versions and validate documentation exists."""
    # Parse requirements for RC/alpha/beta versions
    # Verify DEPENDENCIES.md documents each pre-release
    # Fail if undocumented pre-release found
```

### Acceptance Criteria
- [ ] Either migrate to stable ldap3==2.9.1, or document justification for RC version
- [ ] If keeping RC: Create DEPENDENCIES.md with pre-release policy
- [ ] If keeping RC: Establish monitoring procedures
- [ ] If keeping RC: Subscribe to ldap3 security advisories
- [ ] Optional: Implement automated pre-release detection script
- [ ] Unit test verifying the fix

### References
- Source reports: L1:15.2.1.md
- Related findings: None
- ASVS sections: 15.2.1

### Priority
Low