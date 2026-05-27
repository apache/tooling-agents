# Security Issues

---
## Issue: FINDING-001 - Cross-Site WebSocket Hijacking (CSWSH) - Missing Origin Validation on WebSocket Upgrade
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The WebSocket server authenticates connections using JWT cookies but does not validate the `Origin` or `Sec-Fetch-*` headers during the upgrade handshake. This allows an attacker-controlled web page to establish an authenticated WebSocket connection using the victim's automatically sent cookies, leading to unauthorized access to sensitive data streams.

### Details
- **CWE:** CWE-346 (Origin Validation Error)
- **ASVS Sections:** 3.5.1, 3.5.3 (Level 1)
- **Affected File:** `superset-websocket/src/index.ts`

The `httpUpgrade` handler authenticates WebSocket connections via JWT cookies without verifying the request origin. When a victim visits a malicious website while authenticated to Superset, the attacker's page can initiate a WebSocket connection that includes the victim's cookies (if SameSite attribute permits). This enables the attacker to receive real-time async query result events intended for the victim on their channel.

### Remediation
1. Add Origin header validation in the `httpUpgrade` handler to reject cross-origin WebSocket connections
2. Alternatively, validate `Sec-Fetch-Site` header to ensure requests originate from same-origin
3. Implement a configurable `allowedOrigins` list to specify trusted origins
4. Ensure JWT cookies have appropriate SameSite attribute (`Strict` or `Lax`) as defense-in-depth

### Acceptance Criteria
- [ ] Origin header validation implemented in WebSocket upgrade handler
- [ ] Cross-origin WebSocket connection attempts are rejected
- [ ] Configurable allowedOrigins list added to server configuration
- [ ] Test added for cross-origin WebSocket connection rejection
- [ ] JWT cookie SameSite attribute verified

### References
- Source Reports: 3.5.1.md, 3.5.3.md
- [OWASP: Cross-Site WebSocket Hijacking](https://owasp.org/www-community/attacks/Cross-Site_WebSocket_Hijacking)

### Priority
Medium

---
## Issue: FINDING-002 - Missing format validation for last_id query parameter
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `last_id` query parameter is not validated against the expected Redis stream ID format (`\d+-\d+`). Malformed inputs are processed without validation, potentially leading to unexpected behavior.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS Sections:** 2.2.1 (Level 1)
- **Affected File:** `superset-websocket/src/index.ts`

When malformed inputs like `last_id=abc-xyz` are provided, they produce `abc-NaN` after `incrementId` processing. While Redis handles these gracefully and users can only query their own channel's stream, no positive validation enforces the expected format. This violates input validation best practices.

### Remediation
Add regex validation (`/^\d{1,15}-\d{1,10}$/`) to `getLastId` function before processing, returning null for invalid formats.

Example:
```typescript
function getLastId(lastId: string | undefined): string | null {
  if (!lastId) return null;
  if (!/^\d{1,15}-\d{1,10}$/.test(lastId)) return null;
  return incrementId(lastId);
}
```

### Acceptance Criteria
- [ ] Regex validation added to `getLastId` function
- [ ] Invalid formats return null instead of being processed
- [ ] Test added for valid Redis stream ID formats
- [ ] Test added for rejection of malformed inputs

### References
- Source Report: 2.2.1.md
- [Redis Streams ID Format](https://redis.io/docs/data-types/streams/)

### Priority
Low

---
## Issue: FINDING-003 - No JWT expiration enforcement allows indefinite token validity
**Labels:** bug, security, priority:low
**Description:**
### Summary
JWT verification in `readChannelId()` does not use the `maxAge` option, allowing tokens to remain valid indefinitely regardless of age. This enables prolonged unauthorized access if a JWT token is leaked or stolen.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS Sections:** 7.2.2 (Level 1)
- **Affected File:** `superset-websocket/src/index.ts`
- **Related Findings:** FINDING-004

A leaked or stolen JWT token can be used to establish WebSocket connections and access event streams indefinitely. While this requires prior token compromise, the lack of token expiration enforcement violates session management best practices and extends the window of opportunity for attackers.

**Impact:** Indefinite WebSocket access to event stream for the channel embedded in the JWT.

### Remediation
Add `maxAge` option to `jwt.verify()` call to enforce maximum token lifetime:

```typescript
jwt.verify(token, secret, { 
  maxAge: opts.jwtMaxAge || '1h',
  algorithms: ['HS256']
})
```

Make `jwtMaxAge` configurable via server options with a reasonable default (e.g., 1 hour).

### Acceptance Criteria
- [ ] `maxAge` option added to JWT verification
- [ ] Configurable `jwtMaxAge` option added to server configuration
- [ ] Expired tokens are rejected during WebSocket upgrade
- [ ] Test added for expired token rejection
- [ ] Documentation updated with recommended token lifetime

### References
- Source Report: 7.2.2.md
- Related: FINDING-004 (session invalidation)

### Priority
Low

---
## Issue: FINDING-004 - No mechanism to invalidate or rotate WebSocket sessions on JWT compromise
**Labels:** bug, security, priority:low
**Description:**
### Summary
Once a WebSocket connection is established, it remains active regardless of whether the original JWT or the user's session in the main application has been revoked. This defense-in-depth gap allows compromised connections to persist until manually closed.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS Sections:** 7.2.4, 7.4.1, 7.4.2 (Level 1)
- **Affected File:** `superset-websocket/src/index.ts`
- **Related Findings:** FINDING-003

WebSocket connections are inherently persistent. When a user's account is disabled, deleted, or their session is revoked in the main Superset application, active WebSocket connections remain open. While the data accessible through this channel (async query status events) has limited sensitivity, this represents a defense-in-depth gap.

**Exploitation requires:** Prior token compromise or account takeover.

### Remediation
1. Add user ID tracking to `SocketInstance` interface
2. Implement a Redis pub/sub subscription for account lifecycle events:
   - `user:disabled`
   - `user:deleted`
   - `user:session_revoked`
3. Terminate all associated WebSocket connections upon receiving such events
4. Consider implementing periodic re-authentication for long-lived connections

### Acceptance Criteria
- [ ] User ID extracted from JWT and tracked in SocketInstance
- [ ] Redis pub/sub subscription implemented for user lifecycle events
- [ ] WebSocket connections terminated when user account is disabled/deleted
- [ ] Test added for connection termination on account lifecycle events
- [ ] Documentation added for account lifecycle event integration

### References
- Source Reports: 7.2.4.md, 7.4.1.md, 7.4.2.md
- Related: FINDING-003 (JWT expiration)
- Merged from: ASVS-724-LOW-001, CH07-3, CH07-4

### Priority
Low