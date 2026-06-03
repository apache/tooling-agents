# Security Issues

*12 actionable finding(s). 1 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

---
## Issue: FINDING-001 - Token type / purpose validation missing in websocket JWT verification
**Labels:** bug, security, priority:medium
**Description:**

### Summary
The WebSocket JWT verification logic does not validate the token's intended purpose or type, allowing tokens issued for other purposes (e.g., session, CSRF, guest/embedding) to be accepted as WebSocket authentication credentials if they contain the required `channel` claim.

### Details
**Location:** `superset-websocket/src/index.ts`, function `readChannelId`, lines 255–269

**Data Flow:**
1. `session`/`async-token` cookie → `jwt.verify()` (signature + expiration only)
2. `channel` claim extracted and used to scope Redis subscription
3. No validation of token type/purpose claim (e.g., `type`, `typ`, `use`, `scope`)

**Attacker Capability Required:**
An authenticated actor who can obtain any JWT minted by the Flask backend under the same shared secret for a different purpose, where the token contains (or can be made to contain) a value under the configured `channel` key.

**Impact:**
Token-cross-usage / authentication-purpose-confusion bypass. Tokens issued for other purposes are accepted as WebSocket authentication credentials, allowing the holder to open a streaming connection scoped to whatever `channel` value the token carries.

**CWE:** CWE-345 - Insufficient Verification of Data Authenticity  
**ASVS:** 9.2.2 (Level 2)

### Remediation
1. Require and validate an explicit purpose/type claim that the issuer sets exclusively for WebSocket auth tokens
2. Pass `audience` parameter to `jwt.verify()` 
3. Reject any token where `jwtPayload['type'] !== 'ws_async'` (or equivalent)
4. Coordinate with the Flask issuer to stamp a dedicated `type`/`use` claim and audience so other token types signed with the same secret are not interchangeable

### Acceptance Criteria
- [ ] Token type/purpose claim validation implemented in `readChannelId`
- [ ] Flask backend updated to include dedicated `type` claim for WebSocket tokens
- [ ] Test added verifying rejection of tokens with incorrect/missing type claim
- [ ] Test added verifying acceptance only of properly-typed WebSocket tokens
- [ ] Documentation updated with token type requirements

### References
- Related: FINDING-002 (Audience validation)
- ASVS 9.2.2

### Priority
**Medium** - Authenticated cross-feature bypass; impact bounded to opening streams for channels already encoded in attacker-controlled tokens

---
## Issue: FINDING-002 - Audience (aud) validation not enforced in websocket JWT verification
**Labels:** bug, security, priority:medium
**Description:**

### Summary
The WebSocket JWT verification does not validate the `aud` (audience) claim, allowing tokens minted for other services/audiences to be accepted as valid WebSocket credentials if they share the same signing secret.

### Details
**Location:** `superset-websocket/src/index.ts`, function `readChannelId`, lines 260–263

**Data Flow:**
1. Cookie JWT → `jwt.verify()` invoked without `audience` option
2. Claims trusted without audience validation
3. No check of `aud` claim against service-specific allowlist

**Attacker Capability Required:**
An authenticated actor holding any JWT validly signed with the shared `jwtSecret` but intended for a different audience/service that shares (or could share) this secret.

**Impact:**
The sidecar accepts tokens minted for other services as valid WebSocket credentials, defeating audience-restriction controls. Combined with missing type validation (FINDING-001), this widens the set of acceptable tokens beyond those issued specifically for the sidecar.

**CWE:** CWE-346 - Origin Validation Error  
**ASVS:** 9.2.3 (Level 2)

### Remediation
1. Add an audience claim on the Flask issuer for WebSocket-specific tokens
2. Enforce audience validation by passing `audience: opts.jwtAudience` to `jwt.verify()`
3. Expose `jwtAudience` as a configuration option in `config.ts` with environment variable override
4. Configure Flask to set matching `aud` claim when issuing sidecar tokens
5. Document the audience configuration requirement in deployment guides

### Acceptance Criteria
- [ ] `jwtAudience` configuration option added to `config.ts`
- [ ] Audience validation enforced in `jwt.verify()` call
- [ ] Flask backend updated to include audience claim in WebSocket tokens
- [ ] Test added verifying rejection of tokens with incorrect/missing audience
- [ ] Test added verifying acceptance of tokens with correct audience
- [ ] Configuration documentation updated

### References
- Related: FINDING-001 (Token type validation)
- ASVS 9.2.3

### Priority
**Medium** - Authenticated cross-service token reuse; impact bounded by channel value in token

---
## Issue: FINDING-003 - JWT signing secret accepted with no minimum-strength validation; empty default and weak placeholder example enable authentication bypass
**Labels:** bug, security, priority:medium
**Description:**

### Summary
The JWT signing secret (`jwtSecret`) has no validation for minimum strength, defaults to an empty string, and ships with a weak placeholder example ('CHANGE-ME'), creating a silent fail-open authentication bypass vulnerability.

### Details
**Location:** `superset-websocket/src/config.ts` (buildConfig function), `superset-websocket/config.example.json`

**Data Flow:**
1. Missing/blank `JWT_SECRET` env var + absent/placeholder config file
2. `_merge` keeps `''` or `'CHANGE-ME'` (zero to ~72 bits entropy)
3. `config.jwtSecret` consumed unchecked by JWT verifier
4. Forgeable HMAC with HS256 → authentication bypass at WebSocket layer
5. Cross-user access to streamed async query results

**Attacker Capability Required:**
Remote unauthenticated attacker who can reach the WebSocket upgrade endpoint on a deployment using the default/example configuration.

**Impact:**
Complete authentication bypass. Attackers can forge valid JWTs and open authenticated channels to access any user's query results. The application starts normally with weak values, creating a silent fail-open condition.

**CWE:** CWE-326 - Inadequate Encryption Strength  
**ASVS:** 11.2.1, 11.2.3, 11.5.1 (Level 2)

### Remediation
1. Add fail-closed validation in `buildConfig()` that:
   - Rejects empty `jwtSecret`
   - Enforces minimum length of 32 bytes (256 bits)
   - Denylists known placeholders like 'CHANGE-ME'
   - Refuses to start the application if validation fails
2. Replace 'CHANGE-ME' placeholder in `config.example.json` with instructions to generate high-entropy secret using CSPRNG (e.g., `openssl rand -base64 48`)
3. Require injection via `JWT_SECRET` environment variable
4. Document secret generation and rotation procedures in deployment guidance
5. Ensure synchronization between Flask issuer and sidecar verifier

### Acceptance Criteria
- [ ] Secret validation implemented with minimum 256-bit requirement
- [ ] Application fails to start with empty/weak secrets
- [ ] Placeholder denylist implemented
- [ ] Example configuration updated with generation instructions
- [ ] Test added verifying rejection of empty secret
- [ ] Test added verifying rejection of weak/placeholder secrets
- [ ] Test added verifying acceptance of strong secrets
- [ ] Deployment documentation updated with secret management procedures

### References
- Related: FINDING-004 (Service configuration secrets)
- ASVS 11.2.1, 11.2.3, 11.5.1

### Priority
**Medium** - Critical authentication bypass, but requires deployment with default/example configuration

---
## Issue: FINDING-004 - WebSocket sidecar accepts empty/placeholder jwtSecret with no fail-closed validation
**Labels:** bug, security, priority:medium
**Description:**

### Summary
The critical JWT signing secret that establishes trust between Flask backend and WebSocket sidecar defaults to an empty string with no validation, representing both a failure to enforce secret rotation requirements and a default credential vulnerability.

### Details
**Location:** `superset-websocket/src/config.ts`, `superset-websocket/config.example.json`

**Configuration Issues:**
- `jwtSecret` defaults to `''` (empty string)
- Example configuration ships with `'CHANGE-ME'` placeholder
- `buildConfig()` performs no validation of secret strength, length, or entropy
- No documentation of secret rotation requirements

**Attacker Capability Required:**
Remote unauthenticated attacker who can reach the sidecar on a deployment using default/example credentials.

**Impact:**
With an empty or known signing key, attackers can forge valid HS256 JWTs and open authenticated channels, yielding cross-user query-result access. This represents an undocumented fail-open default that violates secure configuration principles.

**CWE:** CWE-798 - Use of Hard-coded Credentials  
**ASVS:** 13.1.4, 13.2.3 (Level 2, Level 3)

### Remediation
1. Add fail-closed validation in `buildConfig()` that rejects:
   - Empty secrets
   - Placeholder values (e.g., 'CHANGE-ME')
   - Under-length secrets (< 256 bits)
2. Prevent service from accepting connections before validation passes
3. Document all critical secrets in deployment guide
4. Establish and document deployment-managed rotation schedule
5. Provide tooling/scripts for safe secret rotation
6. Ensure rotation procedure maintains synchronization between Flask and sidecar

### Acceptance Criteria
- [ ] Fail-closed secret validation implemented
- [ ] Service refuses to start with invalid secrets
- [ ] Critical secrets documented with rotation requirements
- [ ] Rotation procedure documented and tested
- [ ] Test added verifying service fails to start with empty secret
- [ ] Test added verifying service fails to start with placeholder secret
- [ ] Deployment guide updated with secret management procedures

### References
- Related: FINDING-003 (Cryptographic key strength)
- ASVS 13.1.4, 13.2.3

### Priority
**Medium** - Default credential vulnerability requiring deployment misconfiguration to exploit

---
## Issue: FINDING-005 - Log injection via unencoded attacker-controlled values (unauthenticated paths)
**Labels:** bug, security, priority:medium
**Description:**

### Summary
Multiple log statements interpolate attacker-controlled, unencoded strings directly into log messages, allowing remote unauthenticated attackers to inject or forge log entries via CR/LF sequences, degrading forensic integrity.

### Details
**Location:** `superset-websocket/src/index.ts`

**Vulnerable Data Flows:**
1. `lastId` from `url.searchParams.get('last_id')` → log message (unencoded)
2. `rawUrl` and `method` from HTTP request line → log message (unencoded)
3. Both sinks reachable before JWT authentication check

**Attack Vector:**
Attacker-controlled values containing CR/LF characters can:
- Split log lines
- Forge additional log entries
- Inject misleading forensic data
- Degrade log parser ability to correlate entries

**Attacker Capability Required:**
Remote unauthenticated access to HTTP endpoints (logged before JWT validation).

**Impact:**
Log injection/forging undermines forensic integrity and incident response capabilities. Attackers can obscure malicious activity or frame legitimate requests as attacks.

**CWE:** CWE-117 - Improper Output Neutralization for Logs  
**ASVS:** 16.2.4, 16.4.1 (Level 2)

### Remediation
1. Encode/sanitize all user-derived values before logging
2. Strip or escape CR/LF and control characters
3. Implement structured logging where field values are serialized safely
4. Create central sanitizing wrapper in `./logger` module
5. Apply sanitization consistently across all log statements
6. Prefer parameterized/structured logging over string concatenation

### Acceptance Criteria
- [ ] Sanitization wrapper implemented in logger module
- [ ] All user-controlled values sanitized before logging
- [ ] CR/LF and control characters stripped/escaped
- [ ] Test added demonstrating prevention of log injection via `lastId`
- [ ] Test added demonstrating prevention of log injection via URL/method
- [ ] Structured logging format adopted where feasible
- [ ] Code review completed for all logging statements

### References
- ASVS 16.2.4, 16.4.1

### Priority
**Medium** - Remote unauthenticated log injection affecting forensic integrity

---
## Issue: FINDING-006 - Successful authentication logged only at debug level with no metadata
**Labels:** bug, security, priority:medium
**Description:**

### Summary
Successful WebSocket authentication events are logged only at `debug` level without any authentication metadata (source IP, user identity, JWT algorithm, channel), effectively going unrecorded in production and defeating security monitoring.

### Details
**Location:** `superset-websocket/src/index.ts`

**Current Behavior:**
- Failed JWT validation: logged at `error` level
- Successful JWT validation: logged at `debug` level only
- No authentication metadata captured:
  - No source IP address
  - No user identity from token
  - No JWT algorithm verification
  - No channel-binding outcome
  - No forwarded-for headers

**Impact:**
In production environments where `debug` level is suppressed (default is `info`), successful WebSocket authentications go unrecorded. This prevents:
- Correlation of who connected, from where, to which channel
- Detection of suspicious authentication patterns
- Incident response and forensic analysis
- Compliance with authentication logging requirements

**CWE:** CWE-778 - Insufficient Logging  
**ASVS:** 16.3.1 (Level 2)

### Remediation
1. Promote successful authentication logging to `info` level
2. Attach connection metadata to all authentication events:
   - Source IP address (via proxy-forwarded headers)
   - Channel identifier
   - JWT algorithm used
   - User identity/subject from token claims
   - Timestamp
3. Ensure failure logging also records source IP and attempted channel
4. Standardize authentication event format for SIEM integration
5. Document authentication logging format and fields

### Acceptance Criteria
- [ ] Successful authentication logged at `info` level
- [ ] Source IP captured from forwarded headers
- [ ] Channel identifier included in log entry
- [ ] JWT algorithm verified and logged
- [ ] User identity extracted and logged (if present)
- [ ] Failed authentication logging enhanced with source IP
- [ ] Test added verifying authentication events logged at correct level
- [ ] Test added verifying all required metadata present
- [ ] SIEM integration documentation updated

### References
- Related: FINDING-007 (Redis error logging)
- ASVS 16.3.1

### Priority
**Medium** - Missing security-critical authentication audit trail

---
## Issue: FINDING-007 - Redis client constructed without an 'error' event handler
**Labels:** bug, security, priority:medium
**Description:**

### Summary
The Redis client is constructed without an `error` event handler, preventing security-relevant backend connection, authentication, and TLS failures from being logged and potentially destabilizing the process.

### Details
**Location:** `superset-websocket/src/index.ts` (Redis client initialization)

**Missing Error Handling:**
The ioredis client emits `error` events for:
- Connection failures
- Authentication failures  
- TLS/handshake failures
- Network errors

**Impact:**
1. Security-relevant backend failures not logged through application logger
2. Unhandled emitter `error` events can destabilize Node.js process
3. No visibility into Redis connectivity/security issues
4. Difficult to diagnose production authentication or TLS problems
5. Violates requirement to log backend TLS failures (ASVS 16.3.4)

**CWE:** CWE-778 - Insufficient Logging  
**ASVS:** 16.3.4 (Level 2)

### Remediation
1. Attach error event handler to Redis client:
   ```javascript
   redis.on('error', (e) => {
     logger.error('redis_connection_error', {
       message: e.message,
       code: e.code,
       timestamp: new Date().toISOString()
     });
   });
   ```
2. Log connection state changes (connect, ready, reconnecting, end)
3. Include error context (authentication, TLS, network)
4. Ensure errors don't crash process but are properly logged
5. Consider circuit breaker pattern for repeated failures

### Acceptance Criteria
- [ ] Redis `error` event handler implemented
- [ ] Connection state changes logged
- [ ] Error context captured in logs (type, code, message)
- [ ] Test added simulating Redis connection failure
- [ ] Test added simulating Redis authentication failure
- [ ] Test added verifying process stability with Redis errors
- [ ] Test added verifying all error types properly logged
- [ ] Documentation updated with Redis error handling

### References
- Related: FINDING-006 (Authentication logging)
- ASVS 16.3.4

### Priority
**Medium** - Missing logging of security-relevant backend failures

---
## Issue: FINDING-008 - Forwarded event payloads (including `user_id` and `result_url`) are logged without redaction
**Labels:** bug, security, priority:low
**Description:**

### Summary
Redis stream event payloads containing sensitive metadata (`user_id`, `result_url`, `job_id`, `channel_id`, `errors`) are logged without redaction, creating potential information disclosure when debug logging is enabled or logs are persisted to files.

### Details
**Location:** `superset-websocket/src/index.ts` (processStreamResults), `superset-websocket/src/logger.ts`

**Data Flow:**
1. Redis stream record (per-user query result metadata) → `processStreamResults`
2. `EventValue` object containing sensitive fields → `logger.debug(...)`
3. Winston Console and File transports (when `logToFile=true`)
4. No redaction/masking of sensitive fields

**Exposed Fields:**
- `user_id` - correlatable user identifiers
- `result_url` - internal result storage references
- `job_id` - job identifiers
- `channel_id` - channel identifiers
- `errors` - potentially sensitive error details

**Exposure Conditions:**
- `logLevel=debug` (not default; default is `info`)
- `logToFile=true` plus access to log file/observability pipeline

**Impact:**
Information disclosure of user identifiers and internal references in logs. While metadata rather than raw query results, these fields enable user correlation and expose internal architecture details.

**ASVS:** 14.2.4, 16.2.5 (Level 2)

### Remediation
1. Implement field redaction in Winston logger configuration
2. Add Winston format that strips sensitive keys centrally in `createLogger`:
   - `user_id`
   - `result_url`
   - Other PII/sensitive fields
3. Avoid logging entire payloads at any level
4. Project only necessary fields for debugging
5. Document which fields are considered sensitive
6. Apply redaction consistently across all log statements

### Acceptance Criteria
- [ ] Winston redaction format implemented in logger module
- [ ] Sensitive fields (`user_id`, `result_url`) redacted from logs
- [ ] Redaction applied to both console and file transports
- [ ] Test added verifying `user_id` redacted in debug logs
- [ ] Test added verifying `result_url` redacted in debug logs
- [ ] Test added verifying necessary debugging info still present
- [ ] Documentation updated with sensitive field definitions
- [ ] Code review completed for all payload logging

### References
- ASVS 14.2.4, 16.2.5

### Priority
**Low** - Exposure requires non-default debug logging and log access; metadata rather than raw data

---
## Issue: FINDING-009 - Security-event logs missing required metadata (who/where/what)
**Labels:** bug, security, priority:low
**Description:**

### Summary
Failed JWT validation and other security events are logged with insufficient metadata, missing critical "who/where/what" context needed for incident response and attack correlation.

### Details
**Location:** `superset-websocket/src/index.ts`

**Missing Metadata:**
Failed JWT validation logs only the bare error object without:
- **Who:** No subject/claims that did parse, no user context
- **Where:** No source IP, no `X-Forwarded-For` header, no requested path
- **What:** No indication this was upgrade-authentication failure on specific channel

**Other Affected Events:**
- Reconnect/pong events log socket ID with no connection context
- No standardized event type field
- No outcome/reason fields

**Impact:**
Authentication failure events cannot be correlated to sources during incident response, weakening:
- Detection of authentication probing/brute-force attempts
- Identification of attack sources
- Pattern analysis across multiple failures
- Compliance with security logging requirements

**ASVS:** 16.2.1 (Level 2)

### Remediation
1. Standardize security event log structure with required fields:
   - `event` - event type identifier
   - `sourceIp` - direct connection IP
   - `forwardedFor` - X-Forwarded-For header value
   - `path` - requested path/endpoint
   - `outcome` - success/failure
   - `reason` - failure reason (never log full token)
   - `channel` - target channel (when applicable)
   - `timestamp` - event timestamp
2. Apply structure to all security-relevant events:
   - Authentication success/failure
   - Authorization failures
   - Connection events
   - Rate limit violations
3. Log `err.message` only, never full tokens or secrets
4. Extract and log parseable claims from failed tokens (when safe)

### Acceptance Criteria
- [ ] Standardized security event structure defined
- [ ] Source IP extraction from forwarded headers implemented
- [ ] All authentication events include required metadata
- [ ] Path/endpoint logged for all security events
- [ ] Outcome and reason fields populated
- [ ] Test added verifying all required fields present
- [ ] Test added verifying no tokens/secrets logged
- [ ] Documentation updated with security event schema

### References
- ASVS 16.2.1

### Priority
**Low** - Impacts incident response effectiveness but not direct security control

---
## Issue: FINDING-010 - WebSocket error logging bypasses centralized logger via console.error
**Labels:** bug, security, priority:low
**Description:**

### Summary
WebSocket-level errors are written directly via `console.error` instead of the centralized logger, causing inconsistent log formatting, routing, and correlation capabilities.

### Details
**Location:** `superset-websocket/src/index.ts` (WebSocket error handlers)

**Current Behavior:**
- WebSocket errors written to `console.error`
- Bypasses centralized Winston logger configuration
- Different log format than application logs
- May route to different sink than `logFilename`
- Lacks structured metadata and context

**Impact:**
- Inconsistent log format hampers parsing and correlation
- WebSocket errors may be lost or separated from application logs
- Missing structured metadata (timestamp, level, context)
- Difficult to aggregate in centralized logging systems
- SIEM integration challenges

**ASVS:** 16.2.4 (Level 2)

### Remediation
1. Route all WebSocket errors through centralized logger:
   ```javascript
   ws.on('error', (e) => {
     logger.error('ws_socket_error', {
       reason: (e as Error).message,
       code: (e as any).code,
       socketId: ws.id
     });
   });
   ```
2. Remove direct `console.error` calls
3. Ensure consistent error context across all error types
4. Apply same structured logging format
5. Verify errors route to configured transports (console, file)

### Acceptance Criteria
- [ ] All WebSocket errors routed through centralized logger
- [ ] `console.error` calls removed from WebSocket handlers
- [ ] Consistent error structure with application logs
- [ ] Test added verifying WebSocket errors logged correctly
- [ ] Test added verifying errors route to configured transports
- [ ] Test added verifying structured metadata present
- [ ] Documentation updated with error logging patterns

### References
- ASVS 16.2.4

### Priority
**Low** - Log consistency issue; does not affect security controls directly

---
## Issue: FINDING-011 - No process-level last-resort exception handler; wsConnection re-parses JWT without try/catch
**Labels:** bug, security, priority:low
**Description:**

### Summary
The application lacks process-level exception handlers for uncaught exceptions and unhandled promise rejections, and re-parses JWTs in `wsConnection` without error handling, risking process termination and loss of forensic logging for security-relevant failures.

### Details
**Location:** `superset-websocket/src/index.ts`

**Missing Safeguards:**
1. No `process.on('uncaughtException')` handler
2. No `process.on('unhandledRejection')` handler  
3. `wsConnection` calls `readChannelId` without try/catch wrapper
4. Unguarded event-loop callbacks could terminate process

**Impact:**
- Exception in unguarded callback terminates process
- All live WebSocket connections dropped
- No application-level log entry for security-relevant failure
- Reduced forensic visibility
- Availability impact (process restart required)

**Risk Assessment:**
- No concrete attacker-reachable trigger demonstrated
- Primary auth path already has error handling
- Impact bounded to availability/resilience
- Defensive-depth issue rather than direct vulnerability

**ASVS:** 16.3.4, 16.5.4 (Level 2, Level 3)

### Remediation
1. Add process-level last-resort handlers:
   ```javascript
   process.on('uncaughtException', (err) => {
     logger.error('uncaught_exception', {
       message: err.message,
       stack: err.stack
     });
     // Graceful shutdown
     process.exit(1);
   });

   process.on('unhandledRejection', (reason, promise) => {
     logger.error('unhandled_rejection', {
       reason: String(reason),
       promise: String(promise)
     });
   });
   ```
2. Wrap duplicate `readChannelId` call in `wsConnection` with try/catch
3. Terminate socket gracefully on JWT parse failure
4. Log full error context before any process exit
5. Consider graceful shutdown sequence for active connections

### Acceptance Criteria
- [ ] `uncaughtException` handler implemented with logging
- [ ] `unhandledRejection` handler implemented with logging
- [ ] `readChannelId` in `wsConnection` wrapped in try/catch
- [ ] Socket terminated gracefully on parse failure
- [ ] Test added simulating uncaught exception
- [ ] Test added simulating unhandled rejection
- [ ] Test added verifying errors logged before exit
- [ ] Test added verifying graceful connection cleanup

### References
- ASVS 16.3.4, 16.5.4

### Priority
**Low** - Defensive depth / availability resilience; no demonstrated attacker-reachable trigger

---
## Issue: FINDING-012 - Redis global-stream read loop retries with no backoff or circuit breaker
**Labels:** bug, security, priority:low
**Description:**

### Summary
The Redis stream read loop retries immediately on connection failure without exponential backoff or circuit breaker, causing CPU consumption and log flooding during Redis outages.

### Details
**Location:** `superset-websocket/src/index.ts` (Redis stream read loop)

**Current Behavior:**
- `while(true)` loop with no backoff delay
- When Redis is down, `xread` rejects immediately
- Loop spins as fast as event loop allows
- `BLOCK` timeout only applies when connected

**Impact:**
- High CPU consumption during Redis outage
- Log flooding with connection errors
- Reduced service responsiveness
- Difficult to diagnose root cause in logs
- No graceful degradation pattern

**Risk Assessment:**
- No direct attacker control
- Service does not fail-open or serve stale data
- Impact limited to CPU/log pressure during dependency outage
- Availability/operational issue rather than security vulnerability

**CWE:** CWE-400 - Uncontrolled Resource Consumption  
**ASVS:** 16.5.2 (Level 2)

### Remediation
1. Implement capped exponential backoff:
   ```javascript
   let retryDelay = 100; // Start at 100ms
   const maxRetryDelay = 30000; // Cap at 30s

   while (true) {
     try {
       // xread logic
       retryDelay = 100; // Reset on success
     } catch (err) {
       logger.error('redis_read_error', { error: err.message });
       await new Promise(resolve => setTimeout(resolve, retryDelay));
       retryDelay = Math.min(retryDelay * 2, maxRetryDelay);
     }
   }
   ```
2. Reset backoff delay on successful read
3. Consider circuit breaker pattern for repeated failures
4. Add health check endpoint reflecting Redis connectivity
5. Log backoff/retry behavior for operations visibility

### Acceptance Criteria
- [ ] Exponential backoff implemented with configurable parameters
- [ ] Backoff delay reset on successful read
- [ ] Maximum retry delay enforced
- [ ] Test added simulating Redis outage with backoff verification
- [ ] Test added verifying backoff reset on recovery
- [ ] Test added measuring CPU usage during outage
- [ ] Health check endpoint added reflecting Redis status
- [ ] Documentation updated with retry/backoff behavior

### References
- ASVS 16.5.2

### Priority
**Low** - Operational/availability issue during dependency outage; no direct security impact