# Security Issues

---
## Issue: FINDING-001 - No Per-User or Total Connection Cap Allows Resource Starvation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The WebSocket server implements no limits on the number of connections that can be established, either per-user (per-channel) or in total. Any authenticated user can open unlimited WebSocket connections, exhausting server resources and preventing other legitimate users from establishing connections.

### Details
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **ASVS:** 15.4.4 (Level 3)
- **Affected File:** `superset-websocket/src/index.ts`

The `trackClient` function does not enforce any connection limits. This directly violates the requirement for fair resource access and allows resource starvation attacks where a single authenticated user can monopolize server connection capacity.

### Remediation
Implement per-user and total connection limits in `trackClient` and reject connections when limits are exceeded. Configure `MAX_CONNECTIONS_PER_CHANNEL` and `MAX_TOTAL_CONNECTIONS` with appropriate thresholds based on capacity planning.

### Acceptance Criteria
- [ ] Per-channel connection limit implemented and enforced
- [ ] Total connection limit implemented and enforced
- [ ] Configuration parameters added for both limits
- [ ] Connections rejected with appropriate error when limits exceeded
- [ ] Test added verifying connection limit enforcement
- [ ] Test added verifying existing connections continue working when limit reached

### References
- Source Report: 15.4.4.md

### Priority
High

---
## Issue: FINDING-002 - No Backpressure Handling Allows Slow-Client Resource Starvation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The service does not implement backpressure handling when broadcasting events to WebSocket clients. Slow or malicious clients that stop consuming messages cause unbounded buffering in the server's memory, eventually exhausting resources and degrading service quality for all users.

### Details
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **ASVS:** 15.4.4 (Level 3)
- **Affected File:** `superset-websocket/src/index.ts`
- **Related Findings:** FINDING-003

This violates fair resource allocation by allowing slow clients to monopolize server memory through unbounded message buffering.

### Remediation
Add WebSocket backpressure handling by checking `bufferedAmount` before sending and terminating clients that exceed a configurable buffer threshold. Example implementation:
```typescript
if (ws.bufferedAmount > MAX_BUFFER_SIZE) {
  logger.warn('Client buffer exceeded, terminating', { channelId, bufferedAmount: ws.bufferedAmount });
  ws.terminate();
}
```

### Acceptance Criteria
- [ ] `bufferedAmount` check added before message send
- [ ] Configurable `MAX_BUFFER_SIZE` threshold implemented
- [ ] Clients exceeding threshold are terminated with logging
- [ ] Test added simulating slow client consumption
- [ ] Test verifies client termination when buffer exceeded
- [ ] Metrics added for buffer-related disconnections

### References
- Source Report: 15.4.4.md

### Priority
High

---
## Issue: FINDING-003 - Synchronous Event Processing Without Yielding Can Starve Event Loop
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The service processes Redis stream results synchronously without yielding to the Node.js event loop. Under high event volume, this monopolizes the event loop, delaying or preventing other critical operations like health checks, new connection handling, and ping/pong processing.

### Details
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **ASVS:** 15.4.4 (Level 3)
- **Affected File:** `superset-websocket/src/index.ts`
- **Related Findings:** FINDING-002

This creates unfair resource allocation where bulk event processing starves connection management operations, potentially causing connection timeouts and health check failures.

### Remediation
Introduce event-loop yielding in `processStreamResults` for large batches using `setImmediate()` to prevent starvation of connection management and health check operations. Example:
```typescript
for (let i = 0; i < results.length; i++) {
  if (i > 0 && i % YIELD_BATCH_SIZE === 0) {
    await new Promise(resolve => setImmediate(resolve));
  }
  // process result
}
```

### Acceptance Criteria
- [ ] Event loop yielding implemented with configurable batch size
- [ ] `YIELD_BATCH_SIZE` configuration parameter added
- [ ] Test added verifying event loop responsiveness under load
- [ ] Test verifies health check endpoints remain responsive
- [ ] Performance impact measured and documented

### References
- Source Report: 15.4.4.md

### Priority
Medium

---
## Issue: FINDING-004 - WebSocket sidecar forwards entire Redis payload without schema-based field projection
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `processStreamResults` function forwards entire Redis payload to WebSocket clients using spread operator `{ id, ...data }` without an allowlist-based field projection. If the backend's Redis publishing logic were to include additional internal metadata, the sidecar would forward them without filtering.

### Details
- **CWE:** CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer)
- **ASVS:** 15.3.1 (Level 1)
- **Affected File:** `superset-websocket/src/index.ts` (lines 226-236)

Test evidence confirms `user_id` field is forwarded to client. While the Redis content is controlled by the Flask backend, the lack of explicit filtering creates risk if backend publishing logic changes.

### Remediation
Apply an explicit allowlist when constructing the outbound message, only forwarding fields intended for client consumption:
```typescript
const clientMessage = {
  id,
  channel_id: data.channel_id,
  job_id: data.job_id,
  status: data.status,
  errors: data.errors,
  result_url: data.result_url
};
```

### Acceptance Criteria
- [ ] Explicit field allowlist implemented in message construction
- [ ] Only intended fields forwarded to clients
- [ ] Test added verifying internal fields not forwarded
- [ ] Test verifies expected fields are forwarded
- [ ] Documentation updated with allowed field list

### References
- Source Report: 15.3.1.md

### Priority
Low

---
## Issue: FINDING-005 - Object literals used as lookup registries instead of Map or null-prototype objects
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `channels` and `sockets` registries use plain object literals (`{}`), which inherit from `Object.prototype`. The `in` operator checks the entire prototype chain, meaning keys like `__proto__` would match inherited properties.

### Details
- **CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
- **ASVS:** 15.3.6 (Level 2)
- **Affected File:** `superset-websocket/src/index.ts` (lines 121-122)

While exploitation requires forging a JWT signed with the server's secret (not achievable by external attacker), the pattern is defensively suboptimal per ASVS 15.3.6 which recommends Map() or Object.create(null).

### Remediation
Replace object literal registries with Map instances:
```typescript
export let channels: Map<string, ChannelValue> = new Map();
export let sockets: Map<string, SocketValue> = new Map();
```
Update all access patterns from `channels[key]` to `channels.get(key)` and `key in channels` to `channels.has(key)`.

### Acceptance Criteria
- [ ] `channels` registry converted to Map
- [ ] `sockets` registry converted to Map
- [ ] All access patterns updated (get, set, has, delete)
- [ ] Tests added verifying Map behavior
- [ ] Tests confirm prototype pollution not possible

### References
- Source Report: 15.3.6.md

### Priority
Low

---
## Issue: FINDING-006 - Log Entries Missing Timestamp Metadata
**Labels:** bug, security, priority:low
**Description:**
### Summary
The winston logger is configured with `format.json()` and `format.errors()` but does NOT include `winston.format.timestamp()`. As a result, structured JSON log entries lack a `timestamp` field, omitting the "when" metadata required for timeline investigation.

### Details
- **CWE:** CWE-778 (Insufficient Logging)
- **ASVS:** 16.2.1, 16.2.2 (Level 2)
- **Affected File:** `superset-websocket/src/logger.ts`
- **Related Findings:** FINDING-007, FINDING-008, FINDING-010, FINDING-011

In winston 3.x, timestamps are not added automatically; they must be explicitly included in the format pipeline. While container runtimes may prepend timestamps to stdout, this is not under application control and may use local time without explicit offset.

### Remediation
Add `winston.format.timestamp({ format: () => new Date().toISOString() })` to the format pipeline:
```typescript
format: format.combine(
  format.timestamp({ format: () => new Date().toISOString() }),
  format.errors({ stack: true }),
  format.json()
)
```

### Acceptance Criteria
- [ ] Timestamp format added to winston configuration
- [ ] Timestamps in ISO 8601 UTC format with Z suffix
- [ ] Test added verifying timestamp presence in log output
- [ ] Test verifies timestamp format is ISO 8601 UTC
- [ ] Documentation updated with logging format specification

### References
- Source Reports: 16.2.1.md, 16.2.2.md

### Priority
Low

---
## Issue: FINDING-007 - Security Events Lack "Who" Metadata
**Labels:** bug, security, priority:low
**Description:**
### Summary
The websocket sidecar logs authentication failures with minimal metadata (only the exception object) and successful authentications only at debug level. Failed authentication log entries lack source IP, attempted channel, authentication type, or timestamp context.

### Details
- **CWE:** CWE-778 (Insufficient Logging)
- **ASVS:** 16.2.1, 16.3.1 (Level 2)
- **Affected File:** `superset-websocket/src/index.ts`
- **Related Findings:** FINDING-006, FINDING-008, FINDING-010, FINDING-011

No distinction between different failure modes (expired token, invalid signature, missing token). Incident response teams cannot reconstruct authentication timelines or identify attack patterns.

### Remediation
Add structured authentication event logging in `httpUpgrade()` for both success (info level) and failure (warn level) paths:
```typescript
logger.info('Authentication success', {
  event: 'auth_success',
  sourceIp: request.socket.remoteAddress,
  channelId,
  authType: 'jwt'
});

logger.warn('Authentication failure', {
  event: 'auth_failure',
  sourceIp: request.socket.remoteAddress,
  channelId,
  authType: 'jwt',
  reason: error.message
});
```

### Acceptance Criteria
- [ ] Structured logging added for authentication success (info level)
- [ ] Structured logging added for authentication failure (warn level)
- [ ] Logs include sourceIp, channelId, authType, and failure reason
- [ ] Test added verifying log output for success case
- [ ] Test added verifying log output for failure cases
- [ ] Different failure modes logged with distinct reasons

### References
- Source Reports: 16.2.1.md, 16.3.1.md

### Priority
Low

---
## Issue: FINDING-008 - Direct Console Output Bypasses Logger Configuration
**Labels:** bug, security, priority:low
**Description:**
### Summary
Multiple code paths output directly to `console.error` and `console.warn` instead of using the configured winston logger. These outputs bypass the JSON format, the `silent` flag, and the file transport, and are not documented as separate log destinations.

### Details
- **CWE:** CWE-778 (Insufficient Logging)
- **ASVS:** 16.2.3, 16.3.4 (Level 2)
- **Affected File:** `superset-websocket/src/index.ts` (line 449)
- **Related Findings:** FINDING-006, FINDING-007, FINDING-010, FINDING-011

The WebSocket error handler at line 449 (`ws.on('error', console.error)`) handles runtime errors that could contain diagnostic information but bypasses structured logging.

### Remediation
Replace console.error/warn calls with logger calls:
```typescript
ws.on('error', (error) => {
  logger.error('WebSocket error', {
    event: 'ws_error',
    channelId,
    error: error.message,
    stack: error.stack
  });
});
```

### Acceptance Criteria
- [ ] All `console.error` calls replaced with `logger.error`
- [ ] All `console.warn` calls replaced with `logger.warn`
- [ ] Structured metadata added to error logs
- [ ] Test added verifying logger receives error events
- [ ] Test verifies console methods not called directly
- [ ] Audit completed for any remaining console usage

### References
- Source Reports: 16.2.3.md, 16.3.4.md

### Priority
Low

---
## Issue: FINDING-009 - Debug-Level Logging of Raw Event Stream Data
**Labels:** bug, security, priority:low
**Description:**
### Summary
When debug logging is enabled, the raw Redis stream results are logged via string interpolation. The `EventValue` interface shows these records contain `user_id`, `job_id`, `channel_id`, and potentially `result_url`.

### Details
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **ASVS:** 16.2.5 (Level 2)
- **Affected File:** `superset-websocket/src/index.ts`

While debug-level logging is typically disabled in production, there is no data classification check or filtering mechanism preventing sensitive event metadata from appearing in logs when debug is enabled.

### Remediation
Log a summary (event count) rather than raw data at debug level:
```typescript
logger.debug('Processing stream results', {
  event: 'stream_results',
  eventCount: results.length,
  streamId: results[0]?.id
});
```

### Acceptance Criteria
- [ ] Raw event data logging removed from debug output
- [ ] Summary metadata logged instead (count, IDs)
- [ ] Sensitive fields (user_id, result_url) never logged
- [ ] Test added verifying sensitive data not in debug logs
- [ ] Test verifies useful diagnostic info still present
- [ ] Documentation updated with logging data classification policy

### References
- Source Report: 16.2.5.md

### Priority
Low

---
## Issue: FINDING-010 - No Logging of Security Control Bypass Attempts
**Labels:** bug, security, priority:low
**Description:**
### Summary
The service does not differentiate between benign errors and potential attack patterns. Repeated authentication failures, malformed requests, or unexpected request patterns are not logged as security events.

### Details
- **CWE:** CWE-778 (Insufficient Logging)
- **ASVS:** 16.3.3 (Level 2)
- **Affected File:** `superset-websocket/src/index.ts`
- **Related Findings:** FINDING-006, FINDING-007, FINDING-008, FINDING-011

No distinction between 'JWT expired' vs 'JWT wrong signature' vs 'JWT missing' in logged events. Unexpected HTTP requests logged generically without security context. This prevents detection of credential stuffing, token replay, or other attack patterns.

### Remediation
Classify JWT failure types and log as structured security events with sourceIp and failure reason at warn level:
```typescript
try {
  jwt.verify(token, jwtSecret);
} catch (error) {
  const failureReason = error.name === 'TokenExpiredError' ? 'token_expired' :
                        error.name === 'JsonWebTokenError' ? 'invalid_signature' :
                        'verification_failed';
  logger.warn('Authentication failure', {
    event: 'auth_failure',
    securityEvent: true,
    sourceIp: request.socket.remoteAddress,
    failureReason,
    channelId
  });
}
```

### Acceptance Criteria
- [ ] JWT failure types classified and logged distinctly
- [ ] Security events tagged with `securityEvent: true` flag
- [ ] Source IP included in all security event logs
- [ ] Test added for each failure type (expired, invalid, missing)
- [ ] Test verifies security event flag present
- [ ] Documentation added for security event log schema

### References
- Source Report: 16.3.3.md

### Priority
Low

---
## Issue: FINDING-011 - Redis Connection Errors Logged Without Context
**Labels:** bug, security, priority:low
**Description:**
### Summary
Redis connection failures are logged via `logger.error(e)` but without contextual metadata about what operation failed or whether it represents a security control failure (e.g., TLS handshake failure to Redis).

### Details
- **CWE:** CWE-778 (Insufficient Logging)
- **ASVS:** 16.3.4 (Level 2)
- **Affected File:** `superset-websocket/src/index.ts`
- **Related Findings:** FINDING-006, FINDING-007, FINDING-008, FINDING-010

Lack of context prevents distinguishing between transient network issues and security-relevant failures like authentication or TLS failures.

### Remediation
Add structured metadata to Redis error logs indicating the operation context:
```typescript
subscriber.on('error', (error) => {
  logger.error('Redis subscriber error', {
    event: 'redis_error',
    component: 'subscriber',
    operation: 'connection',
    error: error.message,
    code: error.code,
    securityRelevant: error.code === 'ECONNREFUSED' || error.message.includes('TLS')
  });
});
```

### Acceptance Criteria
- [ ] Structured metadata added to all Redis error logs
- [ ] Operation context included (connection, subscribe, stream read)
- [ ] Security-relevant errors flagged
- [ ] Error codes included when available
- [ ] Test added verifying structured error logging
- [ ] Documentation updated with Redis error handling

### References
- Source Report: 16.3.4.md

### Priority
Low

---
## Issue: FINDING-012 - No `unhandledRejection` handler; last-resort exception handler does not prevent process termination
**Labels:** bug, security, priority:low
**Description:**
### Summary
No `process.on('unhandledRejection')` handler is registered. In Node.js 15+, unhandled promise rejections terminate the process by default with output to stderr (not to Winston's structured JSON logger).

### Details
- **CWE:** CWE-755 (Improper Handling of Exceptional Conditions)
- **ASVS:** 16.5.4 (Level 3)
- **Affected Files:** 
  - `superset-websocket/src/logger.ts`
  - `superset-websocket/src/index.ts`

Winston's default `exitOnError: true` means the process terminates after logging synchronous exceptions. Async errors escaping try/catch blocks would terminate the process with unstructured stderr output, preventing investigation and causing service disruption.

### Remediation
Add `process.on('unhandledRejection')` and `process.on('uncaughtException')` handlers that log to the structured Winston logger:
```typescript
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled promise rejection', {
    event: 'unhandled_rejection',
    reason: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined
  });
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception', {
    event: 'uncaught_exception',
    error: error.message,
    stack: error.stack
  });
  // Graceful shutdown
  process.exit(1);
});
```
Consider setting `exitOnError: false` with graceful shutdown logic.

### Acceptance Criteria
- [ ] `unhandledRejection` handler registered and logging to Winston
- [ ] `uncaughtException` handler registered and logging to Winston
- [ ] Graceful shutdown implemented for uncaught exceptions
- [ ] Test added simulating unhandled rejection
- [ ] Test verifies structured log output for both handlers
- [ ] Test verifies process behavior (exit vs continue)
- [ ] Documentation updated with error handling strategy

### References
- Source Report: 16.5.4.md

### Priority
Low