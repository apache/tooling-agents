# Security Issues

*2 actionable finding(s). 2 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

---
## Issue: FINDING-001 - No Timeout or Error Handling Documentation for fetchGuestToken Callback
**Labels:** bug, security, priority:low
**Description:**

### Summary
The SDK awaits the host-provided `fetchGuestToken` callback without timeout protection, potentially causing indefinite hangs during initial embed or refresh cycles. There is no documentation defining timeout settings, failure handling, or retry limits for this external service callback.

### Details
**CWE:** CWE-400 (Uncontrolled Resource Consumption)  
**ASVS:** 13.1.3 (Level 3)  
**Affected File:** `superset-embedded-sdk/src/index.ts`

When the SDK calls the host-provided `fetchGuestToken` callback:
- If the promise never resolves, the SDK hangs indefinitely during initial embed
- Subsequent token refresh cycles stall without recovery mechanism
- No timeout configuration is available to hosts
- No documented guidance on expected behavior or failure modes
- Resource consumption can grow unbounded during hung requests

This creates a potential denial-of-service condition where the embedding application becomes unresponsive due to an external callback failure.

### Remediation
1. Wrap the host-provided callback with a configurable timeout mechanism (e.g., `Promise.race` with a timeout promise)
2. Add SDK configuration option for timeout duration (suggested default: 30 seconds)
3. Document expected behavior of `fetchGuestToken` including:
   - Timeout expectations
   - Failure modes and error handling
   - Retry logic recommendations
4. Implement graceful degradation when callback fails or times out
5. Add resource-management strategies to SDK documentation

### Acceptance Criteria
- [ ] Timeout wrapper implemented around `fetchGuestToken` callback
- [ ] Configurable timeout option added to SDK configuration
- [ ] Documentation updated with timeout, failure handling, and retry guidance
- [ ] Test added for timeout scenario
- [ ] Test added for callback failure handling
- [ ] Error handling provides clear feedback to host application

### References
- Source Report: `13.1.3.md`
- Related: ASVS-1313-LOW-001

### Priority
**Low** - While this can cause application hangs, it requires the host application to provide a faulty callback implementation. However, defensive programming and clear documentation are security best practices.

---
## Issue: FINDING-002 - Token Refresh Timer Not Cleaned Up on Unmount — Resource Leak
**Labels:** bug, security, priority:low
**Description:**

### Summary
After calling `unmount()` to terminate an embedded session, the `refreshGuestToken` recursive timer loop continues indefinitely, causing multiple resource leaks including credential retention, unnecessary backend calls, and timer accumulation.

### Details
**CWE:** CWE-404 (Improper Resource Shutdown or Release)  
**ASVS:** 13.1.3 (Level 3), 14.3.1 (Level 1)  
**Affected File:** `superset-embedded-sdk/src/index.ts`

When `unmount()` is called, the following resources are not properly released:

1. **Credential Leak:** The guest token (authentication credential) persists in the JavaScript closure after session termination
2. **Unnecessary Network Calls:** New guest tokens continue being fetched from the host app's backend
3. **Port Leak:** The `Switchboard` port reference (`ourPort`) is never disconnected
4. **Timer Accumulation:** If a host application embeds/unmounts multiple times (e.g., SPA route changes), timer instances accumulate, leading to:
   - Multiple concurrent token refresh loops
   - Exponential growth in backend token requests
   - Memory leaks from retained closures

This violates secure resource management principles and can lead to performance degradation and unnecessary exposure of authentication credentials.

### Remediation
1. Store the `setTimeout` handle in a variable when scheduling token refresh
2. In the `unmount()` function:
   - Clear the timeout using `clearTimeout()`
   - Disconnect the Switchboard port
   - Clear any stored token references
3. Add a flag to prevent new refresh cycles after unmount
4. Document resource-release procedures in the SDK's resource-management strategy
5. Consider implementing a cleanup registry pattern for multiple resource types

### Acceptance Criteria
- [ ] Timer handle stored and cleared in `unmount()`
- [ ] Switchboard port properly disconnected on unmount
- [ ] Token references cleared from memory
- [ ] Flag added to prevent post-unmount operations
- [ ] Test added verifying timer cleanup on unmount
- [ ] Test added for multiple mount/unmount cycles
- [ ] Documentation updated with resource-management procedures

### References
- Source Reports: `13.1.3.md`, `14.3.1.md`
- Related: ASVS-1313-LOW-002, SENSITIVE-3

### Priority
**Low** - While this is a clear resource leak, the impact is gradual and primarily affects applications with frequent mount/unmount cycles. However, it does involve credential management which elevates its importance.