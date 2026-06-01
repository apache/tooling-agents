# Security Issues

---

## Issue: FINDING-001 - `unmount()` does not cancel token refresh timer, leaving guest tokens actively refreshed after session termination

**Labels:** bug, security, priority:low

**Description:**

### Summary
The `unmount()` function in the embedded SDK fails to properly clean up the token refresh timer and message channel port, allowing guest tokens to continue being generated and refreshed in memory after the session has been terminated. This extends the window during which valid authentication tokens exist beyond the intended session boundary.

### Details
**Severity:** Low  
**CWE:** CWE-404 (Improper Resource Shutdown or Release)  
**ASVS:** 14.3.1 (Level L1)

**Affected Files:**
- `superset-embedded-sdk/src/index.ts`

**Attack Scenario:**
After `unmount()` is called, the `fetchGuestToken` callback continues to be invoked periodically via `setTimeout`, generating new guest tokens that remain in the closure. The `Switchboard` port (`ourPort`) is not explicitly closed. An attacker with local access to the browser's JavaScript execution context on the same page after `unmount()` is called could potentially access these tokens. This is **not remotely exploitable** and requires local access to the execution context.

**Technical Impact:**
Valid authentication tokens persist in memory beyond the host application's intended session boundary, increasing the attack surface for local exploitation scenarios.

### Remediation
1. Store the timer ID returned by `setTimeout` when scheduling token refresh
2. Call `clearTimeout()` on the stored `refreshTimerId` in the `unmount()` function
3. Close the message channel port by calling `ourPort.stop()` or equivalent cleanup method
4. Ensure all references to tokens are cleared to allow garbage collection

**Example implementation:**
```typescript
let refreshTimerId: number | null = null;

// When setting up refresh:
refreshTimerId = setTimeout(fetchGuestToken, refreshTiming);

// In unmount():
if (refreshTimerId !== null) {
  clearTimeout(refreshTimerId);
  refreshTimerId = null;
}
if (ourPort) {
  ourPort.stop(); // or appropriate cleanup method
}
```

### Acceptance Criteria
- [ ] Fixed: Timer ID is stored and cancelled on `unmount()`
- [ ] Fixed: Message channel port is explicitly closed on `unmount()`
- [ ] Fixed: Token references are cleared to enable garbage collection
- [ ] Test added: Unit test verifies timer is cancelled when `unmount()` is called
- [ ] Test added: Unit test verifies port is closed when `unmount()` is called
- [ ] Test added: Integration test confirms no token refresh occurs after `unmount()`

### References
- Source Report: `14.3.1.md`
- Related CWE: [CWE-404: Improper Resource Shutdown or Release](https://cwe.mitre.org/data/definitions/404.html)
- ASVS 4.0: Section 14.3.1

### Priority
**Low** - Requires local access to browser execution context; not remotely exploitable. Should be addressed in regular maintenance cycle to improve security hygiene and proper resource management.