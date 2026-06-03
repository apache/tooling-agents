# Security Issues

*6 actionable finding(s). 1 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

---
## Issue: FINDING-001 - Process-wide binary-digest LRU cache mutated without synchronization
**Labels:** bug, security, priority:high
**Description:**
### Summary
Multiple supervisor task threads concurrently access `_read_bundle_metadata`, which performs unsynchronized operations on a shared process-wide `_BinaryDigestCache` OrderedDict. This race condition can cause RuntimeError/KeyError exceptions, corrupt LRU ordering, or trigger incorrect eviction behavior.

### Details
- **CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
- **ASVS:** 15.4.1 (Level 3)
- **Affected File:** `task-sdk/src/airflow/sdk/coordinators/executable/coordinator.py`

When multiple threads interleave `move_to_end` operations with `popitem`/eviction loops on the shared OrderedDict, the following issues can occur:
- Unhandled exceptions that abort task bundle resolution (local DoS)
- Inconsistent cache state due to race conditions
- Over- or under-eviction of cache entries

While not attacker-driven, this is a correctness/availability defect triggered by concurrency that the code anticipates. The documented domain model requires coordinator shared caches to be lock-protected. Note: Cache integrity is preserved as cache hits still return digests compared against `footer.binary_sha256`.

### Remediation
Add a `threading.Lock` around all `_BinaryDigestCache.get/put/clear` operations to ensure all mutations of the shared OrderedDict are serialized and thread-safe.

### Acceptance Criteria
- [ ] Threading lock implemented around all _BinaryDigestCache mutations
- [ ] Fixed
- [ ] Test added for concurrent cache access scenarios
- [ ] Verify no RuntimeError/KeyError under concurrent load

### References
- Related: FINDING-002 (Coordinator instance cache race)
- Source: 15.4.1.md

### Priority
**Medium** - Concurrency defect affecting availability and correctness, but not exploitable by attackers

---
## Issue: FINDING-002 - Coordinator instance cache is check-then-act racy, allowing duplicate instantiation
**Labels:** bug, security, priority:low
**Description:**
### Summary
`CoordinatorManager._find_queue` uses a check-then-act pattern on the shared `_created_coordinators` dict without synchronization, allowing concurrent `for_queue` callers to both construct coordinator instances, with the second assignment overwriting the first.

### Details
- **CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
- **ASVS:** 15.4.1 (Level 3)
- **Affected File:** `task-sdk/src/airflow/sdk/execution_time/coordinator.py`

The race condition occurs in this sequence:
1. Thread A checks cache, finds no coordinator
2. Thread B checks cache, finds no coordinator
3. Thread A constructs coordinator
4. Thread B constructs coordinator
5. Both threads write to dict (last-writer-wins)

While dict assignment is atomic preventing corruption, this results in redundant construction and two short-lived instances. No confidentiality, integrity, or availability impact occurs. This is a concurrency-only issue not controllable by attackers.

### Remediation
Guard the read-miss-construct-store sequence with a lock to ensure coordinator construction happens exactly once per queue.

### Acceptance Criteria
- [ ] Lock added around cache check and coordinator construction
- [ ] Fixed
- [ ] Test added verifying single coordinator per queue under concurrent access
- [ ] Verify no duplicate instantiation in concurrent scenarios

### References
- Related: FINDING-001 (Binary digest cache race)
- Source: 15.4.1.md

### Priority
**Low** - No C/I/A impact, only redundant object construction

---
## Issue: FINDING-003 - Direct-database-access security control raises but does not log the bypass attempt
**Labels:** bug, security, priority:low
**Description:**
### Summary
`BlockedDBSession.__init__` and `block_orm_access` functions raise exceptions when task code attempts ORM/DB access, but do not log the security-relevant bypass attempt, reducing forensic visibility.

### Details
- **ASVS:** 16.3.3 (Level 2)
- **Affected File:** `task-sdk/src/airflow/sdk/execution_time/supervisor.py`

The security control correctly fails closed by raising `RuntimeError`/`AttributeError` when task code attempts to circumvent metadata-DB isolation. However, no log statement records that a bypass was attempted.

**Impact:** Security-relevant events (attempts to circumvent isolation boundaries) are not recorded, reducing forensic visibility if:
- A misconfigured dependency probes the boundary
- A compromised dependency attempts DB access
- Debugging requires understanding task behavior

The actor is a DAG author within the trust boundary, so this is not an external attack vector but rather a monitoring gap for insider/misconfiguration scenarios.

### Remediation
Emit a log line at the denial point before raising the exception, using a fork-safe module logger guarded against logging recursion. Example:
```python
log.warning("Blocked direct ORM session creation from task process")
```

### Acceptance Criteria
- [ ] Log statement added before raising exception in BlockedDBSession.__init__
- [ ] Log statement added before raising exception in block_orm_access
- [ ] Fixed
- [ ] Test added verifying log output on bypass attempt
- [ ] Verify logging does not cause recursion or fork issues

### References
- Source: 16.3.3.md

### Priority
**Low** - Monitoring gap, control fails closed correctly

---
## Issue: FINDING-004 - Terminal-state IPC send failure for SKIPPED / UP_FOR_RESCHEDULE / DEFERRED can be misclassified as SUCCESS
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When `SUPERVISOR_COMMS.send(msg)` raises during terminal-state reporting in the `task_runner.py` finally block, only FAILED/UP_FOR_RETRY states set `_terminal_state_send_failed`. SKIPPED/UP_FOR_RESCHEDULE/DEFERRED failures are not fail-closed, causing `main()` to exit 0 and `supervisor.final_state` to incorrectly return SUCCESS.

### Details
- **ASVS:** 16.5.3 (Level 2)
- **Affected Files:** 
  - `task-sdk/src/airflow/sdk/execution_time/task_runner.py`
  - `task-sdk/src/airflow/sdk/execution_time/supervisor.py`

**Impact:** Data integrity issue where a task that should be marked DEFERRED/RESCHEDULED/SKIPPED is recorded as SUCCESS. This can:
- Advance downstream tasks based on incorrect state
- Break DAG execution logic
- Cause data pipeline inconsistencies

Triggered by infrastructure/IPC failures, not attacker-controlled. The fail-closed behavior is inconsistently applied across terminal states.

### Remediation
Extend the fail-closed signal so **any** terminal-state send failure (not only FAILED/UP_FOR_RETRY) prevents a clean exit-0 SUCCESS classification. Alternatively, have `final_state` distinguish "exit 0 with no acknowledged terminal state" from genuine success.

### Acceptance Criteria
- [ ] All terminal states (including SKIPPED/UP_FOR_RESCHEDULE/DEFERRED) trigger fail-closed behavior on IPC failure
- [ ] Fixed
- [ ] Test added simulating IPC failure for each terminal state
- [ ] Verify no SUCCESS misclassification occurs
- [ ] Verify downstream tasks do not advance on incorrect state

### References
- Source: 16.5.3.md

### Priority
**Medium** - Integrity issue affecting workflow correctness, triggered by infrastructure failure

---
## Issue: FINDING-005 - Execution API HTTP client does not apply explicit connection-pool / max-parallel-connections limit in all construction paths
**Labels:** bug, security, priority:low
**Description:**
### Summary
The Execution API HTTP client does not consistently apply explicit connection pool limits across all construction paths. While `supervisor._ensure_client` applies limits, other construction sites (`InProcessTestSupervisor._api_client`, `connection_test_supervisor`) fall back to httpx defaults instead of deployment-documented values.

### Details
- **ASVS:** 13.2.6 (Level 3)
- **Affected Files:**
  - `task-sdk/src/airflow/sdk/api/client.py`
  - `task-sdk/src/airflow/sdk/execution_time/supervisor.py`

**Current behavior:**
- `supervisor._ensure_client`: applies `httpx.Limits(max_keepalive_connections=1, max_connections=10)`
- Other construction sites: use httpx defaults (max_connections=100, max_keepalive=20)
- `Client.__init__`: does not apply limits, silently using httpx defaults

This is a Level 3 documentation-alignment / defense-in-depth gap rather than a C/I/A-affecting defect. No concrete exploit path exists due to:
- Single-client-per-supervisor model
- Sane httpx defaults
- Timeouts and retry strategy are applied

### Remediation
Either:
1. Surface configurable pool limit and apply it explicitly in `Client.__init__` (e.g., read `execution_api_max_connections` / `execution_api_max_keepalive` from `[workers]` config), OR
2. Document explicitly that the Execution API client intentionally relies on httpx defaults and that concurrency is bounded by the supervisor model

### Acceptance Criteria
- [ ] Consistent connection limits applied across all Client construction paths
- [ ] Fixed
- [ ] Configuration documentation updated
- [ ] Test added verifying connection limits are honored
- [ ] Verify documented behavior matches implementation

### References
- Source: 13.2.6.md

### Priority
**Low** - Documentation/consistency gap, no C/I/A impact with current defaults

---
## Issue: FINDING-006 - Execution API client relies on httpx's implicit default to avoid following redirects rather than explicitly disabling it
**Labels:** bug, security, priority:low
**Description:**
### Summary
The Execution API client relies on httpx's implicit `follow_redirects=False` default rather than explicitly setting it. The constructor forwards arbitrary `**kwargs` to `super().__init__()`, allowing future callers to silently enable redirect following, which could leak the Bearer auth token to unintended hosts.

### Details
- **CWE:** CWE-601 (URL Redirection to Untrusted Site)
- **ASVS:** 15.3.2 (Level 2)
- **Affected File:** `task-sdk/src/airflow/sdk/api/client.py`

**Current state:** httpx.Client defaults to `follow_redirects=False`, so the requirement is satisfied in practice.

**Risk:** Defense-in-depth gap where:
- Safe behavior is never explicitly asserted
- Future caller or kwargs default could silently enable `follow_redirects=True`
- Bearer auth token attached via `BearerAuth.auth_flow` could leak on cross-origin redirect
- Task JWT could be exposed to unintended hosts

**Exploitation requirements:**
- Control/MITM of Execution API server response, OR
- Future misconfigured kwargs default
- Not remotely exploitable in default deployment

### Remediation
Set the value explicitly so the safe posture is intentional and cannot be silently overridden. Options:
1. Use `kwargs.setdefault("follow_redirects", False)`, OR
2. Pass `follow_redirects=False` explicitly and strip it from forwarded kwargs

### Acceptance Criteria
- [ ] `follow_redirects=False` explicitly set in Client.__init__
- [ ] Fixed
- [ ] Test added verifying redirects are not followed
- [ ] Test added verifying explicit setting cannot be overridden via kwargs
- [ ] Verify Bearer token is not leaked in redirect scenarios

### References
- Source: 15.3.2.md

### Priority
**Low** - Defense-in-depth hardening, currently safe due to httpx defaults