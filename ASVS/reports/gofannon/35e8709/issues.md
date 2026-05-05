# Security Issues

## Issue: FINDING-007 - Open Redirect via Unvalidated return_to Parameter in OAuth Flow
**Labels:** bug, security, priority:high
**Description:**
### Summary
User-controlled query param `return_to` is stored in a cookie and used directly as a redirect target without validation against an allowlist. This enables phishing attacks that leverage the application's legitimate OAuth flow to build trust.

### Details
When the parameter contains an absolute URL (starting with http:// or https://), it is used without any origin validation. A user sees a legitimate consent screen from their OAuth provider, then lands on an attacker-controlled page immediately after authentication when users have high trust.

**CWE:** CWE-601  
**ASVS:** 10.4.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/routes_auth.py:130-140`
- `webapp/packages/api/user-service/routes_auth.py:170-180`

### Remediation
Validate `return_to` against allowed origins:

```python
from urllib.parse import urlparse, quote

def _validate_return_to(return_to: str, frontend_url: str) -> str:
    """Validate and sanitize return_to parameter."""
    if not return_to or return_to == "/":
        return frontend_url + "/"
    
    # Parse both URLs
    parsed_return = urlparse(return_to)
    parsed_frontend = urlparse(frontend_url)
    
    # If absolute URL, must match frontend origin
    if parsed_return.scheme:
        if parsed_return.netloc != parsed_frontend.netloc:
            return frontend_url + "/"
        return return_to
    
    # Relative path - prefix with frontend URL
    path = return_to if return_to.startswith("/") else "/" + return_to
    return frontend_url + path
```

Only allow relative paths or paths matching FRONTEND_URL origin.

### Acceptance Criteria
- [ ] return_to validation implemented against allowlist
- [ ] Test added verifying external URLs are rejected
- [ ] Test added verifying relative paths work correctly
- [ ] Test added verifying same-origin absolute URLs work
- [ ] Security documentation updated with redirect validation

### References
- Source reports: 10.4.1.md, 10.4.5.md

### Priority
**High** - Enables phishing attacks via trusted authentication flow

---

## Issue: FINDING-008 - No Rate Limiting or Throttling on Authentication Endpoints
**Labels:** bug, security, priority:high
**Description:**
### Summary
The authentication endpoints in `routes_auth.py` lack any rate limiting or throttling controls. External attackers can script rapid requests to initiate login flows and attempt code exchanges without any throttling.

### Details
This enables:
- Credential stuffing against the dev_stub provider (user UID enumeration)
- State token exhaustion attacks
- Rapid code replay attempts for external OAuth providers
- No protection against distributed brute force attacks across the authentication flow

**ASVS:** 6.3.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/routes_auth.py` (all auth endpoints)

### Remediation
Implement rate limiting middleware using a library such as SlowAPI with Redis backend:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@router.get("/auth/login/{type}")
@limiter.limit("10/minute")
async def login_redirect(...):
    ...

@router.get("/auth/callback/{type}")
@limiter.limit("5/minute")
async def login_callback(...):
    ...
```

Apply limits:
- 10 login initiations per minute per IP for `/auth/login/{type}`
- 5 callback attempts per minute per IP for `/auth/callback/{type}`

### Acceptance Criteria
- [ ] Rate limiting middleware implemented with Redis backend
- [ ] Rate limits applied to all authentication endpoints
- [ ] Test added verifying rate limits are enforced
- [ ] Test added verifying legitimate traffic not blocked
- [ ] Monitoring/alerting configured for rate limit violations

### References
- Source reports: 6.3.1.md

### Priority
**High** - No protection against credential stuffing and brute force attacks

---

## Issue: FINDING-009 - No Mechanism to Terminate All Sessions When User Account is Disabled or Deleted
**Labels:** bug, security, priority:high
**Description:**
### Summary
There is no function, endpoint, or mechanism to find and terminate all sessions belonging to a specific user. When an admin disables or deletes a user account, the user's existing sessions remain valid in CouchDB until individual TTL expiry (default: 24 hours).

### Details
A disabled or deleted user retains access for up to the session TTL. In security-critical scenarios (employee termination, compromised account), this window is unacceptable. The application cannot enforce immediate access revocation.

**ASVS:** 7.4.2 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/services/session_service.py`

### Remediation
Add a `terminate_all_for_user(user_uid: str)` method to SessionService:

```python
async def terminate_all_for_user(self, user_uid: str) -> int:
    """Terminate all sessions for a specific user.
    
    Returns:
        Number of sessions terminated
    """
    # Query sessions by user_uid using CouchDB view/index
    sessions = self.db.find("user_sessions", {"user_uid": user_uid})
    
    terminated_count = 0
    for session in sessions:
        await self.delete(session["session_id"])
        terminated_count += 1
    
    return terminated_count
```

Implement a CouchDB view/index on `user_uid` in the user_sessions collection. Add an admin endpoint (e.g., `POST /admin/terminate-user-sessions/{user_uid}`) to expose this functionality. Wire account disable/delete actions to automatically call this method.

### Acceptance Criteria
- [ ] terminate_all_for_user method implemented in SessionService
- [ ] CouchDB view/index created for user_uid queries
- [ ] Admin endpoint added for manual session termination
- [ ] User disable/delete actions automatically terminate sessions
- [ ] Test added verifying all sessions are terminated
- [ ] Test added verifying terminated sessions cannot be used

### References
- Source reports: 7.4.2.md

### Priority
**High** - Cannot enforce immediate access revocation for security incidents

---

## Issue: FINDING-010 - Chat Ticket IDOR — Any User Can Read Another User's Chat Response
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `get_chat_status` endpoint accepts a `ticket_id` parameter and returns the full chat response including LLM output without validating that the authenticated user owns the ticket.

### Details
While ticket IDs are UUIDv4 (hard to guess), there is no validation that the authenticated user owns the ticket. If an attacker obtains a ticket ID through logs, shared URLs, browser history, or network interception, they can read another user's complete chat response including potentially sensitive LLM output.

**Impact:** Unauthorized access to potentially sensitive LLM conversations. Attacker who obtains a ticket ID can read another user's complete chat response.

**CWE:** CWE-639  
**ASVS:** 8.2.2 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/routes.py:369-382`

### Remediation
Add user ownership validation to chat ticket retrieval:

```python
@router.get("/chat/status/{ticket_id}")
async def get_chat_status(
    ticket_id: str,
    user: dict = Depends(get_current_user),
    chat_service: ChatService = Depends(get_chat_service)
):
    ticket_data = await chat_service.get_ticket_status(ticket_id)
    
    # Validate ownership
    if ticket_data.get('userId') != user.get('uid'):
        raise HTTPException(status_code=404, detail='Ticket not found')
    
    return ticket_data
```

Store the user ID with the ticket during creation and verify it on retrieval.

### Acceptance Criteria
- [ ] User ownership validation added to chat ticket retrieval
- [ ] userId stored with tickets during creation
- [ ] Test added verifying users cannot access other users' tickets
- [ ] Test added verifying proper error response (404)
- [ ] Similar validation added to all ticket-related endpoints

### References
- Related findings: FINDING-001, FINDING-002, FINDING-011, FINDING-031
- Source reports: 8.2.2.md

### Priority
**High** - IDOR vulnerability exposing potentially sensitive conversations

---

## Issue: FINDING-011 - Session Config IDOR — Any User Can Read/Modify/Delete Another User's Session Configuration
**Labels:** bug, security, priority:high
**Description:**
### Summary
Session configuration endpoints (`update_session_config` and `delete_session`) accept arbitrary `session_id` path parameters without verifying the requesting user owns the session.

### Details
User-controlled `session_id` flows directly to database operations with no user/session ownership comparison.

**Impact:** Attacker can modify another user's session configuration, potentially redirecting their LLM calls to attacker-controlled endpoints, changing provider settings, or deleting sessions to cause denial of service.

**CWE:** CWE-639  
**ASVS:** 8.2.2 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/routes.py:385-415`

### Remediation
Add ownership validation to session config routes:

```python
async def validate_session_ownership(
    session_id: str,
    user: dict = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service)
):
    session = await session_service.get(session_id)
    if not session or session.get('user_uid') != user.get('uid'):
        raise HTTPException(status_code=404, detail='Session not found')
    return session

@router.put("/sessions/{session_id}")
async def update_session_config(
    session_id: str,
    config: SessionConfig,
    session: dict = Depends(validate_session_ownership),
    ...
):
    ...
```

Validate that the requesting user owns the session being modified. Store session ownership metadata and verify it before allowing any read, write, or delete operations.

### Acceptance Criteria
- [ ] Ownership validation implemented for all session config endpoints
- [ ] Test added verifying users cannot access other users' sessions
- [ ] Test added verifying proper error responses (403/404)
- [ ] Session ownership metadata properly stored and indexed

### References
- Related findings: FINDING-001, FINDING-002, FINDING-010, FINDING-031
- Source reports: 8.2.2.md

### Priority
**High** - IDOR allowing session hijacking and configuration manipulation

---

## Issue: FINDING-012 - Background Task Loses Authorization Context — No Re-verification of Permissions During Execution
**Labels:** bug, security, priority:high
**Description:**
### Summary
Background tasks don't have access to dependency injection, so service instances are obtained directly. The 'user' dict is passed from the original request without re-checking permissions. If a user's permissions change (revoked) between request submission and execution, the stale authorization context persists.

### Details
Given LLM calls can take 15-30 minutes (per timeout configuration), this window is significant. The background task runs later with stale credentials and performs no re-verification before agent access.

**ASVS:** 8.3.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/dependencies.py:383-504`

### Remediation
Add background task authorization refresh:

```python
async def _background_agent_execution(
    agent_id: str,
    user_snapshot: dict,
    input_dict: dict,
    ...
):
    # Re-validate user permissions before executing
    session_service = get_session_service()
    current_user = await session_service.get_user(user_snapshot['uid'])
    
    if not current_user or not current_user.get('active'):
        logger.warning(f"User {user_snapshot['uid']} no longer active, aborting task")
        return
    
    # Re-check workspace access
    agent = db.get('agents', agent_id)
    user_workspaces = {w['workspaceId'] for w in current_user.get('workspaces', [])}
    if agent.get('workspaceId') not in user_workspaces:
        logger.warning(f"User {user_snapshot['uid']} lost access to agent {agent_id}")
        return
    
    # Continue with execution...
```

Before executing long-running operations, re-validate the user's current permissions against the session service rather than relying on the snapshot from request time.

### Acceptance Criteria
- [ ] Background tasks re-validate user permissions before execution
- [ ] Test added verifying revoked permissions prevent execution
- [ ] Test added verifying disabled users cannot execute tasks
- [ ] Failed authorization attempts logged
- [ ] Grace period handling documented

### References
- Source reports: 8.3.1.md

### Priority
**High** - Stale authorization allows revoked users to execute operations

---

## Issue: FINDING-013 - No Execution Timeout on Agent Code
**Labels:** bug, security, priority:high
**Description:**
### Summary
Agent code execution via `run_function()` is awaited without any timeout mechanism. This allows malicious or buggy agent code to run indefinitely, consuming CPU and memory resources, potentially causing denial of service.

### Details
The lack of timeout enables:
- Infinite loops
- Memory exhaustion attacks
- Event loop starvation that prevents other requests from processing

**CWE:** CWE-400  
**ASVS:** 1.3.2 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/dependencies.py:334-350`

### Remediation
Wrap the `await run_function()` call in `asyncio.wait_for()` with a configurable timeout:

```python
import asyncio

AGENT_EXECUTION_TIMEOUT = int(os.getenv("AGENT_EXECUTION_TIMEOUT", "300"))

try:
    result = await asyncio.wait_for(
        run_function(input_dict=input_dict, tools=tools),
        timeout=AGENT_EXECUTION_TIMEOUT
    )
except asyncio.TimeoutError:
    if trace:
        trace.error(f"Agent execution timed out after {AGENT_EXECUTION_TIMEOUT}s")
    raise HTTPException(
        status_code=408,
        detail=f"Agent execution exceeded timeout of {AGENT_EXECUTION_TIMEOUT} seconds"
    )
```

Handle `asyncio.TimeoutError` exceptions by logging to trace if available and raising an HTTPException with status code 408.

### Acceptance Criteria
- [ ] Execution timeout implemented with configurable duration
- [ ] Test added verifying timeout is enforced
- [ ] Test added verifying timeout error handling
- [ ] Timeout value documented and configurable via environment
- [ ] Monitoring added for timeout events

### References
- Source reports: 1.3.2.md

### Priority
**High** - Enables denial of service via resource exhaustion

---

## Issue: FINDING-014 - Reflected XSS in dev_stub_picker HTML generation — user input interpolated without HTML encoding
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `users` and `state` query parameters are directly interpolated into an HTML document without any HTML entity encoding. This endpoint is accessible on any deployment where the auth router is mounted (i.e., when ANY auth provider is enabled, not just dev_stub).

### Details
Query parameter `users` is split on comma and each value is interpolated into HTML href attributes AND element content. The `state` parameter is also interpolated into HTML href attributes. The endpoint returns text/html with no encoding applied.

This is a Type B gap where the control (`html.escape`) EXISTS in the same file (`_render_deny_page` function correctly uses it) but is NOT CALLED here.

**CWE:** CWE-79  
**ASVS:** 1.2.1, 1.3.1, 1.2.2 (Level L1)

**Affected Files:**
- `routes_auth.py:197-215`
- `webapp/packages/api/user-service/routes_auth.py:195`

### Remediation
Apply HTML entity encoding using `html.escape()` to all user-controlled values interpolated into HTML element content, and use `urllib.parse.quote()` for values interpolated into URL attributes:

```python
import html as _html
from urllib.parse import quote

@router.get("/auth/dev-stub-picker", response_class=HTMLResponse)
async def dev_stub_picker(...) -> HTMLResponse:
    user_list = [u for u in users.split(",") if u]
    links = "".join(
        f'<li><a href="/auth/callback/dev_stub?code={quote(u)}&state={quote(state)}">'
        f'{_html.escape(u)}</a></li>'
        for u in user_list
    )
    # ...
```

Additionally, add a guard that returns 404 if the dev_stub provider is not enabled in the registry.

### Acceptance Criteria
- [ ] HTML encoding applied to all user-controlled output
- [ ] URL encoding applied to URL parameters
- [ ] Test added verifying XSS payloads are neutralized
- [ ] Guard added to prevent access when dev_stub disabled
- [ ] Security review of all HTML-generating endpoints

### References
- Related findings: FINDING-023, FINDING-064
- Source reports: 1.2.1.md, 1.3.1.md, 2.2.2.md, 1.2.2.md

### Priority
**High** - Reflected XSS in authentication flow

---

## Issue: FINDING-015 - Open redirect via unvalidated `return_to` parameter accepting absolute URLs
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `return_to` value originates from a user-controlled query parameter, is stored in a cookie, and then used as the redirect target after authentication. When it's an absolute URL, no validation is performed to ensure it points to a trusted domain.

### Details
Data flow: `/auth/login/{type}?return_to=https://evil.com` → cookie `gofannon_return_to` → `/auth/callback/{type}` reads cookie → if starts with `http://`/`https://` → used directly as `RedirectResponse(url=...)`

Only safe URL protocols are checked, but the domain is unrestricted.

**ASVS:** 1.2.2 (Level L1)

**Affected Files:**
- `routes_auth.py:149-157`

### Remediation
Validate that absolute `return_to` URLs point to the configured frontend domain:

```python
from urllib.parse import urlparse

frontend_base = os.getenv("FRONTEND_URL", "http://localhost:3000").rstrip("/")
frontend_host = urlparse(frontend_base).netloc

raw_target = return_to or "/"
if raw_target.startswith(("http://", "https://")):
    parsed = urlparse(raw_target)
    if parsed.netloc != frontend_host:
        # Reject or fall back to root
        redirect_url = frontend_base + "/"
    else:
        redirect_url = raw_target
else:
    if not raw_target.startswith("/"):
        raw_target = "/" + raw_target
    redirect_url = frontend_base + raw_target
```

### Acceptance Criteria
- [ ] Absolute URL validation implemented against frontend domain
- [ ] Test added verifying external URLs are rejected
- [ ] Test added verifying same-origin URLs work
- [ ] Test added verifying relative paths work
- [ ] Security documentation updated

### References
- Source reports: 1.2.2.md, 2.2.2.md

### Priority
**High** - Open redirect enabling phishing attacks

---

## Issue: FINDING-016 - No schema validation on deployed agent input
**Labels:** bug, security, priority:high
**Description:**
### Summary
The deployed agent endpoint reads the request body as raw JSON without any Pydantic model validation. Each deployed agent has a defined `input_schema` stored in its configuration, but this schema is never validated against the incoming request.

### Details
This is a Type B gap — the control (input_schema) EXISTS but is NOT CALLED at this entry point. Arbitrarily structured or sized payloads reach agent execution. Could enable:
- Denial of service via oversized inputs
- Unexpected behavior in agent code
- Injection if agent code uses input values in unsafe contexts

**ASVS:** 2.2.1, 2.2.2 (Level L1)

**Affected Files:**
- `routes.py:395`

### Remediation
Validate `input_dict` against the agent's declared `input_schema` before execution using jsonschema.validate:

```python
import jsonschema

@router.post("/agents/deployed/{friendly_name}")
async def run_deployed_agent(
    friendly_name: str,
    request: Request,
    ...
):
    input_dict = await request.json()
    
    # Fetch deployment and agent
    deployment = db.get('deployments', {'friendly_name': friendly_name})
    agent = db.get('agents', deployment['agent_id'])
    
    # Validate against schema
    input_schema = agent.get('inputSchema')
    if input_schema:
        try:
            jsonschema.validate(instance=input_dict, schema=input_schema)
        except jsonschema.ValidationError as e:
            raise HTTPException(status_code=422, detail=str(e))
    
    # Continue with execution...
```

### Acceptance Criteria
- [ ] Input schema validation implemented for deployed agents
- [ ] Test added verifying invalid input is rejected
- [ ] Test added verifying valid input is accepted
- [ ] Test added verifying appropriate error messages (422)
- [ ] Schema validation applied to all agent execution paths

### References
- Source reports: 2.2.1.md, 2.2.2.md

### Priority
**High** - Missing input validation enabling various attacks

---

## Issue: FINDING-017 - No HSTS Header Configuration — Allows Downgrade to HTTP
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application does not include a Strict-Transport-Security header on responses. Without HSTS, the application is vulnerable to protocol downgrade attacks and SSL stripping.

### Details
There is no middleware, response hook, or configuration anywhere in the provided code that adds a `Strict-Transport-Security` header to responses.

Given that the application uses cookie-based session authentication (`credentials: 'include'`), session cookies could be intercepted over an HTTP connection if the user's first request is not over HTTPS or if a MITM intercepts the initial redirect. An attacker performing an SSL-stripping attack could downgrade the connection to HTTP, intercepting the `gofannon_sid` session cookie.

**ASVS:** 12.2.1, 3.4.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/app_factory.py:56-83`

### Remediation
Add HSTS middleware to the FastAPI application:

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class HSTSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response

def create_app() -> FastAPI:
    app = FastAPI(lifespan=lifespan)
    app.add_middleware(HSTSMiddleware)
    # ... rest of configuration
```

Alternatively, configure HSTS at the reverse proxy (Nginx/CloudFront), but document this explicitly as a deployment requirement.

### Acceptance Criteria
- [ ] HSTS middleware implemented or proxy configuration documented
- [ ] Test added verifying HSTS header is present
- [ ] Test added verifying header includes appropriate max-age
- [ ] Deployment documentation updated with HSTS requirements
- [ ] Security headers documented comprehensively

### References
- Source reports: 12.2.1.md, 3.4.1.md

### Priority
**High** - Enables SSL stripping and session cookie interception

---

## Issue: FINDING-018 - Missing CSRF Protection on Cookie-Based Authentication
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application uses cookie-based authentication with credentials automatically included in cross-origin requests, but lacks any CSRF protection mechanism.

### Details
There is no:
- CSRF token generation or validation
- Custom header requirement
- Origin header validation on state-changing requests
- Visible SameSite cookie attribute configuration

The CORS middleware only controls response headers and does not prevent simple (non-preflight) cross-origin requests from executing. This allows an attacker to potentially perform state-changing operations on behalf of authenticated users through cross-site requests.

**CWE:** CWE-352  
**ASVS:** 3.5.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/app_factory.py:22-75`
- `fetchInterceptor.js`

### Remediation
Implement one or more CSRF protection mechanisms:

1. **Require a custom header** (e.g., X-Requested-With: XMLHttpRequest) on all authenticated requests:

```python
class CSRFHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            if not request.headers.get("X-Requested-With"):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Missing required header"}
                )
        return await call_next(request)
```

Update fetchInterceptor.js to include this header.

2. **Add server-side Origin header validation**:

```python
class OriginValidationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            origin = request.headers.get("Origin")
            if origin and origin not in ALLOWED_ORIGINS:
                return JSONResponse(status_code=403, content={"detail": "Invalid origin"})
        return await call_next(request)
```

3. **Configure SameSite cookie attribute** explicitly as Lax or Strict

4. **Require Content-Type: application/json** on all state-changing API endpoints

### Acceptance Criteria
- [ ] CSRF protection mechanism implemented
- [ ] Test added verifying cross-origin requests are blocked
- [ ] Test added verifying legitimate requests work
- [ ] Frontend updated to include required headers
- [ ] SameSite attribute configured on session cookies
- [ ] Security documentation updated

### References
- Related findings: FINDING-019
- Source reports: 3.5.1.md

### Priority
**High** - No CSRF protection on state-changing operations

---

## Issue: FINDING-019 - CORS Middleware Does Not Block Simple Cross-Origin Requests
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application relies on Starlette's CORSMiddleware to prevent disallowed cross-origin use of sensitive functionality, but this middleware only adds/omits response headers and does not reject non-preflight requests from non-allowed origins server-side.

### Details
Cross-origin 'simple' POST requests with Content-Type: application/x-www-form-urlencoded do not trigger CORS preflight and are processed by backend endpoints, allowing state changes to occur. The attacker cannot read the response due to browser CORS enforcement, but blind state-changing attacks succeed.

This creates false confidence that CORS is preventing CSRF attacks.

**CWE:** CWE-352  
**ASVS:** 3.5.2 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/app_factory.py:22-40`

### Remediation
Validate the Content-Type header server-side and reject non-JSON content types for API endpoints:

```python
class ContentTypeValidationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("Content-Type", "")
            if not content_type.startswith("application/json"):
                return JSONResponse(
                    status_code=415,
                    content={"detail": "Content-Type must be application/json"}
                )
        return await call_next(request)
```

This ensures all state-changing requests trigger a CORS preflight.

Alternatively, require a non-safelisted header like X-Requested-With on all authenticated requests. Additionally, implement server-side Origin header validation for state-changing requests, returning 403 if Origin is present but not in the allowlist.

### Acceptance Criteria
- [ ] Content-Type validation middleware implemented
- [ ] Test added verifying non-JSON requests are rejected
- [ ] Test added verifying JSON requests work correctly
- [ ] Origin header validation implemented
- [ ] Documentation clarifies CORS vs CSRF protection

### References
- Related findings: FINDING-018
- Source reports: 3.5.2.md

### Priority
**High** - False sense of security; CSRF still possible

---

## Issue: FINDING-020 - Race Condition in Spend Allowance Check Enables Concurrent Bypass (TOCTOU)
**Labels:** bug, security, priority:high
**Description:**
### Summary
A Time-of-Check-Time-of-Use (TOCTOU) race condition exists between the allowance check (line 113-115) and usage recording (line 328). Multiple concurrent requests can all pass the `require_allowance()` check simultaneously before any usage is recorded.

### Details
A user with $5 remaining allowance could send 50 concurrent requests, all of which pass the check, resulting in potentially $250+ in charges before any usage is recorded. The LLM call takes 1-600 seconds between check and usage recording, creating a large window for exploitation.

**ASVS:** 2.3.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/services/llm_service.py:113-115`
- `webapp/packages/api/user-service/services/llm_service.py:328`

### Remediation
Use atomic decrement or pessimistic locking. Reserve estimated cost atomically BEFORE the LLM call:

```python
async def call_llm(...):
    # Estimate cost upfront
    estimated_cost = estimate_llm_cost(model, max_tokens)
    
    # Atomically reserve allowance
    reservation_id = await user_service.reserve_allowance(
        user_id, 
        estimated_cost
    )
    
    try:
        # Make LLM call
        response = await litellm.acompletion(...)
        actual_cost = response.usage.total_cost
        
        # Finalize with actual cost
        await user_service.finalize_reservation(
            reservation_id,
            actual_cost
        )
    except Exception as e:
        # Release reservation on error
        await user_service.release_reservation(reservation_id)
        raise
```

This ensures allowance is decremented before the expensive operation executes.

### Acceptance Criteria
- [ ] Atomic allowance reservation implemented
- [ ] Test added demonstrating race condition is prevented
- [ ] Test added verifying reservations are released on error
- [ ] Test added verifying concurrent requests respect limits
- [ ] Monitoring added for reservation/finalization metrics

### References
- Source reports: 2.3.1.md

### Priority
**High** - Race condition enabling unlimited spend

---

## Issue: FINDING-021 - Streaming Endpoint Skips Cost Recording Step Entirely
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `stream_llm` function explicitly notes cost tracking is unavailable. While `require_allowance` is called before streaming (positive), actual cost is never deducted from user allowance after streaming completes.

### Details
Users could accumulate LLM costs through streaming without proper accounting, potentially exhausting shared resources or infrastructure budgets without triggering allowance enforcement post-call.

**ASVS:** 2.3.1, 15.2.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/services/llm_service.py:348-410`

### Remediation
Add usage recording to `stream_llm()` using a finally block:

```python
async def stream_llm(...):
    accumulated_tokens = 0
    accumulated_content = []
    
    try:
        async for chunk in litellm.acompletion(..., stream=True):
            # Track tokens/content
            if hasattr(chunk, 'usage'):
                accumulated_tokens += chunk.usage.total_tokens
            
            accumulated_content.append(chunk.choices[0].delta.content or "")
            yield chunk
    finally:
        # Record usage even if stream is interrupted
        if user_service and user_id:
            # Estimate cost based on accumulated tokens
            estimated_cost = estimate_cost_from_tokens(
                model, 
                accumulated_tokens
            )
            await user_service.add_usage(user_id, estimated_cost)
```

Track usage based on streamed content using litellm's stream_cost_tracking or estimate based on tokens.

### Acceptance Criteria
- [ ] Usage recording implemented for streaming endpoint
- [ ] Test added verifying costs are recorded for streams
- [ ] Test added verifying partial streams record partial costs
- [ ] Test added verifying interrupted streams still record usage
- [ ] Monitoring added for streaming cost tracking

### References
- Source reports: 2.3.1.md, 15.2.1.md

### Priority
**High** - Complete bypass of cost tracking for streaming

---

## Issue: FINDING-022 - No Rate Limiting Controls Implemented or Documented for LLM API Endpoints
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application lacks rate limiting controls for LLM API endpoints in both `chat_service.py` and `llm_service.py`. No per-IP rate limiting, per-user request rate limiting, anti-automation controls, adaptive response mechanisms, or circuit breakers for external LLM service calls are implemented.

### Details
Without rate limiting, the system is vulnerable to:
- Credential stuffing (if authentication endpoints exist)
- Resource exhaustion via unlimited concurrent LLM requests
- Cost amplification when combined with spend allowance bypass
- DoS attacks via unlimited background task spawning

**ASVS:** 6.1.1 (Level L1)

**Affected Files:**
- `chat_service.py` (all public methods)
- `llm_service.py` (all public functions)

### Remediation
Implement rate limiting middleware with documented configuration:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address
import redis

redis_client = redis.from_url(os.getenv("REDIS_URL"))
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.getenv("REDIS_URL")
)

class ChatService:
    def __init__(self):
        self.max_requests_per_minute = int(
            os.getenv("CHAT_RATE_LIMIT_REQUESTS", "10")
        )
        self.max_concurrent_tasks = int(
            os.getenv("CHAT_MAX_CONCURRENT", "20")
        )
```

Configure limits:
- Per-user: 10 requests/minute for chat ticket creation, 5 concurrent streams, 30 requests/minute for LLM calls
- Per-IP: 100 requests/minute for all endpoints, 5 attempts/minute for authentication
- Adaptive response: 5-minute cooldown after 3x rate limit hits, 1-hour lockout after 10x hits in 1 hour

### Acceptance Criteria
- [ ] Rate limiting middleware implemented with Redis backend
- [ ] Per-user and per-IP limits configured
- [ ] Test added verifying rate limits are enforced
- [ ] Test added verifying legitimate traffic not blocked
- [ ] Adaptive response mechanisms implemented
- [ ] Monitoring/alerting configured for rate limit violations
- [ ] Configuration documented with environment variables

### References
- Source reports: 6.1.1.md

### Priority
**High** - No protection against resource exhaustion and DoS

---

## Issue: FINDING-023 - Reflected XSS in Dev-Stub Picker via Unescaped Query Parameters
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `dev_stub_picker` function embeds user-controlled query parameters (state and users) directly into HTML output without proper escaping. This creates a reflected XSS vulnerability enabling arbitrary JavaScript execution in the application's origin context.

### Details
Despite httponly cookies, this enables DOM manipulation, phishing overlays, and keylogging on the login page. The state and users parameters are embedded directly into HTML href attributes and link text without proper encoding.

**CWE:** CWE-79  
**ASVS:** 10.4.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/routes_auth.py:253-266`

### Remediation
Apply proper output encoding:

```python
import html
from urllib.parse import quote

@router.get("/auth/dev-stub-picker")
async def dev_stub_picker(users: str, state: str):
    # Check environment
    if os.getenv("APP_ENV", "").lower() == "production":
        raise HTTPException(status_code=404)
    
    user_list = [u.strip() for u in users.split(",") if u.strip()]
    
    links_html = "\n".join(
        f'<li><a href="/auth/callback/dev_stub?'
        f'code={quote(user, safe="")}&state={quote(state, safe="")}">'
        f'{html.escape(user)}</a></li>'
        for user in user_list
    )
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Dev Stub Login</title>
    </head>
    <body>
        <h1>Select User (Dev Only)</h1>
        <ul>{links_html}</ul>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
```

Apply:
1. `urllib.parse.quote()` for URL parameters in href attributes
2. `html.escape()` for user values displayed as text content
3. Add `charset=UTF-8` meta tag to HTML head
4. Implement environment-based guard to prevent dev_stub from loading in production

### Acceptance Criteria
- [ ] HTML encoding applied to all user-controlled output
- [ ] URL encoding applied to all URL parameters
- [ ] Test added verifying XSS payloads are neutralized
- [ ] Environment guard prevents production access
- [ ] charset meta tag added to HTML responses

### References
- Related findings: FINDING-014, FINDING-064
- Source reports: 10.4.1.md, 10.4.5.md

### Priority
**Medium** - XSS in development-only endpoint

---

## Issue: FINDING-024 - No Failed Authentication Attempt Tracking or Account Lockout
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `login_callback` function does not track failed authentication attempts per user or per IP address. When provider code exchange fails, the application raises an HTTP 502 exception without logging attempt counts or triggering any lockout mechanism.

### Details
This provides:
- No visibility into brute force patterns
- No automatic lockout mechanism
- No ability to detect ongoing credential stuffing attacks through application-level metrics

**ASVS:** 6.3.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/routes_auth.py` (login_callback function)

### Remediation
Implement failed authentication attempt tracking and account lockout:

```python
class RateLimitService:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.max_attempts = 5
        self.lockout_duration = 900  # 15 minutes
    
    async def record_failed_attempt(self, ip: str, provider: str):
        key = f"auth_fail:{ip}:{provider}"
        count = await self.redis.incr(key)
        await self.redis.expire(key, self.lockout_duration)
        return count
    
    async def is_locked_out(self, ip: str, provider: str) -> bool:
        key = f"auth_fail:{ip}:{provider}"
        count = await self.redis.get(key)
        return int(count or 0) >= self.max_attempts

@router.get("/auth/callback/{type}")
async def login_callback(
    type: str,
    request: Request,
    rate_limit: RateLimitService = Depends(get_rate_limit_service),
    audit: AuditService = Depends(get_audit_service)
):
    ip = request.client.host
    
    # Check lockout
    if await rate_limit.is_locked_out(ip, type):
        await audit.log_failed_auth(ip, type, "locked_out")
        raise HTTPException(status_code=429, detail="Too many failed attempts")
    
    try:
        # ... authentication logic ...
    except AuthenticationError as e:
        await rate_limit.record_failed_attempt(ip, type)
        await audit.log_failed_auth(ip, type, str(e))
        raise
```

### Acceptance Criteria
- [ ] Failed attempt tracking implemented with Redis
- [ ] Account lockout enforced after threshold
- [ ] All failed attempts logged to audit service
- [ ] Test added verifying lockout after max attempts
- [ ] Test added verifying lockout expires correctly
- [ ] Monitoring/alerting configured for failed auth patterns

### References
- Source reports: 6.3.1.md

### Priority
**Medium** - No protection against brute force attacks

---

## Issue: FINDING-025 - Default Site Admin Account Without Hard Production Block
**Labels:** bug, security, priority:medium
**Description:**
### Summary
If dev_stub is accidentally enabled in production (only a logged warning prevents this), an unauthenticated attacker gains full site administrator access with a well-known default account identifier. Site admins can bypass workspace boundaries per the application's design.

### Details
The `.dev-auth.yaml` configuration file contains a default `site_admin_1` account that can be accessed without credentials through the dev_stub authentication provider. The session service only logs a warning when dev_stub is enabled in non-development environments rather than blocking initialization entirely.

**ASVS:** 6.3.2 (Level L1)

**Affected Files:**
- `.dev-auth.yaml:37-41`
- `.dev-auth.yaml:43-44`
- `webapp/packages/api/user-service/auth/providers/dev_stub.py`

### Remediation
In dev_stub provider `__init__`, hard-fail if APP_ENV is production:

```python
import os

class DevStubProvider(AuthProvider):
    def __init__(self, config: dict):
        app_env = os.getenv("APP_ENV", "local").lower()
        if app_env not in ("local", "dev", "test"):
            raise RuntimeError(
                f"FATAL: dev_stub provider cannot be enabled in "
                f"APP_ENV={app_env}. This is a misconfiguration."
            )
        super().__init__(config)
        # ... rest of initialization
```

### Acceptance Criteria
- [ ] Hard production block implemented in dev_stub provider
- [ ] Test added verifying dev_stub fails in production
- [ ] Test added verifying dev_stub works in development
- [ ] Startup validation checks for misconfiguration
- [ ] Documentation updated with environment requirements

### References
- Source reports: 6.3.2.md

### Priority
**Medium** - Default credentials with admin access if misconfigured

---

## Issue: FINDING-026 - Cookie Names Lack Required __Secure- or __Host- Prefix
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ASVS 3.3.1 requires that if the __Host- prefix is not used for a cookie name, the __Secure- prefix must be used. All three authentication-related cookies use unprefixed names, removing a browser-enforced security constraint that prevents cookie injection from insecure contexts or subdomains.

### Details
Affected cookies:
- `gofannon_sid` (primary session identifier)
- `gofannon_auth_state` (OAuth CSRF token)
- `gofannon_return_to` (post-login redirect target)

The lack of prefix means the browser won't reject cookies set over non-HTTPS channels for this name. The __Secure- prefix instructs browsers to only accept cookies set with the Secure attribute, providing an additional browser-level enforcement layer.

**ASVS:** 3.3.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/services/session_service.py:35`
- `webapp/packages/api/user-service/routes_auth.py:114`
- `webapp/packages/api/user-service/routes_auth.py:122`
- `webapp/packages/api/user-service/routes_auth.py:188-194`

### Remediation
Update cookie names to use __Host- or __Secure- prefix:

```python
# In session_service.py
_COOKIE_NAME = "__Host-gofannon_sid"  # Preferred

# Or if Domain needs to be set:
_COOKIE_NAME = "__Secure-gofannon_sid"

# In routes_auth.py
AUTH_STATE_COOKIE = "__Secure-gofannon_auth_state"
RETURN_TO_COOKIE = "__Secure-gofannon_return_to"
```

When using __Host- prefix:
- Ensure `path="/"` is set
- Ensure `domain` is NOT set
- Ensure `secure=True` is always set

When using __Secure- prefix:
- Ensure `secure=True` is always set

Update all Cookie(alias=...) parameters and delete_cookie calls to use the new prefixed names.

### Acceptance Criteria
- [ ] All authentication cookies use __Host- or __Secure- prefix
- [ ] Cookie attributes configured correctly for chosen prefix
- [ ] Test added verifying cookie names have correct prefix
- [ ] Test added verifying cookies work across authentication flow
- [ ] Documentation updated with cookie naming requirements

### References
- Source reports: 3.3.1.md

### Priority
**Medium** - Missing browser-level cookie security enforcement

---

## Issue: FINDING-027 - Secure Attribute Conditionally Set Based on Scheme Auto-Detection
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The Secure attribute is determined by `_is_secure_cookie()` which checks `request.url.scheme == "https"`. This means in deployments behind TLS-terminating reverse proxies where forwarded headers are not properly configured, the session cookie will be sent without the Secure flag, allowing it to be transmitted over unencrypted HTTP connections.

### Details
In production deployments behind nginx/ALB that terminate TLS at the load balancer with internal HTTP traffic to the FastAPI app, if `--proxy-headers` is not configured in uvicorn, `request.url.scheme` returns "http" and the session cookie is set without the Secure flag. If a user ever visits an HTTP URL on the same domain, the session cookie is exposed in cleartext.

**ASVS:** 3.3.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/routes_auth.py:62-68`
- `webapp/packages/api/user-service/routes_auth.py:117`
- `webapp/packages/api/user-service/routes_auth.py:125`
- `webapp/packages/api/user-service/routes_auth.py:192`

### Remediation
**Option 1 (recommended):** Add environment-driven override:

```python
def _is_secure_cookie(request: Request) -> bool:
    """Determine if cookies should have Secure flag."""
    # Force secure in production
    force_secure = os.getenv("FORCE_SECURE_COOKIES", "true").lower() == "true"
    if force_secure:
        return True
    
    # Fall back to scheme detection for local dev
    return request.url.scheme == "https"
```

**Option 2:** Use __Host- prefix for session cookie which requires Secure=True at browser level

**Option 3:** Use __Secure- prefix which requires Secure=True at browser level

Document deployment requirement: uvicorn must be started with `--proxy-headers` behind TLS-terminating proxies.

### Acceptance Criteria
- [ ] Environment-driven secure cookie override implemented
- [ ] Test added verifying Secure flag in production config
- [ ] Test added verifying behavior in development config
- [ ] Deployment documentation updated with proxy-headers requirement
- [ ] Cookie prefix updated to enforce browser-level Secure requirement

### References
- Source reports: 3.3.1.md

### Priority
**Medium** - Session cookies may be transmitted over HTTP in production

---

## Issue: FINDING-028 - Previous Session Not Terminated on Re-authentication
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The callback handler does not accept/read the existing `gofannon_sid` cookie to terminate it before creating the new session. When a user re-authenticates, a new session is created and the cookie is overwritten, but the old session document persists in CouchDB and remains valid until TTL expiry.

### Details
This means compromised session tokens remain usable after re-authentication, contrary to the principle that re-authentication should reset the security state. While 256-bit session IDs make blind guessing infeasible, a stolen token retains validity.

**ASVS:** 7.2.4 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/routes_auth.py:127-189`

### Remediation
Read the existing `gofannon_sid` cookie in the callback handler and call `session_svc.delete(existing_sid)` before creating the new session:

```python
@router.get("/auth/callback/{type}")
async def login_callback(
    type: str,
    code: str,
    state: str,
    existing_sid: Optional[str] = Cookie(default=None, alias="gofannon_sid"),
    session_svc: SessionService = Depends(get_session_service),
    ...
):
    # Terminate previous session if it exists
    if existing_sid:
        try:
            await session_svc.delete(existing_sid)
        except Exception as e:
            # Log but don't fail authentication
            logger.warning(f"Failed to delete previous session: {e}")
    
    # ... continue with authentication and new session creation
```

### Acceptance Criteria
- [ ] Previous session termination implemented in callback handler
- [ ] Test added verifying old session is invalidated on re-auth
- [ ] Test added verifying new session is created successfully
- [ ] Test added verifying re-auth works when no previous session exists
- [ ] Error handling ensures authentication succeeds even if deletion fails

### References
- Source reports: 7.2.4.md

### Priority
**Medium** - Stolen sessions remain valid after re-authentication

---

## Issue: FINDING-029 - Workspace Role Permissions Not Mapped to Route-Level Access Controls
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `WorkspaceRole` type defines 'member' and 'admin' roles, and `MembershipSource` tracks where memberships originate, but there is no documentation or code artifact that maps these roles to specific function-level or data-level permissions.

### Details
- No documentation exists defining what 'admin' vs 'member' can do within a workspace
- No route annotations or permission matrices define required roles per endpoint
- The `require_admin_access` dependency checks a shared password unrelated to workspace roles
- The `get_current_user` dependency extracts workspaces from session but no downstream handler inspects role values

**ASVS:** 8.1.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/models/workspace.py:36-37`
- `webapp/packages/api/user-service/routes.py` (all route handlers)

### Remediation
Create an authorization matrix document (or in-code decorator annotations) mapping each route to required workspace role and ownership conditions:

```python
from enum import Enum
from functools import wraps

class WorkspacePermission(Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"

def requires_workspace_role(permission: WorkspacePermission):
    """Decorator to enforce workspace role requirements."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user and resource workspace from kwargs
            user = kwargs.get('user')
            resource_workspace = kwargs.get('workspace_id')
            
            # Check user has required permission in workspace
            user_role = get_user_role_in_workspace(user, resource_workspace)
            if not has_permission(user_role, permission):
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

@router.delete("/agents/{agent_id}")
@requires_workspace_role(WorkspacePermission.ADMIN)
async def delete_agent(agent_id: str, ...):
    """Only workspace admins can delete agents."""
    ...
```

### Acceptance Criteria
- [ ] Authorization matrix documented for all endpoints
- [ ] Role-based access control decorators implemented
- [ ] Test added verifying members cannot perform admin actions
- [ ] Test added verifying admins can perform admin actions
- [ ] Documentation includes permission model explanation

### References
- Source reports: 8.1.1.md

### Priority
**Medium** - Undefined authorization model for workspace roles

---

## Issue: FINDING-030 - run_deployed_agent Performs No Authorization Check on Agent Workspace Membership
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The deployed agent execution path only validates that a deployment exists by its friendly name, without checking whether the authenticated user has permission to invoke that agent.

### Details
The user-controlled `friendly_name` parameter leads to deployment lookup and agent code execution without workspace membership verification. Any authenticated user can execute any deployed agent by knowing or guessing the friendly name. Since friendly names are discoverable via `GET /deployments` and `GET /providers` (which lists gofannon models), this is easily exploitable.

**ASVS:** 8.3.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/dependencies.py:877-900`
- `webapp/packages/api/user-service/routes.py:779`

### Remediation
Implement resource-level ownership validation for deployed agent execution:

```python
async def validate_deployment_access(
    friendly_name: str,
    user: dict = Depends(get_current_user),
    db: DatabaseService = Depends(get_db)
):
    """Validate user has access to execute the deployment."""
    deployment = db.find_one('deployments', {'friendly_name': friendly_name})
    if not deployment:
        raise HTTPException(status_code=404, detail='Deployment not found')
    
    agent = db.get('agents', deployment['agent_id'])
    agent_workspace = agent.get('workspaceId')
    
    user_workspaces = {w['workspaceId'] for w in user.get('workspaces', [])}
    if agent_workspace not in user_workspaces and not user.get('is_site_admin'):
        raise HTTPException(status_code=403, detail='Access denied')
    
    return deployment

@router.post("/agents/deployed/{friendly_name}")
async def run_deployed_agent(
    friendly_name: str,
    deployment: dict = Depends(validate_deployment_access),
    ...
):
    ...
```

At minimum, associate a workspace_id or owner_uid with each resource and validate it against the authenticated user's workspace memberships before any read/write operation.

### Acceptance Criteria
- [ ] Workspace access validation implemented for deployed agent execution
- [ ] Test added verifying users cannot execute other workspaces' agents
- [ ] Test added verifying workspace members can execute their agents
- [ ] Test added verifying proper error responses (403/404)
- [ ] Similar validation applied to all resource access paths

### References
- Source reports: 8.3.1.md

### Priority
**Medium** - Authorization bypass for deployed agent execution

---

## Issue: FINDING-031 - Deployment Listing Exposes All Tenants' Deployed Agent Details
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `list_deployments_route` endpoint and `get_available_providers` function return all deployments from all tenants without filtering by workspace membership. All authenticated users can discover every deployed agent across all workspaces, including their friendly names, input schemas, and descriptions.

### Details
**Impact:** All authenticated users can discover every deployed agent across all workspaces, including their friendly names, input schemas, and descriptions. This information disclosure enables reconnaissance for further attacks.

**CWE:** CWE-639  
**ASVS:** 8.2.2 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/routes.py:582`
- `webapp/packages/api/user-service/dependencies.py` (various)

### Remediation
Scope deployment list endpoints to the user's workspace memberships:

```python
@router.get("/deployments")
async def list_deployments_route(
    user: dict = Depends(get_current_user),
    db: DatabaseService = Depends(get_db)
):
    """List deployments accessible to the user."""
    user_workspaces = {w['workspaceId'] for w in user.get('workspaces', [])}
    
    # Filter deployments by workspace membership
    all_deployments = db.find('deployments', {})
    accessible_deployments = []
    
    for deployment in all_deployments:
        agent = db.get('agents', deployment['agent_id'])
        agent_workspace = agent.get('workspaceId')
        
        if agent_workspace in user_workspaces or user.get('is_site_admin'):
            accessible_deployments.append(deployment)
    
    return accessible_deployments
```

Filter deployments by workspace_id based on the authenticated user's workspace memberships before returning results.

### Acceptance Criteria
- [ ] Deployment listing filtered by workspace membership
- [ ] Test added verifying users only see their workspaces' deployments
- [ ] Test added verifying site admins see all deployments
- [ ] Provider listing similarly filtered
- [ ] Performance optimized with database-level filtering

### References
- Related findings: FINDING-001, FINDING-002, FINDING-010, FINDING-011
- Source reports: 8.2.2.md

### Priority
**Medium** - Information disclosure enabling reconnaissance

---

## Issue: FINDING-032 - compile() Used Without Source Identification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `compile()` call uses the generic filename '&lt;string&gt;' which makes forensic analysis of errors and potential exploits harder. When exceptions occur in agent code, tracebacks will show 'File "&lt;string&gt;"' without identifying which agent or run produced the error.

### Details
Multiple concurrent agent executions produce indistinguishable stack traces, slowing incident response when investigating exploitation attempts.

**CWE:** CWE-778  
**ASVS:** 1.3.2 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/dependencies.py:293`

### Remediation
Include agent identifier in the compile filename for better forensics:

```python
# Generate descriptive source label
agent_name = agent_doc.get('name', 'unnamed')
trace_id = trace._stack[-1] if trace and trace._stack else 'no-trace'
source_label = f'<agent:{agent_name}:trace:{trace_id}>'

# Compile with descriptive filename
code_obj = compile(code, source_label, 'exec')
```

This ensures stack traces clearly identify which agent and execution context produced errors, enabling faster incident response and forensic analysis.

### Acceptance Criteria
- [ ] Agent identifier included in compile filename
- [ ] Test added verifying tracebacks show agent name
- [ ] Test added verifying multiple agents produce distinguishable traces
- [ ] Logging updated to include source labels
- [ ] Documentation updated with forensic analysis guidance

### References
- Related findings: FINDING-004
- Source reports: 1.3.2.md

### Priority
**Medium** - Impairs incident response and forensic analysis

---

## Issue: FINDING-033 - Database abstraction passes user-controllable path parameters to `db.find()` without explicit NoSQL injection sanitization
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `namespace` path parameter flows directly into the `db.find()` filter dictionary. While FastAPI ensures path parameters are strings (mitigating MongoDB-style operator injection), the `DatabaseService` abstraction does not provide any documented safety guarantees.

### Details
For backends like CouchDB that may use Mango selectors, or custom query builders, there is no explicit validation that filter values cannot be interpreted as operators or contain special characters that alter query semantics.

This is a Type B gap: the application uses a database abstraction layer (analogous to an ORM), but the abstraction doesn't explicitly enforce or document injection prevention for its `find()` method.

**CWE:** CWE-89  
**ASVS:** 1.2.4 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/routes.py:405`
- `webapp/packages/api/user-service/routes.py:420`

### Remediation
Add explicit input validation for all values passed to `db.find()` filters:

```python
import re

SAFE_NAMESPACE_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")

@router.get("/data-store/namespaces/{namespace}/records")
async def list_records(
    namespace: str,
    user: dict = Depends(get_current_user),
    db: DatabaseService = Depends(get_db)
):
    # Validate namespace format
    if not SAFE_NAMESPACE_PATTERN.match(namespace):
        raise HTTPException(
            status_code=400,
            detail="Invalid namespace format"
        )
    
    user_id = user.get("uid", "anonymous")
    docs = db.find(
        "agent_data_store",
        {"userId": user_id, "namespace": namespace}
    )
    return docs
```

Additionally, the `DatabaseService.find()` method should document and enforce that filter values are treated as literal equality matches, never as operators.

### Acceptance Criteria
- [ ] Input validation implemented for namespace parameters
- [ ] Test added verifying invalid namespaces are rejected
- [ ] Test added verifying valid namespaces work correctly
- [ ] DatabaseService.find() behavior documented
- [ ] Similar validation applied to all db.find() calls

### References
- Source reports: 1.2.4.md

### Priority
**Medium** - Potential NoSQL injection via undocumented abstraction layer

---

## Issue: FINDING-034 - Missing documented validation rules for business-critical numeric fields
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No documented constraints (min/max, allowed ranges) for numerical fields with clear business limits. `temperature` has well-known provider-specific ranges (0-2 for OpenAI), `max_tokens` should have an upper bound to prevent resource abuse, and `monthly_allowance`/`spend_remaining` should not accept negative values.

### Details
The lack of documented rules means developers implementing these fields cannot verify correctness.

Data flow: Client request → Pydantic model (type-checked only) → service layer → database/LLM provider

**Impact:** 
- Developers have no specification to implement against
- QA cannot verify business logic correctness
- Negative allowances or extreme token counts may propagate to downstream systems causing unexpected behavior

**ASVS:** 2.1.1 (Level L1)

**Affected Files:**
- `models/agent.py:107-112`
- `routes.py:138-151`

### Remediation
Add Field constraints documenting business rules:

```python
from pydantic import Field

class AgentConfig(BaseModel):
    max_tokens: Optional[int] = Field(
        None,
        alias="maxTokens",
        ge=1,
        le=200000,
        description="Maximum tokens for LLM response"
    )
    temperature: Optional[float] = Field(
        None,
        ge=0.0,
        le=2.0,
        description="LLM temperature (0.0-2.0)"
    )
    reasoning_effort: Optional[str] = Field(
        None,
        pattern="^(low|medium|high)$",
        description="Reasoning effort level"
    )

class AdminUpdateUserRequest(BaseModel):
    monthly_allowance: Optional[float] = Field(
        None,
        gt=0,
        le=100000,
        description="Monthly spend allowance in USD"
    )
```

### Acceptance Criteria
- [ ] Field constraints added to all business-critical numeric fields
- [ ] Test added verifying constraints are enforced
- [ ] Test added verifying valid values are accepted
- [ ] API documentation updated with valid ranges
- [ ] Error messages include valid range information

### References
- Source reports: 2.1.1.md

### Priority
**Medium** - Missing business logic validation enables abuse

---

## Issue: FINDING-035 - No documented format rules for URL-type inputs
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Fields that clearly represent URLs (`url`, `mcp_url`) have no documented format rules defining valid URL structures, allowed protocols (http/https only), or prohibited patterns (e.g., internal IPs, loopback addresses).

### Details
Without documented rules, SSRF protection is ad-hoc.

**Impact:** No clear specification for implementing SSRF protections; impossible to verify whether the application correctly restricts URL inputs.

**ASVS:** 2.1.1, 1.2.2 (Level L1)

**Affected Files:**
- `routes.py:131`
- `routes.py:124`

### Remediation
Use Pydantic's `AnyHttpUrl` type or add a validator:

```python
from pydantic import field_validator, AnyHttpUrl
from urllib.parse import urlparse

class FetchSpecRequest(BaseModel):
    url: AnyHttpUrl  # Enforces http/https only
    
    @field_validator('url')
    @classmethod
    def validate_url_not_internal(cls, v):
        """Prevent SSRF to internal addresses."""
        parsed = urlparse(str(v))
        hostname = parsed.hostname
        
        # Block internal IP ranges
        if hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
            raise ValueError('Internal URLs not allowed')
        
        # Block private IP ranges (simplified)
        if hostname.startswith(('10.', '172.16.', '192.168.')):
            raise ValueError('Private IP ranges not allowed')
        
        return v
```

### Acceptance Criteria
- [ ] URL validation implemented with protocol restrictions
- [ ] Test added verifying non-http/https URLs are rejected
- [ ] Test added verifying internal IPs are blocked
- [ ] Test added verifying private IP ranges are blocked
- [ ] Test added verifying valid external URLs work
- [ ] SSRF protection documented

### References
- Source reports: 2.1.1.md, 1.2.2.md

### Priority
**Medium** - Missing SSRF protection on URL inputs

---

## Issue: FINDING-036 - Provider and model fields not validated against allowed values
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The provider and model fields accept arbitrary strings without validation against the known set of providers from PROVIDER_CONFIG. The `_ensure_mutually_exclusive` validator accesses `PROVIDER_CONFIG.get(provider, {})` which silently returns empty for unknown providers, bypassing all parameter validation.

### Details
This is a business logic validation gap — the application has a known set of allowed providers but doesn't enforce it at input time.

**Impact:**
- Unknown provider/model combinations bypass parameter validation entirely
- Could cause confusing errors deep in processing rather than clear 422 rejections
- Provider selection logic may be exploitable depending on downstream implementation

**ASVS:** 2.2.1 (Level L1)

**Affected Files:**
- `models/chat.py:44`

### Remediation
Add a model validator to check against known providers:

```python
from pydantic import model_validator

class ChatMessage(BaseModel):
    provider: Optional[str] = None
    model: Optional[str] = None
    
    @model_validator(mode='after')
    def validate_provider_and_model(self):
        """Validate provider and model against PROVIDER_CONFIG."""
        if self.provider:
            if self.provider not in PROVIDER_CONFIG:
                raise ValueError(
                    f"Unknown provider: {self.provider}. "
                    f"Valid providers: {', '.join(PROVIDER_CONFIG.keys())}"
                )
            
            if self.model:
                provider_config = PROVIDER_CONFIG[self.provider]
                valid_models = provider_config.get('models', [])
                if valid_models and self.model not in valid_models:
                    raise ValueError(
                        f"Unknown model {self.model} for provider {self.provider}. "
                        f"Valid models: {', '.join(valid_models)}"
                    )
        
        return self
```

### Acceptance Criteria
- [ ] Provider validation implemented against PROVIDER_CONFIG
- [ ] Model validation implemented for each provider
- [ ] Test added verifying unknown providers are rejected
- [ ] Test added verifying unknown models are rejected
- [ ] Test added verifying valid combinations work
- [ ] Error messages include valid options

### References
- Source reports: 2.2.1.md

### Priority
**Medium** - Business logic bypass via invalid provider/model

---

## Issue: FINDING-037 - No range validation on business-critical numeric inputs
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Financial/billing fields accept any float value including negative numbers and extreme values. A negative `response_cost` would increase the user's remaining spend. A negative `monthly_allowance` has undefined business semantics.

### Details
**Impact:**
- Users could manipulate their billing by submitting negative costs
- Extremely large allowance values could overflow downstream calculations

**ASVS:** 2.2.1 (Level L1)

**Affected Files:**
- `routes.py:138`
- `routes.py:148`
- `routes.py:153`
- `models/agent.py:107`

### Remediation
Add Field constraints to enforce positive values and reasonable upper bounds:

```python
from pydantic import Field

class AdminUpdateUserRequest(BaseModel):
    monthly_allowance: Optional[float] = Field(
        None,
        gt=0,
        le=100000,
        description="Monthly spend allowance in USD (must be positive)"
    )

class UsageRecord(BaseModel):
    response_cost: float = Field(
        ...,
        ge=0,
        le=1000,
        description="Cost of LLM response in USD (must be non-negative)"
    )
```

Apply similar constraints to all financial and billing-related numeric fields.

### Acceptance Criteria
- [ ] Range validation implemented for all financial fields
- [ ] Test added verifying negative values are rejected
- [ ] Test added verifying extreme values are rejected
- [ ] Test added verifying valid values are accepted
- [ ] Business rules documented for all numeric fields

### References
- Source reports: 2.2.1.md

### Priority
**Medium** - Missing validation enables billing manipulation

---

## Issue: FINDING-038 - No length constraints on string inputs that control resource allocation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
String fields have no max_length constraints. An extremely long `content` field flows into LLM prompts (potential token cost abuse) and an extremely long name/description stores unbounded data in the database.

### Details
This enables:
- Denial of service through memory exhaustion
- Excessive LLM token consumption driving up costs
- Database storage abuse

**ASVS:** 2.2.1 (Level L1)

**Affected Files:**
- `models/agent.py:57`
- `models/agent.py:58`
- `models/chat.py:43`

### Remediation
Add max_length constraints appropriate to the business context:

```python
from pydantic import Field

class ChatMessage(BaseModel):
    content: str = Field(
        ...,
        max_length=100000,
        description="Message content (max 100k chars)"
    )

class Agent(BaseModel):
    name: str = Field(
        ...,
        max_length=200,
        description="Agent name (max 200 chars)"
    )
    description: Optional[str] = Field(
        None,
        max_length=2000,
        description="Agent description (max 2000 chars)"
    )
```

Apply reasonable limits based on UI and business requirements.

### Acceptance Criteria
- [ ] Length constraints added to all string fields
- [ ] Test added verifying oversized inputs are rejected
- [ ] Test added verifying valid-length inputs work
- [ ] Constraints documented in API documentation
- [ ] Error messages include maximum length

### References
- Source reports: 2.2.1.md

### Priority
**Medium** - Missing constraints enable resource exhaustion

---

## Issue: FINDING-039 - Operations log accumulates sensitive data previews destined for client-side UI with no cleanup mechanism
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The ops_log accumulates `valuePreview` entries containing up to 200 characters of actual stored data. The class documentation explicitly states this data is surfaced to a sandbox UI. If this data is transmitted to the client, it persists in the client's DOM or JavaScript memory with no cleanup mechanism.

### Details
There is no mechanism to:
- Clear the ops_log after session termination
- Set Clear-Site-Data header when the session ends
- Provide client-side cleanup callback or signal
- Evict old entries (ops_log grows unbounded during a session)

After session termination, value previews containing fragments of user data (potentially including sensitive information stored by agents) could remain in browser memory, DOM nodes, or JavaScript objects until the page is closed or garbage collected.

**ASVS:** 14.3.1 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/services/data_store_service.py:228-237`
- `webapp/packages/api/user-service/services/data_store_service.py:218-226`

### Remediation
Implement multi-layer cleanup:

**Server-side:** Ensure session termination endpoints emit Clear-Site-Data header:

```python
@router.post('/auth/logout')
async def logout(response: Response):
    response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    return {'status': 'logged_out'}
```

**Client-side:** Implement cleanup in the frontend consuming the ops_log:

```javascript
window.addEventListener('beforeunload', () => {
    opsLog = [];
    sessionStorage.clear();
    document.querySelectorAll('.ops-timeline').forEach(el => el.innerHTML = '');
});
```

**Service-side:** Add an explicit clear method:

```python
def clear_ops_log(self) -> None:
    """Clear the operations log."""
    if self._ops_log is not None:
        self._ops_log.clear()
```

### Acceptance Criteria
- [ ] Clear-Site-Data header added to logout endpoint
- [ ] Client-side cleanup implemented in frontend
- [ ] Service-side clear method implemented
- [ ] Test added verifying ops_log is cleared on logout
- [ ] Test added verifying Clear-Site-Data header is sent
- [ ] Documentation updated with data retention policies

### References
- Source reports: 14.3.1.md

### Priority
**Medium** - Sensitive data persists in client memory after logout

---

## Issue: FINDING-040 - Abstract auth provider interface does not enforce token validation requirements for OAuth token responses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `AuthProvider.__init__()` accepts a raw `config: dict` without any schema validation for key material sources. For OAuth providers that validate JWTs (ID tokens), the configuration should specify trusted JWKS URIs, expected issuers, and whether header claims like `jku`, `x5u`, `jwk` are ever followed.

### Details
The abstract interface does not:
1. Define required config keys for key material
2. Validate that key sources are from trusted, pre-configured URIs
3. Prohibit following untrusted key references in token headers

A misconfigured provider could accept key material references from within tokens themselves (e.g., following a `jku` header to an attacker-controlled JWKS endpoint), allowing token forgery.

**ASVS:** 9.1.1, 9.1.2, 9.1.3 (Level L1)

**Affected Files:**
- `webapp/packages/api/user-service/auth/base.py:104-116`

### Remediation
Document and optionally enforce key material requirements:

```python
class AuthProvider(ABC):
    # Required config keys that subclasses must validate in __init__
    REQUIRED_KEY_CONFIG = []  # Subclasses override, e.g., ["jwks_uri", "issuer"]
    
    def __init__(self, config: dict):
        self.config = config
        self._validate_key_config()
    
    def _validate_key_config(self):
        """Ensure key material sources are pre-configured, not dynamic."""
        for key in self.REQUIRED_KEY_CONFIG:
            if key not in self.config:
                raise ValueError(
                    f"Provider {self.type} requires '{key}' in config "
                    f"for trusted key material resolution"
                )
        
        # Ensure jwks_uri is a trusted, pre-configured value
        if 'jwks_uri' in self.config:
            jwks_uri = self.config['jwks_uri']
            if not jwks_uri.startswith('https://'):
                raise ValueError("jwks_uri must use HTTPS")
```

Additionally, document that:
- JWKS URIs must be pre-configured, never derived from token headers
- Token header claims like `jku`, `x5u`, `jwk` should never be followed
- Expected issuer must be pinned in configuration

### Acceptance Criteria
- [ ] Key material validation requirements documented
- [ ] REQUIRED_KEY_CONFIG mechanism implemented
- [ ] Test added verifying missing key config is rejected
- [ ] Test added verifying non-HTTPS JWKS URIs are rejected
- [ ] Documentation includes token validation security requirements
- [ ] Audit of existing providers for compliance

### References
- Source reports: 9.1.1.md, 9.1.2.md, 9.1.3.md

### Priority
**Medium** - Misconfiguration could enable token forgery

## Issue: FINDING-041 - No Application-Level TLS Protocol Version Enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The FastAPI application factory does not configure any TLS protocol version constraints. There is no application-level defense-in-depth ensuring TLS 1.2+ is enforced if the infrastructure layer is misconfigured or if the application is run directly during development.

### Details
The application has zero visibility into or control over TLS protocol negotiation. While infrastructure-level TLS termination is acceptable, the application should at minimum document and validate its deployment assumptions. If the infrastructure layer (cloud load balancer, reverse proxy) is misconfigured or if the application is ever run directly (e.g., during development with `uvicorn --host 0.0.0.0`), there is no application-level defense-in-depth.

**Affected Files:**
- `webapp/packages/api/user-service/app_factory.py` (entire file scope)

**ASVS:** 12.1.1 (L1)

### Remediation
For direct deployment, create an SSL context with minimum TLS version 1.2:
```python
import ssl

def create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')
    return ctx
```

Alternatively, add a startup check that verifies TLS is being terminated upstream:
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.getenv("REQUIRE_TLS_PROXY", "true").lower() == "true":
        if not os.getenv("TLS_TERMINATION_CONFIRMED"):
            logger.log(level="WARNING", event_type="security",
                       message="No TLS_TERMINATION_CONFIRMED env var. Ensure TLS 1.2+ is enforced at proxy.")
    yield
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 12.1.1.md

### Priority
Medium

---

## Issue: FINDING-042 - Default CORS Origin Uses HTTP Scheme — No HTTPS Enforcement for Frontend Communication
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The default `FRONTEND_URL` environment variable is `http://localhost:3000` (plaintext HTTP). The CORS configuration directly uses this value as the allowed origin without validating that it uses HTTPS in production deployments.

### Details
If `FRONTEND_URL` is accidentally left as default or configured with `http://` in production, the CORS policy explicitly permits cross-origin requests from an insecure origin. This means browsers will allow the insecure origin to make credentialed requests and there's no programmatic check ensuring the frontend communicates over HTTPS.

**Affected Files:**
- `webapp/packages/api/user-service/app_factory.py:28`

**ASVS:** 12.2.1, 3.4.2 (L1)

### Remediation
Add validation in the `_configure_cors()` function to check that `FRONTEND_URL` uses the HTTPS scheme in non-development environments. Raise a `ValueError` at startup if an HTTP origin is configured in production or staging environments, preventing deployment with insecure configuration.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 12.2.1.md, 3.4.2.md

### Priority
Medium

---

## Issue: FINDING-043 - No HTTP-to-HTTPS Redirect Middleware
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not include Starlette's `HTTPSRedirectMiddleware` or any equivalent mechanism to redirect plaintext HTTP requests to HTTPS.

### Details
If the application receives HTTP traffic (e.g., due to infrastructure misconfiguration or direct access), it will serve responses over plaintext. If a client connects over HTTP, the application will process the request and return sensitive data in plaintext, violating the requirement that communications 'do not fall back to insecure or unencrypted communications.'

**Affected Files:**
- `webapp/packages/api/user-service/app_factory.py:56-83`

**ASVS:** 12.2.1 (L1)

### Remediation
Add Starlette's `HTTPSRedirectMiddleware` to the middleware stack in production environments. Configure it to respect the `X-Forwarded-Proto` header set by load balancers. Only enable this middleware when `ENVIRONMENT` is not set to 'development' to avoid interfering with local development workflows.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 12.2.1.md

### Priority
Medium

---

## Issue: FINDING-044 - No Certificate Configuration or Validation Visible in Application Code
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application factory does not configure any TLS certificate (neither server certificates for serving HTTPS nor CA bundles for validating upstream services). There is no evidence of certificate pinning, OCSP stapling configuration, or certificate transparency enforcement.

### Details
Without application-level certificate configuration or deployment validation checks: (1) There is no defense-in-depth ensuring publicly trusted certificates are used, (2) Self-signed or internal CA certificates could be deployed without application-level detection, (3) Certificate rotation failures would not trigger application-level alerts.

**Affected Files:**
- `webapp/packages/api/user-service/app_factory.py` (entire file scope)

**ASVS:** 12.2.2 (L1)

### Remediation
Add a startup health check that validates the deployment's certificate configuration using ssl.create_default_context() to verify the service is reachable via publicly-trusted TLS. The function should verify certificates against system CA bundle and log verification status. Additionally, document the requirement in deployment manifests that TLS certificates MUST be from publicly-trusted CAs (Let's Encrypt, DigiCert, etc.) and that self-signed certificates are NOT acceptable. Add HSTS middleware with max-age=31536000; includeSubDomains, add HTTPS scheme validation for FRONTEND_URL in non-development environments, and add HTTPSRedirectMiddleware for production deployments.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 12.2.2.md

### Priority
Medium

---

## Issue: FINDING-045 - Wildcard CORS methods allow all HTTP methods without visible Sec-Fetch-* validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The CORS configuration uses allow_methods: ["*"] which permits all HTTP methods cross-origin. No visible Sec-Fetch-* header validation exists, and no global middleware enforces that state-changing operations use only POST/PUT/PATCH/DELETE.

### Details
Without seeing route definitions, the risk is that GET requests to sensitive endpoints could trigger state changes (e.g., /api/v1/agents/{id}/execute?action=delete). If any state-changing or resource-intensive endpoints respond to GET requests, they can be exploited via simple resource loads (&lt;img&gt;, &lt;script&gt;, &lt;link&gt;) or navigation, bypassing CORS entirely since these are not cross-origin script requests.

**Affected Files:**
- `webapp/packages/api/user-service/app_factory.py:31`

**ASVS:** 3.5.3 (L1)

### Remediation
1. Ensure all sensitive endpoints use appropriate HTTP methods at the route level (POST/PUT/PATCH/DELETE, not GET). 
2. Add Sec-Fetch-* validation middleware for defense-in-depth to block cross-site navigation requests to API endpoints. 
3. Restrict CORS methods to only those needed: allow_methods: ["GET", "POST", "PUT", "PATCH", "DELETE"] instead of wildcard. 
4. Replace allow_headers: ["*"] with explicit header list: ["Content-Type", "Authorization", "X-Requested-With"].

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 3.5.3.md

### Priority
Medium

---

## Issue: FINDING-046 - Session configuration endpoint returns unfiltered database document
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The endpoint returns raw database document content without a `response_model` or explicit field selection. The `provider_config` sub-document is returned directly from the database service with no schema-based filtering.

### Details
Any field stored in that sub-document (including potentially sensitive internal metadata, revision fields, or inadvertently stored secrets) will be exposed to the client.

**Affected Files:**
- `webapp/packages/api/user-service/routes.py:410-414`

**ASVS:** 15.3.1 (L1)

### Remediation
Define and apply a Pydantic response model (ProviderConfig) to the endpoint. Example: 
```python
@router.get("/sessions/{session_id}/config", response_model=ProviderConfig)
```
and return `ProviderConfig(**config_data)` instead of raw dictionary.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 15.3.1.md

### Priority
Medium

---

## Issue: FINDING-047 - Provider configuration endpoints expose internal implementation details
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Provider configuration endpoints return the full output of `get_available_providers()` or sub-objects thereof without any `response_model`. This function returns provider configuration dictionaries that may contain internal implementation details.

### Details
Endpoint URLs, pricing metadata, capability flags, internal identifiers not intended for client consumption may be exposed.

**Affected Files:**
- `webapp/packages/api/user-service/routes.py:206-237`

**ASVS:** 15.3.1 (L1)

### Remediation
Define explicit Pydantic response models (ProviderResponse, ProviderDetailResponse, ModelSummary) that declare only the fields needed by clients. Apply these models using the response_model parameter on all provider-related endpoints.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 15.3.1.md

### Priority
Medium

---

## Issue: FINDING-048 - Agent chain and deployment endpoints return unfiltered service data
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Agent chain and deployment endpoints return service function results without `response_model` filtering. The `build_agent_chain()` function walks transitive dependencies and may include internal IDs, raw database document fields, or infrastructure details.

### Details
MCP server URLs, internal routing information that should be filtered before client delivery may be exposed.

**Affected Files:**
- `webapp/packages/api/user-service/routes.py:469-481`
- `webapp/packages/api/user-service/routes.py:586-589`

**ASVS:** 15.3.1 (L1)

### Remediation
Define response models (ChainNode, DeploymentInfo) that explicitly declare the fields needed by the Chain View UI. Apply these models to the agent chain and deployment endpoints to filter out internal infrastructure details.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 15.3.1.md

### Priority
Medium

---

## Issue: FINDING-049 - Missing charset parameter in text/event-stream Content-Type header
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The Server-Sent Events (SSE) streaming endpoint sets `media_type="text/event-stream"` without including the `charset=utf-8` parameter.

### Details
Since `text/event-stream` is a `text/*` content type, the ASVS requirement mandates a charset specification. Without it, intermediary proxies or older clients could misinterpret the character encoding, potentially leading to content misinterpretation or injection vectors in multi-byte character contexts. If a reverse proxy or client has a different default charset assumption (e.g., ISO-8859-1 per HTTP/1.1 spec for text/* without charset), multi-byte UTF-8 characters in agent trace output could be misinterpreted.

**Affected Files:**
- `webapp/packages/api/user-service/routes.py:600-744`

**ASVS:** 4.1.1 (L1)

### Remediation
Add charset parameter to the media_type. Change `media_type="text/event-stream"` to `media_type="text/event-stream; charset=utf-8"` in the StreamingResponse call.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 4.1.1.md

### Priority
Medium

---

## Issue: FINDING-050 - No size constraints on swagger specification content accepted for processing
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `swagger_specs` accept content with a `name` and `content` field. There is no validation that the spec has an expected extension, contains valid OpenAPI/Swagger specification content, or that the content type matches what `spec.name` implies.

### Details
If the parser doesn't validate, malicious content (e.g., YAML bombs, XXE in XML-based specs, or binary content) could be processed. If the parser handles multiple formats (JSON, YAML, XML), unexpected content types could trigger parser-specific vulnerabilities. Even without exploitation, non-spec content wastes processing resources.

**Affected Files:**
- `webapp/packages/api/user-service/agent_factory/__init__.py:34-41`
- `webapp/packages/api/user-service/agent_factory/__init__.py:191`

**ASVS:** 5.2.1, 5.2.2 (L1)

### Remediation
Validate file extension against allowed list (ALLOWED_SPEC_EXTENSIONS = {'.json', '.yaml', '.yml'}). Validate content matches expected format by checking if JSON content starts with '{' or '[', and implementing similar checks for YAML. Apply os.path.splitext() to extract and validate extension. Raise ValueError for unsupported formats or mismatched content-extension pairs.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 5.2.1.md, 5.2.2.md

### Priority
Medium

---

## Issue: FINDING-051 - Ticket Retrieval Lacks Ownership Verification (Authorization Step Absent)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The get_ticket_status() function retrieves ticket data without verifying that the requesting user owns the ticket. There is no session_id comparison or ownership verification.

### Details
Any authenticated user can retrieve any other user's chat tickets if they can guess or enumerate UUID ticket IDs. The ticket contains sensitive data: messages, session_id, model used, and full LLM responses. While UUIDs are hard to guess, if ticket IDs are exposed in URLs or logs, cross-user data access is possible.

**Affected Files:**
- `webapp/packages/api/user-service/services/chat_service.py:109-117`

**ASVS:** 2.3.1 (L1)

### Remediation
Add session_id parameter to get_ticket_status(). After loading ticket data, verify that ticket_data.get('session_id') matches the requesting user's session_id. Return None or raise 403 if ownership verification fails. This ensures the authorization step is not skipped in the business logic flow.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 2.3.1.md

### Priority
Medium

---

## Issue: FINDING-052 - No Documented Configuration for Preventing Malicious Account Lockout via Spend Allowance
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The spend allowance mechanism in llm_service.py lacks documentation defining how require_allowance() differentiates between legitimate high-usage and malicious behavior.

### Details
Without documented configuration, operators cannot properly configure the system to prevent: attackers from exhausting user budgets via stolen session tokens, legitimate users being locked out due to automated integrations, or cost-based denial-of-service attacks. There is no documentation on whether attackers can deliberately exhaust user allowances via compromised sessions, how allowances reset, whether alerts are sent when users approach limits, and whether separate rate-based limits prevent burst consumption.

**Affected Files:**
- `webapp/packages/api/user-service/services/llm_service.py:113-115`

**ASVS:** 6.1.1 (L1)

### Remediation
Create comprehensive documentation covering: allowance structure (monthly allowance per user configurable via admin panel, reset on 1st of month at 00:00 UTC, 10% over-limit grace period for in-flight requests), abuse prevention mechanisms (max 5 simultaneous LLM calls per user, burst detection triggering temporary rate limit after >20 requests in 60s, alerts at 80% and 95% of allowance), and recovery procedures (emergency allowance increase via support, admin reset capability without waiting for monthly cycle, session token revocation without affecting allowance).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 6.1.1.md

### Priority
Medium

---

## Issue: FINDING-053 - No Circuit Breaker or Backpressure Documentation for External LLM Service Failures
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The retry logic in llm_service.py handles timeouts but lacks circuit breaker functionality to stop calling failed providers after repeated failures.

### Details
During an LLM provider outage, all user requests will queue up with 600-second timeouts, consuming server resources (memory, connections, asyncio tasks) without producing results, potentially cascading into full service outage. There is no documentation of system behavior under sustained LLM provider outage, backpressure mechanisms to reject new requests when external services are degraded, and documentation of how MAX_TIMEOUT_RETRIES and LLM_TIMEOUT_SECONDS should be configured for different deployment scenarios.

**Affected Files:**
- `webapp/packages/api/user-service/services/llm_service.py:256-268`

**ASVS:** 6.1.1 (L1)

### Remediation
Document and implement circuit breaker configuration with: failure threshold (5 failures in 30 seconds triggers circuit open), circuit open duration (60 seconds before half-open probe), half-open state (1 probe request allowed, success closes circuit). Configure timeouts appropriately (LLM_TIMEOUT_SECONDS: 120 for production instead of 600 default, LLM_TIMEOUT_RETRIES: 1 for production instead of 0 default, total max wait 240s). Implement backpressure with max 50 concurrent LLM calls per instance and HTTP 503 responses with Retry-After headers for queue overflow.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 6.1.1.md

### Priority
Medium

---

## Issue: FINDING-054 - No Evidence of Documented Risk-Based Remediation Timeframes for Third-Party Components
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application lacks documented risk-based remediation timeframes for third-party component vulnerabilities. Third-party libraries are used throughout the application runtime with no referenced policy governing update cadence or vulnerability remediation deadlines.

### Details
No code comments, configuration files, or documentation references define SLA timelines for vulnerability remediation. No SBOM file reference or generation mechanism is visible. LiteLLM is identified as a critical trust point but the codebase shows no corresponding classification or tiered remediation policy. Without documented remediation timeframes, teams lack clear deadlines for patching known vulnerabilities, prioritization becomes ad-hoc rather than risk-based, compliance audit evidence cannot demonstrate timely response to disclosed CVEs, and critical components may remain unpatched during active exploitation.

**Affected Files:**
- `webapp/packages/api/user-service/services/llm_service.py:1-20`
- `webapp/packages/api/user-service/app_factory.py:1-10`

**ASVS:** 15.1.1 (L1)

### Remediation
Create a DEPENDENCY_POLICY.md or equivalent governance document defining risk classification criteria and remediation SLAs. Classify components as Critical/High/Medium/Low based on criteria such as handling auth, secrets, or direct user input. Define remediation SLAs from CVE publication date: Critical components with Critical vulnerabilities (CVSS 9.0+) should be remediated within 24 hours, Critical components with High vulnerabilities (CVSS 7.0-8.9) within 72 hours, etc. Establish regular update cadence with Critical components reviewed monthly minimum and all components on quarterly update cycle. Implement automated scanning daily via dependabot/pip-audit/npm audit. Reference this policy in code comments and generate SBOM using scripts/generate_sbom.sh.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 15.1.1.md

### Priority
Medium

---

## Issue: FINDING-055 - No Automated Mechanism to Enforce Dependency Update SLA Compliance
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No CI/CD gate or runtime check visible that validates dependencies against known CVE databases. No version assertion or compatibility check for LiteLLM at startup.

### Details
The code uses `litellm.aresponses` which is a relatively new API; older vulnerable versions might not have it but could silently fail. No `pip-audit`, `safety`, or equivalent integration referenced in the codebase. No deployment-time SBOM validation against a vulnerability database. Without a documented remediation timeframe (ASVS 15.1.1), compliance with update deadlines cannot be verified or enforced.

**Affected Files:**
- `webapp/packages/api/user-service/app_factory.py` (entire file)
- `webapp/packages/api/user-service/services/llm_service.py:1-20`

**ASVS:** 15.2.1 (L1)

### Remediation
Implement multi-layer dependency compliance: (1) Create scripts/check_dependency_compliance.py to run in CI/CD and optionally at application startup, validating all dependencies against documented SLA timeframes using pip-audit with severity-based remediation deadlines (critical: 24h, high: 7d, medium: 30d, low: 90d). (2) Add runtime dependency version logging at startup in app_factory.py to log critical dependency versions (litellm, fastapi) for audit trail. (3) Add minimum version assertions for LiteLLM to fail fast if incompatible/vulnerable version is deployed. (4) Configure Dependabot/Renovate with update schedules aligned to remediation policy. (5) Implement supply chain verification using pip install --require-hashes.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 15.2.1.md

### Priority
Medium

---

## Issue: FINDING-056 - No Defense-in-Depth Middleware to Block Source Control Metadata Paths
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not register any middleware or route guard that explicitly blocks requests to well-known source control metadata paths (e.g., /.git/config, /.git/HEAD, /.svn/entries).

### Details
While FastAPI will return 404 for undefined routes, if the application is deployed behind a reverse proxy that serves static files from the application directory (common with nginx try_files patterns), source control metadata could be exposed. An attacker who gains access to .git/ can reconstruct the entire source code repository, including historical commits that may contain secrets, internal architecture details, and configuration that aids further attacks.

**Affected Files:**
- `webapp/packages/api/user-service/app_factory.py:55`

**ASVS:** 13.4.1 (L1)

### Remediation
Add middleware to explicitly block requests to source control metadata paths. Implement BlockSensitivePathsMiddleware that blocks prefixes like /.git, /.svn, /.hg, /.env, /.bzr by returning 404 responses. Register this middleware in the create_app() function before other middleware to ensure it executes first.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 13.4.1.md

### Priority
Medium

---

## Issue: FINDING-057 - OAuth Access Tokens Stored on Mutable Object Without Clear Lifecycle
**Labels:** bug, security, priority:low
**Description:**
### Summary
OAuth access tokens from upstream providers are attached to UserInfo dataclass objects as ad-hoc private attributes using dynamic attribute assignment (e.g., user_info._access_token). While these tokens appear to be short-lived and scoped to a single request, the lifecycle is implicit and the pattern lacks explicit cleanup.

### Details
The use of type: ignore[attr-defined] annotations indicates recognized design smell. If UserInfo objects are ever serialized (logged, cached, stored), tokens could leak. Current code does not persist these tokens, but the pattern creates risk for future code changes.

**Affected Files:**
- `auth/providers/github.py:153`
- `auth/providers/google.py:172`
- `auth/providers/microsoft.py:156`

**ASVS:** 10.4.5 (L1)

### Remediation
Refactor to use an explicit ExchangeResult context object that separates concerns. Create a dataclass with user_info and access_token fields, use the token for membership queries within the exchange_code method, then return only the UserInfo object so the token goes out of scope. Alternatively, add explicit token cleanup by deleting the _access_token attribute at the end of exchange_code after all token usage is complete.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: CWE-922
- Source: 10.4.5.md

### Priority
Low

---

## Issue: FINDING-058 - Dev_Stub Provider Authorization Codes Are Reusable
**Labels:** bug, security, priority:low
**Description:**
### Summary
In the dev_stub flow, authorization "codes" (user UIDs) can be reused indefinitely. Each use creates a new session. While this is by design for development, it means there is no single-use enforcement.

### Details
No token revocation occurs on reuse. Severity is LOW because: (1) dev_stub is explicitly dev-only, (2) the CSRF state cookie provides a 10-minute window, and (3) real OAuth providers handle single-use enforcement externally.

**Affected Files:**
- `webapp/packages/api/user-service/auth/providers/dev_stub.py` (exchange_code method)

**ASVS:** 10.4.2 (L1)

### Remediation
For completeness in the dev_stub (useful if it's ever used in integration testing that should mirror production behavior), track used nonces and reject reuse:
```python
class DevStubProvider(AuthProvider):
    def __init__(self, config: dict):
        super().__init__(config)
        self._used_nonces: set = set()
    
    async def exchange_code(self, code: str, redirect_uri: str, nonce: str = "") -> UserInfo:
        key = f"{nonce}:{code}"
        if key in self._used_nonces:
            raise ValueError("Authorization code already used")
        self._used_nonces.add(key)
        ...
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 10.4.2.md

### Priority
Low

---

## Issue: FINDING-059 - Dev_Stub Authorization Codes Have No Expiration
**Labels:** bug, security, priority:low
**Description:**
### Summary
The dev_stub provider's "authorization codes" are static user UIDs that never expire. However, the indirect protection comes from the CSRF state cookie which has a 10-minute TTL (max_age=600).

### Details
After the state cookie expires, the callback CSRF check fails, effectively providing a 10-minute window. For real OAuth providers, code lifetime is managed by the external authorization server (typically 30-60 seconds for Google/Microsoft, 10 minutes for GitHub). The 10-minute state cookie aligns with the ASVS L1 maximum of 10 minutes for authorization codes, providing adequate protection for the overall flow even though the dev_stub code itself doesn't expire.

**Affected Files:**
- `webapp/packages/api/user-service/auth/providers/dev_stub.py`

**ASVS:** 10.4.3 (L1)

### Remediation
Implement application-side code timestamp validation for dev_stub. Although the state cookie provides a 10-minute window, explicit code expiration would provide defense-in-depth and align with authorization server best practices.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 10.4.3.md

### Priority
Low

---

## Issue: FINDING-060 - Admin Panel Authorization Model Undocumented and Separate from Workspace RBAC
**Labels:** bug, security, priority:low
**Description:**
### Summary
The admin panel uses a shared secret (X-Admin-Password) that is unrelated to the workspace RBAC model (WorkspaceRole, site admin via auth.yaml). There is no documentation defining how these two authorization systems relate or when each should be used.

### Details
Two parallel authorization mechanisms (shared password vs. session-based site admin) create confusion about which grants access where, increasing risk of accidental privilege grants.

**Affected Files:**
- `webapp/packages/api/user-service/dependencies.py:109-114`

**ASVS:** 8.1.1 (L1)

### Remediation
Unify the admin authorization model by replacing or supplementing the shared-password admin panel with the session-based is_site_admin flag, providing per-actor attribution. Document how the two authorization systems relate and when each should be used.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 8.1.1.md

### Priority
Low

---

## Issue: FINDING-061 - Authorization Enforcement Occurs Correctly at Server Layer (Positive Finding with Gap Note)
**Labels:** bug, security, priority:low
**Description:**
### Summary
All authorization checks are performed server-side via FastAPI dependency injection. No authorization logic is delegated to or relies on client-side enforcement. The get_current_user dependency validates sessions/tokens at the trusted service layer.

### Details
While the enforcement location is correct (server-side), the enforcement completeness is deficient (authentication without authorization for most resource operations, as documented in 8.2.1 and 8.2.2 findings).

**Affected Files:**
- `webapp/packages/api/user-service/routes.py`

**ASVS:** 8.3.1 (L1)

### Remediation
While the enforcement layer is correct, implement complete authorization checks as documented in the immediate and short-term recommendations. Ensure that authentication is not conflated with authorization and that workspace-based access control is enforced for all resource operations.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 8.3.1.md

### Priority
Low

---

## Issue: FINDING-062 - Error messages containing user-controlled input serialized into SSE JSON without explicit sanitization context
**Labels:** bug, security, priority:low
**Description:**
### Summary
While `json.dumps` properly encodes the content for JSON consumption (escaping quotes, backslashes, control characters), the error string may contain user-controlled input from `input_dict` or code execution output.

### Details
If a consuming client parses this JSON and renders the error message in a DOM context (e.g., `innerHTML`), the JSON encoding alone doesn't prevent XSS in the browser. This is a defense-in-depth concern — the primary protection must be in the consuming client. The risk is only if consuming clients improperly handle the decoded values.

**Affected Files:**
- `routes.py:324-329`
- `routes.py:338`

**ASVS:** 1.2.3 (L1)

### Remediation
Document that SSE consumers must treat `error` and `result` fields as untrusted when rendering in DOM contexts. Optionally, strip HTML-significant characters from error messages:
```python
import re
final["error"] = re.sub(r'[<>&"\']', '', f"{type(e).__name__}: {e}")
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 1.2.3.md

### Priority
Low

---

## Issue: FINDING-063 - Session and ticket IDs from path parameters used directly in `db.get()` without format validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
Multiple endpoints pass user-controlled path parameters directly to `db.get()` as document IDs. While ID-based lookups are inherently safe against injection in most NoSQL databases, there's no validation that these IDs conform to expected formats (UUID, etc.).

### Details
If the `DatabaseService` implementation for CouchDB constructs REST URLs like `/{db}/{id}`, malformed IDs could potentially lead to path traversal within the CouchDB HTTP API. Direct ID lookups in NoSQL databases are generally safe. The risk exists only if the underlying implementation concatenates the ID into a URL or query string without encoding.

**Affected Files:**
- `webapp/packages/api/user-service/routes.py` (multiple)

**ASVS:** 1.2.4 (L1)

### Remediation
Validate that document IDs conform to the expected format:
```python
UUID_PATTERN = re.compile(r"^[a-f0-9\-]{36}$")

@router.get("/agents/{agent_id}", response_model=Agent)
async def get_agent(agent_id: str, ...):
    if not UUID_PATTERN.match(agent_id):
        raise HTTPException(status_code=400, detail="Invalid agent ID format")
    agent_doc = db.get("agents", agent_id)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: CWE-20
- Source: 1.2.4.md

### Priority
Low

---

## Issue: FINDING-064 - No HTML sanitization on user-generated content fields stored for potential frontend rendering
**Labels:** bug, security, priority:low
**Description:**
### Summary
Fields like description, name, docstring, and SwaggerSpec.content in agent models accept arbitrary string content without server-side sanitization. While these are returned as JSON and not rendered as HTML by the server, they flow to the frontend where they may be rendered in the DOM.

### Details
If the frontend uses unsafe rendering patterns like dangerouslySetInnerHTML, this could result in stored XSS affecting other users viewing the same agent. The risk is LOW because modern frameworks like React escape by default, but the lack of server-side sanitization creates a dependency on correct frontend implementation.

**Affected Files:**
- `webapp/packages/api/user-service/models/agent.py`

**ASVS:** 1.3.1 (L1)

### Remediation
For fields expected to contain rich text or markdown, apply server-side sanitization using a library like bleach or nh3. Example: Use a Pydantic field_validator to sanitize the description field with nh3.clean(v) which strips dangerous HTML while preserving safe content. This provides defense-in-depth regardless of frontend implementation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: CWE-79
- Source: 1.3.1.md
- Related: FINDING-014, FINDING-023

### Priority
Low

---

## Issue: FINDING-065 - Missing documented validation rules for string-identity fields
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `email` field has no format documentation (e.g., RFC 5322 pattern), `provider` has no documented allow-list of valid values, and `display_name` has no length constraints.

### Details
These are common data formats for which ASVS 2.1.1 expects explicit documented rules.

**Affected Files:**
- `models/user.py:36`
- `routes.py:218`

**ASVS:** 2.1.1 (L1)

### Remediation
Add `EmailStr` for email, `Literal` or `pattern` for provider, and `max_length` for display_name.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 2.1.1.md

### Priority
Low

---

## Issue: FINDING-066 - UpdateApiKeyRequest.provider not validated against allowed provider list
**Labels:** bug, security, priority:low
**Description:**
### Summary
The provider field is not validated against the known set of API key providers defined in ApiKeys model (openai, anthropic, gemini, perplexity, openrouter).

### Details
Invalid provider names may cause silent failures or unexpected database writes depending on the update_api_key implementation.

**Affected Files:**
- `routes.py:218`

**ASVS:** 2.2.1 (L1)

### Remediation
Add a regex pattern constraint to the provider field to validate against the known set of providers: pattern="^(openai|anthropic|gemini|perplexity|openrouter)$". Also add min_length=1 to api_key field.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 2.2.1.md

### Priority
Low

---

## Issue: FINDING-067 - Document IDs embed user identifiers suitable for URL path exposure
**Labels:** bug, security, priority:low
**Description:**
### Summary
The composite document ID format `{user_id}:{namespace}:{base64_key}` embeds the user identifier directly. If REST endpoints expose these IDs in responses, and if downstream route handlers construct URLs like `/api/datastore/{doc_id}`, the user_id becomes part of the URL path.

### Details
While `user_id` is an identifier rather than a secret credential, the `key` parameter (base64-encoded) could contain sensitive descriptors. Base64 is encoding, not encryption—it's trivially reversible. Low risk unless route handlers pass these as URL query parameters.

**Affected Files:**
- `webapp/packages/api/user-service/services/data_store_service.py:72`

**ASVS:** 14.2.1 (L1)

### Remediation
Ensure route handlers serving this data use POST request bodies for operations that accept `key` or `namespace` values that could be sensitive, and avoid exposing composite doc_ids in URLs. Example: Use POST body with sensitive identifiers `@router.post("/datastore/get") async def get_data(request: DataStoreGetRequest, user=Depends(get_current_user)): return service.get(user.id, request.namespace, request.key)`. Avoid GET with sensitive key in URL like `@router.get("/datastore/{namespace}/{key}")` as key would be visible in server logs and browser history.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 14.2.1.md

### Priority
Low

---

## Issue: FINDING-068 - No Clear-Site-Data header implementation in the codebase
**Labels:** bug, security, priority:low
**Description:**
### Summary
The provided codebase contains no implementation of the Clear-Site-Data HTTP response header. While this is service-layer code (not route/middleware code), the absence across the entire provided scope suggests the application may not implement this control anywhere.

### Details
The ASVS requirement specifically mentions this header as a mechanism for server-initiated client data cleanup. This could be implemented in middleware or route handlers not provided in this audit scope. This finding has low confidence without seeing the full application.

**Affected Files:**
None specified

**ASVS:** 14.3.1 (L1)

### Remediation
Implement Clear-Site-Data in the logout/session-termination endpoint and in session expiry middleware:
```python
from fastapi import Response
from starlette.middleware.base import BaseHTTPMiddleware

class SessionCleanupMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if getattr(request.state, 'session_terminated', False):
            response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
        return response
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 14.3.1.md

### Priority
Low

---

## Issue: FINDING-069 - Defense-in-Depth Gap in refresh_workspaces
**Labels:** bug, security, priority:low
**Description:**
### Summary
The refresh_workspaces() method operates on a Session object without independently verifying that session.expires_at has not passed. While the intended call flow is get_by_id() → (expiry validated) → refresh_workspaces(), there is no defense-in-depth check within the method itself.

### Details
Potential misuse scenario: Future developer loads a session document directly from the database (bypassing get_by_id()), calls refresh_workspaces() on the expired session, and the session is re-saved to database with updated last_refresh_at — effectively 'touching' an expired session. Current Risk Assessment: LOW — The code structure strongly implies get_by_id() is always called first. This is an observation about missing defense-in-depth, not a current exploit path.

**Affected Files:**
- `webapp/packages/api/user-service/services/session_service.py:156-210`

**ASVS:** 9.2.1 (L1)

### Remediation
Add an independent expiry check at the beginning of refresh_workspaces():
```python
async def refresh_workspaces(self, session: Session) -> Tuple[Session, "RefreshDiff"]:
    """Re-query the provider for current memberships; update the session."""
    # Defense-in-depth: reject expired sessions even if caller failed to check
    if session.expires_at <= datetime.utcnow():
        raise HTTPException(status_code=401, detail="Session expired")
    registry = get_registry()
    provider = registry.get(session.provider_type)
    ...
```
Estimated Remediation Effort: Minimal (< 1 hour)

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 9.2.1.md

### Priority
Low

---

## Issue: FINDING-070 - Fetch interceptor does not enforce `Accept: application/json` header on API requests
**Labels:** bug, security, priority:low
**Description:**
### Summary
The fetch interceptor wraps all API calls to add `credentials: 'include'` but does not enforce an `Accept: application/json` header.

### Details
While server-side content-type enforcement is the primary defense, sending an explicit `Accept` header provides defense-in-depth by signaling to the server that only JSON responses are expected. If an intermediate proxy or CDN serves cached responses with incorrect content types, the lack of `Accept` header means the client hasn't communicated its expected context. Minimal direct impact because response bodies are consumed programmatically via `resp.json()` (which would throw on non-JSON content). However, this reduces the signal available for server-side Sec-Fetch validation and content negotiation.

**Affected Files:**
- `webapp/packages/webui/src/services/fetchInterceptor.js:43-47`

**ASVS:** 3.2.1 (L1)

### Remediation
Extend the fetch interceptor to automatically set `Accept: application/json` header on all API requests:
```javascript
window.fetch = async (input, init = {}) => {
    if (apiMatches(input)) {
      const headers = new Headers(init.headers || {});
      if (!headers.has('Accept')) {
        headers.set('Accept', 'application/json');
      }
      init = { 
        ...init, 
        headers,
        credentials: init.credentials || 'include' 
      };
    }
    return originalFetch(input, init);
};
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 3.2.1.md

### Priority
Low

---

## Issue: FINDING-071 - Deployed agent execution endpoint lacks response envelope
**Labels:** bug, security, priority:low
**Description:**
### Summary
The deployed agent execution endpoint returns the full result from `run_deployed_agent_logic()` without a `response_model`. While agent output is inherently dynamic, the lack of any response envelope or filtering means internal execution metadata could leak alongside the intended result.

### Details
Without a defined response structure, internal execution details may be exposed to clients.

**Affected Files:**
- `webapp/packages/api/user-service/routes.py:810-827`

**ASVS:** 15.3.1 (L1)

### Remediation
Wrap the response in a defined envelope model (DeployedAgentResponse) with explicit fields for result and status. Apply this model using the response_model parameter to ensure consistent response structure and prevent metadata leakage.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 15.3.1.md

### Priority
Low

---

## Issue: FINDING-072 - MCP tools endpoint returns unfiltered external server responses
**Labels:** bug, security, priority:low
**Description:**
### Summary
The MCP tools endpoint returns the raw tool list from `mcp_service.list_tools_for_server()` without a response model. MCP tool definitions returned by remote servers could contain internal metadata fields not appropriate for client exposure.

### Details
Without schema-based filtering, all fields from external MCP server responses are forwarded to clients.

**Affected Files:**
- `webapp/packages/api/user-service/routes.py:544-553`

**ASVS:** 15.3.1 (L1)

### Remediation
Define response models (McpTool, ListMcpToolsResponse) that explicitly declare which tool fields the UI needs (name, description, input_schema). Apply these models to filter external MCP server responses before forwarding to clients.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 15.3.1.md

### Priority
Low

---

## Issue: FINDING-073 - No count limit on MCP tool URLs or gofannon agents per request
**Labels:** bug, security, priority:low
**Description:**
### Summary
A request with hundreds of tool URLs would cause the server to make HTTP connections to all of them sequentially. The code iterates over request.tools (unbounded dict) making iterative remote HTTP calls to each URL via mcp_client.list_tools().

### Details
Similarly, request.gofannon_agents with many IDs would cause many database lookups. This can lead to resource exhaustion through excessive outbound connections or database queries.

**Affected Files:**
- `webapp/packages/api/user-service/agent_factory/__init__.py:24-31`
- `webapp/packages/api/user-service/agent_factory/__init__.py:44-66`

**ASVS:** 5.2.1 (L1)

### Remediation
Add maximum count limits on collection fields in the GenerateCodeRequest Pydantic model. Limit the number of swagger_specs, tools URLs, gofannon_agents, and invokable_models per request to reasonable values (e.g., 10-50 items depending on expected use cases).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 5.2.1.md

### Priority
Low

---

## Issue: FINDING-074 - User-controlled `spec.name` passed to parsing function without sanitization
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `spec.name` field is user-controlled and passed directly to `parse_spec_and_generate_docs()`. If this function uses the `name` parameter to construct file paths, path traversal characters could exploit the system.

### Details
This is classified as LOW severity because: 1. The function name suggests it only generates documentation strings (not file operations), 2. The `swagger_parser` module implementation is not available for verification, 3. Modern parsing libraries typically operate on content strings, not file paths, 4. The `name` parameter appears to be used as a label/title based on how it's consumed.

**Affected Files:**
- `webapp/packages/api/user-service/agent_factory/__init__.py:37`

**ASVS:** 5.3.2 (L1)

### Remediation
Sanitize the spec.name field before passing it to downstream functions:
```python
import re

def sanitize_spec_name(name: str) -> str:
    """Sanitize spec name to prevent path traversal and ensure safe usage."""
    basename = os.path.basename(name)
    sanitized = re.sub(r'[^\w\-.]', '_', basename)
    if not sanitized:
        sanitized = "unnamed_spec"
    return sanitized

for spec in request.swagger_specs:
    safe_name = sanitize_spec_name(spec.name)
    docs_for_spec = parse_spec_and_generate_docs(safe_name, spec.content)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: CWE-22
- Source: 5.3.2.md

### Priority
Low

---

## Issue: FINDING-075 - Critical Dependency (LiteLLM) Not Classified as "Dangerous Functionality" Component
**Labels:** bug, security, priority:low
**Description:**
### Summary
LiteLLM performs HTTP calls to external services, processes API keys, handles untrusted binary/JSON data from external APIs, and dynamically routes to different backends. Per ASVS 15.1.1, components performing raw file or binary data parsing and handling sensitive operations should be documented as containing dangerous functionality.

### Details
No documentation classifies LiteLLM's risk profile or lists it as requiring enhanced scrutiny during updates. Without classifying LiteLLM as a dangerous/critical component, it may not receive expedited remediation when vulnerabilities are disclosed, despite being the primary interface to external LLM providers with access to user API keys.

**Affected Files:**
- `webapp/packages/api/user-service/services/llm_service.py:14-20`

**ASVS:** 15.1.1 (L1)

### Remediation
Add component classification documentation in a dependency_classifications.yaml file. Document critical_trust_components including litellm with reason 'Handles user API keys, makes external HTTP calls, processes untrusted API responses', dangerous_operations including 'external HTTP with secrets', 'dynamic API routing', 'response parsing', and remediation_tier set to critical. Similarly classify OAuth libraries with reason 'Handles OAuth flows, token validation, session establishment', dangerous_operations including 'cryptographic token validation' and 'external IdP communication', and remediation_tier set to critical.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 15.1.1.md

### Priority
Low

---

## Issue: FINDING-076 - API Documentation Endpoints Exposed in Production
**Labels:** bug, security, priority:low
**Description:**
### Summary
The FastAPI() constructor is called without setting docs_url=None or redoc_url=None, which means the interactive API documentation at /docs (Swagger UI) and /redoc (ReDoc) are available to any requester.

### Details
This exposes the complete API surface area, parameter types, and endpoint structure to attackers. Attackers can enumerate all API endpoints, understand parameter schemas, and identify potential attack targets without fuzzing. This violates the principle of not exposing internal API docs or monitoring endpoints publicly and aids reconnaissance for subsequent attacks.

**Affected Files:**
- `webapp/packages/api/user-service/app_factory.py:55`

**ASVS:** 13.4.1 (L1)

### Remediation
Conditionally disable API documentation endpoints in production by setting docs_url=None, redoc_url=None, and openapi_url=None when ENVIRONMENT variable is set to 'production'. Allow documentation endpoints only in development environments.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 13.4.1.md

### Priority
Low

---

## Issue: FINDING-077 - Debug/Configuration Information Printed to stdout
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application uses print() statements to output configuration details and error messages. In containerized deployments, stdout is captured in logs which may be accessible to operators or log aggregation services with insufficient access controls.

### Details
The statements leak configured frontend URL and may include sensitive details about auth configuration errors (e.g., file paths, secret fragments in error messages). This contributes to information leakage.

**Affected Files:**
- `webapp/packages/api/user-service/app_factory.py:30`
- `webapp/packages/api/user-service/app_factory.py:68`

**ASVS:** 13.4.1 (L1)

### Remediation
Replace print() statements with structured logging through the observability service. Log configuration information at appropriate levels (INFO for normal config, WARNING for errors) with sanitized details that do not expose sensitive configuration values or internal paths. Avoid including full error messages that may contain sensitive data.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- CWE: Not specified
- Source: 13.4.1.md

### Priority
Low