# Security Audit Consolidated Report — gofannon

## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L1 |
| **Severity Threshold** | None (all findings included) |
| **Commit** | `35e8709` |
| **Date** | May 05, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 70 |
| **Total Findings** | 77 |

## Executive Summary

### Severity Distribution

| Critical | High | Medium | Low | Info | Total |
|:--------:|:----:|:------:|:---:|:----:|:-----:|
| 6 | 16 | 34 | 21 | 0 | **77** |

```
Critical  ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  6  ( 7.8%)
High      ████████████████░░░░░░░░░░░░░░░░░░░░░░░░  16 (20.8%)
Medium    ██████████████████████████████████░░░░░░  34 (44.2%)
Low       █████████████████████░░░░░░░░░░░░░░░░░░░  21 (27.3%)
```

### Level Coverage

All 77 findings are mapped to **ASVS Level 1** requirements. The audit scope was bounded to L1 controls; no L2- or L3-only requirements were evaluated. This means the findings represent the minimum baseline security posture expected for any internet-facing application.

### Top 5 Risks

| # | Risk Theme | Findings | Severity | Impact Summary |
|---|-----------|----------|----------|----------------|
| 1 | **Systemic Broken Object Level Authorization (BOLA)** | FINDING-001 through FINDING-004, FINDING-010, FINDING-011, FINDING-030, FINDING-031 | 4× Critical, 2× High, 2× Medium | Any authenticated user can read, modify, or delete resources belonging to other users — including agents, demo apps, chat tickets, and session configurations. The workspace role model is defined but not enforced at route level, rendering multi-tenancy boundaries ineffective. |
| 2 | **Unsafe Agent Code Execution Sandbox** | FINDING-005, FINDING-013, FINDING-032 | 1× Critical, 1× High, 1× Medium | Dynamically executed agent code receives unrestricted `__builtins__` (including `__import__`, `open`, `exec`), runs without a timeout, and is compiled without source identification. A malicious or compromised agent definition can achieve arbitrary code execution on the host with the privileges of the application process. |
| 3 | **Business Logic Bypass on Spend Controls** | FINDING-006, FINDING-020, FINDING-021, FINDING-051 | 1× Critical, 2× High, 1× Medium | The spend allowance enforcement — a primary cost-governance control — is bypassed via the chat service path, exploitable through a TOCTOU race condition on concurrent requests, and entirely skipped on streaming endpoints. This enables unbounded LLM API consumption without user awareness or organizational limit enforcement. |
| 4 | **Open Redirect and Cross-Site Scripting (XSS)** | FINDING-007, FINDING-014, FINDING-015, FINDING-023 | 3× High, 1× Medium | The `return_to` parameter in the OAuth flow accepts absolute URLs without allowlist validation, enabling phishing via trusted-domain redirect. The `dev_stub_picker` HTML generator interpolates user input without encoding, creating reflected XSS. Although partially mitigated by `html.escape()` on the deny page, the attack surface remains on the picker and redirect paths. |
| 5 | **Missing Rate Limiting and Authentication Hardening** | FINDING-008, FINDING-022, FINDING-024, FINDING-025 | 2× High, 2× Medium | Authentication endpoints have no rate limiting, lockout, or failed-attempt tracking — enabling credential stuffing and brute-force attacks against the shared admin password. LLM API endpoints similarly lack throttling, amplifying the spend-control bypass risk. A default site-admin account exists without a hard production block. |

### Positive Controls Observed

The audit identified **49 positive security controls** that are correctly implemented and provide meaningful defense-in-depth. Key strengths include:

| Control Area | Summary |
|-------------|---------|
| **OAuth Implementation** | Authorization code flow used exclusively (no implicit or ROPC grants). CSRF state tokens generated with 192-bit entropy (`secrets.token_urlsafe(24)`) and validated with constant-time comparison (`secrets.compare_digest`). State cookies expire in 10 minutes. |
| **Session Architecture** | Server-side opaque session IDs (256-bit entropy via `secrets.token_urlsafe(32)`) stored in CouchDB. Hard expiry enforced on every access with automatic eviction. New session ID generated on every login, preventing session fixation. Immediate revocation capability via server-side delete. |
| **Cookie Security** | `HttpOnly`, `SameSite=Lax`, and conditional `Secure` attributes consistently applied across all authentication cookies. No JWT or bearer tokens exposed to client-side JavaScript. |
| **Provider Hardening** | All OAuth provider modules fail-fast on missing secrets at startup. HTTP client timeouts enforced (10s). GitHub provider explicitly disables signup. Google provider validates `hd` claim server-side. Ban check overrides even site-admin privileges. |
| **Authentication Consistency** | Every route (except `/health`) requires authentication via FastAPI dependency injection (`get_current_user`). All validation is performed server-side with no reliance on client-side JavaScript authorization or `X-Forwarded-*` headers. |

These controls demonstrate mature security thinking in the authentication and session layers. The primary gap is the failure to extend equivalent rigor to the **authorization layer** — where the workspace RBAC model is well-designed but not yet enforced at route level.

---


> **Note:** 6 Critical findings have been redacted from this report and forwarded to the project's PMC private mailing list.


## 3. Findings

## 3.2 High

#### FINDING-007: 🟠 Open Redirect via Unvalidated return_to Parameter in OAuth Flow

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-601 |
| **ASVS Sections** | 10.4.1 |
| **Files** | `webapp/packages/api/user-service/routes_auth.py:130-140`&lt;br&gt;`webapp/packages/api/user-service/routes_auth.py:170-180` |
| **Source Reports** | 10.4.1.md, 10.4.5.md |
| **Related Findings** | - |

**Description:**

User-controlled query param return_to is stored in a cookie and used directly as a redirect target without validation against an allowlist. When the parameter contains an absolute URL (starting with http:// or https://), it is used without any origin validation. This enables phishing attacks that leverage the application's legitimate OAuth flow to build trust. A user sees a legitimate consent screen from their OAuth provider, then lands on an attacker-controlled page immediately after authentication when users have high trust.

**Remediation:**

Validate return_to against allowed origins. Only allow relative paths or paths matching FRONTEND_URL origin. Implement a _validate_return_to function that parses the URL, checks the netloc against the frontend origin, and rejects external redirects. For relative paths, prefix with frontend base URL. Use urllib.parse to validate URL structure and extract origin for comparison.

---

#### FINDING-008: 🟠 No Rate Limiting or Throttling on Authentication Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.3.1 |
| **Files** | `webapp/packages/api/user-service/routes_auth.py:all auth endpoints` |
| **Source Reports** | 6.3.1.md |
| **Related Findings** | - |

**Description:**

The authentication endpoints in routes_auth.py lack any rate limiting or throttling controls. External attackers can script rapid requests to initiate login flows and attempt code exchanges without any throttling. This enables credential stuffing against the dev_stub provider (user UID enumeration), state token exhaustion attacks, rapid code replay attempts for external OAuth providers, and provides no protection against distributed brute force attacks across the authentication flow.

**Remediation:**

Implement rate limiting middleware using a library such as SlowAPI with Redis backend. Apply limits to authentication endpoints: 10 login initiations per minute per IP for /auth/login/{type}, and 5 callback attempts per minute per IP for /auth/callback/{type}. Example implementation: use @limiter.limit decorators on the login_redirect and login_callback route handlers with get_remote_address as the key function.

---

#### FINDING-009: 🟠 No Mechanism to Terminate All Sessions When User Account is Disabled or Deleted

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 7.4.2 |
| **Files** | `webapp/packages/api/user-service/services/session_service.py` |
| **Source Reports** | 7.4.2.md |
| **Related Findings** | - |

**Description:**

There is no function, endpoint, or mechanism anywhere in the provided code to find and terminate all sessions belonging to a specific user. When an admin disables or deletes a user account, the user's existing sessions remain valid in CouchDB until individual TTL expiry (default: 24 hours). A disabled or deleted user retains access for up to the session TTL. In security-critical scenarios (employee termination, compromised account), this window is unacceptable. The application cannot enforce immediate access revocation.

**Remediation:**

Add a terminate_all_for_user(user_uid: str) method to SessionService that queries all sessions for a given user and deletes them. Implement a CouchDB view/index on user_uid in the user_sessions collection to support efficient queries. Add an admin endpoint (e.g., POST /admin/terminate-user-sessions/{user_uid}) to expose this functionality. Wire account disable/delete actions to automatically call this method. Example implementation: query sessions by user_uid, iterate and delete each session document, return count of terminated sessions.

---

#### FINDING-010: 🟠 Chat Ticket IDOR — Any User Can Read Another User's Chat Response

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-639 |
| **ASVS Sections** | 8.2.2 |
| **Files** | `webapp/packages/api/user-service/routes.py:369-382` |
| **Source Reports** | 8.2.2.md |
| **Related Findings** | FINDING-001, FINDING-002, FINDING-011, FINDING-031 |

**Description:**

The get_chat_status endpoint accepts a ticket_id parameter and returns the full chat response including LLM output without validating that the authenticated user owns the ticket. While ticket IDs are UUIDv4 (hard to guess), there is no validation that the authenticated user owns the ticket. If an attacker obtains a ticket ID through logs, shared URLs, browser history, or network interception, they can read another user's complete chat response including potentially sensitive LLM output. Impact: Unauthorized access to potentially sensitive LLM conversations. Attacker who obtains a ticket ID can read another user's complete chat response including potentially sensitive information discussed with the LLM.

**Remediation:**

Add user ownership validation to chat ticket retrieval. Store the user ID with the ticket during creation and verify it on retrieval. Example: if ticket_data.get('userId') != user.get('uid'): raise HTTPException(status_code=404, detail='Ticket not found')

---

#### FINDING-011: 🟠 Session Config IDOR — Any User Can Read/Modify/Delete Another User's Session Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-639 |
| **ASVS Sections** | 8.2.2 |
| **Files** | `webapp/packages/api/user-service/routes.py:385-415` |
| **Source Reports** | 8.2.2.md |
| **Related Findings** | FINDING-001, FINDING-002, FINDING-010, FINDING-031 |

**Description:**

Session configuration endpoints (update_session_config and delete_session) accept arbitrary session_id path parameters without verifying the requesting user owns the session. User-controlled session_id flows directly to database operations with no user/session ownership comparison. Impact: Attacker can modify another user's session configuration, potentially redirecting their LLM calls to attacker-controlled endpoints, changing provider settings, or deleting sessions to cause denial of service.

**Remediation:**

Add ownership validation to session config routes. Validate that the requesting user owns the session being modified. Store session ownership metadata and verify it before allowing any read, write, or delete operations.

---

#### FINDING-012: 🟠 Background Task Loses Authorization Context — No Re-verification of Permissions During Execution

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 8.3.1 |
| **Files** | `webapp/packages/api/user-service/dependencies.py:383-504` |
| **Source Reports** | 8.3.1.md |
| **Related Findings** | - |

**Description:**

Background tasks don't have access to dependency injection, so service instances are obtained directly. The 'user' dict is passed from the original request without re-checking permissions. If a user's permissions change (revoked) between request submission and execution, the stale authorization context persists. Given LLM calls can take 15-30 minutes (per timeout configuration), this window is significant. The background task runs later with stale credentials and performs no re-verification before agent access.

**Remediation:**

Add background task authorization refresh — before executing long-running operations, re-validate the user's current permissions against the session service rather than relying on the snapshot from request time.

---

#### FINDING-013: 🟠 No Execution Timeout on Agent Code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-400 |
| **ASVS Sections** | 1.3.2 |
| **Files** | `webapp/packages/api/user-service/dependencies.py:334-350` |
| **Source Reports** | 1.3.2.md |
| **Related Findings** | - |

**Description:**

Agent code execution via run_function() is awaited without any timeout mechanism. This allows malicious or buggy agent code to run indefinitely, consuming CPU and memory resources, potentially causing denial of service. The lack of timeout enables infinite loops, memory exhaustion attacks, and event loop starvation that prevents other requests from processing.

**Remediation:**

Wrap the await run_function() call in asyncio.wait_for() with a configurable timeout (default 300 seconds). Handle asyncio.TimeoutError exceptions by logging to trace if available and raising an HTTPException with status code 408. Example: result = await asyncio.wait_for(run_function(input_dict=input_dict, tools=tools), timeout=AGENT_EXECUTION_TIMEOUT)

---

#### FINDING-014: 🟠 Reflected XSS in dev_stub_picker HTML generation — user input interpolated without HTML encoding

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.2.1, 1.3.1, 1.2.2 |
| **Files** | `routes_auth.py:197-215`&lt;br&gt;`webapp/packages/api/user-service/routes_auth.py:195` |
| **Source Reports** | 1.2.1.md, 1.3.1.md, 2.2.2.md, 1.2.2.md |
| **Related Findings** | FINDING-023, FINDING-064 |

**Description:**

The `users` and `state` query parameters are directly interpolated into an HTML document without any HTML entity encoding. Query parameter `users` is split on comma and each value is interpolated into HTML href attributes AND element content. The `state` parameter is also interpolated into HTML href attributes. The endpoint returns text/html with no encoding applied. This endpoint is accessible on any deployment where the auth router is mounted (i.e., when ANY auth provider is enabled, not just dev_stub). The `_render_deny_page` function correctly uses `html.escape()` but this pattern was not applied to `dev_stub_picker`. This is a Type B gap where the control (`html.escape`) EXISTS in the same file but is NOT CALLED here.

**Remediation:**

Apply HTML entity encoding using `html.escape()` to all user-controlled values interpolated into HTML element content, and use `urllib.parse.quote()` for values interpolated into URL attributes. Example fix:

```python
import html as _html
from urllib.parse import quote

@router.get("/auth/dev-stub-picker", response_class=HTMLResponse)
async def dev_stub_picker(...) -> HTMLResponse:
    user_list = [u for u in users.split(",") if u]
    links = "".join(
        f'<li><a href="/auth/callback/dev_stub?code={quote(u)}&state={quote(state)}">{_html.escape(u)}</a></li>'
        for u in user_list
    )
    # ...
```

Additionally, add a guard that returns 404 if the dev_stub provider is not enabled in the registry.

---

#### FINDING-015: 🟠 Open redirect via unvalidated `return_to` parameter accepting absolute URLs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 1.2.2 |
| **Files** | `routes_auth.py:149-157` |
| **Source Reports** | 1.2.2.md, 2.2.2.md |
| **Related Findings** | - |

**Description:**

The `return_to` value originates from a user-controlled query parameter (`/auth/login/{type}?return_to=...`), is stored in a cookie, and then used as the redirect target after authentication. When it's an absolute URL, no validation is performed to ensure it points to a trusted domain. Only safe URL protocols are checked (`http://`, `https://`), but the domain is unrestricted. Data flow: `/auth/login/{type}?return_to=https://evil.com` → cookie `gofannon_return_to` → `/auth/callback/{type}` reads cookie → if starts with `http://`/`https://` → used directly as `RedirectResponse(url=...)`

**Remediation:**

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

---

#### FINDING-016: 🟠 No schema validation on deployed agent input

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.2.1, 2.2.2 |
| **Files** | `routes.py:395` |
| **Source Reports** | 2.2.1.md, 2.2.2.md |
| **Related Findings** | - |

**Description:**

The deployed agent endpoint reads the request body as raw JSON without any Pydantic model validation. Each deployed agent has a defined input_schema stored in its configuration, but this schema is never validated against the incoming request. This is a Type B gap — the control (input_schema) EXISTS but is NOT CALLED at this entry point. Arbitrarily structured or sized payloads reach agent execution. Could enable denial of service via oversized inputs, unexpected behavior in agent code, or injection if agent code uses input values in unsafe contexts (e.g., string formatting into shell commands or queries).

**Remediation:**

Validate input_dict against the agent's declared input_schema before execution using jsonschema.validate. Fetch the agent deployment and agent document, then validate the incoming JSON against the stored inputSchema. Raise HTTPException with status 422 if validation fails.

---

#### FINDING-017: 🟠 No HSTS Header Configuration — Allows Downgrade to HTTP

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 12.2.1, 3.4.1 |
| **Files** | `webapp/packages/api/user-service/app_factory.py:56-83` |
| **Source Reports** | 12.2.1.md, 3.4.1.md |
| **Related Findings** | - |

**Description:**

The application does not include a Strict-Transport-Security header on responses. HTTP Response → Missing `Strict-Transport-Security` header → Browser does not enforce HTTPS-only connections. There is no middleware, response hook, or configuration anywhere in the provided code that adds a `Strict-Transport-Security` header to responses. Without HSTS, the application is vulnerable to protocol downgrade attacks and SSL stripping. Given that the application uses cookie-based session authentication (`credentials: 'include'`), session cookies could be intercepted over an HTTP connection if the user's first request is not over HTTPS or if a MITM intercepts the initial redirect. An attacker performing an SSL-stripping attack (e.g., via a MITM on a coffee shop Wi-Fi) could downgrade the connection to HTTP, intercepting the `gofannon_sid` session cookie since no HSTS enforcement instructs the browser to refuse HTTP connections.

**Remediation:**

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

---

#### FINDING-018: 🟠 Missing CSRF Protection on Cookie-Based Authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 3.5.1 |
| **Files** | `webapp/packages/api/user-service/app_factory.py:22-75`&lt;br&gt;`fetchInterceptor.js` |
| **Source Reports** | 3.5.1.md |
| **Related Findings** | FINDING-019 |

**Description:**

The application uses cookie-based authentication with credentials automatically included in cross-origin requests, but lacks any CSRF protection mechanism. There is no CSRF token generation or validation, no custom header requirement, no Origin header validation on state-changing requests, and no visible SameSite cookie attribute configuration. The CORS middleware only controls response headers and does not prevent simple (non-preflight) cross-origin requests from executing. This allows an attacker to potentially perform state-changing operations on behalf of authenticated users through cross-site requests.

**Remediation:**

Implement one or more CSRF protection mechanisms: (1) Require a custom header (e.g., X-Requested-With: XMLHttpRequest) on all authenticated requests that triggers CORS preflight, enforced via middleware that returns 403 if missing on non-safe methods. Update fetchInterceptor.js to include this header. (2) Add server-side Origin header validation middleware that checks the Origin header against the allowlist for all state-changing requests (POST/PUT/PATCH/DELETE) and returns 403 for invalid origins. (3) Explicitly configure SameSite=Lax or SameSite=Strict on session cookies. (4) Require Content-Type: application/json on all state-changing API endpoints to trigger preflight.

---

#### FINDING-019: 🟠 CORS Middleware Does Not Block Simple Cross-Origin Requests

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 3.5.2 |
| **Files** | `webapp/packages/api/user-service/app_factory.py:22-40` |
| **Source Reports** | 3.5.2.md |
| **Related Findings** | FINDING-018 |

**Description:**

The application relies on Starlette's CORSMiddleware to prevent disallowed cross-origin use of sensitive functionality, but this middleware only adds/omits response headers and does not reject non-preflight requests from non-allowed origins server-side. Cross-origin 'simple' POST requests with Content-Type: application/x-www-form-urlencoded do not trigger CORS preflight and are processed by backend endpoints, allowing state changes to occur. The attacker cannot read the response due to browser CORS enforcement, but blind state-changing attacks succeed. This creates false confidence that CORS is preventing CSRF attacks.

**Remediation:**

Validate the Content-Type header server-side and reject non-JSON content types for API endpoints using a ContentTypeValidationMiddleware. This ensures all state-changing requests trigger a CORS preflight. Alternatively, require a non-safelisted header like X-Requested-With on all authenticated requests. Additionally, implement server-side Origin header validation for state-changing requests, returning 403 if Origin is present but not in the allowlist.

---

#### FINDING-020: 🟠 Race Condition in Spend Allowance Check Enables Concurrent Bypass (TOCTOU)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.3.1 |
| **Files** | `webapp/packages/api/user-service/services/llm_service.py:113-115`&lt;br&gt;`webapp/packages/api/user-service/services/llm_service.py:328` |
| **Source Reports** | 2.3.1.md |
| **Related Findings** | - |

**Description:**

A Time-of-Check-Time-of-Use (TOCTOU) race condition exists between the allowance check (line 113-115) and usage recording (line 328). Multiple concurrent requests can all pass the require_allowance() check simultaneously before any usage is recorded. A user with $5 remaining allowance could send 50 concurrent requests, all of which pass the check, resulting in potentially $250+ in charges before any usage is recorded. The LLM call takes 1-600 seconds between check and usage recording, creating a large window for exploitation.

**Remediation:**

Use atomic decrement or pessimistic locking. Reserve estimated cost atomically BEFORE the LLM call using reserve_allowance(). After the call completes, finalize the reservation with actual cost using finalize_reservation(). On error, release the reservation. This ensures allowance is decremented before the expensive operation executes.

---

#### FINDING-021: 🟠 Streaming Endpoint Skips Cost Recording Step Entirely

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.3.1, 15.2.1 |
| **Files** | `webapp/packages/api/user-service/services/llm_service.py:348-410` |
| **Source Reports** | 2.3.1.md, 15.2.1.md |
| **Related Findings** | - |

**Description:**

The `stream_llm` function explicitly notes cost tracking is unavailable. While `require_allowance` is called before streaming (positive), actual cost is never deducted from user allowance after streaming completes. This relates to ASVS 15.2.1's section on preventing loss of availability due to overusing resource-demanding functionality. LiteLLM's streaming mode is identified in the domain context as potentially resource-intensive. Users could accumulate LLM costs through streaming without proper accounting, potentially exhausting shared resources or infrastructure budgets without triggering allowance enforcement post-call.

**Remediation:**

Add usage recording to stream_llm() using a finally block. Track usage based on streamed content using litellm's stream_cost_tracking or estimate based on tokens. Call user_service.add_usage() with the estimated cost after streaming completes to ensure the final step in the business logic flow is executed.

---

#### FINDING-022: 🟠 No Rate Limiting Controls Implemented or Documented for LLM API Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.1.1 |
| **Files** | `chat_service.py:all public methods`&lt;br&gt;`llm_service.py:all public functions` |
| **Source Reports** | 6.1.1.md |
| **Related Findings** | - |

**Description:**

The application lacks rate limiting controls for LLM API endpoints in both chat_service.py and llm_service.py. No per-IP rate limiting, per-user request rate limiting, anti-automation controls (CAPTCHA, progressive delays), adaptive response mechanisms, or circuit breakers for external LLM service calls are implemented. Additionally, no documentation artifacts reference rate limiting configuration. Without rate limiting, the system is vulnerable to credential stuffing (if authentication endpoints exist), resource exhaustion via unlimited concurrent LLM requests, cost amplification when combined with spend allowance bypass, and DoS attacks via unlimited background task spawning.

**Remediation:**

Implement rate limiting middleware with documented configuration including: per-user limits (10 requests/minute for chat ticket creation, 5 concurrent streams, 30 requests/minute for LLM calls), per-IP limits (100 requests/minute for all endpoints, 5 attempts/minute for authentication), and adaptive response mechanisms (5-minute cooldown after 3x rate limit hits, 1-hour lockout after 10x hits in 1 hour). Configure via RATE_LIMIT_* environment variables with Redis backend for distributed rate limiting. Add rate limiter to ChatService class with max_requests=10, window_seconds=60, and max_concurrent_tasks=20. Implement checks before processing requests and raise 429 errors when limits are exceeded.

### 3.3 Medium

#### FINDING-023: Reflected XSS in Dev-Stub Picker via Unescaped Query Parameters

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 10.4.1 |
| **Files** | `webapp/packages/api/user-service/routes_auth.py:253-266` |
| **Source Reports** | 10.4.1.md, 10.4.5.md |
| **Related Findings** | FINDING-014, FINDING-064 |

**Description:**

The dev_stub_picker function embeds user-controlled query parameters (state and users) directly into HTML output without proper escaping. This creates a reflected XSS vulnerability. An attacker can execute arbitrary JavaScript in the context of the application's origin. Despite httponly cookies, this enables DOM manipulation, phishing overlays, and keylogging on the login page. The state and users parameters are embedded directly into HTML href attributes and link text without proper encoding.

**Remediation:**

Apply proper output encoding: (1) Use urllib.parse.quote() for URL parameters in href attributes, (2) Use html.escape() for user values displayed as text content, (3) Add charset=UTF-8 meta tag to HTML head. Additionally, implement an environment-based guard to prevent dev_stub from loading in production by checking APP_ENV and raising an exception or returning 404 if the environment is production.

---

#### FINDING-024: No Failed Authentication Attempt Tracking or Account Lockout

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.3.1 |
| **Files** | `webapp/packages/api/user-service/routes_auth.py:login_callback function` |
| **Source Reports** | 6.3.1.md |
| **Related Findings** | - |

**Description:**

The login_callback function in routes_auth.py does not track failed authentication attempts per user or per IP address. When provider code exchange fails, the application raises an HTTP 502 exception without logging attempt counts or triggering any lockout mechanism. This provides no visibility into brute force patterns, no automatic lockout mechanism, and prevents the security team from detecting ongoing credential stuffing attacks through application-level metrics.

**Remediation:**

Implement failed authentication attempt tracking and account lockout. Log all failed authentication attempts with audit_service.log_failed_auth including IP, provider_type, and reason. Implement a rate_limit_service to increment and track failed attempt counts per IP. When failed_count exceeds MAX_FAILED_ATTEMPTS threshold, return HTTP 429 (Too Many Requests) and temporarily block further attempts from that IP address.

---

#### FINDING-025: Default Site Admin Account Without Hard Production Block

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.3.2 |
| **Files** | `.dev-auth.yaml:37-41`, `.dev-auth.yaml:43-44`, `webapp/packages/api/user-service/auth/providers/dev_stub.py` |
| **Source Reports** | 6.3.2.md |
| **Related Findings** | - |

**Description:**

If dev_stub is accidentally enabled in production (only a logged warning prevents this), an unauthenticated attacker gains full site administrator access with a well-known default account identifier. Site admins can bypass workspace boundaries per the application's design. The .dev-auth.yaml configuration file contains a default site_admin_1 account that can be accessed without credentials through the dev_stub authentication provider. The session service only logs a warning when dev_stub is enabled in non-development environments rather than blocking initialization entirely.

**Remediation:**

In dev_stub provider __init__, hard-fail if APP_ENV is production:

```python
import os

class DevStubProvider(AuthProvider):
    def __init__(self, config: dict):
        app_env = os.getenv("APP_ENV", "local").lower()
        if app_env not in ("local", "dev", "test"):
            raise RuntimeError(
                "FATAL: dev_stub provider cannot be enabled in "
                f"APP_ENV={app_env}. This is a misconfiguration."
            )
        super().__init__(config)
        ...
```

---

#### FINDING-026: Cookie Names Lack Required __Secure- or __Host- Prefix

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 3.3.1 |
| **Files** | `webapp/packages/api/user-service/services/session_service.py:35`, `webapp/packages/api/user-service/routes_auth.py:114`, `webapp/packages/api/user-service/routes_auth.py:122`, `webapp/packages/api/user-service/routes_auth.py:188-194` |
| **Source Reports** | 3.3.1.md |
| **Related Findings** | - |

**Description:**

ASVS 3.3.1 requires that if the __Host- prefix is not used for a cookie name, the __Secure- prefix must be used. All three authentication-related cookies use unprefixed names, removing a browser-enforced security constraint that prevents cookie injection from insecure contexts or subdomains. Affected cookies: gofannon_sid (primary session identifier), gofannon_auth_state (OAuth CSRF token), and gofannon_return_to (post-login redirect target). The lack of prefix means the browser won't reject cookies set over non-HTTPS channels for this name. The __Secure- prefix instructs browsers to only accept cookies set with the Secure attribute, providing an additional browser-level enforcement layer.

**Remediation:**

Update session_service.py line 35 to use _COOKIE_NAME = "__Secure-gofannon_sid" or preferably "__Host-gofannon_sid" since the session cookie already uses path="/" and doesn't set a Domain attribute. Update auxiliary cookie names in routes_auth.py: use "__Secure-gofannon_auth_state" in login_redirect() and "__Secure-gofannon_return_to" in login_callback(). Update all Cookie(alias=...) parameters in route functions to match new cookie names. Update all delete_cookie calls to use the new prefixed names. When using __Secure- prefix, ensure secure=True is always set.

---

#### FINDING-027: Secure Attribute Conditionally Set Based on Scheme Auto-Detection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 3.3.1 |
| **Files** | `webapp/packages/api/user-service/routes_auth.py:62-68`, `webapp/packages/api/user-service/routes_auth.py:117`, `webapp/packages/api/user-service/routes_auth.py:125`, `webapp/packages/api/user-service/routes_auth.py:192` |
| **Source Reports** | 3.3.1.md |
| **Related Findings** | - |

**Description:**

The Secure attribute is determined by _is_secure_cookie() which checks request.url.scheme == "https". This means in deployments behind TLS-terminating reverse proxies (common in production) where forwarded headers are not properly configured, the session cookie will be sent without the Secure flag, allowing it to be transmitted over unencrypted HTTP connections. In production deployments behind nginx/ALB that terminate TLS at the load balancer with internal HTTP traffic to the FastAPI app, if --proxy-headers is not configured in uvicorn, request.url.scheme returns "http" and the session cookie is set without the Secure flag. If a user ever visits an HTTP URL on the same domain, the session cookie is exposed in cleartext.

**Remediation:**

Option 1 (recommended): Add environment-driven override with FORCE_SECURE_COOKIES environment variable (default true in production) to ensure the Secure flag is always set regardless of detected scheme. Only disable for local development. Option 2: Use __Host- prefix for session cookie which requires Secure=True at browser level, making it a hard failure if Secure is accidentally omitted. Option 3: Use __Secure- prefix which requires Secure=True at browser level. Document deployment requirement: uvicorn must be started with --proxy-headers behind TLS-terminating proxies.

---

#### FINDING-028: Previous Session Not Terminated on Re-authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 7.2.4 |
| **Files** | `webapp/packages/api/user-service/routes_auth.py:127-189` |
| **Source Reports** | 7.2.4.md |
| **Related Findings** | - |

**Description:**

The callback handler does not accept/read the existing gofannon_sid cookie to terminate it before creating the new session. When a user re-authenticates, a new session is created and the cookie is overwritten, but the old session document persists in CouchDB and remains valid until TTL expiry. This means compromised session tokens remain usable after re-authentication, contrary to the principle that re-authentication should reset the security state. While 256-bit session IDs make blind guessing infeasible, a stolen token retains validity.

**Remediation:**

Read the existing gofannon_sid cookie in the callback handler and call session_svc.delete(existing_sid) before creating the new session. Add existing_sid: Optional[str] = Cookie(default=None, alias="gofannon_sid") to the login_callback function parameters, then terminate the previous session with: if existing_sid: await session_svc.delete(existing_sid)

---

#### FINDING-029: Workspace Role Permissions Not Mapped to Route-Level Access Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 8.1.1 |
| **Files** | `webapp/packages/api/user-service/models/workspace.py:36-37`, `webapp/packages/api/user-service/routes.py:all route handlers` |
| **Source Reports** | 8.1.1.md |
| **Related Findings** | - |

**Description:**

The WorkspaceRole type defines 'member' and 'admin' roles, and MembershipSource tracks where memberships originate, but there is no documentation or code artifact that maps these roles to specific function-level or data-level permissions. No documentation exists defining what 'admin' vs 'member' can do within a workspace. No route annotations or permission matrices define required roles per endpoint. The require_admin_access dependency in dependencies.py checks a shared password unrelated to workspace roles. The get_current_user dependency extracts workspaces from session but no downstream handler inspects role values.

**Remediation:**

Create an authorization matrix document (or in-code decorator annotations) mapping each route to required workspace role and ownership conditions. Example: use decorators like @requires_workspace_role('admin') to document and enforce that only workspace admins can delete agents.

---

#### FINDING-030: run_deployed_agent Performs No Authorization Check on Agent Workspace Membership

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 8.3.1 |
| **Files** | `webapp/packages/api/user-service/dependencies.py:877-900`, `webapp/packages/api/user-service/routes.py:779` |
| **Source Reports** | 8.3.1.md |
| **Related Findings** | - |

**Description:**

The deployed agent execution path only validates that a deployment exists by its friendly name, without checking whether the authenticated user has permission to invoke that agent. The user-controlled friendly_name parameter leads to deployment lookup and agent code execution without workspace membership verification. Any authenticated user can execute any deployed agent by knowing or guessing the friendly name. Since friendly names are discoverable via GET /deployments and GET /providers (which lists gofannon models), this is easily exploitable.

**Remediation:**

Implement resource-level ownership validation for all agent, demo, and deployment routes. At minimum, associate a workspace_id or owner_uid with each resource and validate it against the authenticated user's workspace memberships before any read/write operation. Create a require_workspace_access(resource_type, resource_id) dependency that can be applied uniformly to all resource routes, enforcing workspace-scoped access.

---

#### FINDING-031: Deployment Listing Exposes All Tenants' Deployed Agent Details

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-639 |
| **ASVS Sections** | 8.2.2 |
| **Files** | `webapp/packages/api/user-service/routes.py:582`, `webapp/packages/api/user-service/dependencies.py:various` |
| **Source Reports** | 8.2.2.md |
| **Related Findings** | FINDING-001, FINDING-002, FINDING-010, FINDING-011 |

**Description:**

The list_deployments_route endpoint and get_available_providers function return all deployments from all tenants without filtering by workspace membership. All authenticated users can discover every deployed agent across all workspaces, including their friendly names, input schemas, and descriptions. Impact: All authenticated users can discover every deployed agent across all workspaces, including their friendly names, input schemas, and descriptions. This information disclosure enables reconnaissance for further attacks.

**Remediation:**

Scope deployment list endpoints to the user's workspace memberships. Filter deployments by workspace_id based on the authenticated user's workspace memberships before returning results.

---

#### FINDING-032: compile() Used Without Source Identification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-778 |
| **ASVS Sections** | 1.3.2 |
| **Files** | `webapp/packages/api/user-service/dependencies.py:293` |
| **Source Reports** | 1.3.2.md |
| **Related Findings** | FINDING-004 |

**Description:**

The compile() call uses the generic filename '&lt;string&gt;' which makes forensic analysis of errors and potential exploits harder. When exceptions occur in agent code, tracebacks will show 'File "&lt;string&gt;"' without identifying which agent or run produced the error. Multiple concurrent agent executions produce indistinguishable stack traces, slowing incident response when investigating exploitation attempts.

**Remediation:**

Include agent identifier in the compile filename for better forensics. Example: source_label = f'&lt;agent:{agent_name or "unnamed"}:{trace._stack[-1] if trace else "no-trace"}&gt;'; code_obj = compile(code, source_label, 'exec')

---

#### FINDING-033: Database abstraction passes user-controllable path parameters to `db.find()` without explicit NoSQL injection sanitization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-89 |
| **ASVS Sections** | 1.2.4 |
| **Files** | `webapp/packages/api/user-service/routes.py:405`, `webapp/packages/api/user-service/routes.py:420` |
| **Source Reports** | 1.2.4.md |
| **Related Findings** | - |

**Description:**

The `namespace` path parameter flows directly into the `db.find()` filter dictionary. While FastAPI ensures path parameters are strings (mitigating MongoDB-style operator injection like `{"$gt": ""}`), the `DatabaseService` abstraction does not provide any documented safety guarantees. For backends like CouchDB that may use Mango selectors, or custom query builders, there is no explicit validation that filter values cannot be interpreted as operators or contain special characters that alter query semantics. The reliance is entirely on: (1) FastAPI path parameter typing (always string) — implicit protection, and (2) The undocumented behavior of the `DatabaseService.find()` implementation. This is a Type B gap: the application uses a database abstraction layer (analogous to an ORM), but the abstraction doesn't explicitly enforce or document injection prevention for its `find()` method.

**Remediation:**

Add explicit input validation for all values passed to `db.find()` filters:

```python
import re

SAFE_NAMESPACE_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,128}$")

@router.get("/data-store/namespaces/{namespace}/records")
async def list_records(namespace: str, ...):
    if not SAFE_NAMESPACE_PATTERN.match(namespace):
        raise HTTPException(status_code=400, detail="Invalid namespace format")
    user_id = user.get("uid", "anonymous")
    docs = db.find("agent_data_store", {"userId": user_id, "namespace": namespace})
```

Additionally, the `DatabaseService.find()` method should document and enforce that filter values are treated as literal equality matches, never as operators.

---

#### FINDING-034: Missing documented validation rules for business-critical numeric fields

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.1.1 |
| **Files** | `models/agent.py:107-112`, `routes.py:138-151` |
| **Source Reports** | 2.1.1.md |
| **Related Findings** | - |

**Description:**

No documented constraints (min/max, allowed ranges) for numerical fields with clear business limits. `temperature` has well-known provider-specific ranges (0-2 for OpenAI), `max_tokens` should have an upper bound to prevent resource abuse, and `monthly_allowance`/`spend_remaining` should not accept negative values. The lack of documented rules means developers implementing these fields cannot verify correctness. Data flow: Client request → Pydantic model (type-checked only) → service layer → database/LLM provider. Impact: Developers have no specification to implement against; QA cannot verify business logic correctness; negative allowances or extreme token counts may propagate to downstream systems causing unexpected behavior.

**Remediation:**

Add Field constraints documenting business rules: `max_tokens: Optional[int] = Field(None, alias="maxTokens", ge=1, le=200000)`, `temperature: Optional[float] = Field(None, ge=0.0, le=2.0)`, `reasoning_effort: Optional[str] = Field(None, pattern="^(low|medium|high)$")`

---

#### FINDING-035: No documented format rules for URL-type inputs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.1.1, 1.2.2 |
| **Files** | `routes.py:131`, `routes.py:124` |
| **Source Reports** | 2.1.1.md, 1.2.2.md |
| **Related Findings** | - |

**Description:**

Fields that clearly represent URLs (`url`, `mcp_url`) have no documented format rules defining valid URL structures, allowed protocols (http/https only), or prohibited patterns (e.g., internal IPs, loopback addresses). Without documented rules, SSRF protection is ad-hoc. Impact: No clear specification for implementing SSRF protections; impossible to verify whether the application correctly restricts URL inputs.

**Remediation:**

Use Pydantic's `AnyHttpUrl` type or add a validator:

```python
from pydantic import field_validator

class FetchSpecRequest(BaseModel):
    url: str
    
    @field_validator('url')
    @classmethod
    def validate_url_protocol(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('Only http and https protocols are allowed')
        return v
```

---

#### FINDING-036: Provider and model fields not validated against allowed values

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.2.1 |
| **Files** | `models/chat.py:44` |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | - |

**Description:**

The provider and model fields accept arbitrary strings without validation against the known set of providers from PROVIDER_CONFIG. The _ensure_mutually_exclusive validator accesses PROVIDER_CONFIG.get(provider, {}) which silently returns empty for unknown providers, bypassing all parameter validation. This is a business logic validation gap — the application has a known set of allowed providers but doesn't enforce it at input time. Unknown provider/model combinations bypass parameter validation entirely; could cause confusing errors deep in processing rather than clear 422 rejections; provider selection logic may be exploitable depending on downstream implementation.

**Remediation:**

Add a model validator to check against known providers from PROVIDER_CONFIG and validate that the specified model exists for that provider. Raise ValueError for unknown provider or model combinations.

---

#### FINDING-037: No range validation on business-critical numeric inputs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.2.1 |
| **Files** | `routes.py:138`, `routes.py:148`, `routes.py:153`, `models/agent.py:107` |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | - |

**Description:**

Financial/billing fields accept any float value including negative numbers and extreme values. A negative response_cost would increase the user's remaining spend. A negative monthly_allowance has undefined business semantics. Users could manipulate their billing by submitting negative costs; extremely large allowance values could overflow downstream calculations.

**Remediation:**

Add Field constraints to enforce positive values and reasonable upper bounds. For monthly_allowance use gt=0 and le=100000. For response_cost use ge=0. Apply similar constraints to all financial and billing-related numeric fields.

---

#### FINDING-038: No length constraints on string inputs that control resource allocation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.2.1 |
| **Files** | `models/agent.py:57`, `models/agent.py:58`, `models/chat.py:43` |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | - |

**Description:**

String fields have no max_length constraints. An extremely long content field flows into LLM prompts (potential token cost abuse) and an extremely long name/description stores unbounded data in the database. This enables denial of service through memory exhaustion; excessive LLM token consumption driving up costs; database storage abuse.

**Remediation:**

Add max_length constraints appropriate to the business context. For ChatMessage.content use max_length=100000. For agent name and description fields, apply reasonable limits based on UI and business requirements.

---

#### FINDING-039: Operations log accumulates sensitive data previews destined for client-side UI with no cleanup mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 14.3.1 |
| **Files** | `webapp/packages/api/user-service/services/data_store_service.py:228-237`, `webapp/packages/api/user-service/services/data_store_service.py:218-226` |
| **Source Reports** | 14.3.1.md |
| **Related Findings** | - |

**Description:**

The ops_log accumulates valuePreview entries containing up to 200 characters of actual stored data. The class documentation explicitly states this data is surfaced to a sandbox UI. If this data is transmitted to the client (via WebSocket, SSE, or HTTP response), it persists in the client's DOM or JavaScript memory. There is no mechanism in this code to clear the ops_log after session termination, no Clear-Site-Data header set when the session ends, no client-side cleanup callback or signal, and the ops_log grows unbounded during a session (no eviction). After session termination, value previews containing fragments of user data (potentially including sensitive information stored by agents) could remain in browser memory, DOM nodes, or JavaScript objects until the page is closed or garbage collected. If another user accesses the same browser session, this data could be exposed.

**Remediation:**

Server-side: Ensure session termination endpoints emit Clear-Site-Data header: @router.post('/auth/logout') async def logout(response: Response): response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'; return {'status': 'logged_out'}. Client-side: Implement cleanup in the frontend consuming the ops_log: window.addEventListener('beforeunload', () => { opsLog = []; sessionStorage.clear(); document.querySelectorAll('.ops-timeline').forEach(el => el.innerHTML = ''); });. Service-side: Add an explicit clear method: def clear_ops_log(self) -> None: if self._ops_log is not None: self._ops_log.clear();

---

#### FINDING-040: Abstract auth provider interface does not enforce token validation requirements for OAuth token responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 9.1.1, 9.1.2, 9.1.3 |
| **Files** | `webapp/packages/api/user-service/auth/base.py:104-116` |
| **Source Reports** | 9.1.1.md, 9.1.2.md, 9.1.3.md |
| **Related Findings** | - |

**Description:**

The `AuthProvider.__init__()` accepts a raw `config: dict` without any schema validation for key material sources. For OAuth providers that validate JWTs (ID tokens), the configuration should specify: Trusted JWKS URIs (not user-controllable), Expected issuers (pinned, not from token headers), Whether `jku`, `x5u`, `jwk` header claims are ever followed. The abstract interface does not: 1) Define required config keys for key material, 2) Validate that key sources are from trusted, pre-configured URIs, 3) Prohibit following untrusted key references in token headers. A misconfigured provider could accept key material references from within tokens themselves (e.g., following a `jku` header to an attacker-controlled JWKS endpoint), allowing token forgery.

**Remediation:**

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
```

---

#### FINDING-041: No Application-Level TLS Protocol Version Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 12.1.1 |
| **Files** | `webapp/packages/api/user-service/app_factory.py:entire file scope` |
| **Source Reports** | 12.1.1.md |
| **Related Findings** | - |

**Description:**

The FastAPI application factory does not configure any TLS protocol version constraints. There is no `ssl_context` configuration, no `SSLContext` with `minimum_version` set to `TLSVersion.TLSv1_2`, and no middleware that enforces protocol version requirements. If the infrastructure layer (cloud load balancer, reverse proxy) is misconfigured or if the application is ever run directly (e.g., during development with `uvicorn --host 0.0.0.0`), there is no application-level defense-in-depth ensuring TLS 1.2+ is enforced. The application has zero visibility into or control over TLS protocol negotiation.

**Remediation:**

While infrastructure-level TLS termination is acceptable, the application should at minimum document and validate its deployment assumptions. For direct deployment, create an SSL context with minimum TLS version 1.2:

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

---

#### FINDING-042: Default CORS Origin Uses HTTP Scheme — No HTTPS Enforcement for Frontend Communication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 12.2.1, 3.4.2 |
| **Files** | `webapp/packages/api/user-service/app_factory.py:28` |
| **Source Reports** | 12.2.1.md, 3.4.2.md |
| **Related Findings** | - |

**Description:**

The default `FRONTEND_URL` environment variable is `http://localhost:3000` (plaintext HTTP). While this is a development default, the CORS configuration directly uses this value as the allowed origin without validating that it uses HTTPS in production deployments. If `FRONTEND_URL` is accidentally left as default or configured with `http://` in production, the CORS policy explicitly permits cross-origin requests from an insecure origin. This means browsers will allow the insecure origin to make credentialed requests and there's no programmatic check ensuring the frontend communicates over HTTPS.

**Remediation:**

Add validation in the `_configure_cors()` function to check that `FRONTEND_URL` uses the HTTPS scheme in non-development environments. Raise a `ValueError` at startup if an HTTP origin is configured in production or staging environments, preventing deployment with insecure configuration.

---

#### FINDING-043: No HTTP-to-HTTPS Redirect Middleware

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 12.2.1 |
| **Files** | `webapp/packages/api/user-service/app_factory.py:56-83` |
| **Source Reports** | 12.2.1.md |
| **Related Findings** | - |

**Description:**

The application does not include Starlette's `HTTPSRedirectMiddleware` or any equivalent mechanism to redirect plaintext HTTP requests to HTTPS. If the application receives HTTP traffic (e.g., due to infrastructure misconfiguration or direct access), it will serve responses over plaintext. If a client connects over HTTP (directly or due to infrastructure misconfiguration), the application will process the request and return sensitive data in plaintext, violating the requirement that communications 'do not fall back to insecure or unencrypted communications.'

**Remediation:**

Add Starlette's `HTTPSRedirectMiddleware` to the middleware stack in production environments. Configure it to respect the `X-Forwarded-Proto` header set by load balancers. Only enable this middleware when `ENVIRONMENT` is not set to 'development' to avoid interfering with local development workflows.

---

#### FINDING-044: No Certificate Configuration or Validation Visible in Application Code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 12.2.2 |
| **Files** | `webapp/packages/api/user-service/app_factory.py:entire file scope` |
| **Source Reports** | 12.2.2.md |
| **Related Findings** | - |

**Description:**

The application factory does not configure any TLS certificate (neither server certificates for serving HTTPS nor CA bundles for validating upstream services). There is no evidence of certificate pinning, OCSP stapling configuration, or certificate transparency enforcement. While TLS termination is expected at the infrastructure layer, the application makes no programmatic assertion about certificate requirements. Without application-level certificate configuration or deployment validation checks: (1) There is no defense-in-depth ensuring publicly trusted certificates are used, (2) Self-signed or internal CA certificates could be deployed without application-level detection, (3) Certificate rotation failures would not trigger application-level alerts.

**Remediation:**

Add a startup health check that validates the deployment's certificate configuration using ssl.create_default_context() to verify the service is reachable via publicly-trusted TLS. The function should verify certificates against system CA bundle and log verification status. Additionally, document the requirement in deployment manifests that TLS certificates MUST be from publicly-trusted CAs (Let's Encrypt, DigiCert, etc.) and that self-signed certificates are NOT acceptable. Add HSTS middleware with max-age=31536000; includeSubDomains, add HTTPS scheme validation for FRONTEND_URL in non-development environments, and add HTTPSRedirectMiddleware for production deployments.

---

#### FINDING-045: Wildcard CORS methods allow all HTTP methods without visible Sec-Fetch-* validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 3.5.3 |
| **Files** | `webapp/packages/api/user-service/app_factory.py:31` |
| **Source Reports** | 3.5.3.md |
| **Related Findings** | - |

**Description:**

The CORS configuration uses allow_methods: ["*"] which permits all HTTP methods cross-origin. No visible Sec-Fetch-* header validation exists, and no global middleware enforces that state-changing operations use only POST/PUT/PATCH/DELETE. Without seeing route definitions, the risk is that GET requests to sensitive endpoints could trigger state changes (e.g., /api/v1/agents/{id}/execute?action=delete). If any state-changing or resource-intensive endpoints respond to GET requests, they can be exploited via simple resource loads (&lt;img&gt;, &lt;script&gt;, &lt;link&gt;) or navigation, bypassing CORS entirely since these are not cross-origin script requests.

**Remediation:**

1. Ensure all sensitive endpoints use appropriate HTTP methods at the route level (POST/PUT/PATCH/DELETE, not GET). 2. Add Sec-Fetch-* validation middleware for defense-in-depth to block cross-site navigation requests to API endpoints. 3. Restrict CORS methods to only those needed: allow_methods: ["GET", "POST", "PUT", "PATCH", "DELETE"] instead of wildcard. 4. Replace allow_headers: ["*"] with explicit header list: ["Content-Type", "Authorization", "X-Requested-With"].

---

#### FINDING-046: Session configuration endpoint returns unfiltered database document

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 15.3.1 |
| **Files** | `webapp/packages/api/user-service/routes.py:410-414` |
| **Source Reports** | 15.3.1.md |
| **Related Findings** | - |

**Description:**

The endpoint returns raw database document content without a `response_model` or explicit field selection. The `provider_config` sub-document is returned directly from the database service with no schema-based filtering, meaning any field stored in that sub-document (including potentially sensitive internal metadata, revision fields, or inadvertently stored secrets) will be exposed to the client.

**Remediation:**

Define and apply a Pydantic response model (ProviderConfig) to the endpoint. Example: @router.get("/sessions/{session_id}/config", response_model=ProviderConfig) and return ProviderConfig(**config_data) instead of raw dictionary.

---

#### FINDING-047: Provider configuration endpoints expose internal implementation details

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 15.3.1 |
| **Files** | `webapp/packages/api/user-service/routes.py:206-237` |
| **Source Reports** | 15.3.1.md |
| **Related Findings** | - |

**Description:**

Provider configuration endpoints return the full output of `get_available_providers()` or sub-objects thereof without any `response_model`. This function returns provider configuration dictionaries that may contain internal implementation details (endpoint URLs, pricing metadata, capability flags, internal identifiers) not intended for client consumption.

**Remediation:**

Define explicit Pydantic response models (ProviderResponse, ProviderDetailResponse, ModelSummary) that declare only the fields needed by clients. Apply these models using the response_model parameter on all provider-related endpoints.

---

#### FINDING-048: Agent chain and deployment endpoints return unfiltered service data

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 15.3.1 |
| **Files** | `webapp/packages/api/user-service/routes.py:469-481`, `webapp/packages/api/user-service/routes.py:586-589` |
| **Source Reports** | 15.3.1.md |
| **Related Findings** | - |

**Description:**

Agent chain and deployment endpoints return service function results without `response_model` filtering. The `build_agent_chain()` function walks transitive dependencies and may include internal IDs, raw database document fields, or infrastructure details (MCP server URLs, internal routing information) that should be filtered before client delivery.

**Remediation:**

Define response models (ChainNode, DeploymentInfo) that explicitly declare the fields needed by the Chain View UI. Apply these models to the agent chain and deployment endpoints to filter out internal infrastructure details.

---

#### FINDING-049: Missing charset parameter in text/event-stream Content-Type header

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 4.1.1 |
| **Files** | `webapp/packages/api/user-service/routes.py:600-744` |
| **Source Reports** | 4.1.1.md |
| **Related Findings** | - |

**Description:**

The Server-Sent Events (SSE) streaming endpoint sets `media_type="text/event-stream"` without including the `charset=utf-8` parameter. Since `text/event-stream` is a `text/*` content type, the ASVS requirement mandates a charset specification. Without it, intermediary proxies or older clients could misinterpret the character encoding, potentially leading to content misinterpretation or injection vectors in multi-byte character contexts. A response is delivered with header `Content-Type: text/event-stream` instead of `Content-Type: text/event-stream; charset=utf-8`. If a reverse proxy or client has a different default charset assumption (e.g., ISO-8859-1 per HTTP/1.1 spec for text/* without charset), multi-byte UTF-8 characters in agent trace output could be misinterpreted.

**Remediation:**

Add charset parameter to the media_type. Change `media_type="text/event-stream"` to `media_type="text/event-stream; charset=utf-8"` in the StreamingResponse call.

---

#### FINDING-050: No size constraints on swagger specification content accepted for processing

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 5.2.1, 5.2.2 |
| **Files** | `webapp/packages/api/user-service/agent_factory/__init__.py:34-41`, `webapp/packages/api/user-service/agent_factory/__init__.py:191` |
| **Source Reports** | 5.2.1.md, 5.2.2.md |
| **Related Findings** | - |

**Description:**

The `swagger_specs` accept content with a `name` and `content` field. There is no validation that: 1. `spec.name` has an expected extension (e.g., `.json`, `.yaml`, `.yml`) 2. `spec.content` is actually a valid OpenAPI/Swagger specification (checking magic bytes equivalent — e.g., verifying it starts with `openapi:` or `swagger:` for YAML, or contains `"openapi"` key for JSON) 3. The content type matches what `spec.name` implies. The `parse_spec_and_generate_docs` function is imported lazily and its implementation is not visible, so it's unknown whether it performs internal validation. If it doesn't validate, malicious content (e.g., YAML bombs, XXE in XML-based specs, or binary content) could be processed. If the parser handles multiple formats (JSON, YAML, XML), unexpected content types could trigger parser-specific vulnerabilities. Even without exploitation, non-spec content wastes processing resources.

**Remediation:**

Validate file extension against allowed list (ALLOWED_SPEC_EXTENSIONS = {'.json', '.yaml', '.yml'}). Validate content matches expected format by checking if JSON content starts with '{' or '[', and implementing similar checks for YAML. Apply os.path.splitext() to extract and validate extension. Raise ValueError for unsupported formats or mismatched content-extension pairs. Example code provided in report shows implementation of extension validation, content format validation, and error handling.

---

#### FINDING-051: Ticket Retrieval Lacks Ownership Verification (Authorization Step Absent)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.3.1 |
| **Files** | `webapp/packages/api/user-service/services/chat_service.py:109-117` |
| **Source Reports** | 2.3.1.md |
| **Related Findings** | - |

**Description:**

The get_ticket_status() function retrieves ticket data without verifying that the requesting user owns the ticket. There is no session_id comparison or ownership verification. Any authenticated user can retrieve any other user's chat tickets if they can guess or enumerate UUID ticket IDs. The ticket contains sensitive data: messages, session_id, model used, and full LLM responses. While UUIDs are hard to guess, if ticket IDs are exposed in URLs or logs, cross-user data access is possible.

**Remediation:**

Add session_id parameter to get_ticket_status(). After loading ticket data, verify that ticket_data.get('session_id') matches the requesting user's session_id. Return None or raise 403 if ownership verification fails. This ensures the authorization step is not skipped in the business logic flow.

---

#### FINDING-052: No Documented Configuration for Preventing Malicious Account Lockout via Spend Allowance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.1.1 |
| **Files** | `webapp/packages/api/user-service/services/llm_service.py:113-115` |
| **Source Reports** | 6.1.1.md |
| **Related Findings** | - |

**Description:**

The spend allowance mechanism in llm_service.py (line 113-115) lacks documentation defining how require_allowance() differentiates between legitimate high-usage and malicious behavior, whether attackers can deliberately exhaust user allowances via compromised sessions (denial of service), how allowances reset, whether alerts are sent when users approach limits, and whether separate rate-based limits prevent burst consumption. Without documented configuration, operators cannot properly configure the system to prevent attackers from exhausting user budgets via stolen session tokens, legitimate users being locked out due to automated integrations, or cost-based denial-of-service attacks.

**Remediation:**

Create comprehensive documentation covering: allowance structure (monthly allowance per user configurable via admin panel, reset on 1st of month at 00:00 UTC, 10% over-limit grace period for in-flight requests), abuse prevention mechanisms (max 5 simultaneous LLM calls per user, burst detection triggering temporary rate limit after >20 requests in 60s, alerts at 80% and 95% of allowance), and recovery procedures (emergency allowance increase via support, admin reset capability without waiting for monthly cycle, session token revocation without affecting allowance).

#### FINDING-053: No Circuit Breaker or Backpressure Documentation for External LLM Service Failures

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 6.1.1 |
| **Affected File(s)** | `webapp/packages/api/user-service/services/llm_service.py:256-268` |
| **Source Report(s)** | 6.1.1.md |
| **Related Finding(s)** | None |

**Description:**

The retry logic in llm_service.py (lines 256-268) handles timeouts but lacks circuit breaker functionality to stop calling failed providers after repeated failures, documentation of system behavior under sustained LLM provider outage, backpressure mechanisms to reject new requests when external services are degraded, and documentation of how MAX_TIMEOUT_RETRIES and LLM_TIMEOUT_SECONDS should be configured for different deployment scenarios. During an LLM provider outage, all user requests will queue up with 600-second timeouts, consuming server resources (memory, connections, asyncio tasks) without producing results, potentially cascading into full service outage.

**Remediation:**

Document and implement circuit breaker configuration with: failure threshold (5 failures in 30 seconds triggers circuit open), circuit open duration (60 seconds before half-open probe), half-open state (1 probe request allowed, success closes circuit). Configure timeouts appropriately (LLM_TIMEOUT_SECONDS: 120 for production instead of 600 default, LLM_TIMEOUT_RETRIES: 1 for production instead of 0 default, total max wait 240s). Implement backpressure with max 50 concurrent LLM calls per instance and HTTP 503 responses with Retry-After headers for queue overflow.

---

#### FINDING-054: No Evidence of Documented Risk-Based Remediation Timeframes for Third-Party Components

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.1.1 |
| **Affected File(s)** | `webapp/packages/api/user-service/services/llm_service.py:1-20`, `webapp/packages/api/user-service/app_factory.py:1-10` |
| **Source Report(s)** | 15.1.1.md |
| **Related Finding(s)** | None |

**Description:**

The application lacks documented risk-based remediation timeframes for third-party component vulnerabilities. Third-party libraries (litellm, FastAPI, Pydantic, OAuth) are used throughout the application runtime with no referenced policy governing update cadence or vulnerability remediation deadlines. No code comments, configuration files, or documentation references define SLA timelines for vulnerability remediation. No SBOM file reference or generation mechanism is visible. LiteLLM is identified as a critical trust point but the codebase shows no corresponding classification or tiered remediation policy. Without documented remediation timeframes, teams lack clear deadlines for patching known vulnerabilities, prioritization becomes ad-hoc rather than risk-based, compliance audit evidence cannot demonstrate timely response to disclosed CVEs, and critical components may remain unpatched during active exploitation.

**Remediation:**

Create a DEPENDENCY_POLICY.md or equivalent governance document defining risk classification criteria and remediation SLAs. Classify components as Critical/High/Medium/Low based on criteria such as handling auth, secrets, or direct user input. Define remediation SLAs from CVE publication date: Critical components with Critical vulnerabilities (CVSS 9.0+) should be remediated within 24 hours, Critical components with High vulnerabilities (CVSS 7.0-8.9) within 72 hours, etc. Establish regular update cadence with Critical components reviewed monthly minimum and all components on quarterly update cycle. Implement automated scanning daily via dependabot/pip-audit/npm audit. Reference this policy in code comments and generate SBOM using scripts/generate_sbom.sh.

---

#### FINDING-055: No Automated Mechanism to Enforce Dependency Update SLA Compliance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.2.1 |
| **Affected File(s)** | `webapp/packages/api/user-service/app_factory.py:entire file`, `webapp/packages/api/user-service/services/llm_service.py:1-20` |
| **Source Report(s)** | 15.2.1.md |
| **Related Finding(s)** | None |

**Description:**

No CI/CD gate or runtime check visible that validates dependencies against known CVE databases. No version assertion or compatibility check for LiteLLM at startup (the code uses `litellm.aresponses` which is a relatively new API; older vulnerable versions might not have it but could silently fail). No `pip-audit`, `safety`, or equivalent integration referenced in the codebase. No deployment-time SBOM validation against a vulnerability database. Without a documented remediation timeframe (ASVS 15.1.1), compliance with update deadlines cannot be verified or enforced.

**Remediation:**

Implement multi-layer dependency compliance: (1) Create scripts/check_dependency_compliance.py to run in CI/CD and optionally at application startup, validating all dependencies against documented SLA timeframes using pip-audit with severity-based remediation deadlines (critical: 24h, high: 7d, medium: 30d, low: 90d). (2) Add runtime dependency version logging at startup in app_factory.py to log critical dependency versions (litellm, fastapi) for audit trail. (3) Add minimum version assertions for LiteLLM to fail fast if incompatible/vulnerable version is deployed. (4) Configure Dependabot/Renovate with update schedules aligned to remediation policy. (5) Implement supply chain verification using pip install --require-hashes.

---

#### FINDING-056: No Defense-in-Depth Middleware to Block Source Control Metadata Paths

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 13.4.1 |
| **Affected File(s)** | `webapp/packages/api/user-service/app_factory.py:55` |
| **Source Report(s)** | 13.4.1.md |
| **Related Finding(s)** | None |

**Description:**

The application does not register any middleware or route guard that explicitly blocks requests to well-known source control metadata paths (e.g., /.git/config, /.git/HEAD, /.svn/entries). While FastAPI will return 404 for undefined routes, if the application is deployed behind a reverse proxy that serves static files from the application directory (common with nginx try_files patterns), source control metadata could be exposed. An attacker who gains access to .git/ can reconstruct the entire source code repository, including historical commits that may contain secrets, internal architecture details, and configuration that aids further attacks.

**Remediation:**

Add middleware to explicitly block requests to source control metadata paths. Implement BlockSensitivePathsMiddleware that blocks prefixes like /.git, /.svn, /.hg, /.env, /.bzr by returning 404 responses. Register this middleware in the create_app() function before other middleware to ensure it executes first.

### 3.4 Low

#### FINDING-057: OAuth Access Tokens Stored on Mutable Object Without Clear Lifecycle

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-922 |
| **ASVS Section(s)** | 10.4.5 |
| **Files** | `auth/providers/github.py:153`&lt;br&gt;`auth/providers/google.py:172`&lt;br&gt;`auth/providers/microsoft.py:156` |
| **Source Reports** | 10.4.5.md |
| **Related Findings** | None |

**Description:**

OAuth access tokens from upstream providers are attached to UserInfo dataclass objects as ad-hoc private attributes using dynamic attribute assignment (e.g., user_info._access_token). While these tokens appear to be short-lived and scoped to a single request, the lifecycle is implicit and the pattern lacks explicit cleanup. The use of type: ignore[attr-defined] annotations indicates recognized design smell. If UserInfo objects are ever serialized (logged, cached, stored), tokens could leak. Current code does not persist these tokens, but the pattern creates risk for future code changes.

**Remediation:**

Refactor to use an explicit ExchangeResult context object that separates concerns. Create a dataclass with user_info and access_token fields, use the token for membership queries within the exchange_code method, then return only the UserInfo object so the token goes out of scope. Alternatively, add explicit token cleanup by deleting the _access_token attribute at the end of exchange_code after all token usage is complete.

---

#### FINDING-058: Dev_Stub Provider Authorization Codes Are Reusable

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 10.4.2 |
| **Files** | `webapp/packages/api/user-service/auth/providers/dev_stub.py` (exchange_code method) |
| **Source Reports** | 10.4.2.md |
| **Related Findings** | None |

**Description:**

In the dev_stub flow, authorization "codes" (user UIDs) can be reused indefinitely. Each use creates a new session. While this is by design for development, it means there is no single-use enforcement. No token revocation occurs on reuse. Severity is LOW because: (1) dev_stub is explicitly dev-only, (2) the CSRF state cookie provides a 10-minute window, and (3) real OAuth providers handle single-use enforcement externally.

**Remediation:**

For completeness in the dev_stub (useful if it's ever used in integration testing that should mirror production behavior):

```python
class DevStubProvider(AuthProvider):
    def __init__(self, config: dict):
        super().__init__(config)
        self._used_nonces: set = set()  # Track used state+code combinations
    
    async def exchange_code(self, code: str, redirect_uri: str, nonce: str = "") -> UserInfo:
        key = f"{nonce}:{code}"
        if key in self._used_nonces:
            raise ValueError("Authorization code already used")
        self._used_nonces.add(key)
        ...
```

---

#### FINDING-059: Dev_Stub Authorization Codes Have No Expiration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 10.4.3 |
| **Files** | `webapp/packages/api/user-service/auth/providers/dev_stub.py` |
| **Source Reports** | 10.4.3.md |
| **Related Findings** | None |

**Description:**

The dev_stub provider's "authorization codes" are static user UIDs that never expire. However, the indirect protection comes from the CSRF state cookie which has a 10-minute TTL (max_age=600). After the state cookie expires, the callback CSRF check fails, effectively providing a 10-minute window. For real OAuth providers, code lifetime is managed by the external authorization server (typically 30-60 seconds for Google/Microsoft, 10 minutes for GitHub). The 10-minute state cookie aligns with the ASVS L1 maximum of 10 minutes for authorization codes, providing adequate protection for the overall flow even though the dev_stub code itself doesn't expire.

**Remediation:**

Implement application-side code timestamp validation for dev_stub. Although the state cookie provides a 10-minute window, explicit code expiration would provide defense-in-depth and align with authorization server best practices.

---

#### FINDING-060: Admin Panel Authorization Model Undocumented and Separate from Workspace RBAC

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 8.1.1 |
| **Files** | `webapp/packages/api/user-service/dependencies.py:109-114` |
| **Source Reports** | 8.1.1.md |
| **Related Findings** | None |

**Description:**

The admin panel uses a shared secret (X-Admin-Password) that is unrelated to the workspace RBAC model (WorkspaceRole, site admin via auth.yaml). There is no documentation defining how these two authorization systems relate or when each should be used. Two parallel authorization mechanisms (shared password vs. session-based site admin) create confusion about which grants access where, increasing risk of accidental privilege grants.

**Remediation:**

Unify the admin authorization model by replacing or supplementing the shared-password admin panel with the session-based is_site_admin flag, providing per-actor attribution. Document how the two authorization systems relate and when each should be used.

---

#### FINDING-061: Authorization Enforcement Occurs Correctly at Server Layer (Positive Finding with Gap Note)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 8.3.1 |
| **Files** | `webapp/packages/api/user-service/routes.py` |
| **Source Reports** | 8.3.1.md |
| **Related Findings** | None |

**Description:**

All authorization checks are performed server-side via FastAPI dependency injection. No authorization logic is delegated to or relies on client-side enforcement. The get_current_user dependency validates sessions/tokens at the trusted service layer. However, while the enforcement location is correct (server-side), the enforcement completeness is deficient (authentication without authorization for most resource operations, as documented in 8.2.1 and 8.2.2 findings).

**Remediation:**

While the enforcement layer is correct, implement complete authorization checks as documented in the immediate and short-term recommendations. Ensure that authentication is not conflated with authorization and that workspace-based access control is enforced for all resource operations.

---

#### FINDING-062: Error messages containing user-controlled input serialized into SSE JSON without explicit sanitization context

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 1.2.3 |
| **Files** | `routes.py:324-329`&lt;br&gt;`routes.py:338` |
| **Source Reports** | 1.2.3.md |
| **Related Findings** | None |

**Description:**

While `json.dumps` properly encodes the content for JSON consumption (escaping quotes, backslashes, control characters), the error string may contain user-controlled input from `input_dict` or code execution output. If a consuming client parses this JSON and renders the error message in a DOM context (e.g., `innerHTML`), the JSON encoding alone doesn't prevent XSS in the browser. This is a defense-in-depth concern — the primary protection must be in the consuming client. The risk is only if consuming clients improperly handle the decoded values.

**Remediation:**

Document that SSE consumers must treat `error` and `result` fields as untrusted when rendering in DOM contexts. Optionally, strip HTML-significant characters from error messages:

```python
import re
final["error"] = re.sub(r'[<>&"\']', '', f"{type(e).__name__}: {e}")
```

---

#### FINDING-063: Session and ticket IDs from path parameters used directly in `db.get()` without format validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 1.2.4 |
| **Files** | `webapp/packages/api/user-service/routes.py` (multiple) |
| **Source Reports** | 1.2.4.md |
| **Related Findings** | None |

**Description:**

Multiple endpoints pass user-controlled path parameters directly to `db.get()` as document IDs. While ID-based lookups are inherently safe against injection in most NoSQL databases (they map to direct key lookups), there's no validation that these IDs conform to expected formats (UUID, etc.). If the `DatabaseService` implementation for CouchDB constructs REST URLs like `/{db}/{id}`, malformed IDs could potentially lead to path traversal within the CouchDB HTTP API. Direct ID lookups in NoSQL databases are generally safe. The risk exists only if the underlying implementation concatenates the ID into a URL or query string without encoding.

**Remediation:**

Validate that document IDs conform to the expected format:

```python
UUID_PATTERN = re.compile(r"^[a-f0-9\-]{36}$")

@router.get("/agents/{agent_id}", response_model=Agent)
async def get_agent(agent_id: str, ...):
    if not UUID_PATTERN.match(agent_id):
        raise HTTPException(status_code=400, detail="Invalid agent ID format")
    agent_doc = db.get("agents", agent_id)
```

---

#### FINDING-064: No HTML sanitization on user-generated content fields stored for potential frontend rendering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.3.1 |
| **Files** | `webapp/packages/api/user-service/models/agent.py` |
| **Source Reports** | 1.3.1.md |
| **Related Findings** | FINDING-014, FINDING-023 |

**Description:**

Fields like description, name, docstring, and SwaggerSpec.content in agent models accept arbitrary string content without server-side sanitization. While these are returned as JSON and not rendered as HTML by the server, they flow to the frontend where they may be rendered in the DOM. If the frontend uses unsafe rendering patterns like dangerouslySetInnerHTML, this could result in stored XSS affecting other users viewing the same agent. The risk is LOW because modern frameworks like React escape by default, but the lack of server-side sanitization creates a dependency on correct frontend implementation.

**Remediation:**

For fields expected to contain rich text or markdown, apply server-side sanitization using a library like bleach or nh3. Example: Use a Pydantic field_validator to sanitize the description field with nh3.clean(v) which strips dangerous HTML while preserving safe content. This provides defense-in-depth regardless of frontend implementation.

---

#### FINDING-065: Missing documented validation rules for string-identity fields

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 2.1.1 |
| **Files** | `models/user.py:36`&lt;br&gt;`routes.py:218` |
| **Source Reports** | 2.1.1.md |
| **Related Findings** | None |

**Description:**

The `email` field has no format documentation (e.g., RFC 5322 pattern), `provider` has no documented allow-list of valid values, and `display_name` has no length constraints. These are common data formats for which ASVS 2.1.1 expects explicit documented rules.

**Remediation:**

Add `EmailStr` for email, `Literal` or `pattern` for provider, and `max_length` for display_name.

---

#### FINDING-066: UpdateApiKeyRequest.provider not validated against allowed provider list

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | `routes.py:218` |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | None |

**Description:**

The provider field is not validated against the known set of API key providers defined in ApiKeys model (openai, anthropic, gemini, perplexity, openrouter). Invalid provider names may cause silent failures or unexpected database writes depending on the update_api_key implementation.

**Remediation:**

Add a regex pattern constraint to the provider field to validate against the known set of providers: pattern="^(openai|anthropic|gemini|perplexity|openrouter)$". Also add min_length=1 to api_key field.

---

#### FINDING-067: Document IDs embed user identifiers suitable for URL path exposure

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 14.2.1 |
| **Files** | `webapp/packages/api/user-service/services/data_store_service.py:72` |
| **Source Reports** | 14.2.1.md |
| **Related Findings** | None |

**Description:**

The composite document ID format `{user_id}:{namespace}:{base64_key}` embeds the user identifier directly. If REST endpoints expose these IDs in responses (e.g., for direct retrieval), and if downstream route handlers construct URLs like `/api/datastore/{doc_id}`, the user_id becomes part of the URL path. While `user_id` is an identifier rather than a secret credential, the `key` parameter (base64-encoded) could contain sensitive descriptors. Base64 is encoding, not encryption—it's trivially reversible. Low risk unless route handlers pass these as URL query parameters. The base64 encoding is purely for URL-safety, not confidentiality.

**Remediation:**

Ensure route handlers serving this data use POST request bodies for operations that accept `key` or `namespace` values that could be sensitive, and avoid exposing composite doc_ids in URLs. Example: Use POST body with sensitive identifiers `@router.post("/datastore/get") async def get_data(request: DataStoreGetRequest, user=Depends(get_current_user)): return service.get(user.id, request.namespace, request.key)`. Avoid GET with sensitive key in URL like `@router.get("/datastore/{namespace}/{key}")` as key would be visible in server logs and browser history.

---

#### FINDING-068: No Clear-Site-Data header implementation in the codebase

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 14.3.1 |
| **Files** | None |
| **Source Reports** | 14.3.1.md |
| **Related Findings** | None |

**Description:**

The provided codebase contains no implementation of the Clear-Site-Data HTTP response header. While this is service-layer code (not route/middleware code), the absence across the entire provided scope suggests the application may not implement this control anywhere. The ASVS requirement specifically mentions this header as a mechanism for server-initiated client data cleanup. This could be implemented in middleware or route handlers not provided in this audit scope. This finding has low confidence without seeing the full application.

**Remediation:**

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

---

#### FINDING-069: Defense-in-Depth Gap in refresh_workspaces

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 9.2.1 |
| **Files** | `webapp/packages/api/user-service/services/session_service.py:156-210` |
| **Source Reports** | 9.2.1.md |
| **Related Findings** | None |

**Description:**

The refresh_workspaces() method operates on a Session object without independently verifying that session.expires_at has not passed. While the intended call flow is get_by_id() → (expiry validated) → refresh_workspaces(), there is no defense-in-depth check within the method itself. Potential misuse scenario: Future developer loads a session document directly from the database (bypassing get_by_id()), calls refresh_workspaces() on the expired session, and the session is re-saved to database with updated last_refresh_at — effectively 'touching' an expired session. Current Risk Assessment: LOW — The code structure strongly implies get_by_id() is always called first. This is an observation about missing defense-in-depth, not a current exploit path.

**Remediation:**

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

---

#### FINDING-070: Fetch interceptor does not enforce `Accept: application/json` header on API requests

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 3.2.1 |
| **Files** | `webapp/packages/webui/src/services/fetchInterceptor.js:43-47` |
| **Source Reports** | 3.2.1.md |
| **Related Findings** | None |

**Description:**

The fetch interceptor wraps all API calls to add `credentials: 'include'` but does not enforce an `Accept: application/json` header. While server-side content-type enforcement is the primary defense, sending an explicit `Accept` header provides defense-in-depth by signaling to the server that only JSON responses are expected. If an intermediate proxy or CDN serves cached responses with incorrect content types, the lack of `Accept` header means the client hasn't communicated its expected context. Minimal direct impact because response bodies are consumed programmatically via `resp.json()` (which would throw on non-JSON content). However, this reduces the signal available for server-side Sec-Fetch validation and content negotiation.

**Remediation:**

Extend the fetch interceptor to automatically set `Accept: application/json` header on all API requests. Recommended implementation:

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

---

#### FINDING-071: Deployed agent execution endpoint lacks response envelope

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 15.3.1 |
| **Files** | `webapp/packages/api/user-service/routes.py:810-827` |
| **Source Reports** | 15.3.1.md |
| **Related Findings** | None |

**Description:**

The deployed agent execution endpoint returns the full result from `run_deployed_agent_logic()` without a `response_model`. While agent output is inherently dynamic, the lack of any response envelope or filtering means internal execution metadata could leak alongside the intended result.

**Remediation:**

Wrap the response in a defined envelope model (DeployedAgentResponse) with explicit fields for result and status. Apply this model using the response_model parameter to ensure consistent response structure and prevent metadata leakage.

---

#### FINDING-072: MCP tools endpoint returns unfiltered external server responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 15.3.1 |
| **Files** | `webapp/packages/api/user-service/routes.py:544-553` |
| **Source Reports** | 15.3.1.md |
| **Related Findings** | None |

**Description:**

The MCP tools endpoint returns the raw tool list from `mcp_service.list_tools_for_server()` without a response model. MCP tool definitions returned by remote servers could contain internal metadata fields not appropriate for client exposure.

**Remediation:**

Define response models (McpTool, ListMcpToolsResponse) that explicitly declare which tool fields the UI needs (name, description, input_schema). Apply these models to filter external MCP server responses before forwarding to clients.

---

#### FINDING-073: No count limit on MCP tool URLs or gofannon agents per request

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 5.2.1 |
| **Files** | `webapp/packages/api/user-service/agent_factory/__init__.py:24-31`&lt;br&gt;`webapp/packages/api/user-service/agent_factory/__init__.py:44-66` |
| **Source Reports** | 5.2.1.md |
| **Related Findings** | None |

**Description:**

A request with hundreds of tool URLs would cause the server to make HTTP connections to all of them sequentially. The code iterates over request.tools (unbounded dict) making iterative remote HTTP calls to each URL via mcp_client.list_tools(). Similarly, request.gofannon_agents with many IDs would cause many database lookups. This can lead to resource exhaustion through excessive outbound connections or database queries.

**Remediation:**

Add maximum count limits on collection fields in the GenerateCodeRequest Pydantic model. Limit the number of swagger_specs, tools URLs, gofannon_agents, and invokable_models per request to reasonable values (e.g., 10-50 items depending on expected use cases).

---

#### FINDING-074: User-controlled `spec.name` passed to parsing function without sanitization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS Section(s)** | 5.3.2 |
| **Files** | `webapp/packages/api/user-service/agent_factory/__init__.py:37` |
| **Source Reports** | 5.3.2.md |
| **Related Findings** | None |

**Description:**

The `spec.name` field is user-controlled and passed directly to `parse_spec_and_generate_docs()`. If this function uses the `name` parameter to construct file paths (e.g., writing a temp file for parsing, or logging), path traversal characters (`../`, absolute paths) could exploit the system. However, this is classified as LOW severity because: 1. The function name suggests it only generates documentation strings (not file operations), 2. The `swagger_parser` module implementation is not available for verification, 3. Modern parsing libraries typically operate on content strings, not file paths, 4. The `name` parameter appears to be used as a label/title based on how it's consumed (for generating section headers in documentation).

**Remediation:**

Sanitize the spec.name field before passing it to downstream functions. Apply `os.path.basename()` to strip path components and use regular expressions to allow only alphanumeric characters, hyphens, underscores, and dots. Example implementation:

```python
import re

def sanitize_spec_name(name: str) -> str:
    """Sanitize spec name to prevent path traversal and ensure safe usage."""
    # Extract just the filename, strip path components
    basename = os.path.basename(name)
    # Allow only alphanumeric, hyphens, underscores, dots
    sanitized = re.sub(r'[^\w\-.]', '_', basename)
    if not sanitized:
        sanitized = "unnamed_spec"
    return sanitized

for spec in request.swagger_specs:
    safe_name = sanitize_spec_name(spec.name)
    docs_for_spec = parse_spec_and_generate_docs(safe_name, spec.content)
```

---

#### FINDING-075: Critical Dependency (LiteLLM) Not Classified as "Dangerous Functionality" Component

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 15.1.1 |
| **Files** | `webapp/packages/api/user-service/services/llm_service.py:14-20` |
| **Source Reports** | 15.1.1.md |
| **Related Findings** | None |

**Description:**

LiteLLM performs HTTP calls to external services, processes API keys, handles untrusted binary/JSON data from external APIs, and dynamically routes to different backends. Per ASVS 15.1.1 section description, components performing raw file or binary data parsing and handling sensitive operations should be documented as containing dangerous functionality. No documentation classifies LiteLLM's risk profile or lists it as requiring enhanced scrutiny during updates. The domain context explicitly identifies LiteLLM's model loading as resource-intensive and LiteLLM and OAuth libraries as critical trust points, but this is not reflected in the codebase. Without classifying LiteLLM as a dangerous/critical component, it may not receive expedited remediation when vulnerabilities are disclosed, despite being the primary interface to external LLM providers with access to user API keys.

**Remediation:**

Add component classification documentation in a dependency_classifications.yaml file. Document critical_trust_components including litellm with reason 'Handles user API keys, makes external HTTP calls, processes untrusted API responses', dangerous_operations including 'external HTTP with secrets', 'dynamic API routing', 'response parsing', and remediation_tier set to critical. Similarly classify OAuth libraries with reason 'Handles OAuth flows, token validation, session establishment', dangerous_operations including 'cryptographic token validation' and 'external IdP communication', and remediation_tier set to critical.

---

#### FINDING-076: API Documentation Endpoints Exposed in Production

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 13.4.1 |
| **Files** | `webapp/packages/api/user-service/app_factory.py:55` |
| **Source Reports** | 13.4.1.md |
| **Related Findings** | None |

**Description:**

The FastAPI() constructor is called without setting docs_url=None or redoc_url=None, which means the interactive API documentation at /docs (Swagger UI) and /redoc (ReDoc) are available to any requester. This exposes the complete API surface area, parameter types, and endpoint structure to attackers. Attackers can enumerate all API endpoints, understand parameter schemas, and identify potential attack targets without fuzzing. This violates the principle of not exposing internal API docs or monitoring endpoints publicly and aids reconnaissance for subsequent attacks.

**Remediation:**

Conditionally disable API documentation endpoints in production by setting docs_url=None, redoc_url=None, and openapi_url=None when ENVIRONMENT variable is set to 'production'. Allow documentation endpoints only in development environments.

---

#### FINDING-077: Debug/Configuration Information Printed to stdout

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 13.4.1 |
| **Files** | `webapp/packages/api/user-service/app_factory.py:30`&lt;br&gt;`webapp/packages/api/user-service/app_factory.py:68` |
| **Source Reports** | 13.4.1.md |
| **Related Findings** | None |

**Description:**

The application uses print() statements to output configuration details and error messages. In containerized deployments, stdout is captured in logs which may be accessible to operators or log aggregation services with insufficient access controls. The statements leak configured frontend URL and may include sensitive details about auth configuration errors (e.g., file paths, secret fragments in error messages). This contributes to information leakage.

**Remediation:**

Replace print() statements with structured logging through the observability service. Log configuration information at appropriate levels (INFO for normal config, WARNING for errors) with sanitized details that do not expose sensitive configuration values or internal paths. Avoid including full error messages that may contain sensitive data.

---

# 4. Positive Security Controls

| Control | Evidence | Files | Domain |
|---------|----------|-------|--------|
| Authorization code flow (not implicit) prevents token exposure in URLs | Application correctly uses authorization code flow across all providers | google.py, microsoft.py, github.py, asf.py, dev_stub.py | pluggable_authentication |
| CSRF state token validation on OAuth flow | Present in login_redirect and login_callback functions using secrets.compare_digest() for constant-time comparison | routes_auth.py | pluggable_authentication |
| HTML escaping in deny page | _render_deny_page() uses html.escape() | routes_auth.py | pluggable_authentication |
| Relative return_to paths correctly prefixed with FRONTEND_URL | Prevents host-relative open redirect for relative paths | routes_auth.py | pluggable_authentication |
| External OAuth provider redirect_uri validation | Google, GitHub, and Microsoft validate redirect_uri against pre-registered values | External providers | pluggable_authentication |
| CSRF state cookie with 10-minute TTL | State cookie has max_age=600 (10 minutes), which aligns with the ASVS L1/L2 maximum | routes_auth.py:login_redirect | pluggable_authentication |
| Provider-side code expiration | External providers (Google: ~5 min, Microsoft: ~10 min, GitHub: ~10 min) enforce code lifetimes within acceptable ranges | External providers | pluggable_authentication |
| Implicit flow (token grant) not implemented | No response_type=token found in codebase | All files | pluggable_authentication |
| Resource Owner Password Credentials flow not implemented | No password grant flow found in codebase | All files | pluggable_authentication |
| GitHub provider prevents unauthorized account creation | allow_signup: false explicitly set | github.py | pluggable_authentication |
| Secure Cookie Defaults | Auto-detects HTTPS for Secure flag; always sets httponly + samesite=lax on session cookies | routes_auth.py:_is_secure_cookie | pluggable_authentication |
| Server-Side Session Architecture | Session ID is opaque; all authorization state is server-side; no JWT/bearer tokens used. Inherently prevents token replay attacks with immediate revocation capability | routes_auth.py:login_callback | pluggable_authentication |
| Hosted Domain Enforcement | Server-side validation of hd claim in ID token for Google OAuth | auth/providers/google.py:exchange_code | pluggable_authentication |
| Banned User Hard Deny | Ban check overrides even site-admin privileges, preventing privilege escalation | auth/providers/asf.py:evaluate_login | pluggable_authentication |
| Provider Configuration Fail-Fast | Missing secrets raise exceptions at startup in all provider __init__ methods | github.py, google.py, microsoft.py, asf.py | pluggable_authentication |
| HTTP Client Timeouts | All provider modules use httpx.AsyncClient(timeout=10.0) to prevent hanging requests | github.py, google.py, microsoft.py, asf.py | pluggable_authentication |
| Cryptographically strong state token generation | secrets.token_urlsafe(24) generates state tokens with 192 bits of entropy | routes_auth.py | pluggable_authentication |
| Provider type prefixed to UIDs | UID prefixing pattern (e.g., dev_stub:site_admin_1) makes collision with real provider accounts impossible | .dev-auth.yaml, dev_stub.py | pluggable_authentication |
| Strong session ID generation | secrets.token_urlsafe(32) providing 256 bits of entropy | session_service.py:183 | session_management |
| HttpOnly attribute consistently applied | Applied to all authentication cookies | routes_auth.py:115, 123, 190 | session_management |
| SameSite=lax consistently applied | Applied to all authentication cookies for CSRF protection | routes_auth.py:116, 124, 191 | session_management |
| OAuth state CSRF protection | Using secrets.token_urlsafe(24) with constant-time comparison via secrets.compare_digest | routes_auth.py:155 | session_management |
| Server-side session with hard expiry checking | Automatic eviction of expired sessions on every access | session_service.py:89-122 | session_management |
| Session fixation prevention | New session ID generation on each login using _new_session_id() | session_service.py:209-211 | session_management |
| HTML escaping in error pages | Using html.escape() to prevent reflected XSS | routes_auth.py | session_management |
| Short-lived state cookies | 10 minute expiry (max_age=600) | routes_auth.py | session_management |
| All session validation is server-side | Backend-only verification, never trusts client-side state | session_service.py:89-122 | session_management |
| Cryptographically secure PRNG | Using Python secrets module providing OS-level CSPRNG | session_service.py:211 | session_management |
| Session termination | SessionService.delete() removes session document from CouchDB | session_service.py:124-133, routes_auth.py:199 | session_management |
| Session documents contain user_uid | Enabling future bulk-delete queries | session_service.py:79 | session_management |
| Clear ID format documentation | Module-level docstrings document conventions with examples | models/workspace.py | workspace_access_control |
| MembershipSource tracking | Tracks provenance of permissions, enabling future auditability | models/workspace.py:38-48 | workspace_access_control |
| Audit service infrastructure | Pre-built for cross-workspace access logging | services/audit_service.py | workspace_access_control |
| Module-level docstrings | Describe intended security semantics | models/workspace.py, audit_service.py | workspace_access_control |
| WorkspaceRole type definition | Provides foundation for RBAC | models/workspace.py:36 | workspace_access_control |
| WorkspaceMembership model | Defined and cached in session | models/workspace.py:46-77 | workspace_access_control |
| Authentication on all routes | All routes (except /health) require authentication via get_current_user | routes.py:117 | workspace_access_control |
| Session carries workspace memberships | Infrastructure carries workspace memberships and role information | routes.py:88-89 | workspace_access_control |
| Admin panel can be disabled | Via ADMIN_PANEL_ENABLED setting | Configuration | workspace_access_control |
| Data store routes demonstrate correct pattern | Filtering by user_id at the query level | routes.py:911-1013 | workspace_access_control |
| Data Store routes properly enforce user scoping | All data store routes filter by user_id at the query level | routes.py:911-1013 | workspace_access_control |
| AgentDataStoreProxy binds user_id | Binds user_id at construction time, preventing cross-user access | dependencies.py | workspace_access_control |
| UUIDv4 ticket IDs | Provide defense-in-depth against casual enumeration | routes.py:369-382 | workspace_access_control |
| Consistent authentication on all routes | Every route has user: dict = Depends(get_current_user) | routes.py:various | workspace_access_control |
| Well-designed workspace model | Clear semantics in models/workspace.py | models/workspace.py | workspace_access_control |
| Session validation performed server-side | FastAPI dependency injection system | routes.py:_verify_session_cookie | workspace_access_control |
| Firebase token validation performed server-side | FastAPI dependency injection system | routes.py:_verify_firebase_token | workspace_access_control |
| Admin password check performed server-side | FastAPI dependency injection system | dependencies.py:require_admin_access | workspace_access_control |
| No client-side JavaScript authorization | All authentication performed server-side through FastAPI dependency injection | All files | workspace_access_control |
| OAuth2 scheme extracts tokens server-side | Server-side implementation | oauth2_scheme | workspace_access_control |
| Trace observability system with event caps | MAX_EVENTS_PER_TRACE = 2000 and MAX_EVENT_MESSAGE_BYTES = 4096, contextvar-based scoping | services/agent_trace.py:37-42, 71-83 | agent_code_sandbox |
| LLM timeout auto-scaling | call_llm_with_context wrapper intelligently scales timeouts based on parameters | dependencies.py:224-240 | agent_code_sandbox |
| Agent chain cycle detection | Proper cycle detection with path set tracking, depth limiting at 8 levels | dependencies.py | agent_code_sandbox |
| Data store user scoping | AgentDataStoreProxy initialized with user_id and agent_name | dependencies.py:267-277 | agent_code_sandbox |
| Output schema validation | Advisory validation that checks types, missing keys, and extra keys | dependencies.py | agent_code_sandbox |
| Event source tagging | Events tagged with source: 'system' vs source: 'stdout'/'log' | services/agent_trace.py | agent_code_sandbox |
| Operator control over trace capture | GOFANNON_DISABLE_USER_TRACE allows silencing noisy user-origin events | services/agent_trace.py | agent_code_sandbox |
| LLM call tracing | Every LLM call records provider, model, duration, and error status | dependencies.py:242-264 | agent_code_sandbox |
| html.escape() used in _render_deny_page | Properly uses html.escape() on the reason parameter | routes_auth.py:249 | api_input_validation |
| FastAPI JSON serialization | Automatic response serialization handles JSON encoding correctly | All API endpoints | api_input_validation |
| Pydantic model_dump serialization | Response models use Pydantic serialization for proper JSON encoding | All models | api_input_validation |
| SSE streaming JSON encoding | Uses json.dumps() which properly escapes special characters | routes.py:~338, ~348 | api_input_validation |
| Relative return_to paths correctly prefixed | Applied for relative paths only, preventing protocol-relative URLs | routes_auth.py:153-156 | api_input_validation |
| _default_redirect_uri function | Builds redirect URIs from server's own base URL | routes_auth.py:53-56 | api_input_validation |
| Protocol-scheme check on return_to | Checks protocol but not domain, prevents javascript: and data: URLs | routes_auth.py:149 | api_input_validation |
| DatabaseService abstraction | Uses method-based access rather than raw query strings | services/database_service.py | api_input_validation |
| Pydantic model validation with extra='ignore' | Prevents unexpected fields from being saved to database | models/agent.py:77, 96 | api_input_validation |
| FastAPI path parameter typing | Route definitions ensure string type for path params | routes.py | api_input_validation |
| User-scoped queries | Data store queries always include {"userId": user_id} from authenticated session | routes.py:405, 420 | api_input_validation |
| No shell/subprocess calls | No shell command execution in analyzed files | All analyzed files | api_input_validation |
| Agent code sandbox | Execution uses Python interpreter, not OS shell | dependencies | agent_code_sandbox |
| ChatMessage.role positive validation | Exemplary allow-list validation enforcing user|assistant|system roles | models/chat.py:42 | api_input_validation |
| _ensure_mutually_exclusive | Good business logic validation for provider-specific parameters | models/chat.py:9-31 | api_input_validation |
| FastAPI Pydantic auto-validation | All router endpoints use Pydantic model parameters | routes.py | api_input_validation |
| Server-side auth validation | get_current_user dependency applied to all authenticated endpoints | routes.py | api_input_validation |
| Base64 URL-safe encoding of keys | Provides URL safety, not confidentiality | services/data_store_service.py:74 | database_abstraction_layer |
| User ID scoping via parameters | All service methods accept user_id as programmatic parameter | services/data_store_service.py | database_abstraction_layer |
| Service-layer abstraction | Separates data access from HTTP concerns | services/data_store_service.py | database_abstraction_layer |
| AgentDataStoreProxy designed for injection | Designed for injection with user_id from server-side auth layer | services/data_store_service.py | database_abstraction_layer |
| No URL construction with sensitive data | No HTTP URLs containing API keys, session tokens, or user secrets | services/data_store_service.py | database_abstraction_layer |
| Value preview truncation | _VALUE_PREVIEW_MAX = 200 limits data in ops_log entries | services/data_store_service.py:218-226 | database_abstraction_layer |
| Conditional ops_log | _log() method checks if self._ops_log is None, making logging opt-in | services/data_store_service.py:228-237 | database_abstraction_layer |
| Server-side data scoping | DataStoreService keeps all raw data server-side | services/data_store_service.py | database_abstraction_layer |
| Opaque token architecture | Using secrets.token_urlsafe(32) for session IDs | session_service.py:_new_session_id() | cryptographic_operations |
| Server-side session storage | Session data stored in user_sessions collection | session_service.py:create_from_login() | cryptographic_operations |
| No block cipher usage | No ECB mode, CBC mode, or PKCS#1 v1.5 padding usage | auth/base.py, services/session_service.py | cryptographic_operations |
| No hash function usage for session generation | secrets.token_urlsafe(32) provides 256 bits of entropy directly from OS CSPRNG | session_service.py:_new_session_id() | cryptographic_operations |
| Session expiry enforcement | get_by_id() enforces validity time span, returns None when expired | session_service.py:130-137 | cryptographic_operations |
| Hard expiry enforcement | session.expires_at <= datetime.utcnow() ensures expired sessions cannot be reused | session_service.py:~130 | cryptographic_operations |
| Proper session lifetime configuration | Session lifetime set at creation with configurable TTL (default 24 hours) | session_service.py:75-77 | cryptographic_operations |
| Fail-closed on deserialization errors | Session rejected and evicted if expires_at or any field cannot be deserialized | session_service.py:119-126 | cryptographic_operations |
| Static provider configuration | Providers instantiated once at startup from AUTH_CONFIG['providers'] | auth/base.py:__init__() | cryptographic_operations |
| Provider type tracking | UserInfo.provider_type and session.provider_type ensure no token confusion | auth/base.py:30-39 | cryptographic_operations |
| Infrastructure-level TLS termination | Deployment on cloud platforms typically handles TLS at load balancers | Documentation | tls_and_transport_security |
| Modern framework with TLS support | FastAPI/Starlette with uvicorn can enforce modern TLS versions | app_factory.py | tls_and_transport_security |
| CORS origins restricted | CORS restricted to single configured frontend URL rather than wildcard | app_factory.py:28 | tls_and_transport_security |
| CORS allow_credentials correct pattern | allow_credentials: True combined with specific origin (not *) | app_factory.py:28 | tls_and_transport_security |
| Environment variables for origin configuration | FRONTEND_URL environment variable used to configure CORS origins | app_factory.py:28 | tls_and_transport_security |
| Infrastructure-level TLS delegation | Delegation to cloud load balancers is a valid pattern | Cloud platforms | tls_and_transport_security |
| No insecure certificate bypass code | No self-signed certificate generation or verify=False code present | app_factory.py | tls_and_transport_security |

---

# 5. ASVS Compliance Summary

| ASVS ID | Title | Status | Notes |
|---------|-------|--------|-------|
| **Authentication (6.x)** |
| 6.1.1 | Authentication Documentation | **Fail** | No rate limiting controls documented for LLM API endpoints |
| 6.2.1 | Password Minimum Length | **N/A** | OAuth-only authentication, no password storage |
| 6.2.2 | Password Change Capability | **N/A** | OAuth-only authentication |
| 6.2.3 | Password Change Requires Current Password | **N/A** | OAuth-only authentication |
| 6.2.4 | Breached Password Check | **N/A** | OAuth-only authentication |
| 6.2.5 | No Password Composition Rules | **Pass** | OAuth-only, no password composition rules |
| 6.2.6 | Password Input Field Masking | **N/A** | OAuth-only authentication |
| 6.2.7 | Paste Functionality and Password Managers Permitted | **N/A** | OAuth-only authentication |
| 6.2.8 | Password Verified Without Modification | **N/A** | OAuth-only authentication |
| 6.3.1 | Controls to Prevent Credential Stuffing and Brute Force | **Fail** | No rate limiting or throttling on authentication endpoints |
| 6.3.2 | Default User Accounts | **Fail** | Default site admin account without hard production block |
| 6.4.1 | System Generated Initial Passwords/Activation Codes | **N/A** | OAuth-only authentication |
| 6.4.2 | No Password Hints or Knowledge-Based Authentication | **Pass** | OAuth-only, no password hints or KBA |
| **Session Management (7.x)** |
| 7.2.1 | Backend Verification | **Pass** | Server-side session validation via FastAPI dependency injection |
| 7.2.2 | Dynamic Token Generation | **Pass** | secrets.token_urlsafe(32) for session IDs |
| 7.2.3 | Reference Token Entropy | **Pass** | 256 bits of entropy from OS CSPRNG |
| 7.2.4 | New Token on Authentication | **Partial** | New session created but previous not terminated |
| 7.4.1 | Session Termination | **Pass** | /auth/logout endpoint calls SessionService.delete() |
| 7.4.2 | Session Termination — Account Disable/Delete | **Fail** | No mechanism to terminate all sessions when user disabled/deleted |
| **Access Control (8.x)** |
| 8.1.1 | Authorization Documentation | **Fail** | Workspace role permissions not mapped to route-level controls |
| 8.2.1 | General Authorization Design (Function-Level) | **Fail** | Multiple BOLA vulnerabilities in agent resources |
| 8.2.2 | General Authorization Design (Data-Specific / IDOR) | **Fail** | Multiple IDOR vulnerabilities (agents, chat tickets, session configs) |
| 8.3.1 | Operation Level Authorization | **Fail** | Background tasks lose authorization context |
| **Input Validation (1.x, 2.x)** |
| 1.2.1 | Output Encoding for HTTP Response | **Fail** | Reflected XSS in dev_stub_picker HTML generation |
| 1.2.2 | URL Encoding and Safe Protocols | **Fail** | Open redirect via unvalidated return_to parameter |
| 1.2.3 | JavaScript/JSON Output Encoding | **Pass** | FastAPI JSON serialization and json.dumps() handle encoding |
| 1.2.4 | Injection Prevention — Database Injection | **Partial** | DatabaseService abstraction but user-controllable path parameters |
| 1.2.5 | Injection Prevention — OS Command Injection | **Pass** | No shell/subprocess calls in analyzed files |
| 1.3.1 | HTML Input Sanitization | **Fail** | No HTML sanitization on user-generated content fields |
| 1.3.2 | Dynamic Code Execution | **Fail** | Unrestricted __builtins__ passed to dynamically executed agent code |
| 1.5.1 | XML Parser Configuration and XXE Prevention | **Pass** | No XML parsing in analyzed code |
| 2.1.1 | Validation and Business Logic Documentation | **Partial** | Missing documented validation rules for business-critical fields |
| 2.2.1 | Input Validation | **Fail** | Provider and model fields not validated against allowed values |
| 2.2.2 | Server-side Input Validation | **Partial** | FastAPI Pydantic validation present but gaps in schema validation |
| 2.3.1 | Business Logic Security | **Fail** | Multiple business logic gaps (spend allowance bypass, ticket ownership) |
| **Cookie Security (3.3.x)** |
| 3.3.1 | Cookie Setup | **Fail** | Cookie names lack __Secure- or __Host- prefix |
| **HTTP Security Headers (3.x)** |
| 3.2.1 | Unintended Content Interpretation - Context Controls | **Partial** | No Accept: application/json enforcement in fetch interceptor |
| 3.2.2 | Safe Text Rendering | **Pass** | text/plain used for error responses |
| 3.4.1 | Strict-Transport-Security Header | **Fail** | No HSTS header configuration |
| 3.4.2 | CORS Access-Control-Allow-Origin | **Partial** | Specific origin but uses HTTP scheme by default |
| 3.5.1 | CSRF Protection | **Fail** | Missing CSRF protection on cookie-based authentication |
| 3.5.2 | CORS Preflight Reliance Verification | **Fail** | CORS middleware does not block simple cross-origin requests |
| 3.5.3 | HTTP Methods for Sensitive Functionality | **Partial** | Wildcard CORS methods without Sec-Fetch-* validation |
| **Web Services (4.x)** |
| 4.1.1 | Generic Web Service Security - Content-Type Header | **Partial** | Missing charset parameter in text/event-stream |
| 4.4.1 | WebSocket over TLS (WSS) | **Pass** | No WebSocket usage in analyzed code |
| **File Upload (5.x)** |
| 5.2.1 | File Upload Size Limits | **Fail** | No size constraints on swagger specification content |
| 5.2.2 | File Extension and Content Type Validation | **Fail** | No validation on swagger specification content |
| 5.3.1 | Preventing Execution of Uploaded Files | **Pass** | No file upload execution risk |
| 5.3.2 | File Path Construction and Sanitization | **Partial** | User-controlled spec.name passed to parsing function |
| **Cryptography (9.x, 11.x)** |
| 9.1.1 | Self-contained Token Signature Validation | **Partial** | Abstract auth provider interface doesn't enforce token validation |
| 9.1.2 | Algorithm Allowlist for Self-contained Tokens | **Partial** | No algorithm allowlist enforcement in abstract interface |
| 9.1.3 | Key Material from Trusted Pre-configured Sources | **Partial** | Static provider configuration but no explicit key source validation |
| 9.2.1 | Token Validity Time Span Verification | **Pass** | Hard expiry enforcement in session validation |
| 11.3.1 | Insecure Block Modes and Weak Padding | **Pass** | No block cipher usage in session layer |
| 11.3.2 | Approved Ciphers and Modes | **N/A** | Opaque token architecture, no encryption needed |
| 11.4.1 | Approved Hash Functions | **Pass** | No hash functions used for session generation |
| **OAuth (10.x)** |
| 10.4.1 | Redirect URI Allowlist Validation | **Fail** | Open redirect via unvalidated return_to parameter |
| 10.4.2 | Authorization Code Single Use | **Partial** | Dev_stub provider codes are reusable |
| 10.4.3 | Authorization Code Short Lifetime | **Partial** | Dev_stub codes have no expiration |
| 10.4.4 | Grant Type Restrictions | **Pass** | Only authorization code flow implemented |
| 10.4.5 | Refresh Token Replay Attack Mitigation | **N/A** | Server-side session architecture, no refresh tokens |
| **TLS (12.x)** |
| 12.1.1 | General TLS Security Guidance | **Fail** | No application-level TLS protocol version enforcement |
| 12.2.1 | HTTPS Communication with External Facing Services | **Fail** | No HSTS header, default CORS uses HTTP scheme |
| 12.2.2 | Publicly Trusted TLS Certificates | **Partial** | No certificate configuration visible in application code |
| **Configuration (13.x)** |
| 13.4.1 | Source Control Metadata Protection | **Partial** | No defense-in-depth middleware to block .git paths |
| **Data Protection (14.x)** |
| 14.2.1 | General Data Protection - Sensitive Data in URLs | **Partial** | Document IDs embed user identifiers |
| 14.3.1 | Client-side Data Protection - Clearing Authenticated Data | **Fail** | Operations log accumulates sensitive data previews |
| **Architecture (15.x)** |
| 15.1.1 | Risk-Based Remediation Timeframes | **Fail** | No documented risk-based remediation timeframes |
| 15.2.1 | Component Update Compliance | **Fail** | No automated mechanism to enforce dependency update SLA |
| 15.3.1 | Return Only Required Fields | **Partial** | Multiple endpoints return unfiltered database documents |

**Summary Statistics:**
- **Pass**: 21 requirements
- **Partial**: 20 requirements
- **Fail**: 33 requirements
- **N/A**: 13 requirements (OAuth-only authentication eliminates password requirements)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Domain | Positive Controls Bypassed/Missing |
|------------|----------|-------------------|--------|-------------------------------------|
| FINDING-001 | Critical | 8.2.1, 8.2.2 | workspace_access_control | Authentication on all routes, Consistent authentication, Well-designed workspace model |
| FINDING-002 | Critical | 8.2.2 | workspace_access_control | Authentication on all routes, Session validation server-side |
| FINDING-003 | Critical | 8.2.1, 8.2.2 | workspace_access_control | Admin password check server-side |
| FINDING-004 | Critical | 8.2.2 | workspace_access_control | Audit service infrastructure |
| FINDING-005 | Critical | 1.3.2 | agent_code_sandbox | Agent code sandbox (restricted globals) |
| FINDING-006 | Critical | 2.3.1 | api_input_validation | Server-side auth validation |
| FINDING-007 | High | 10.4.1 | pluggable_authentication | Relative return_to paths correctly prefixed, Protocol-scheme check |
| FINDING-008 | High | 6.3.1 | pluggable_authentication | HTTP Client Timeouts |
| FINDING-009 | High | 7.4.2 | session_management | Session documents contain user_uid |
| FINDING-010 | High | 8.2.2 | workspace_access_control | UUIDv4 ticket IDs |
| FINDING-011 | High | 8.2.2 | workspace_access_control | Session validation server-side |
| FINDING-012 | High | 8.3.1 | workspace_access_control | Authorization enforcement at server layer |
| FINDING-013 | High | 1.3.2 | agent_code_sandbox | LLM timeout auto-scaling |
| FINDING-014 | High | 1.2.1, 1.3.1, 1.2.2 | api_input_validation | html.escape() used in _render_deny_page |
| FINDING-015 | High | 1.2.2 | api_input_validation | _default_redirect_uri function, Protocol-scheme check |
| FINDING-016 | High | 2.2.1, 2.2.2 | api_input_validation | Output schema validation (advisory only) |
| FINDING-017 | High | 12.2.1, 3.4.1 | tls_and_transport_security | Modern framework with TLS support |
| FINDING-018 | High | 3.5.1 | tls_and_transport_security | SameSite=lax consistently applied, OAuth state CSRF protection |
| FINDING-019 | High | 3.5.2 | tls_and_transport_security | CORS origins restricted |
| FINDING-020 | High | 2.3.1 | api_input_validation | Server-side auth validation |
| FINDING-021 | High | 2.3.1, 15.2.1 | api_input_validation | LLM call tracing |
| FINDING-022 | High | 6.1.1 | pluggable_authentication | HTTP Client Timeouts |
| FINDING-023 | Medium | 10.4.1 | pluggable_authentication | HTML escaping in deny page |
| FINDING-024 | Medium | 6.3.1 | pluggable_authentication | CSRF state token validation |
| FINDING-025 | Medium | 6.3.2 | pluggable_authentication | Provider Configuration Fail-Fast |
| FINDING-026 | Medium | 3.3.1 | session_management | HttpOnly attribute consistently applied, SameSite=lax consistently applied |
| FINDING-027 | Medium | 3.3.1 | session_management | Secure Cookie Defaults |
| FINDING-028 | Medium | 7.2.4 | session_management | Session fixation prevention |
| FINDING-029 | Medium | 8.1.1 | workspace_access_control | WorkspaceRole type definition, Module-level docstrings |
| FINDING-030 | Medium | 8.3.1 | workspace_access_control | Data store user scoping |
| FINDING-031 | Medium | 8.2.2 | workspace_access_control | User-scoped queries |
| FINDING-032 | Medium | 1.3.2 | agent_code_sandbox | Agent code sandbox |
| FINDING-033 | Medium | 1.2.4 | api_input_validation | DatabaseService abstraction, FastAPI path parameter typing |
| FINDING-034 | Medium | 2.1.1 | api_input_validation | _ensure_mutually_exclusive |
| FINDING-035 | Medium | 2.1.1, 1.2.2 | api_input_validation | Protocol-scheme check on return_to |
| FINDING-036 | Medium | 2.2.1 | api_input_validation | ChatMessage.role positive validation |
| FINDING-037 | Medium | 2.2.1 | api_input_validation | Pydantic model validation with extra='ignore' |
| FINDING-038 | Medium | 2.2.1 | api_input_validation | Pydantic model validation with extra='ignore' |
| FINDING-039 | Medium | 14.3.1 | database_abstraction_layer | Value preview truncation, Conditional ops_log, Server-side data scoping |
| FINDING-040 | Medium | 9.1.1, 9.1.2, 9.1.3 | cryptographic_operations | Static provider configuration, Provider type tracking |
| FINDING-041 | Medium | 12.1.1 | tls_and_transport_security | Modern framework with TLS support |
| FINDING-042 | Medium | 12.2.1, 3.4.2 | tls_and_transport_security | CORS origins restricted, Environment variables for origin configuration |
| FINDING-043 | Medium | 12.2.1 | tls_and_transport_security | Infrastructure-level TLS termination |
| FINDING-044 | Medium | 12.2.2 | tls_and_transport_security | Infrastructure-level TLS delegation |
| FINDING-045 | Medium | 3.5.3 | tls_and_transport_security | CORS allow_credentials correct pattern |
| FINDING-046 | Medium | 15.3.1 | workspace_access_control | Session validation server-side |
| FINDING-047 | Medium | 15.3.1 | pluggable_authentication | Provider Configuration Fail-Fast |
| FINDING-048 | Medium | 15.3.1 | workspace_access_control | Agent chain cycle detection |
| FINDING-049 | Medium | 4.1.1 | api_input_validation | SSE streaming JSON encoding |
| FINDING-050 | Medium | 5.2.1, 5.2.2 | api_input_validation | No shell/subprocess calls |
| FINDING-051 | Medium | 2.3.1 | api_input_validation | UUIDv4 ticket IDs |
| FINDING-052 | Medium | 6.1.1 | pluggable_authentication | None - documentation gap |
| FINDING-053 | Medium | 6.1.1 | pluggable_authentication | HTTP Client Timeouts, LLM call tracing |
| FINDING-054 | Medium | 15.1.1 | workspace_access_control | None - documentation gap |
| FINDING-055 | Medium | 15.2.1 | workspace_access_control | None - process gap |
| FINDING-056 | Medium | 13.4.1 | tls_and_transport_security | No insecure certificate bypass code |
| FINDING-057 | Low | 10.4.5 | pluggable_authentication | Server-Side Session Architecture |
| FINDING-058 | Low | 10.4.2 | pluggable_authentication | Authorization code flow, Provider-side code expiration |
| FINDING-059 | Low | 10.4.3 | pluggable_authentication | CSRF state cookie with 10-minute TTL, Provider-side code expiration |
| FINDING-060 | Low | 8.1.1 | workspace_access_control | Module-level docstrings |
| FINDING-061 | Low | 8.3.1 | workspace_access_control | No client-side JavaScript authorization |
| FINDING-062 | Low | 1.2.3 | api_input_validation | FastAPI JSON serialization, Pydantic model_dump serialization |
| FINDING-063 | Low | 1.2.4 | api_input_validation | DatabaseService abstraction, User-scoped queries |
| FINDING-064 | Low | 1.3.1 | api_input_validation | html.escape() used in _render_deny_page |
| FINDING-065 | Low | 2.1.1 | api_input_validation | FastAPI Pydantic auto-validation |
| FINDING-066 | Low | 2.2.1 | api_input_validation | Server-side auth validation |
| FINDING-067 | Low | 14.2.1 | database_abstraction_layer | Base64 URL-safe encoding of keys, User ID scoping via parameters |
| FINDING-068 | Low | 14.3.1 | session_management | Session termination |
| FINDING-069 | Low | 9.2.1 | cryptographic_operations | Hard expiry enforcement, Fail-closed on deserialization errors |
| FINDING-070 | Low | 3.2.1 | tls_and_transport_security | FastAPI JSON serialization |
| FINDING-071 | Low | 15.3.1 | agent_code_sandbox | Data store user scoping |
| FINDING-072 | Low | 15.3.1 | agent_code_sandbox | Event source tagging |
| FINDING-073 | Low | 5.2.1 | api_input_validation | Agent chain cycle detection |
| FINDING-074 | Low | 5.3.2 | api_input_validation | No shell/subprocess calls |
| FINDING-075 | Low | 15.1.1 | workspace_access_control | None - classification gap |
| FINDING-076 | Low | 13.4.1 | tls_and_transport_security | None - deployment configuration gap |
| FINDING-077 | Low | 13.4.1 | tls_and_transport_security | None - logging configuration gap |

**Cross-Reference Insights:**

1. **Authentication Domain**: 8 findings (1 Critical, 3 High, 4 Medium) - Primary gaps in rate limiting and default accounts despite strong OAuth implementation
2. **Authorization Domain**: 16 findings (4 Critical, 5 High, 7 Medium) - Most critical gap area with systematic BOLA/IDOR vulnerabilities
3. **Input Validation**: 20 findings (2 Critical, 3 High, 13 Medium, 2 Low) - Mixed results with good framework controls but application-level gaps
4. **Session Management**: 4 findings (1 High, 2 Medium, 1 Low) - Strong cryptographic foundation with minor lifecycle gaps
5. **TLS/Transport**: 10 findings (2 High, 7 Medium, 1 Low) - Infrastructure delegation pattern creates application-level visibility gaps
6. **Agent Sandbox**: 4 findings (1 Critical, 1 High, 2 Medium) - Critical unrestricted builtins issue alongside good observability controls

**Key Patterns:**
- Strong positive controls exist but are frequently incomplete or not enforced consistently
- Infrastructure delegation (TLS, rate limiting) creates compliance documentation gaps
- Authorization is the weakest domain with systematic implementation gaps
- Cryptographic operations are well-implemented at the primitive level
- Business logic controls (spend allowance) have multiple bypass vectors

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 77 |

**Total consolidated findings: 77**

*End of Consolidated Security Audit Report*