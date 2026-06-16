# asvs_job_runner
#
# Job-state oracle for multi-component audit runs. gofannon has no concept
# of an importable module — all code is an agent invoked by name — so the
# job runner is an AGENT that owns the persistent job-state table and
# answers per-job state operations. The ORCHESTRATOR drives the actual
# concurrency loop (it holds the per-component pipeline closures, which
# cannot cross an agent-call boundary) and calls this agent to decide
# whether each job should run, and to record outcomes.
#
# Supports resume-from-failure: a run that crashes can be restarted with
# the same run_id; already-DONE jobs are skipped and orphaned RUNNING jobs
# (crashed mid-flight) are reset so they re-run.
#
# State table (CouchDB namespace `audit_state:{run_id}`):
#   key:   {component}|{phase}|{section_or_NONE}
#   value: JSON {
#       status: queued|running|done|failed-retry|failed-fatal,
#       attempts: int, last_error: str|null,
#       started_at: iso|null, completed_at: iso|null, output_uri: str|null
#   }
#
# Operations (input_dict["op"]):
#
#   "init"     -> reset orphaned RUNNING jobs to QUEUED (call once at start
#                 of a run, before claiming any jobs). Returns how many were
#                 reset. Idempotent.
#     inputs:  run_id
#
#   "claim"    -> decide whether a job should run now. Returns a decision:
#                   {"decision": "run",          "attempt": N}   run it
#                   {"decision": "skipped-done", "output_uri": ...}
#                   {"decision": "skipped-fatal","error": ...}
#                 On "run" the job is marked RUNNING with attempt=N so a
#                 concurrent/restarted runner won't double-claim it.
#     inputs:  run_id, component, phase, section?(opt)
#
#   "complete" -> record success. Marks DONE.
#     inputs:  run_id, component, phase, section?, output_uri?(opt)
#
#   "fail"     -> record a failed attempt. Returns whether to retry:
#                   {"decision": "retry", "backoff_seconds": S, "attempt": N}
#                   {"decision": "fatal", "attempt": N}
#                 Marks QUEUED (retry) or FAILED_FATAL. The orchestrator is
#                 responsible for sleeping backoff_seconds OUTSIDE its
#                 concurrency gate before re-claiming.
#     inputs:  run_id, component, phase, section?, error,
#              is_rate_limit?(opt bool), is_timeout?(opt bool),
#              max_attempts?(opt, default 3)
#
#   "summary"  -> snapshot of all job state for the run_id (by_status,
#                 by_component). Read-only.
#     inputs:  run_id
#
# Output: {"outputText": <JSON>} for every op (JSON so the orchestrator can
# json.loads it). Errors surface as {"error": "..."} inside that JSON.
#
# No LLM call. Pure CouchDB state I/O.

QUEUED = "queued"
RUNNING = "running"
DONE = "done"
FAILED_RETRY = "failed-retry"
FAILED_FATAL = "failed-fatal"
DEFAULT_MAX_ATTEMPTS = 3


async def run(input_dict, tools):
    # Imports inside run() per gofannon convention (run() is recompiled in a
    # fresh namespace at invocation time, so module-level imports/helpers do
    # not survive — everything the op needs lives in here).
    import json
    from datetime import datetime, timezone

    # State-status constants must be defined inside run() too, for the same
    # reason: module-level names are not in scope when run() executes.
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED_RETRY = "failed-retry"
    FAILED_FATAL = "failed-fatal"
    DEFAULT_MAX_ATTEMPTS = 3

    def _now():
        return datetime.now(timezone.utc).isoformat()

    def _key(component, phase, section=None):
        return f"{component}|{phase}|{section if section else 'NONE'}"

    def _ns(run_id):
        return data_store.use_namespace(f"audit_state:{run_id}")

    def _read(ns, key):
        try:
            raw = ns.get(key)
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def _write(ns, key, status, **kwargs):
        existing = _read(ns, key) or {
            "status": QUEUED, "attempts": 0, "last_error": None,
            "started_at": None, "completed_at": None, "output_uri": None,
        }
        existing["status"] = status
        for k, v in kwargs.items():
            existing[k] = v
        ns.set(key, json.dumps(existing))
        return existing

    def _backoff_seconds(attempts, is_rate_limit):
        b = min(60, 2 ** attempts)
        if is_rate_limit:
            b = max(b, 30)
        return b

    try:
        # All inputs arrive as a JSON object in inputText (same convention as
        # asvs_guidance_upload / asvs_push_github). A single inputText field
        # carries whatever keys the op needs — which vary per op — so the
        # agent's input schema stays one field regardless of operation:
        #   init:     {"op":"init","run_id":...}
        #   claim:    {"op":"claim","run_id":...,"component":...,"phase":...,"section":...?}
        #   complete: {"op":"complete","run_id":...,"component":...,"phase":...,"section":...?,"output_uri":...?}
        #   fail:     {"op":"fail","run_id":...,"component":...,"phase":...,"section":...?,
        #              "error":...,"is_rate_limit":bool?,"is_timeout":bool?,"max_attempts":int?}
        #   summary:  {"op":"summary","run_id":...}
        input_text = input_dict.get("inputText", "")
        if not input_text:
            return {"outputText": json.dumps({"error": "inputText is required (JSON with at least 'op' and 'run_id')"})}
        try:
            params = json.loads(input_text)
        except Exception as e:
            return {"outputText": json.dumps({"error": f"inputText must be valid JSON: {e}"})}
        if not isinstance(params, dict):
            return {"outputText": json.dumps({"error": "inputText must be a JSON object"})}

        op = (params.get("op") or "").strip()
        run_id = (params.get("run_id") or "").strip()
        if not op:
            return {"outputText": json.dumps({"error": "op is required "
                    "(init|claim|complete|fail|summary)"})}
        if not run_id:
            return {"outputText": json.dumps({"error": "run_id is required"})}

        ns = _ns(run_id)

        # ----- init: reset orphaned RUNNING jobs to QUEUED -----
        if op == "init":
            reset = 0
            for key in ns.list_keys():
                st = _read(ns, key)
                if st and st.get("status") == RUNNING:
                    _write(ns, key, QUEUED, last_error=(
                        "Orphaned RUNNING state reset on run init "
                        "(previous worker likely crashed)."))
                    reset += 1
            print(f"[runner:{run_id}] init: reset {reset} orphaned RUNNING "
                  f"job(s)", flush=True)
            return {"outputText": json.dumps({"reset": reset})}

        # ----- summary: read-only snapshot -----
        if op == "summary":
            by_status, by_component = {}, {}
            for key in ns.list_keys():
                st = _read(ns, key)
                if not st:
                    continue
                s = st.get("status", "unknown")
                by_status[s] = by_status.get(s, 0) + 1
                comp = key.split("|")[0]
                by_component.setdefault(comp, {})
                by_component[comp][s] = by_component[comp].get(s, 0) + 1
            return {"outputText": json.dumps({
                "run_id": run_id, "by_status": by_status,
                "by_component": by_component})}

        # The remaining ops are per-job and need component/phase.
        component = (params.get("component") or "").strip()
        phase = (params.get("phase") or "").strip()
        section = params.get("section") or None
        if not component or not phase:
            return {"outputText": json.dumps({"error":
                    "component and phase are required for "
                    f"op={op}"})}
        key = _key(component, phase, section)
        state = _read(ns, key)

        # ----- claim: decide run / skip, mark RUNNING on run -----
        if op == "claim":
            if state and state.get("status") == DONE:
                print(f"[runner:{run_id}] SKIP {key} (already done)", flush=True)
                return {"outputText": json.dumps({
                    "decision": "skipped-done",
                    "output_uri": state.get("output_uri")})}
            if state and state.get("status") == FAILED_FATAL:
                print(f"[runner:{run_id}] SKIP {key} (previously fatal)", flush=True)
                return {"outputText": json.dumps({
                    "decision": "skipped-fatal",
                    "error": state.get("last_error")})}
            attempt = (state.get("attempts", 0) if state else 0) + 1
            _write(ns, key, RUNNING, attempts=attempt,
                   started_at=_now(), last_error=None)
            print(f"[runner:{run_id}] CLAIM {key} (attempt {attempt})", flush=True)
            return {"outputText": json.dumps({
                "decision": "run", "attempt": attempt})}

        # ----- complete: mark DONE -----
        if op == "complete":
            output_uri = params.get("output_uri")
            _write(ns, key, DONE, completed_at=_now(), output_uri=output_uri)
            print(f"[runner:{run_id}] DONE {key}", flush=True)
            return {"outputText": json.dumps({"decision": "done"})}

        # ----- fail: record attempt, decide retry vs fatal -----
        if op == "fail":
            error = params.get("error") or "(no message)"
            is_rate_limit = bool(params.get("is_rate_limit", False))
            is_timeout = bool(params.get("is_timeout", False))
            max_attempts = int(params.get("max_attempts", DEFAULT_MAX_ATTEMPTS))
            attempt = state.get("attempts", 1) if state else 1

            # Retry if attempts remain. Rate-limit / timeout are retryable by
            # nature; other errors are retryable until the attempt cap.
            if attempt < max_attempts:
                _write(ns, key, QUEUED, last_error=str(error)[:500])
                backoff = _backoff_seconds(attempt, is_rate_limit)
                print(f"[runner:{run_id}] RETRY {key} (attempt {attempt}/"
                      f"{max_attempts}, backoff {backoff}s): "
                      f"{str(error)[:120]}", flush=True)
                return {"outputText": json.dumps({
                    "decision": "retry", "backoff_seconds": backoff,
                    "attempt": attempt})}
            else:
                _write(ns, key, FAILED_FATAL, last_error=str(error)[:500],
                       completed_at=_now())
                print(f"[runner:{run_id}] FATAL {key} after {attempt} "
                      f"attempt(s): {str(error)[:120]}", flush=True)
                return {"outputText": json.dumps({
                    "decision": "fatal", "attempt": attempt})}

        return {"outputText": json.dumps({"error": f"unknown op: {op}"})}

    except Exception as e:
        import json as _json
        return {"outputText": _json.dumps({
            "error": f"{type(e).__name__}: {str(e) or '(no message)'}"})}