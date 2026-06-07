# asvs_job_runner
#
# Lightweight in-process job queue with persistent state in CouchDB.
# Drives per-component, per-section work for multi-component audit runs.
# Supports resume-from-failure: a multi-day run that crashes can be
# restarted with the same run_id and skips already-completed cells.
#
# Not a heavyweight workflow engine — just enough state to make long
# runs survivable. ~200 lines.
#
# Usage:
#   runner = JobRunner(run_id="airflow-2026-06-03", max_concurrent=4)
#   results = await runner.run_all([
#       lambda: _component_pipeline(c1),
#       lambda: _component_pipeline(c2),
#       ...
#   ])
#
# State table layout (CouchDB namespace `audit_state:{run_id}`):
#   key:   {component}|{phase}|{section_or_NONE}
#   value: JSON {
#       status: queued|running|done|failed-retry|failed-fatal,
#       attempts: int,
#       last_error: str|null,
#       started_at: iso8601|null,
#       completed_at: iso8601|null,
#       output_uri: str|null   # location of phase output in CouchDB
#   }

import asyncio
import json
import time
from datetime import datetime, timezone


class JobRunner:
    """
    Concurrent job runner with CouchDB-backed state.

    Each "job" is a unit of work to schedule and track. Jobs run on the
    runner's worker pool up to max_concurrent in flight. State is persisted
    so a crashed run can be resumed.
    """

    # Statuses
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED_RETRY = "failed-retry"
    FAILED_FATAL = "failed-fatal"

    MAX_ATTEMPTS = 3
    HEARTBEAT_INTERVAL_SEC = 30

    def __init__(self, run_id, max_concurrent=4, max_attempts=None):
        self.run_id = run_id
        self.state_ns_name = f"audit_state:{run_id}"
        self.state_ns = data_store.use_namespace(self.state_ns_name)
        self.semaphore = asyncio.Semaphore(max_concurrent)
        if max_attempts is not None:
            self.MAX_ATTEMPTS = max_attempts

    # ----- State helpers -----

    def _key(self, component, phase, section=None):
        section_part = section if section else "NONE"
        return f"{component}|{phase}|{section_part}"

    def _read_state(self, key):
        try:
            raw = self.state_ns.get(key)
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def _write_state(self, key, status, **kwargs):
        existing = self._read_state(key) or {
            "status": self.QUEUED,
            "attempts": 0,
            "last_error": None,
            "started_at": None,
            "completed_at": None,
            "output_uri": None,
        }
        existing["status"] = status
        for k, v in kwargs.items():
            existing[k] = v
        self.state_ns.set(key, json.dumps(existing))

    def _now(self):
        return datetime.now(timezone.utc).isoformat()

    # ----- Resume support -----

    def reset_orphaned_running_jobs(self):
        """
        On startup, find any state entries marked RUNNING (which means the
        previous run crashed mid-job) and reset them to QUEUED so they can
        be retried.
        """
        reset_count = 0
        for key in self.state_ns.list_keys():
            state = self._read_state(key)
            if state and state.get("status") == self.RUNNING:
                self._write_state(
                    key,
                    self.QUEUED,
                    last_error=(
                        f"Orphaned RUNNING state reset on runner startup "
                        f"(previous worker likely crashed). "
                        f"Will retry on next claim."
                    ),
                )
                reset_count += 1
        if reset_count > 0:
            print(
                f"[runner] reset {reset_count} orphaned RUNNING job(s) to "
                f"QUEUED",
                flush=True,
            )

    # ----- Job execution -----

    async def run_job(self, component, phase, callable_, section=None):
        """
        Run one job under the runner's semaphore. Persists state at every
        transition. Skips if already DONE.

        Args:
          component: str, component name from the manifest
          phase: str, one of discover|audit|filter|consolidate
          callable_: async callable returning a dict (the phase's result)
          section: optional str, for per-section phases

        Returns:
          The job's result dict, or None if already done / fatally failed.
        """
        key = self._key(component, phase, section)
        state = self._read_state(key)

        # Skip if already complete
        if state and state.get("status") == self.DONE:
            print(
                f"[runner] SKIP {key} (already done in attempt "
                f"{state.get('attempts', '?')})",
                flush=True,
            )
            return {"status": "skipped-done", "output_uri": state.get("output_uri")}

        # Skip if fatally failed
        if state and state.get("status") == self.FAILED_FATAL:
            print(
                f"[runner] SKIP {key} (previously fatal: "
                f"{state.get('last_error', '?')[:120]})",
                flush=True,
            )
            return {"status": "skipped-fatal", "error": state.get("last_error")}

        # Claim the job. Retry as an internal loop (NOT recursion): the
        # old code recursed into run_job while still holding self.semaphore
        # and slept during backoff inside the held semaphore. Both are bugs
        # at concurrency >= max_concurrent: asyncio.Semaphore is not
        # reentrant, so N jobs all retrying would each hold a slot while
        # waiting for a slot -> deadlock; and a backing-off job needlessly
        # occupied a slot for up to 60s. Now the semaphore is held only for
        # the attempt itself, and the backoff sleep happens after release.
        attempts = (state.get("attempts", 0) if state else 0)

        while True:
            attempts += 1

            async with self.semaphore:
                self._write_state(
                    key,
                    self.RUNNING,
                    attempts=attempts,
                    started_at=self._now(),
                    last_error=None,
                )
                try:
                    result = await callable_()
                    self._write_state(
                        key,
                        self.DONE,
                        completed_at=self._now(),
                        output_uri=(
                            result.get("output_uri")
                            if isinstance(result, dict)
                            else None
                        ),
                    )
                    print(
                        f"[runner] DONE {key} (attempt {attempts})",
                        flush=True,
                    )
                    return result

                except Exception as e:
                    err_type = type(e).__name__
                    err_msg = str(e) or "(no message)"
                    is_rate_limit = "RateLimitError" in err_type or "429" in err_msg

                    if attempts >= self.MAX_ATTEMPTS:
                        self._write_state(
                            key,
                            self.FAILED_FATAL,
                            last_error=f"{err_type}: {err_msg}",
                            completed_at=self._now(),
                        )
                        print(
                            f"[runner] FATAL {key} after {attempts} "
                            f"attempt(s): {err_type}: {err_msg[:120]}",
                            flush=True,
                        )
                        return {"status": "failed-fatal", "error": err_msg}

                    # Mark for retry; compute backoff. The sleep happens
                    # AFTER the semaphore is released (below), so a
                    # backing-off job does not hold a concurrency slot.
                    self._write_state(
                        key,
                        self.QUEUED,
                        last_error=f"{err_type}: {err_msg}",
                    )
                    backoff = min(60, 2 ** attempts)
                    if is_rate_limit:
                        backoff = max(backoff, 30)
                    print(
                        f"[runner] RETRY {key} after {backoff}s "
                        f"(attempt {attempts}/{self.MAX_ATTEMPTS}): "
                        f"{err_type}: {err_msg[:120]}",
                        flush=True,
                    )

            # Semaphore released. Back off without holding a slot, then loop.
            await asyncio.sleep(backoff)

    # ----- Bulk run -----

    async def run_all(self, jobs):
        """
        Run a list of jobs concurrently under the semaphore.

        Each job is a tuple (component, phase, callable, section?) or a
        dict with the same keys.
        """
        self.reset_orphaned_running_jobs()

        tasks = []
        for j in jobs:
            if isinstance(j, dict):
                component = j["component"]
                phase = j["phase"]
                callable_ = j["callable"]
                section = j.get("section")
            else:
                component, phase, callable_ = j[0], j[1], j[2]
                section = j[3] if len(j) > 3 else None
            tasks.append(self.run_job(component, phase, callable_, section))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Print summary. Count each bucket explicitly; do NOT fold skips
        # into success (the old `not in (failed-fatal, skipped-fatal)`
        # counted skipped-done as a fresh success and miscounted raised
        # exceptions). A successful phase result is a dict without a
        # failure/skip status.
        def _status(r):
            if isinstance(r, dict):
                return r.get("status")
            return "exception"

        completed = sum(1 for r in results if _status(r) in (None, "ok"))
        failed = sum(1 for r in results if _status(r) == "failed-fatal")
        skipped_done = sum(1 for r in results if _status(r) == "skipped-done")
        skipped_fatal = sum(1 for r in results if _status(r) == "skipped-fatal")
        raised = sum(1 for r in results if _status(r) == "exception")
        print(
            f"[runner] run complete: {completed} completed, "
            f"{failed} fatal, "
            f"{skipped_done} skipped (already done), "
            f"{skipped_fatal} skipped (previously fatal), "
            f"{raised} raised",
            flush=True,
        )

        return results

    # ----- Progress reporting -----

    def progress_summary(self):
        """
        Snapshot of all job state for this run_id. Useful for tailing a
        long-running audit.
        """
        summary = {
            "run_id": self.run_id,
            "by_status": {},
            "by_component": {},
        }
        for key in self.state_ns.list_keys():
            state = self._read_state(key)
            if not state:
                continue
            status = state.get("status", "unknown")
            summary["by_status"][status] = summary["by_status"].get(status, 0) + 1
            component = key.split("|")[0]
            comp_summary = summary["by_component"].setdefault(component, {})
            comp_summary[status] = comp_summary.get(status, 0) + 1
        return summary
