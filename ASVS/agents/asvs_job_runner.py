# asvs_job_runner
#
# Bounded-concurrency job runner with per-job persisted state, used by the
# multi-component orchestration path (MULTI_COMPONENT_MODE) to run each
# component's pipeline under a concurrency cap with resume support.
#
# State for every job is written to a CouchDB namespace keyed by run_id, so
# a re-run skips jobs already DONE and refuses jobs already FAILED_FATAL
# (resume / idempotency). Concurrency is bounded by an asyncio.Semaphore.
#
# IMPORTANT (gofannon runtime): data_store and asyncio are injected into the
# run() namespace at invocation time. This module is imported BY the
# orchestrator agent (`from asvs_job_runner import JobRunner`) inside its
# run(), so data_store/asyncio are in scope when JobRunner methods execute.
#
# Job tuple shape consumed by run_all():
#   (component, phase, callable_)            # section defaults to None
#   (component, phase, callable_, section)   # explicit section
# `callable_` is a zero-arg coroutine function (await callable_()).

import asyncio
import json
import time


class JobRunner:
    # Job states (persisted under the run namespace).
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED_FATAL = "failed-fatal"

    # Max attempts per job before it is marked FAILED_FATAL.
    MAX_ATTEMPTS = 3

    def __init__(self, run_id, max_concurrent=4):
        self.run_id = run_id
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        # Per-run state namespace. data_store is injected into the
        # orchestrator's run() namespace by the gofannon runtime.
        self.ns = data_store.use_namespace(f"jobrunner:{run_id}")

    # ----- State helpers -----

    def _now(self):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _job_key(self, component, phase, section=None):
        if section:
            return f"{component}::{phase}::{section}"
        return f"{component}::{phase}"

    def _read_state(self, key):
        raw = self.ns.get(key)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def _write_state(self, key, status, **fields):
        state = self._read_state(key) or {}
        state["status"] = status
        for k, v in fields.items():
            state[k] = v
        try:
            self.ns.set(key, json.dumps(state))
        except Exception as e:
            # State persistence is best-effort; a write failure must not
            # crash the job itself.
            print(
                f"[runner] WARN: could not persist state for {key}: "
                f"{type(e).__name__}: {e}",
                flush=True,
            )

    # ----- Single job -----

    async def run_job(self, component, phase, callable_, section=None):
        key = self._job_key(component, phase, section)
        state = self._read_state(key)

        # Resume support: skip jobs already completed or permanently failed
        # in a prior run.
        if state and state.get("status") == self.DONE:
            print(f"[runner] SKIP {key} (already done)", flush=True)
            return {"status": "skipped-done", "output_uri": state.get("output_uri")}
        if state and state.get("status") == self.FAILED_FATAL:
            print(
                f"[runner] SKIP {key} (previously fatal: {state.get('last_error')})",
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
                        f"[runner] RETRY {key} (attempt {attempts} failed, "
                        f"backoff {backoff}s): "
                        f"{err_type}: {err_msg[:120]}",
                        flush=True,
                    )

            # Semaphore released. Back off without holding a slot, then loop.
            await asyncio.sleep(backoff)

    # ----- Bulk run -----

    async def run_all(self, jobs):
        """Run a list of jobs under the concurrency cap.

        Each job is a tuple:
            (component, phase, callable_)            -> section=None
            (component, phase, callable_, section)
        callable_ is a zero-arg coroutine function.
        """
        tasks = []
        for j in jobs:
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

        # Normalize raised exceptions into result dicts so callers get a
        # uniform shape.
        normalized = []
        for r in results:
            if isinstance(r, dict):
                normalized.append(r)
            else:
                normalized.append({"status": "exception", "error": str(r)})
        return normalized
