# asvs_fetch_issues_prs
#
# Snapshots a repo's OPEN issues and OPEN pull requests (PRs with their
# changed-file lists) into the data store, pinned to the commit the audit is
# running against. Read after consolidation by asvs_compare_open_issues_prs.
#
# WHY PINNED TO A COMMIT: a PR/issue closing during a long run is a race, not
# signal. Snapshotting at the same commit the code was downloaded at makes the
# later comparison a comparison against a fixed point. The orchestrator passes
# its already-resolved commit_hash here.
#
# SCALE: built for Apache-scale repos (airflow/superset have 600+ open issues
# AND 600+ open PRs). Uses the GitHub GraphQL API, which returns PRs together
# with their changed files in one paginated query (50 per page) -- so a repo
# with 600 PRs costs ~12 GraphQL calls instead of ~1,200 REST calls (list +
# per-PR file fetch). Issues are fetched 100/page. NO coverage cap: every open
# issue and PR is snapshotted with full file lists. Rate limiting is handled by
# reading the GraphQL rateLimit block and pausing until reset when the budget
# runs low, rather than silently truncating.
#
# Storage layout:
#   namespace: issues_prs:{repo}@{sha}
#   key:       issue-{number} | pr-{number}
#   value:     JSON record
#   key:       __meta__ -> {repo, sha, fetched_at, counts, complete}
#
# Inputs (inputText = JSON object):
#   repo   (required): owner/repo
#   sha    (required): the audit's commit_hash
#   token  (required): GitHub PAT. GraphQL REQUIRES auth (no anonymous access).
#   pr_files_per_pr (optional, default 100): changed files fetched per PR.
#
# Output (outputText = JSON): {repo, sha, namespace, counts, complete, note}
#
# No LLM call.


async def run(input_dict, tools):
    import json
    import asyncio
    from datetime import datetime, timezone

    import httpx

    def _err(msg):
        return {"outputText": json.dumps({"error": msg})}

    try:
        input_text = input_dict.get("inputText", "")
        if not input_text:
            return _err("inputText is required (JSON with 'repo' and 'sha')")
        try:
            params = json.loads(input_text)
        except Exception as e:
            return _err(f"inputText must be valid JSON: {e}")
        if not isinstance(params, dict):
            return _err("inputText must be a JSON object")

        repo = (params.get("repo") or "").strip().strip("/")
        sha = (params.get("sha") or "").strip()
        token = (params.get("token") or "").strip()
        pr_files_per_pr = int(params.get("pr_files_per_pr", 100))

        if not repo or "/" not in repo:
            return _err("repo is required in owner/repo form (e.g. 'apache/mina')")
        if not sha:
            return _err("sha is required (the audit's commit_hash)")
        if not token:
            return _err("token is required: the GitHub GraphQL API does not "
                        "allow anonymous access. Pass sourceToken through the "
                        "orchestrator.")

        owner, name = repo.split("/", 1)
        gql_url = "https://api.github.com/graphql"
        headers = {"Authorization": f"Bearer {token}",
                   "Content-Type": "application/json"}

        ns_name = f"issues_prs:{repo}@{sha}"
        ns = data_store.use_namespace(ns_name)
        try:
            ns.clear()
        except Exception:
            pass

        records = {}
        issue_count = 0
        pr_count = 0
        complete = True
        note_extra = ""

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=15.0, read=60.0, write=30.0, pool=30.0)
        ) as client:

            async def _gql(query, variables):
                for attempt in range(5):
                    try:
                        resp = await client.post(
                            gql_url, headers=headers,
                            json={"query": query, "variables": variables})
                    except Exception:
                        if attempt < 4:
                            await asyncio.sleep(2 ** attempt)
                            continue
                        raise
                    if resp.status_code == 200:
                        payload = resp.json()
                        if payload.get("errors"):
                            errs = payload["errors"]
                            msgs = "; ".join(e.get("message", "") for e in errs)
                            if "RATE_LIMITED" in str(errs) or "rate limit" in msgs.lower():
                                raise RuntimeError("rate-limited")
                            raise RuntimeError(f"GraphQL errors: {msgs[:300]}")
                        return payload.get("data") or {}
                    if resp.status_code in (502, 503, 504) and attempt < 4:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    if resp.status_code == 401:
                        raise RuntimeError("GraphQL 401: token invalid/expired")
                    raise RuntimeError(f"GraphQL HTTP {resp.status_code}: {resp.text[:200]}")
                raise RuntimeError("GraphQL retries exhausted")

            async def _maybe_wait(rl):
                nonlocal complete, note_extra
                try:
                    remaining = int(rl.get("remaining", 1)) if rl else 1
                except Exception:
                    remaining = 1
                if remaining >= 50:
                    return True
                reset = (rl or {}).get("resetAt")
                wait = 60
                try:
                    if reset:
                        dt = datetime.fromisoformat(reset.replace("Z", "+00:00"))
                        wait = max(5, int((dt - datetime.now(timezone.utc)).total_seconds()) + 2)
                except Exception:
                    pass
                if wait > 300:
                    complete = False
                    note_extra = (f" stopped early: rate budget low and reset "
                                  f"is {wait}s away")
                    return False
                print(f"[fetch_issues_prs] rate budget low ({remaining}); "
                      f"waiting {wait}s for reset", flush=True)
                await asyncio.sleep(wait)
                return True

            # ----- Issues (open) -----
            ISSUES_Q = """
            query($owner:String!,$name:String!,$cursor:String){
              rateLimit { remaining resetAt }
              repository(owner:$owner,name:$name){
                issues(first:100,states:OPEN,after:$cursor,
                       orderBy:{field:UPDATED_AT,direction:DESC}){
                  pageInfo{ hasNextPage endCursor }
                  nodes{ number title bodyText url createdAt updatedAt
                         labels(first:20){ nodes{ name } } }
                }
              }
            }"""
            cursor = None
            try:
                while True:
                    data = await _gql(ISSUES_Q, {"owner": owner, "name": name, "cursor": cursor})
                    repo_node = (data or {}).get("repository") or {}
                    conn = repo_node.get("issues") or {}
                    for nd in conn.get("nodes", []):
                        num = nd.get("number")
                        if num is None:
                            continue
                        records[f"issue-{num}"] = {
                            "type": "issue", "number": num,
                            "title": nd.get("title") or "",
                            "body": (nd.get("bodyText") or "")[:4000],
                            "state": "open",
                            "labels": [l.get("name") for l in
                                       (nd.get("labels") or {}).get("nodes", [])],
                            "url": nd.get("url"),
                            "created_at": nd.get("createdAt"),
                            "updated_at": nd.get("updatedAt"),
                        }
                        issue_count += 1
                    pi = conn.get("pageInfo") or {}
                    if not await _maybe_wait((data or {}).get("rateLimit")):
                        break
                    if pi.get("hasNextPage"):
                        cursor = pi.get("endCursor")
                    else:
                        break
            except RuntimeError as e:
                complete = False
                note_extra += f" (issues fetch stopped: {e})"

            # ----- PRs (open) WITH changed files -----
            PRS_Q = """
            query($owner:String!,$name:String!,$cursor:String,$files:Int!){
              rateLimit { remaining resetAt }
              repository(owner:$owner,name:$name){
                pullRequests(first:50,states:OPEN,after:$cursor,
                             orderBy:{field:UPDATED_AT,direction:DESC}){
                  pageInfo{ hasNextPage endCursor }
                  nodes{ number title bodyText url createdAt updatedAt
                         labels(first:20){ nodes{ name } }
                         files(first:$files){ nodes{ path } } }
                }
              }
            }"""
            cursor = None
            try:
                while True:
                    data = await _gql(PRS_Q, {"owner": owner, "name": name,
                                              "cursor": cursor,
                                              "files": pr_files_per_pr})
                    repo_node = (data or {}).get("repository") or {}
                    conn = repo_node.get("pullRequests") or {}
                    for nd in conn.get("nodes", []):
                        num = nd.get("number")
                        if num is None:
                            continue
                        changed = [f.get("path") for f in
                                   (nd.get("files") or {}).get("nodes", [])
                                   if f.get("path")]
                        records[f"pr-{num}"] = {
                            "type": "pr", "number": num,
                            "title": nd.get("title") or "",
                            "body": (nd.get("bodyText") or "")[:4000],
                            "state": "open",
                            "labels": [l.get("name") for l in
                                       (nd.get("labels") or {}).get("nodes", [])],
                            "url": nd.get("url"),
                            "created_at": nd.get("createdAt"),
                            "updated_at": nd.get("updatedAt"),
                            "changed_files": changed,
                        }
                        pr_count += 1
                    pi = conn.get("pageInfo") or {}
                    if not await _maybe_wait((data or {}).get("rateLimit")):
                        break
                    if pi.get("hasNextPage"):
                        cursor = pi.get("endCursor")
                    else:
                        break
            except RuntimeError as e:
                complete = False
                note_extra += f" (PR fetch stopped: {e})"

        # ----- Persist -----
        meta = {
            "repo": repo, "sha": sha,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "counts": {"issues": issue_count, "prs": pr_count},
            "complete": complete,
        }
        to_write = {k: json.dumps(v) for k, v in records.items()}
        to_write["__meta__"] = json.dumps(meta)
        try:
            if hasattr(ns, "set_many"):
                ns.set_many(to_write)
            else:
                for k, v in to_write.items():
                    ns.set(k, v)
        except Exception as e:
            return _err(f"failed to persist snapshot to {ns_name}: "
                        f"{type(e).__name__}: {e}")

        note = (f"Snapshot of {issue_count} open issue(s) and {pr_count} open "
                f"PR(s) (with changed files) for {repo} pinned to {sha}, "
                f"stored in {ns_name}.")
        if not complete:
            note += (" WARNING: snapshot INCOMPLETE --" + (note_extra or
                     " stopped before all pages were fetched.") +
                     " Re-run to complete; matching will use what was captured.")
        print(f"[fetch_issues_prs] {note}", flush=True)

        return {"outputText": json.dumps({
            "repo": repo, "sha": sha, "namespace": ns_name,
            "counts": {"issues": issue_count, "prs": pr_count},
            "complete": complete, "note": note,
        })}

    except Exception as e:
        import json as _json
        return {"outputText": _json.dumps({
            "error": f"{type(e).__name__}: {str(e) or '(no message)'}"})}