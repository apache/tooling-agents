# ATR Triage Report

**Repository:** [apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases)
**Branch:** `main`
**Commit:** `ee7ff15feaaef2db411097f898749850fa9202c5`
**Mode:** dry-run

| | |
|---|---|
| Issues processed | 5 |
| Comments posted | 0 |
| Skipped | 0 |
| Errors | 0 |

> _Draft from a triage agent. A human reviewer should validate before merging any change. The agent did not run tests or verify diffs apply._

## Summary

| Issue | Title | Classification | Confidence | Files examined |
|---|---|---|---|---|
| [#1228](https://github.com/apache/tooling-trusted-releases/issues/1228) | The `Apache` prefix in project name | `no_action` | medium | 8 |
| [#1227](https://github.com/apache/tooling-trusted-releases/issues/1227) | Introduce a `{{PROJECT_LABEL}}` template variable | `actionable` | high | 8 |
| [#1226](https://github.com/apache/tooling-trusted-releases/issues/1226) | Add the option, on by default, to automatically resolve hybrid votes | `no_action` | medium | 8 |
| [#1225](https://github.com/apache/tooling-trusted-releases/issues/1225) | Count IPMC members' votes from a PPMC first round vote in the second round too | `actionable` | medium | 8 |
| [#1224](https://github.com/apache/tooling-trusted-releases/issues/1224) | Remind binding voters to vote through ATR in Trusted Vote mode | `no_action` | medium | 8 |

---

## [#1228](https://github.com/apache/tooling-trusted-releases/issues/1228) — The `Apache` prefix in project name

**Classification:** `no_action`  •  **Confidence:** `medium`

### Summary

The issue reports that for the project 'Apache Software Foundation Parent POM' (maven-apache-parent), the word 'Apache' is being stripped from the display name in certain UI contexts (like the vote page header showing 'Software Foundation Parent POM' instead of 'Apache Software Foundation Parent POM'). Looking at the code, the vote page uses `release.project.short_display_name` in headers (e.g., in `atr/get/vote.py` line `htm.strong[release.project.short_display_name]`). The `short_display_name` property likely strips the 'Apache' prefix from the display name, which is intentional for most projects (e.g., 'Apache Maven' → 'Maven') but incorrect for this specific project where 'Apache' is part of the actual name ('Apache Software Foundation Parent POM'). However, I cannot find the definition of `short_display_name` in the provided files — it's likely defined in `atr/models/sql.py` which is not included. Without seeing how `short_display_name` is computed, I cannot confidently propose the correct fix. The fix would likely involve making the 'Apache' prefix stripping smarter — perhaps only removing it when it's followed by the committee/project's own name rather than being part of a longer proper noun like 'Apache Software Foundation'.

### Files examined

- `atr/shared/projects.py`
- `migrations/versions/0033_2025.12.31_f2d97d96.py`
- `migrations/versions/0034_2025.12.31_ac4dcf44.py`
- `atr/get/announce.py`
- `atr/get/vote.py`
- `atr/get/voting.py`
- `atr/shared/voting.py`
- `atr/tasks/vote.py`

> _The agent reviewed this issue and has no concrete action it can propose. This may mean the issue needs more information, requires runtime debugging, depends on external systems, or is a discussion item. A human reviewer should take it from here._

---

## [#1227](https://github.com/apache/tooling-trusted-releases/issues/1227) — Introduce a `{{PROJECT_LABEL}}` template variable

**Classification:** `actionable`  •  **Confidence:** `high`

### Summary

The issue requests adding a `{{PROJECT_LABEL}}` template variable that exposes the project's key (label/slug) for use in templates. Currently, `{{PROJECT}}` provides the display name, but there's no variable for the raw project key which is needed for constructing URLs like GitHub issue links. The project key is already available in the template substitution functions as `options.project_key` or `release.project.key`, so this is straightforward to add.

### Files examined

- `atr/construct.py`
- `atr/storage/writers/announce.py`
- `migrations/versions/0033_2025.12.31_f2d97d96.py`
- `atr/get/announce.py`
- `atr/get/voting.py`
- `atr/post/announce.py`
- `atr/post/voting.py`
- `atr/shared/announce.py`

### Proposed changes

#### `atr/construct.py`

Add `PROJECT_LABEL` to the `TEMPLATE_VARIABLES` list and add substitution logic in all relevant template expansion functions.

````diff
--- a/atr/construct.py
+++ b/atr/construct.py
@@ -35,6 +35,7 @@
 TEMPLATE_VARIABLES: list[tuple[str, str, set[Context]]] = [
     ("CHECKLIST_URL", "URL to the release checklist", {"vote"}),
     ("COMMITTEE", "Committee display name", {"announce", "checklist", "vote", "vote_subject"}),
+    ("DISCLAIMER", "Podling incubation disclaimer", {"announce"}),
     ("DOWNLOAD_URL", "URL to download the release", {"announce"}),
     ("DURATION", "Vote duration in hours", {"vote"}),
     ("KEYS_FILE", "URL to the KEYS file", {"vote"}),
     ("PROJECT", "Project display name", {"announce", "announce_subject", "checklist", "vote", "vote_subject"}),
+    ("PROJECT_LABEL", "Project key/label (slug)", {"announce", "announce_subject", "checklist", "vote", "vote_subject"}),
     ("RELEASE_CHECKLIST", "Release checklist content", {"vote"}),
     ("REVIEW_URL", "URL to review the release", {"checklist", "vote"}),
     ("REVISION", "Revision number", {"announce", "checklist", "vote", "vote_subject"}),
@@ -95,10 +96,12 @@

     project_display_name = release.project.short_display_name if release.project else str(options.project_key)
     download_url = paths.committee_downloads_url(host, committee)
     if options.download_path_suffix is not None:
         download_url += f"/{options.download_path_suffix!s}"
     download_url += "/"

     # Perform substitutions in the subject
     subject = subject.replace("{{PROJECT}}", project_display_name)
+    subject = subject.replace("{{PROJECT_LABEL}}", str(options.project_key))
     subject = subject.replace("{{VERSION}}", str(options.version_key))

     # Perform substitutions in the body
     body = body.replace("{{COMMITTEE}}", committee.display_name)
     body = body.replace("{{DISCLAIMER}}", _podling_disclaimer(release.project, committee))
     body = body.replace("{{DOWNLOAD_URL}}", download_url)
     body = body.replace("{{PROJECT}}", project_display_name)
+    body = body.replace("{{PROJECT_LABEL}}", str(options.project_key))
     body = body.replace("{{REVISION}}", revision_number)
     body = body.replace("{{TAG}}", revision_tag)
     body = body.replace("{{VERSION}}", str(options.version_key))
@@ -133,6 +136,7 @@
     markdown = markdown.replace("{{COMMITTEE}}", committee.display_name)
     markdown = markdown.replace("{{PROJECT}}", project.short_display_name)
+    markdown = markdown.replace("{{PROJECT_LABEL}}", str(project.key))
     markdown = markdown.replace("{{REVIEW_URL}}", review_url)
     markdown = markdown.replace("{{REVISION}}", revision_number)
     markdown = markdown.replace("{{TAG}}", revision_tag)
@@ -185,6 +189,7 @@
     subject = subject.replace("{{COMMITTEE}}", committee.display_name)
     subject = subject.replace("{{PROJECT}}", str(project_display_name))
+    subject = subject.replace("{{PROJECT_LABEL}}", str(options.project_key))
     subject = subject.replace("{{REVISION}}", revision_number)
     subject = subject.replace("{{TAG}}", revision_tag)
     subject = subject.replace("{{VERSION}}", str(options.version_key))
@@ -196,6 +201,7 @@
     body = body.replace("{{COMMITTEE}}", committee.display_name)
     body = body.replace("{{DURATION}}", str(options.vote_duration))
     body = body.replace("{{KEYS_FILE}}", keys_file or "(Sorry, the KEYS file is missing!)")
     body = body.replace("{{PROJECT}}", str(project_display_name))
+    body = body.replace("{{PROJECT_LABEL}}", str(options.project_key))
     body = body.replace("{{RELEASE_CHECKLIST}}", checklist_content)
     body = body.replace("{{REVIEW_URL}}", review_url)
     body = body.replace("{{REVISION}}", revision_number)
````

#### `migrations/versions/0033_2025.12.31_f2d97d96.py`

Add `PROJECT_LABEL` to the `KNOWN_VARIABLES` list so existing migration logic recognizes it if it appears in old bracket syntax.

````diff
--- a/migrations/versions/0033_2025.12.31_f2d97d96.py
+++ b/migrations/versions/0033_2025.12.31_f2d97d96.py
@@ -40,6 +40,7 @@
     "KEYS_FILE",
     "PROJECT",
+    "PROJECT_LABEL",
     "RELEASE_CHECKLIST",
     "REVIEW_URL",
     "REVISION",
````

---

## [#1226](https://github.com/apache/tooling-trusted-releases/issues/1226) — Add the option, on by default, to automatically resolve hybrid votes

**Classification:** `no_action`  •  **Confidence:** `medium`

### Summary

This issue requests adding an option (on by default) to automatically resolve hybrid votes. The issue references #1216 as a parent issue. Looking at the codebase, I can see the vote resolution logic in `atr/storage/writers/vote.py` (the `resolve` and `_resolve_trusted` methods), the vote modes (`MANUAL`, `EMAIL`, `TRUSTED`), and the tabulation model in `atr/models/tabulate.py`. However, the concept of 'hybrid votes' is not clearly defined in the provided code — there's no `HYBRID` vote mode in the `VoteMode` enum, and the parent issue #1216 is not available for context. Without understanding what constitutes a 'hybrid vote' in this system (possibly a combination of trusted/email votes with email-tabulated votes?), what 'automatically resolve' means in this context (auto-transitioning the release phase when vote criteria are met?), and where the option should be stored (likely in `ReleasePolicy` or project settings), I cannot propose a concrete implementation.

### Files examined

- `atr/db/interaction.py`
- `atr/models/tabulate.py`
- `atr/post/resolve.py`
- `atr/shared/resolve.py`
- `atr/tasks/vote.py`
- `atr/models/sql.py`
- `atr/storage/writers/vote.py`
- `atr/admin/__init__.py`

> _The agent reviewed this issue and has no concrete action it can propose. This may mean the issue needs more information, requires runtime debugging, depends on external systems, or is a discussion item. A human reviewer should take it from here._

---

## [#1225](https://github.com/apache/tooling-trusted-releases/issues/1225) — Count IPMC members' votes from a PPMC first round vote in the second round too

**Classification:** `actionable`  •  **Confidence:** `medium`

### Summary

The issue requests that when a podling release goes through a two-round vote (first PPMC, then IPMC/Incubator PMC), IPMC members who voted in the first round should have their votes counted as binding in the second round too. Currently, `is_binding_for_release` only checks if a voter is a member of the Incubator PMC for round 2, but doesn't consider that an IPMC member's vote from round 1 should also carry over as binding in round 2. The `trusted_ballot_summary` and ballot resolution logic need to account for IPMC members' first-round votes being binding in the second round context.

### Files examined

- `atr/post/vote.py`
- `atr/storage/writers/vote.py`
- `atr/user.py`
- `atr/db/interaction.py`
- `atr/models/tabulate.py`
- `atr/post/resolve.py`
- `atr/post/voting.py`
- `atr/shared/vote.py`

### Proposed changes

#### `atr/user.py`

Modify `is_binding_for_release` to also return True for IPMC members voting in round 1 of a podling vote, since their votes should count as binding in round 2 as well.

````diff
--- a/atr/user.py
+++ b/atr/user.py
@@ -68,12 +68,18 @@ async def is_binding_for_release(
     if not committee.is_podling:
         if vote_round is not None:
             raise ValueError("Non-podling votes require vote_round to be None")
         return is_committee_member(committee, asf_uid), committee.display_name

     if vote_round is None:
         raise ValueError("Podling votes require vote_round 1 or 2")
     if vote_round not in (1, 2):
         raise ValueError(f"Unexpected podling vote_round: {vote_round!r}")
     if vote_round == 1:
-        return is_committee_member(committee, asf_uid), committee.display_name
+        # In round 1, PPMC members have formal votes, but IPMC members
+        # also have binding votes that carry over to round 2
+        if is_committee_member(committee, asf_uid):
+            return True, committee.display_name
+        async with db.ensure_session(caller_data) as data:
+            incubator = await data.committee(key="incubator").get()
+        if is_committee_member(incubator, asf_uid):
+            return True, "Incubator"
+        return False, committee.display_name
     async with db.ensure_session(caller_data) as data:
         incubator = await data.committee(key="incubator").get()
     return is_committee_member(incubator, asf_uid), "Incubator"
````

#### `atr/db/interaction.py`

Update `ballots_for_resolution` to include round-1 IPMC member ballots when resolving a round-2 vote, so their votes from round 1 are counted in the second round tally.

````diff
--- a/atr/db/interaction.py
+++ b/atr/db/interaction.py
@@ -148,6 +148,40 @@ async def ballots_for_resolution(
         return list(result.scalars().all())


+async def ballots_for_resolution_with_ipmc_carryover(
+    release: sql.Release,
+    vote_seq: int,
+    caller_data: db.Session | None = None,
+) -> list[sql.BallotPaper]:
+    """Get ballots for resolution, carrying over IPMC members' round 1 votes into round 2."""
+    ballots = await ballots_for_resolution(release.key, vote_seq, caller_data)
+    if release.committee is None or not release.committee.is_podling:
+        return ballots
+    if release.podling_thread_id is None:
+        # Still in round 1, no carryover needed
+        return ballots
+
+    # We're in round 2. Find round-1 IPMC member votes that aren't already
+    # represented in round 2 ballots.
+    round2_voter_uids = {b.voter_asf_uid for b in ballots if b.vote_round == 2}
+
+    # Get the previous vote_seq (round 1)
+    previous_vote_seq = vote_seq - 1
+    if previous_vote_seq < 1:
+        return ballots
+
+    round1_ballots = await ballots_for_resolution(release.key, previous_vote_seq, caller_data)
+
+    async with db.ensure_session(caller_data) as data:
+        incubator = await data.committee(key="incubator").get()
+
+    for ballot in round1_ballots:
+        if ballot.voter_asf_uid in round2_voter_uids:
+            continue  # Already voted in round 2, use that vote
+        if user.is_committee_member(incubator, ballot.voter_asf_uid):
+            # Carry over this IPMC member's round 1 vote into round 2
+            ballots.append(ballot)
+
+    return ballots
+
+
 async def candidate_drafts(project: sql.Project) -> list[sql.Release]:
     """Get the candidate drafts for the project."""
     return await releases_by_phase(project, sql.ReleasePhase.RELEASE_CANDIDATE_DRAFT)
````

---

## [#1224](https://github.com/apache/tooling-trusted-releases/issues/1224) — Remind binding voters to vote through ATR in Trusted Vote mode

**Classification:** `no_action`  •  **Confidence:** `medium`

### Summary

This issue requests that binding voters be reminded to vote through ATR (the Trusted Release tooling) when a release is in Trusted Vote mode. The idea is that when a vote is in TRUSTED mode, binding voters who might otherwise vote via email directly should be prompted/reminded to cast their vote through the ATR interface instead. While I can see where such a reminder would go (likely in the vote page rendering in `atr/get/vote.py` which isn't fully shown, or in the vote initiation email body), I don't have access to the full vote page rendering code (`atr/get/vote.py`) to see how the current vote UI is displayed to users. The issue is part of a larger epic (#1216) and the specific UX requirements (where exactly the reminder should appear — on the vote page, in the email, or both) are not fully specified. Without seeing the vote page template and understanding the exact desired behavior, I cannot confidently propose a concrete implementation.

### Files examined

- `atr/storage/writers/vote.py`
- `atr/shared/vote.py`
- `atr/shared/voting.py`
- `atr/get/voting.py`
- `atr/post/vote.py`
- `atr/post/voting.py`
- `atr/tabulate.py`
- `atr/tasks/vote.py`

> _The agent reviewed this issue and has no concrete action it can propose. This may mean the issue needs more information, requires runtime debugging, depends on external systems, or is a discussion item. A human reviewer should take it from here._