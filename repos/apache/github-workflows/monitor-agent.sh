#!/bin/bash
# monitor-agent.sh — tmux dashboard for CI analyzer agent progress
# Usage: chmod +x monitor-agent.sh && ./monitor-agent.sh

COUCH_URL="http://user:password@localhost:5984"
DB="agent_data_store"
SESSION="ci-monitor"

# Kill existing session if any
tmux kill-session -t "$SESSION" 2>/dev/null

tmux new-session -d -s "$SESSION" -x 220 -y 50

# ── Pane 0 (top-left): Namespace doc counts ──
tmux send-keys "watch -n 5 'echo \"=== Doc Counts ===\"; echo; \
curl -s \"${COUCH_URL}/${DB}/_find\" \
  -H \"Content-Type: application/json\" \
  -d \"{\\\"selector\\\":{\\\"namespace\\\":{\\\"\\\$in\\\":[\\\"ci-classification:apache\\\",\\\"ci-workflows:apache\\\",\\\"ci-report:apache\\\"]}},\\\"fields\\\":[\\\"namespace\\\"],\\\"limit\\\":9999}\" \
| python3 -c \"
import sys, json
from collections import Counter
docs = json.load(sys.stdin)[\\\"docs\\\"]
counts = Counter(d[\\\"namespace\\\"] for d in docs)
print(f\\\"Total: {len(docs)} docs\\\")
for ns, count in sorted(counts.items()):
    print(f\\\"  {count}\\t{ns}\\\")
if not docs:
    print(\\\"  (empty)\\\")
\"'" C-m

# ── Pane 1 (top-right): Completed repos + in-progress ──
tmux split-window -h
tmux send-keys "watch -n 10 'echo \"=== Repo Status ===\"; echo; \
curl -s \"${COUCH_URL}/${DB}/_find\" \
  -H \"Content-Type: application/json\" \
  -d \"{\\\"selector\\\":{\\\"namespace\\\":\\\"ci-classification:apache\\\",\\\"key\\\":{\\\"\\\$regex\\\":\\\"^__meta__:\\\"}},\\\"fields\\\":[\\\"key\\\",\\\"value\\\"],\\\"limit\\\":9999}\" \
| python3 -c \"
import sys, json
docs = json.load(sys.stdin)[\\\"docs\\\"]
done = [d for d in docs if d.get(\\\"value\\\", {}).get(\\\"complete\\\")]
with_wf = [d for d in done if d.get(\\\"value\\\", {}).get(\\\"workflows\\\")]
without_wf = [d for d in done if not d.get(\\\"value\\\", {}).get(\\\"workflows\\\")]
print(f\\\"Completed: {len(done)} repos ({len(with_wf)} with workflows, {len(without_wf)} empty)\\\")
print()
for d in sorted(with_wf, key=lambda x: x[\\\"key\\\"]):
    repo = d[\\\"key\\\"].replace(\\\"__meta__:\\\", \\\"\\\")
    wfs = d[\\\"value\\\"].get(\\\"workflows\\\", [])
    print(f\\\"  ✓ {repo}: {len(wfs)} workflows\\\")
\"'" C-m

# ── Pane 2 (bottom): In-progress repo + latest classified files ──
tmux select-pane -t 0
tmux split-window -v
tmux send-keys "watch -n 5 'echo \"=== In-Progress Workflows ===\"; echo; \
curl -s \"${COUCH_URL}/${DB}/_find\" \
  -H \"Content-Type: application/json\" \
  -d \"{\\\"selector\\\":{\\\"namespace\\\":\\\"ci-classification:apache\\\",\\\"key\\\":{\\\"\\\$not\\\":{\\\"\\\$regex\\\":\\\"^__meta__:\\\"}}},\\\"fields\\\":[\\\"key\\\",\\\"updatedAt\\\"],\\\"limit\\\":9999}\" \
| python3 -c \"
import sys, json
docs = json.load(sys.stdin)[\\\"docs\\\"]

# Get completed repos
import subprocess
meta_raw = subprocess.run(
    [\\\"curl\\\", \\\"-s\\\", \\\"${COUCH_URL}/${DB}/_find\\\",
     \\\"-H\\\", \\\"Content-Type: application/json\\\",
     \\\"-d\\\", json.dumps({\\\"selector\\\": {\\\"namespace\\\": \\\"ci-classification:apache\\\", \\\"key\\\": {\\\"\\\$regex\\\": \\\"^__meta__:\\\"}}, \\\"fields\\\": [\\\"key\\\", \\\"value\\\"], \\\"limit\\\": 9999})],
    capture_output=True, text=True
).stdout
meta_docs = json.loads(meta_raw)[\\\"docs\\\"]
complete_repos = {d[\\\"key\\\"].replace(\\\"__meta__:\\\", \\\"\\\") for d in meta_docs if d.get(\\\"value\\\", {}).get(\\\"complete\\\")}

# Group classification docs by repo
by_repo = {}
for d in docs:
    key = d[\\\"key\\\"]
    repo = key.split(\\\":\\\")[0] if \\\":\\\" in key else \\\"unknown\\\"
    by_repo.setdefault(repo, []).append(key)

# Find in-progress repos (have classification docs but no __meta__ complete)
in_progress = {r: files for r, files in by_repo.items() if r not in complete_repos}

if not in_progress:
    print(\\\"No repos currently being processed.\\\")
    print(f\\\"\\\\nTotal classified: {len(docs)} workflows across {len(by_repo)} repos\\\")
else:
    for repo, files in sorted(in_progress.items()):
        print(f\\\"⏳ {repo}: {len(files)} classified so far\\\")
        # Show last 15 files
        recent = sorted(files)[-15:]
        for f in recent:
            wf_name = f.split(\\\":\\\", 1)[1] if \\\":\\\" in f else f
            print(f\\\"     {wf_name}\\\")
        if len(files) > 15:
            print(f\\\"     ... and {len(files) - 15} more\\\")
    print(f\\\"\\\\nTotal classified: {len(docs)} workflows\\\")
\"'" C-m

# ── Pane 3 (bottom-right): Docker logs tail ──
tmux select-pane -t 3
tmux split-window -v
tmux send-keys "docker compose logs -f api 2>&1 | grep -E '(Scanning|Progress|Rate limit|WARNING|ERROR|Scan complete|classified|cached|Preflight|DEBUG|call_llm)'" C-m

# Layout and attach
tmux select-layout -t "$SESSION" tiled
tmux attach -t "$SESSION"
