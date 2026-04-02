#!/bin/bash
# monitor-agent.sh — tmux dashboard for CI analyzer agents
# Monitors: Publishing Analyzer, Security Scanner, Report Combiner
# Usage: chmod +x monitor-agent.sh && ./monitor-agent.sh

COUCH_URL="http://user:password@localhost:5984"
DB="agent_data_store"
SESSION="ci-monitor"
OWNER="apache"

# Kill existing session if any
tmux kill-session -t "$SESSION" 2>/dev/null

tmux new-session -d -s "$SESSION" -x 220 -y 60

# ── Pane 0 (top-left): All namespace doc counts grouped by agent ──
tmux send-keys "watch -n 5 'echo \"=== Doc Counts (all agents) ===\"; echo; \
curl -s \"${COUCH_URL}/${DB}/_find\" \
  -H \"Content-Type: application/json\" \
  -d \"{\\\"selector\\\":{\\\"namespace\\\":{\\\"\\\$in\\\":[\\\"ci-classification:${OWNER}\\\",\\\"ci-workflows:${OWNER}\\\",\\\"ci-report:${OWNER}\\\",\\\"ci-security:${OWNER}\\\",\\\"ci-combined:${OWNER}\\\"]}},\\\"fields\\\":[\\\"namespace\\\"],\\\"limit\\\":9999}\" \
| python3 -c \"
import sys, json
from collections import Counter
docs = json.load(sys.stdin)[\\\"docs\\\"]
counts = Counter(d[\\\"namespace\\\"] for d in docs)
print(f\\\"Total: {len(docs)} docs\\\")
print()
groups = {
    \\\"Agent 1 (Publishing)\\\": [\\\"ci-classification:${OWNER}\\\", \\\"ci-workflows:${OWNER}\\\", \\\"ci-report:${OWNER}\\\"],
    \\\"Agent 2 (Security)\\\": [\\\"ci-security:${OWNER}\\\"],
    \\\"Agent 3 (Combined)\\\": [\\\"ci-combined:${OWNER}\\\"],
}
for label, namespaces in groups.items():
    group_total = sum(counts.get(ns, 0) for ns in namespaces)
    print(f\\\"{label}: {group_total} docs\\\")
    for ns in namespaces:
        c = counts.get(ns, 0)
        short = ns.split(\\\":\\\")[0]
        print(f\\\"  {c}\\t{short}\\\")
    print()
if not docs:
    print(\\\"  (all empty)\\\")
\"'" C-m

# ── Pane 1 (top-right): Completed repos + classification status ──
tmux split-window -h
tmux send-keys "watch -n 10 'echo \"=== Agent 1: Repo Status ===\"; echo; \
curl -s \"${COUCH_URL}/${DB}/_find\" \
  -H \"Content-Type: application/json\" \
  -d \"{\\\"selector\\\":{\\\"namespace\\\":\\\"ci-classification:${OWNER}\\\",\\\"key\\\":{\\\"\\\$regex\\\":\\\"^__meta__:\\\"}},\\\"fields\\\":[\\\"key\\\",\\\"value\\\"],\\\"limit\\\":9999}\" \
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

# ── Pane 2 (middle-left): In-progress classification ──
tmux select-pane -t 0
tmux split-window -v
tmux send-keys "watch -n 5 'echo \"=== Agent 1: In-Progress ===\"; echo; \
curl -s \"${COUCH_URL}/${DB}/_find\" \
  -H \"Content-Type: application/json\" \
  -d \"{\\\"selector\\\":{\\\"namespace\\\":\\\"ci-classification:${OWNER}\\\",\\\"key\\\":{\\\"\\\$not\\\":{\\\"\\\$regex\\\":\\\"^__meta__:\\\"}}},\\\"fields\\\":[\\\"key\\\"],\\\"limit\\\":9999}\" \
| python3 -c \"
import sys, json, subprocess
docs = json.load(sys.stdin)[\\\"docs\\\"]

meta_raw = subprocess.run(
    [\\\"curl\\\", \\\"-s\\\", \\\"${COUCH_URL}/${DB}/_find\\\",
     \\\"-H\\\", \\\"Content-Type: application/json\\\",
     \\\"-d\\\", json.dumps({\\\"selector\\\": {\\\"namespace\\\": \\\"ci-classification:${OWNER}\\\", \\\"key\\\": {\\\"\\\$regex\\\": \\\"^__meta__:\\\"}}, \\\"fields\\\": [\\\"key\\\", \\\"value\\\"], \\\"limit\\\": 9999})],
    capture_output=True, text=True
).stdout
meta_docs = json.loads(meta_raw)[\\\"docs\\\"]
complete_repos = {d[\\\"key\\\"].replace(\\\"__meta__:\\\", \\\"\\\") for d in meta_docs if d.get(\\\"value\\\", {}).get(\\\"complete\\\")}

by_repo = {}
for d in docs:
    key = d[\\\"key\\\"]
    repo = key.split(\\\":\\\")[0] if \\\":\\\" in key else \\\"unknown\\\"
    by_repo.setdefault(repo, []).append(key)

in_progress = {r: files for r, files in by_repo.items() if r not in complete_repos}

if not in_progress:
    print(\\\"No repos currently being classified.\\\")
    print(f\\\"\\\\nTotal classified: {len(docs)} workflows across {len(by_repo)} repos\\\")
else:
    for repo, files in sorted(in_progress.items()):
        print(f\\\"⏳ {repo}: {len(files)} classified so far\\\")
        recent = sorted(files)[-15:]
        for f in recent:
            wf_name = f.split(\\\":\\\", 1)[1] if \\\":\\\" in f else f
            print(f\\\"     {wf_name}\\\")
        if len(files) > 15:
            print(f\\\"     ... and {len(files) - 15} more\\\")
    print(f\\\"\\\\nTotal classified: {len(docs)} workflows\\\")
\"'" C-m

# ── Pane 3 (middle-right): Agent 2 security findings summary ──
tmux select-pane -t 1
tmux split-window -v
tmux send-keys "watch -n 5 'echo \"=== Agent 2: Security Findings ===\"; echo; \
curl -s \"${COUCH_URL}/${DB}/_find\" \
  -H \"Content-Type: application/json\" \
  -d \"{\\\"selector\\\":{\\\"namespace\\\":\\\"ci-security:${OWNER}\\\"},\\\"fields\\\":[\\\"key\\\",\\\"value\\\"],\\\"limit\\\":9999}\" \
| python3 -c \"
import sys, json
docs = json.load(sys.stdin)[\\\"docs\\\"]

if not docs:
    print(\\\"No security data yet.\\\")
    print(\\\"Run Agent 2 after Agent 1 completes.\\\")
else:
    finding_docs = [d for d in docs if d[\\\"key\\\"].startswith(\\\"findings:\\\")]
    meta_docs = [d for d in docs if d[\\\"key\\\"].startswith(\\\"latest_\\\")]
    
    repos_with_findings = 0
    repos_clean = 0
    total_findings = 0
    severity_counts = {}
    check_counts = {}
    
    for d in finding_docs:
        findings = d.get(\\\"value\\\", [])
        if isinstance(findings, list):
            if findings:
                repos_with_findings += 1
                total_findings += len(findings)
            else:
                repos_clean += 1
            for f in findings:
                if isinstance(f, dict):
                    sev = f.get(\\\"severity\\\", \\\"?\\\")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    chk = f.get(\\\"check\\\", \\\"?\\\")
                    check_counts[chk] = check_counts.get(chk, 0) + 1
    
    print(f\\\"Repos processed: {len(finding_docs)} ({repos_with_findings} with findings, {repos_clean} clean)\\\")
    print(f\\\"Total findings: {total_findings}\\\")
    print()
    
    if severity_counts:
        print(\\\"By severity:\\\")
        for sev in [\\\"CRITICAL\\\", \\\"HIGH\\\", \\\"MEDIUM\\\", \\\"LOW\\\", \\\"INFO\\\"]:
            c = severity_counts.get(sev, 0)
            if c > 0:
                print(f\\\"  {sev}: {c}\\\")
        print()
    
    if check_counts:
        print(\\\"By check:\\\")
        for chk, c in sorted(check_counts.items(), key=lambda x: -x[1])[:10]:
            print(f\\\"  {c}\\t{chk}\\\")
    
    if meta_docs:
        print()
        print(\\\"Reports: \\\", \\\", \\\".join(d[\\\"key\\\"] for d in meta_docs))
\"'" C-m

# ── Pane 4 (bottom): Docker logs tail ──
tmux select-pane -t 2
tmux split-window -v
tmux send-keys "docker compose logs -f --tail=100 api 2>&1 | grep --line-buffered -E '(Scanning|Progress|Rate limit|WARNING|ERROR|Scan complete|classified|cached|Preflight|Security scan|findings|composite|call_llm)'" C-m

# Layout and attach
tmux select-layout -t "$SESSION" tiled
tmux attach -t "$SESSION"