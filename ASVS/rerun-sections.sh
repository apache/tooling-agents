#!/bin/bash
# rerun-sections.sh — Re-run failed/missing ASVS sections
#
# Usage:
#   ./rerun-sections.sh <namespace> <output_repo> <output_token> <output_dir> <section> [section...]
#   ./rerun-sections.sh <namespace> <output_repo> <output_token> <output_dir> --consolidate <section> [section...]
#
# Example:
#   ./rerun-sections.sh "files:apache/steve/v3" apache/tooling-agents ghp_xxx \
#     ASVS/reports/steve/v3/d0aa7e9 1.3.3 1.5.1 1.5.2 1.5.3 3.5.7
#
#   With re-consolidation (pass all domain directories):
#   ./rerun-sections.sh "files:apache/steve/v3" apache/tooling-agents ghp_xxx \
#     ASVS/reports/steve/v3/d0aa7e9 --consolidate 1.3.3 1.5.1 1.5.2 1.5.3 3.5.7

set -euo pipefail

API_BASE="${GOFANNON_API:-http://localhost:8000}"

if [ $# -lt 5 ]; then
    echo "Usage: $0 <namespace> <output_repo> <output_token> <output_dir> [--consolidate] <section> [section...]"
    echo ""
    echo "  namespace     Data store namespace (e.g., files:apache/steve/v3)"
    echo "  output_repo   GitHub repo for reports (e.g., apache/tooling-agents)"
    echo "  output_token  GitHub PAT with write access"
    echo "  output_dir    Report directory (e.g., ASVS/reports/steve/v3/d0aa7e9)"
    echo "  --consolidate Re-run consolidation after auditing (optional)"
    echo "  section       ASVS section numbers (e.g., 1.3.3 1.5.1)"
    exit 1
fi

NAMESPACE="$1"; shift
OUTPUT_REPO="$1"; shift
OUTPUT_TOKEN="$1"; shift
OUTPUT_DIR="$1"; shift

CONSOLIDATE=false
if [ "${1:-}" = "--consolidate" ]; then
    CONSOLIDATE=true
    shift
fi

SECTIONS=("$@")
RERUN_DIR="${OUTPUT_DIR}/rerun"

echo "============================================================"
echo "Re-running ${#SECTIONS[@]} sections"
echo "  Namespace: ${NAMESPACE}"
echo "  Output: ${OUTPUT_REPO}/${RERUN_DIR}"
echo "  Consolidate: ${CONSOLIDATE}"
echo "============================================================"
echo ""

call_agent() {
    local agent_name="$1"
    local input_json="$2"

    curl -s -X POST "${API_BASE}/rest/${agent_name}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer local" \
        -d "${input_json}"
}

SUCCEEDED=0
FAILED=0

for section in "${SECTIONS[@]}"; do
    echo "[${section}] Auditing..."

    # Build audit input
    AUDIT_INPUT=$(python3 -c "
import json
print(json.dumps({
    'inputText': json.dumps({
        'namespaces': ['${NAMESPACE}'],
        'asvs': '${section}',
    })
}))
")

    AUDIT_RESULT=$(call_agent "run_asvs_security_audit" "${AUDIT_INPUT}")
    AUDIT_TEXT=$(echo "${AUDIT_RESULT}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('outputText',''))" 2>/dev/null || echo "")

    if [ -z "${AUDIT_TEXT}" ] || echo "${AUDIT_TEXT}" | grep -q "^Error:"; then
        echo "  AUDIT FAILED: ${AUDIT_TEXT:0:200}"
        FAILED=$((FAILED + 1))
        continue
    fi

    echo "  Audit done: ${#AUDIT_TEXT} chars"

    # Push to GitHub
    PUSH_INPUT=$(python3 -c "
import json
print(json.dumps({
    'inputText': json.dumps({
        'repo': '${OUTPUT_REPO}',
        'token': '${OUTPUT_TOKEN}',
        'directory': '${RERUN_DIR}',
        'filename': '${section}.md',
    }),
    'commitMessage': 'ASVS rerun: ${section}',
    'fileContents': '''$(echo "${AUDIT_TEXT}" | sed "s/'/'\\\\''/g")''',
}))
")

    PUSH_RESULT=$(call_agent "add_markdown_file_to_github_directory" "${PUSH_INPUT}")

    if echo "${PUSH_RESULT}" | python3 -c "import sys,json; d=json.load(sys.stdin).get('outputText',''); exit(0 if 'sha' in d.lower() or 'content' in d.lower() else 1)" 2>/dev/null; then
        echo "  Push OK"
        SUCCEEDED=$((SUCCEEDED + 1))
    else
        echo "  Push FAILED"
        FAILED=$((FAILED + 1))
    fi

    echo ""
done

echo "============================================================"
echo "Complete: ${SUCCEEDED} succeeded, ${FAILED} failed"
echo "============================================================"

if [ "${CONSOLIDATE}" = true ] && [ ${SUCCEEDED} -gt 0 ]; then
    echo ""
    echo "Re-running consolidation..."
    echo "  Reading from: ${OUTPUT_DIR}"

    # List all subdirectories in the output directory
    DIRS=$(curl -s -H "Authorization: token ${OUTPUT_TOKEN}" \
        "https://api.github.com/repos/${OUTPUT_REPO}/contents/${OUTPUT_DIR}" \
        | python3 -c "
import sys, json
items = json.load(sys.stdin)
dirs = [i['name'] for i in items if i['type'] == 'dir']
print(', '.join(f'${OUTPUT_DIR}/{d}' for d in sorted(dirs)))
" 2>/dev/null || echo "${RERUN_DIR}")

    echo "  Directories: ${DIRS}"

    CONSOL_INPUT=$(python3 -c "
import json
print(json.dumps({
    'inputText': '\n'.join([
        'repo: ${OUTPUT_REPO}',
        'pat: ${OUTPUT_TOKEN}',
        'directories: ${DIRS}',
        'output: ${OUTPUT_DIR}',
    ]),
}))
")

    call_agent "consolidate_asvs_security_audit_reports" "${CONSOL_INPUT}"
    echo ""
    echo "Consolidation complete"
fi