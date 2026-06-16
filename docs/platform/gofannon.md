# Gofannon

[Gofannon](https://github.com/The-AI-Alliance/gofannon) is the agent framework used for building and running the security audit pipeline. It provides a web UI for creating agents, a Python execution sandbox, CouchDB-backed persistent storage, and API endpoints for invoking deployed agents.

This guide covers platform setup and the full agent development lifecycle — it is not specific to any particular audit or repository.

## Table of contents

- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Services](#services)
- [Agent lifecycle](#agent-lifecycle)
- [Data store](#data-store)
- [Agent runtime globals](#agent-runtime-globals)
- [Tips](#tips)

## Prerequisites

- Docker and Docker Compose
- At least one LLM provider credential (see `.env` below)
- For Bedrock: AWS credentials with `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` permissions

## Setup

### Quickstart

[Quickstart](https://github.com/The-AI-Alliance/gofannon/tree/main/docs/quickstart) with screenshots

### Clone and configure

```bash
git clone https://github.com/The-AI-Alliance/gofannon.git
cd gofannon/webapp/infra/docker
```

Create `.env` from the example:

```bash
cp example.env .env
```

Edit `.env` with your credentials. Only one LLM provider is required:

```bash
# --- LLM Provider Keys (at least one required) ---

# Anthropic (direct API)
ANTHROPIC_API_KEY=sk-ant-your-key

# OpenAI
OPENAI_API_KEY=sk-proj-your-key

# AWS Bedrock (for Claude via Bedrock)
AWS_BEARER_TOKEN_BEDROCK=your-token
# Or use standard AWS credentials:
# AWS_ACCESS_KEY_ID=your-key
# AWS_SECRET_ACCESS_KEY=your-secret
# AWS_DEFAULT_REGION=us-east-1

# Google Gemini
# GEMINI_API_KEY=...

# --- CouchDB (local persistence, used automatically) ---
COUCHDB_USER=admin
COUCHDB_PASSWORD=password
```

### Start the stack

```bash
docker-compose up --build
```

First build takes a few minutes. Subsequent starts are faster.

### Rebuild after pulling updates

```bash
cd gofannon/webapp/infra/docker
docker-compose down && docker-compose up -d --build
```

CouchDB data persists across rebuilds (stored in Docker volume `couchdb-data`). Agent code changes take effect immediately due to uvicorn's `--reload` flag.

## Services

| Service | Port | URL | Purpose |
|---------|------|-----|---------|
| webui | 3000 | http://localhost:3000 | Web UI for creating and managing agents |
| api | 8000 | http://localhost:8000 | API service that executes agents |
| couchdb | 5984 | http://localhost:5984 | Document store for agents, data, and caches |
| minio | 9000/9001 | http://localhost:9001 | Object storage (used internally by Gofannon) |

### Verify CouchDB is healthy

```bash
curl -s -u admin:password http://localhost:5984/_all_dbs | python3 -m json.tool
```

## Agent lifecycle

### Create an agent

1. Navigate to http://localhost:3000
2. Click **"Create Agent"**
3. Enter a **name** for the agent (this becomes its API identifier, e.g., `run_asvs_security_audit`)
4. Write or paste the **description** (prompt) — this tells Gofannon's code generator what the agent should do

### Set models

Each agent has two model slots:

- **Compose model** — used by Gofannon to generate the agent's code from your prompt. Sonnet works well here.
- **Invokable model** — used by the agent itself when it calls `call_llm()` at runtime. Set this to whatever the agent needs (can be overridden in code).

To set a model:
1. Click the model selector
2. Choose provider (e.g., `bedrock`, `anthropic`, `openai`)
3. Choose model (e.g., `us.anthropic.claude-sonnet-4-5-20250929-v1:0`)
4. Set parameters (temperature, max_tokens, etc.)

### Select tools

Under the **Tools** menu, you can give the agent access to:

- **MCP servers** by URL
- **Swagger specs** by file or URL
- **Other deployed agents** on this Gofannon instance — this is how the orchestrator calls the audit agent and GitHub push agent

When you select another agent as a tool, it becomes callable via `gofannon_client.call()` in your agent's code.

### Generate code

Click **"Generate"** to have the compose model generate Python code from your prompt. The generated code follows this pattern:

```python
from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        # ... agent logic here ...
        return {"outputText": "result"}
    finally:
        await http_client.aclose()
```

### Edit generated code

The generated code is a starting point. For production agents, you'll typically need to:

- Replace the generated code entirely with your tuned version (paste into the code editor)
- Add error handling, retries, and logging
- Add caching via the data store
- Tune LLM parameters

The code editor in the web UI supports direct editing. Changes are saved when you click **"Save"** or **"Update"**.

### Test in sandbox

Click **"Sandbox"** to open the testing interface:

1. Enter your test input in the text field
2. Click **"Run"**
3. View results (output text, errors, execution time)

The sandbox uses the same execution environment as production — same data store, same LLM access, same tool connections. This means sandbox runs will write to the same CouchDB and can call the same external APIs.

### Save and deploy

- **"Save"** / **"Update"** — persists the agent code and configuration to CouchDB
- **"Deploy"** — makes the agent available via the API endpoint at `POST http://localhost:8000/api/agents/{agent_name}/run`

A deployed agent can be called by other agents via `gofannon_client.call()` or directly via the API.

### Delete an agent

In the agent page, click the delete button on the agent card. This removes the agent configuration from CouchDB. It does not delete any data the agent wrote to the data store.

## Data store

The data store is a CouchDB-backed key-value store shared across all agents for a user. It enables workflows where one agent produces data that another consumes.

### Concepts

- **Namespace** — a logical grouping of keys (e.g., `files:apache/tooling-trusted-releases`, `asvs`, `audit-cache:analysis:...`)
- **Key** — a string identifier within a namespace
- **Value** — any JSON-serializable data

### Usage in agent code

Data store operations are **synchronous** (no `await` needed):

```python
# Switch to a namespace
ns = data_store.use_namespace("files:apache/tooling-trusted-releases")

# Basic operations
value = ns.get("path/to/file.py")          # returns value or None
ns.set("path/to/file.py", "file contents")  # create or update
ns.delete("path/to/file.py")                # delete

# Bulk operations
keys = ns.list_keys()                        # all keys in namespace
keys = ns.list_keys(prefix="atr/api/")       # keys with prefix
all_data = ns.get_all()                      # dict of all key:value pairs
ns.set_many({"key1": val1, "key2": val2})    # bulk write

# Discovery
namespaces = data_store.list_namespaces()    # all namespaces with data
```

### CouchDB document schema

Each data store record is a CouchDB document:

```json
{
  "_id": "{userId}:{namespace}:{base64(key)}",
  "_rev": "5-abc123...",
  "userId": "local-dev-user",
  "namespace": "asvs",
  "key": "asvs:requirements:10.4.1",
  "value": { ... },
  "metadata": {},
  "createdByAgent": "ingest_asvs_standard",
  "lastAccessedByAgent": "run_asvs_security_audit",
  "accessCount": 4,
  "createdAt": "2026-03-04T01:06:36.525056",
  "updatedAt": "2026-03-04T01:06:36.525056",
  "lastAccessedAt": "2026-03-22T20:58:39.982262"
}
```

### Querying CouchDB directly

Useful for debugging and cache management:

```bash
# List all namespaces and counts
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{},"fields":["namespace"],"limit":10000}' \
  | python3 -c "
import sys, json
from collections import Counter
docs = json.load(sys.stdin)['docs']
for ns, count in sorted(Counter(d['namespace'] for d in docs).items()):
    print(f'  {count}\t{ns}')"

# Look up a specific document
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"namespace":"asvs","key":"asvs:requirements:7.2.1"},"limit":1}' \
  | python3 -m json.tool

# Delete documents matching a pattern (stop running agents first)
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"namespace":{"$regex":"^audit-cache:analysis"}},"fields":["_id","_rev"],"limit":10000}' \
  | python3 -c "
import sys, json, requests
docs = json.load(sys.stdin).get('docs', [])
for d in docs:
    requests.delete(f'http://admin:password@localhost:5984/agent_data_store/{d[\"_id\"]}?rev={d[\"_rev\"]}')"
```

### Key constraints

- Keys must NOT contain `/` (CouchDB interprets as path separator), whitespace, or quotes
- Values must be JSON-serializable
- The `_id` field uses base64-encoded keys, so the actual CouchDB document ID is `{userId}:{namespace}:{base64(key)}`

## Agent runtime globals

These are available in every agent's `run()` function without importing:

| Global | Type | Description |
|--------|------|-------------|
| `call_llm` | async function | Call any LLM: `content, thoughts = await call_llm(provider, model, messages, parameters, timeout=...)` |
| `count_tokens` | function | Count tokens: `count_tokens(text, provider, model)` |
| `count_message_tokens` | function | Count tokens for full messages list: `count_message_tokens(messages, provider, model)` |
| `get_context_window` | function | Get model context window: `get_context_window(provider, model)` → `200000` |
| `data_store` | AgentDataStoreProxy | Persistent key-value store (see above) |
| `gofannon_client` | GofannonClient | Call other deployed agents: `await gofannon_client.call(agent_name, input_dict)` |
| `asyncio` | module | Python asyncio (for `asyncio.gather`, `asyncio.Semaphore`, etc.) |

### `call_llm` usage

```python
content, thoughts = await call_llm(
    provider="bedrock",
    model="us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    messages=[{"role": "user", "content": "Analyze this code..."}],
    parameters={"temperature": 0.7, "max_tokens": 16384},
    timeout=300,
)
```

The `thoughts` return value contains extended thinking output (if the model supports it), otherwise `None`.

### Token counting best practices

Always use `count_tokens()` and `get_context_window()` when building prompts with variable-length content. Never use character-based estimation (`len(text) / 3`) — it undercounts by 30-50% for code.

```python
CONTEXT_WINDOW = get_context_window(provider, model)
SAFE_LIMIT = int(CONTEXT_WINDOW * 0.80)  # leave 20% headroom

prompt_tokens = count_message_tokens(messages, provider, model)
if prompt_tokens > SAFE_LIMIT:
    # split into batches
    ...
```

## Tips

### Double log lines

Gofannon runs uvicorn with `--reload`, which creates two worker processes. Both log the same output. This is cosmetic — there's only one actual execution.

### Hot reload

Agent code changes are picked up automatically by uvicorn. You don't need to restart the stack after editing code in the web UI and deploying.

### Monitoring

```bash
# Follow API logs
docker-compose logs -f api

# Follow with filtering
docker-compose logs -f api 2>&1 | grep -E "Step|Done|FAILED|ERROR"
```

### CouchDB admin UI

CouchDB has a built-in admin interface at http://localhost:5984/_utils/ (login with COUCHDB_USER/COUCHDB_PASSWORD). Useful for browsing the `agent_data_store` database directly.
