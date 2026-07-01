# asvs_guidance_upload
#
# Stores a guidance document (AGENTS.md, security_model.rst, project
# CONTRIBUTING text, threat-model notes — anything you want Opus to read
# alongside source code) in CouchDB so the ASVS audit pipeline can fold it
# into the audit prompt as additional domain context.
#
# Per-repo isolation: each repo gets its own namespace. By default, this
# agent writes to `audit_guidance:{repo}`. supplementalData on the
# orchestrator then targets that specific namespace so an airflow audit
# only loads airflow's guidance, a mahout audit only loads mahout's, etc.
#
# Typical workflow:
#   1. Call this agent once per guidance file you want available.
#      Each call writes one key under that repo's namespace.
#   2. Run the orchestrator with
#        supplementalData: audit_guidance:{repo}
#      e.g. `audit_guidance:airflow` for airflow audits. The orchestrator
#      threads that namespace into the audit/bundle agents, which load
#      every key under it as part of file scope and feed it to Opus
#      alongside source.
#
# Layout:
#   audit_guidance:airflow → keys: AGENTS.md, security_model.rst, ...
#   audit_guidance:mahout  → keys: AGENTS.md, ...
#   audit_guidance:steve   → keys: ...
#
# Multiple guidance files for one repo all share that repo's namespace
# and get loaded together.
#
# Re-running with the same (repo, filename) overwrites the previous
# value — data_store.set handles _rev internally.
#
# Inputs (input_dict):
#   inputText (required): JSON object with:
#     repo      (required): determines the namespace.
#                           e.g. "airflow", "mahout".
#     filename  (required): becomes the key in that namespace.
#                           e.g. "AGENTS.md", "security_model.rst".
#     namespace (optional): explicit namespace override. If provided,
#                           used as-is and `repo` is only used in the
#                           success message. If omitted, namespace is
#                           constructed as f"audit_guidance:{repo}".
#   fileContents (required): full text of the file.
#
# Output:
#   outputText: success summary with namespace, key, size, and a
#               reminder of the supplementalData value to use, or
#               "Error: <message>" on failure.
#
# Example:
#
#   await gofannon_client.call(
#       agent_name="asvs_guidance_upload",
#       input_dict={
#           "inputText": json.dumps({
#               "repo": "airflow",
#               "filename": "AGENTS.md",
#           }),
#           "fileContents": open("AGENTS.md").read(),
#       },
#   )
#   # Stored at audit_guidance:airflow → key AGENTS.md
#   # Use supplementalData: audit_guidance:airflow on the orchestrator

import json


async def run(input_dict, tools):
    try:
        # --- Parse inputs ---
        input_text = input_dict.get("inputText", "")
        file_contents = input_dict.get("fileContents", "")

        if not input_text:
            return {"outputText": "Error: inputText is required (JSON with repo, filename)"}
        if not file_contents:
            return {"outputText": "Error: fileContents is required and cannot be empty"}

        try:
            params = json.loads(input_text)
        except json.JSONDecodeError as e:
            return {"outputText": f"Error: inputText must be valid JSON: {e}"}

        if not isinstance(params, dict):
            return {"outputText": "Error: inputText must be a JSON object"}

        repo = (params.get("repo") or "").strip()
        filename = (params.get("filename") or "").strip()
        namespace_override = (params.get("namespace") or "").strip()

        if not repo:
            return {"outputText": "Error: 'repo' is required in inputText"}
        if not filename:
            return {"outputText": "Error: 'filename' is required in inputText"}

        # Construct per-repo namespace by default. Each repo gets its
        # own namespace so a given audit run only loads the guidance
        # files for the source it's auditing — matching the per-repo
        # isolation requirement. The user can override with an explicit
        # `namespace` field if they need a different layout.
        namespace = namespace_override or f"audit_guidance:{repo}"

        # --- Reject control characters in key components ---
        # CouchDB keys are flexible but newlines, tabs, and NULs in key
        # segments cause unpleasant surprises later — broken _find
        # selectors, ugly log lines, hard-to-grep keys. Reject up front
        # rather than letting them propagate.
        for arg_name, arg_value in (
            ("repo", repo),
            ("filename", filename),
            ("namespace", namespace),
        ):
            if any(ch in arg_value for ch in ("\n", "\r", "\t", "\0")):
                return {
                    "outputText": (
                        f"Error: '{arg_name}' contains illegal whitespace/control "
                        f"characters; sanitize before sending"
                    )
                }

        # --- Write to data store ---
        # Key is just the filename — the per-repo namespace already
        # provides repo-level isolation, so we don't need to repeat
        # the repo name in the key.
        key = filename

        try:
            ns = data_store.use_namespace(namespace)
            ns.set(key, file_contents)
        except Exception as e:
            err_type = type(e).__name__
            err_msg = str(e) or "(no message)"
            return {
                "outputText": f"Error: failed to write to {namespace}:{key}: {err_type}: {err_msg}"
            }

        size = len(file_contents)
        return {
            "outputText": (
                f"Stored {namespace} → {key} ({size} chars). "
                f"To use during an audit, pass "
                f"supplementalData: {namespace} to the orchestrator."
            )
        }

    except Exception as e:
        # Catch-all so unexpected errors surface cleanly through the
        # gofannon agent runtime rather than as empty outputText.
        #
        # IMPORTANT: this except MUST live inside run(). gofannon
        # recompiles run() in a fresh namespace at invocation time, so
        # module-level wrappers don't survive — putting the except
        # outside run() leads to NameError on the helper symbols.
        # (Lesson learned the hard way during the consolidate agent
        # error-wrapper work earlier in this project.)
        err_type = type(e).__name__
        err_msg = str(e) or "(no message)"
        return {"outputText": f"Error: {err_type}: {err_msg}"}