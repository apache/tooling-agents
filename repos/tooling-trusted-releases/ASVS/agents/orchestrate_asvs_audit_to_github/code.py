# orchestrate_asvs_audit_to_github
from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        import json
        input_text = input_dict.get("inputText", "")
        input_namespace = input_dict.get("inputNamespace", "")
        commit = input_dict.get("commit", "")
        output_repo = input_dict.get("outputRepo", "")
        output_token = input_dict.get("outputToken", "")
        output_directory = input_dict.get("outputDirectory", "")
        instructions = input_dict.get("instructions", "")
        sections = [s.strip() for s in input_text.split(",") if s.strip()]
        namespaces = [ns.strip() for ns in input_namespace.split(",") if ns.strip()]
        print(f"Batch orchestrator: {len(sections)} sections to audit", flush=True)
        all_outputs = []
        successes = []
        failures = []
        for i, section in enumerate(sections):
            print(f"\n{'='*60}", flush=True)
            print(f"[{i+1}/{len(sections)}] Section {section}", flush=True)
            print(f"{'='*60}", flush=True)
            audit_output_text = None
            try:
                audit_result = await gofannon_client.call(
                    agent_name="run_asvs_security_audit",
                    input_dict={
                        "inputText": json.dumps({
                            "namespaces": namespaces,
                            "asvs": section,
                            "instructions": instructions,
                        })
                    }
                )
                audit_output_text = audit_result.get("outputText", "")
                print(f"  Audit done: {len(audit_output_text)} chars", flush=True)
            except Exception as e:
                print(f"  Audit FAILED: {e}", flush=True)
                failures.append(f"{section} (audit): {e}")
                continue
            try:
                github_result = await gofannon_client.call(
                    agent_name="add_markdown_file_to_github_directory",
                    input_dict={
                        "inputText": json.dumps({
                            "repo": output_repo,
                            "token": output_token,
                            "directory": output_directory,
                            "filename": f"{section}.md",
                        }),
                        "commitMessage": f"Add ASVS audit for section {section}",
                        "fileContents": audit_output_text,
                    }
                )
                print(f"  GitHub push OK", flush=True)
                successes.append(section)
            except Exception as e:
                print(f"  GitHub push FAILED: {e}", flush=True)
                failures.append(f"{section} (push): {e}")
            all_outputs.append(audit_output_text)
        print(f"\n{'='*60}", flush=True)
        print(f"Batch complete: {len(successes)} succeeded, {len(failures)} failed", flush=True)
        if failures:
            for f in failures:
                print(f"  - {f}", flush=True)
        final_doc = "\n\n---\n\n".join(all_outputs)
        return {"outputText": final_doc}
    finally:
        await http_client.aclose()
