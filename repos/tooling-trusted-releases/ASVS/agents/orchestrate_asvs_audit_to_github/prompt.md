You will orchestrate a workflow that takes several inputs:

- inputText: list of comma-separated strings each called a section
- inputNamespace: namespace for local data store
- commit
- outputRepo: github owner/repo combination
- outputToken
- outputDirectory

For each section in inputText:

1. Run the tool "run_asvs_security_audit" with the following inputs:
   - namespace
   - section

2. Get the outputText from "run_asvs_security_audit" and run the tool "add_markdown_file_to_github_directory" with the following inputs, using "section.md" as the filename (e.g., for section 1.2.4 send filename 1.2.4.md), and send the contents of outputText as the file contents:
   - filename
   - fileContents
   - outputDirectory
   - outputRepo
   - outputToken

3. Collect all outputText from each "add_markdown_file_to_github_directory" run and concatenate all of them into one final doc.
