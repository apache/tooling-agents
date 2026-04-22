```bash
RESULTS
-------
Aggregate score: 6.2 / 10

Check scores:
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
|  SCORE  |          NAME          |             REASON             |                                               DOCUMENTATION/REMEDIATION                                               |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 10 / 10 | Binary-Artifacts       | no binaries found in the repo  | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#binary-artifacts       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 0 / 10  | Branch-Protection      | branch protection not enabled  | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#branch-protection      |
|         |                        | on development/release         |                                                                                                                       |
|         |                        | branches                       |                                                                                                                       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 10 / 10 | CI-Tests               | 6 out of 6 merged PRs          | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#ci-tests               |
|         |                        | checked by a CI test -- score  |                                                                                                                       |
|         |                        | normalized to 10               |                                                                                                                       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 0 / 10  | CII-Best-Practices     | no effort to earn an OpenSSF   | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#cii-best-practices     |
|         |                        | best practices badge detected  |                                                                                                                       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 0 / 10  | Code-Review            | Found 2/30 approved changesets | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#code-review            |
|         |                        | -- score normalized to 0       |                                                                                                                       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 10 / 10 | Contributors           | project has 34 contributing    | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#contributors           |
|         |                        | companies or organizations     |                                                                                                                       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 10 / 10 | Dangerous-Workflow     | no dangerous workflow patterns | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#dangerous-workflow     |
|         |                        | detected                       |                                                                                                                       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 0 / 10  | Dependency-Update-Tool | no update tool detected        | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#dependency-update-tool |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 0 / 10  | Fuzzing                | project is not fuzzed          | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#fuzzing                |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 10 / 10 | License                | license file detected          | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#license                |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 10 / 10 | Maintained             | 30 commit(s) and 30 issue      | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#maintained             |
|         |                        | activity found in the last 90  |                                                                                                                       |
|         |                        | days -- score normalized to 10 |                                                                                                                       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| ?       | Packaging              | packaging workflow not         | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#packaging              |
|         |                        | detected                       |                                                                                                                       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 4 / 10  | Pinned-Dependencies    | dependency not pinned by hash  | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#pinned-dependencies    |
|         |                        | detected -- score normalized   |                                                                                                                       |
|         |                        | to 4                           |                                                                                                                       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 7 / 10  | SAST                   | SAST tool detected but not run | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#sast                   |
|         |                        | on all commits                 |                                                                                                                       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 10 / 10 | Security-Policy        | security policy file detected  | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#security-policy        |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| ?       | Signed-Releases        | no releases found              | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#signed-releases        |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 9 / 10  | Token-Permissions      | detected GitHub workflow       | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#token-permissions      |
|         |                        | tokens with excessive          |                                                                                                                       |
|         |                        | permissions                    |                                                                                                                       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| 10 / 10 | Vulnerabilities        | 0 existing vulnerabilities     | https://github.com/ossf/scorecard/blob/40bbc9c958aa66327fb026b2136f1951298ca0f8/docs/checks.md#vulnerabilities        |
|         |                        | detected                       |                                                                                                                       |
|---------|------------------------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
```