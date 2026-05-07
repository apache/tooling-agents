# Software Bill of Materials (SBOM)

**Repository:** [apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases)
**Format:** CycloneDX 1.5
**Tool:** git-pkgs 1.0.0
**Generated:** 2026-05-07

This is the full transitive SBOM derived from `uv.lock`, `bootstrap/source/package-lock.json`, GitHub Actions pins, pre-commit pins, and Dockerfiles. For the human-readable list of direct top-level dependencies, see [dependencies.md](./dependencies.md).

## Component counts by ecosystem

| Ecosystem | Components |
|---|---|
| PyPI (locked, with hashes) | 124 |
| npm (locked, with integrity) | 142 |
| GitHub Actions (SHA-pinned) | 18 (across workflows) |
| pre-commit | 9 |
| Docker base images | 3 |

## PyPI components (lockfile-pinned)

These are the resolved, hash-verified versions from `uv.lock`. Sample of security-relevant components — full list in the source CycloneDX document.

| Component | Version | License |
|---|---|---|
| aiofiles | 25.1.0 | Apache-2.0 |
| aiohappyeyeballs | 2.6.1 | PSF-2.0 |
| aiohttp | 3.13.5 | Apache-2.0 |
| aioshutil | 1.6 | BSD-3-Clause |
| aiosignal | 1.4.0 | Apache-2.0 |
| aiosmtplib | 5.1.0 | MIT |
| aiosqlite | 0.22.1 | MIT |
| aiozipstream | 0.4 | BSD-3-Clause |
| alembic | 1.18.4 | MIT |
| annotated-types | 0.7.0 | MIT |
| anyio | 4.13.0 | MIT |
| arrow | 1.4.0 | Apache-2.0 |
| asfpy | 0.58 | Apache-2.0 |
| asfquart | 0.1.13 | Apache-2.0 |
| asyncssh | 2.22.0 | EPL-2.0 |
| attrs | 26.1.0 | MIT |
| blake3 | 1.0.8 | CC0-1.0 |
| blinker | 1.9.0 | MIT |
| blockbuster | 1.5.26 | Apache-2.0 |
| boolean-py | 5.0 | (unspecified) |
| certifi | 2026.4.22 | MPL-2.0 |
| cffi | 2.0.0 | MIT |
| cfgv | 3.5.0 | MIT |
| charset-normalizer | 3.4.7 | MIT |
| click | 8.3.3 | BSD-3-Clause |
| cmarkgfm | 2025.10.22 | MIT |
| colorama | 0.4.6 | BSD-3-Clause |
| cryptography | 46.0.7 | Apache-2.0 |
| cssbeautifier | 1.15.4 | MIT |
| cvss | 3.6 | LGPL-3.0+ |
| cyclonedx-python-lib | 11.7.0 | Apache-2.0 |
| decouple-types | 1.0.2 | MIT |
| **defusedxml** | **0.7.1** | Python-2.0 |
| distlib | 0.4.0 | PSF-2.0 |
| djlint | 1.36.4 | GPL-3.0-or-later |
| dnspython | 2.8.0 | ISC |
| dulwich | 1.2.1 | Apache-2.0 |
| dunamai | 1.26.1 | MIT |
| easydict | 1.13 | LGPL-3.0 |
| editorconfig | 0.17.1 | PSF-2.0 |
| email-validator | 2.3.0 | Unlicense |
| exarch | 0.3.0 | MIT |
| ezt | 1.1 | BSD-3-Clause |
| filelock | 3.29.0 | MIT |
| flask | 3.1.3 | BSD-3-Clause |
| forbiddenfruit | 0.1.4 | GPL-2.0 |
| fqdn | 1.5.1 | MPL-2.0 |
| frozenlist | 1.8.0 | Apache-2.0 |
| gitignore-parser | 0.1.13 | MIT |
| greenlet | 3.5.0 | MIT |
| h11 | 0.16.0 | MIT |
| h2 | 4.3.0 | (other) |
| hpack | 4.1.0 | (other) |
| htpy | 25.12.0 | MIT |
| hypercorn | 0.18.0 | MIT |
| hyperframe | 6.1.0 | (other) |
| hyperscan | 0.8.2 | MIT |
| identify | 2.6.19 | MIT |
| idna | 3.13 | BSD-3-Clause |
| iniconfig | 2.3.0 | MIT |
| isoduration | 20.11.0 | ISC |
| itsdangerous | 2.2.0 | BSD-3-Clause |
| jinja2 | 3.1.6 | BSD-3-Clause |
| jsbeautifier | 1.15.4 | MIT |
| json5 | 0.14.0 | (other) |
| jsonpointer | 3.1.1 | Zed |
| jsonschema | 4.26.0 | MIT |
| jsonschema-specifications | 2025.9.1 | MIT |
| lark | 1.3.1 | MIT |
| ldap3 | 2.10.2rc3 | LGPL-3.0 |
| license-expression | 30.4.4 | Apache-2.0 |
| mako | 1.3.12 | MIT |
| markdown-it-py | 4.1.0 | MIT |
| markupsafe | 3.0.3 | BSD-3-Clause |
| mdurl | 0.1.2 | MIT |
| multidict | 6.7.1 | Apache-2.0 |
| netifaces | 0.11.0 | MIT |
| nodeenv | 1.10.0 | BSD-3-Clause |
| packageurl-python | 0.17.6 | MIT |
| packaging | 26.2 | Apache-2.0 |
| pathspec | 1.1.1 | MPL-2.0 |
| platformdirs | 4.9.6 | MIT |
| playwright | 1.59.0 | Apache-2.0 |
| pluggy | 1.6.0 | MIT |
| pre-commit | 4.6.0 | MIT |
| priority | 2.0.0 | MIT |
| propcache | 0.4.1 | Apache-2.0 |
| psutil | 7.2.2 | BSD-3-Clause |
| puremagic | 2.2.0 | MIT |
| py-serializable | 2.1.0 | Apache-2.0 |
| pyasn1 | 0.6.3 | BSD-2-Clause |
| pycparser | 3.0 | BSD-3-Clause |
| pycryptodomex | 3.23.0 | BSD-3-Clause |
| pydantic | 2.13.4 | MIT |
| pydantic-core | 2.46.4 | (unspecified) |
| pydantic-xml | 2.20.0 | Unlicense |
| pyee | 13.0.1 | MIT |
| pygments | 2.20.0 | BSD-2-Clause |
| pyhumps | 3.8.0 | Unlicense |
| pyjwt | 2.12.1 | MIT |
| pyright | 1.1.409 | MIT |
| pytest | 9.0.3 | MIT |
| pytest-asyncio | 1.3.0 | Apache-2.0 |
| pytest-base-url | 2.1.0 | MPL-2.0 |
| pytest-playwright | 0.7.2 | (other) |
| python-dateutil | 2.9.0.post0 | DOC |
| python-decouple | 3.8 | MIT |
| python-discovery | 1.3.0 | (other) |
| python-slugify | 8.0.4 | MIT |
| pyyaml | 6.0.3 | MIT |
| quart | 0.20.0 | MIT |
| quart-rate-limiter | 0.12.1 | MIT |
| quart-schema | 0.23.0 | MIT |
| quart-uploads | 0.0.4 | MIT |
| quart-wtforms | 1.0.3 | MIT |
| referencing | 0.37.0 | MIT |
| regex | 2026.4.4 | Apache-2.0 |
| requests | 2.33.1 | Apache-2.0 |
| rfc3339-validator | 0.1.4 | MIT |
| rfc3986-validator | 0.1.1 | MIT |
| rfc3987-syntax | 1.1.0 | MIT |
| rich | 15.0.0 | MIT |
| rpds-py | 0.30.0 | MIT |
| rpgp-py | 0.19.7 | (unspecified) |
| ruff | 0.15.12 | MIT |
| semver | 3.0.4 | (other) |
| six | 1.17.0 | MIT |
| sortedcontainers | 2.4.0 | Apache-2.0 |
| sqlalchemy | 2.0.49 | MIT |
| sqlmodel | 0.0.38 | MIT |
| ssh-audit | 3.3.0 | MIT |
| standard-imghdr | 3.13.0 | PSF-2.0 |
| strictyaml | 1.7.3 | MIT |
| structlog | 25.5.0 | MIT |
| text-unidecode | 1.3 | Artistic-2.0 |
| **tooling-trusted-releases** | **0.0.1** | (this repo) |
| tqdm | 4.67.3 | MPL-2.0 |
| types-aiofiles | 25.1.0.20260409 | Apache-2.0 |
| typing-extensions | 4.15.0 | PSF-2.0 |
| typing-inspection | 0.4.2 | MIT |
| tzdata | 2026.2 | Apache-2.0 |
| uri-template | 1.3.0 | MIT |
| urllib3 | 2.6.3 | MIT |
| uvloop | 0.22.1 | MIT |
| virtualenv | 21.3.1 | MIT |
| watchfiles | 1.1.1 | MIT |
| webcolors | 25.10.0 | BSD-3-Clause |
| werkzeug | 3.1.8 | BSD-3-Clause |
| wsproto | 1.3.2 | MIT |
| wtforms | 3.2.2 | (other) |
| yarl | 1.23.0 | Apache-2.0 |
| yyjson | 4.0.6 | (other) |

## npm components (lockfile-pinned)

The Bootstrap/Mermaid frontend bundle pulls in 142 transitive npm packages. Highlights include the d3 family (`d3`, `d3-array`, `d3-axis`, ... `d3-zoom`), the cytoscape graph stack, mermaid+chevrotain, dompurify (sanitizer), marked (markdown), katex (math), and the @types/* TypeScript declarations. Licenses are dominated by MIT and ISC.

## GitHub Actions (SHA-pinned)

See [dependencies.md → GitHub Actions](./dependencies.md#github-actions--pinned-to-commit-shas). Every action reference is pinned to a 40-character commit SHA, which is the recommended supply-chain hygiene practice and the reason zizmor returned zero findings.

## Docker base images

| Image | Version |
|---|---|
| `python` | 3.13.7-alpine3.22 |
| `alpine` | edge |
| `mcr.microsoft.com/playwright/python` | v1.58.0-noble |

## Notes on license diversity

License headers vary widely (MIT/BSD/Apache-2.0 dominate, with EPL-2.0 from asyncssh, MPL-2.0 from certifi/dompurify/tqdm, LGPL-3.0/LGPL-3.0+ from cvss/ldap3/easydict, GPL-2.0 from forbiddenfruit, GPL-3.0-or-later from djlint, Unlicense from email-validator/pydantic-xml/pyhumps). The `forbiddenfruit` (GPL-2.0) and `djlint` (GPL-3.0+) licenses are worth flagging if downstream code redistribution becomes relevant — though as a deployed service distributed under Apache-2.0 by the ASF, this is unlikely to be a current concern.

## Cross-references

- Direct, declared dependencies (human-readable) → [dependencies.md](./dependencies.md)
- Vulnerability advisories on these components → [advisories.md](./advisories.md)
- Workflow security audit → [zizmor.md](./zizmor.md)
