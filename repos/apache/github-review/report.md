# CI Registry Publishing Analysis: apache

## Contents

- [Executive Summary](#executive-summary)
- [Package Ecosystem Distribution](#package-ecosystem-distribution-releases-snapshots-only)
- [Release Artifact Workflows](#release-artifact-workflows) (5)
- [Snapshot / Nightly Workflows](#snapshot-nightly-artifact-workflows) (1)
- [CI Infrastructure Workflows](#ci-infrastructure-image-workflows) (24)
- [Documentation Workflows](#documentation-website-workflows) (6)
- [Security: Low Risk](#security-low-risk-findings) (11)
- [Detailed Results](#detailed-results-release-snapshot-workflows)
  - [apache/airflow](#apacheairflow)
  - [apache/kafka](#apachekafka)
  - [apache/spark](#apachespark)

---

Scanned **3** repositories, **3** had GitHub Actions workflow files, **110** total workflows analyzed.

## Executive Summary

| Metric | Value |
|--------|-------|
| Repositories scanned | 3 |
| Repositories with workflows | 3 |
| Total workflow files | 110 |
| **Repos with any publishing** | **3** |
| Release artifact workflows | 5 |
| Snapshot / nightly workflows | 1 |
| CI infrastructure image workflows | 24 |
| Documentation / website workflows | 6 |
| Security notes flagged | 14 |

## Package Ecosystem Distribution (releases + snapshots only)

| Ecosystem | Workflows | Percentage |
|-----------|-----------|------------|
| docker_hub | 4 | 44.4% |
| maven_central | 2 | 22.2% |
| ghcr | 1 | 11.1% |
| apache_dist | 1 | 11.1% |
| pypi | 1 | 11.1% |

## Release Artifact Workflows

These workflows publish versioned packages to public registries consumed by end users.

| Repository | Workflow | Ecosystems | Trigger | Auth |
|------------|----------|------------|---------|------|
| airflow | `release_dockerhub_image.yml` | docker_hub | workflow_dispatch with airflowVersion input (e.g. 3.0.1, 3.0.1rc1, 3.0.1b1) | DOCKERHUB_USER and DOCKERHUB_TOKEN secrets |
| airflow | `release_single_dockerhub_image.yml` | docker_hub, ghcr | workflow_call | DOCKERHUB_USER/DOCKERHUB_TOKEN secrets for Docker Hub, GITHUB_TOKEN for GHCR |
| kafka | `docker_promote.yml` | docker_hub | workflow_dispatch | secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| kafka | `docker_rc_release.yml` | docker_hub | workflow_dispatch | secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| spark | `release.yml` | apache_dist, maven_central, pypi | workflow_dispatch with inputs for branch, release-version, rc-count, and finalize; also scheduled cron | ASF credentials (ASF_USERNAME, ASF_PASSWORD, ASF_NEXUS_TOKEN), GPG key signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE), PyPI API token (PYPI_API_TOKEN) |

## Snapshot / Nightly Artifact Workflows

These workflows publish snapshot or nightly builds to staging registries.

| Repository | Workflow | Ecosystems | Trigger | Auth |
|------------|----------|------------|---------|------|
| spark | `publish_snapshot.yml` | maven_central | schedule (daily cron) and workflow_dispatch | ASF Nexus credentials (NEXUS_USER, NEXUS_PW, NEXUS_TOKEN) stored in GitHub secrets |

## CI Infrastructure Image Workflows

These workflows push Docker images used only for CI build caching, test execution, or build acceleration. They do not publish end-user artifacts.

<details>
<summary>Show 24 CI infrastructure workflows</summary>

| Repository | Workflow | Target | Summary |
|------------|----------|--------|---------|
| airflow | `additional-ci-image-checks.yml` | ghcr | This workflow pushes early BuildX cache images to GitHub Container Registry (GHC |
| airflow | `ci-image-build.yml` | ghcr | This workflow builds CI Docker images for Apache Airflow and conditionally pushe |
| airflow | `finalize-tests.yml` | ghcr | This workflow finalizes test runs by updating constraints and pushing Docker bui |
| airflow | `prod-image-build.yml` | ghcr | This workflow builds Apache Airflow production Docker images for CI/CD purposes. |
| airflow | `push-image-cache.yml` | ghcr | This workflow pushes CI and PROD Docker image caches to GitHub Container Registr |
| spark | `build_and_test.yml` | ghcr | This workflow builds and pushes Docker images to GitHub Container Registry (GHCR |
| spark | `build_branch35.yml` | ghcr | This workflow calls a reusable workflow (build_and_test.yml) with packages:write |
| spark | `build_branch40.yml` | ghcr | This workflow is a scheduled build job that calls a reusable workflow (build_and |
| spark | `build_branch40_java21.yml` | ghcr | This workflow is a scheduled CI build that runs every 2 days for Apache Spark's |
| spark | `build_branch40_python_pypy3.10.yml` | ghcr | This workflow calls a reusable workflow (build_and_test.yml) with packages:write |
| spark | `build_branch41.yml` | ghcr | Scheduled nightly build workflow for Apache Spark branch-4.1 that calls a reusab |
| spark | `build_branch41_java21.yml` | ghcr | This workflow is a scheduled nightly build that calls a reusable workflow (build |
| spark | `build_branch41_python_pypy3.10.yml` | ghcr | Scheduled workflow that calls a reusable workflow (build_and_test.yml) with pack |
| spark | `build_infra_images_cache.yml` | ghcr | Builds and pushes Docker images to GHCR for CI/CD infrastructure. Multiple test |
| spark | `build_java21.yml` | ghcr | This workflow is a scheduled nightly build that calls a reusable workflow (build |
| spark | `build_java25.yml` | ghcr | This workflow is a scheduled nightly build job that tests Apache Spark with Java |
| spark | `build_main.yml` | ghcr | This workflow calls a reusable workflow (build_and_test.yml) with packages:write |
| spark | `build_python_3.10.yml` | ghcr | This workflow calls a reusable workflow (build_and_test.yml) with packages:write |
| spark | `build_python_3.11.yml` | ghcr | This workflow calls a reusable workflow (build_and_test.yml) with packages:write |
| spark | `build_python_3.12_classic_only.yml` | ghcr | This workflow calls a reusable workflow (build_and_test.yml) with packages:write |
| spark | `build_python_3.12_pandas_3.yml` | ghcr | This workflow is a scheduled nightly build that calls a reusable workflow (build |
| spark | `build_python_3.13.yml` | ghcr | This workflow calls a reusable workflow (build_and_test.yml) with packages:write |
| spark | `build_python_3.14.yml` | ghcr | This workflow calls a reusable workflow (build_and_test.yml) with packages:write |
| spark | `build_python_3.14_nogil.yml` | ghcr | This workflow calls a reusable workflow (build_and_test.yml) with packages:write |

</details>

## Documentation / Website Workflows

<details>
<summary>Show 6 documentation workflows</summary>

| Repository | Workflow | Target | Summary |
|------------|----------|--------|---------|
| airflow | `ci-image-checks.yml` | s3 | This workflow builds Apache Airflow documentation and publishes it to AWS S3 (s3 |
| airflow | `publish-docs-to-s3.yml` | s3 | This workflow builds Apache Airflow documentation and publishes it to AWS S3 buc |
| airflow | `registry-backfill.yml` | s3 | This workflow backfills Apache Airflow provider registry documentation to S3 buc |
| airflow | `registry-build.yml` | s3 | Builds and publishes Apache Airflow provider registry documentation to S3. Extra |
| spark | `build_coverage.yml` | codecov | This workflow runs Python coverage tests on a schedule and uploads results to Co |
| spark | `pages.yml` | github_pages | Builds Apache Spark documentation using Jekyll, Sphinx, and other tools, then de |

</details>

## Security: Low Risk Findings

GitHub-controlled values used directly in `run:` blocks. Not user-injectable but poor practice.

<details>
<summary>Show 11 low-risk findings</summary>

- **apache/airflow** (`prod-image-build.yml`): [LOW] Direct interpolation of github.sha in run block at step 'Build PROD images w/ source providers'. While github.sha is GitHub-controlled and not user-injectable, best practice is to pass through env block.
- **apache/airflow** (`publish-docs-to-s3.yml`): [LOW] GitHub-controlled value github.actor used directly in env blocks
- **apache/airflow** (`publish-docs-to-s3.yml`): [LOW] GitHub-controlled value github.repository used directly in env blocks
- **apache/airflow** (`registry-build.yml`): [LOW] GitHub-controlled value github.event.sender.login used in conditional expression
- **apache/airflow** (`release_dockerhub_image.yml`): [LOW] GitHub-controlled value github.event.inputs.airflowVersion used in concurrency.group
- **apache/airflow** (`release_dockerhub_image.yml`): [LOW] Input parameter airflowVersion passed through environment variables and shell scripts in build-info job
- **apache/airflow** (`release_single_dockerhub_image.yml`): [LOW] GitHub-controlled value github.sha used directly in env block COMMIT_SHA
- **apache/airflow** (`release_single_dockerhub_image.yml`): [LOW] GitHub-controlled value github.repository used directly in env block REPOSITORY
- **apache/airflow** (`release_single_dockerhub_image.yml`): [LOW] GitHub-controlled value github.actor used in docker login command via ACTOR env variable
- **apache/spark** (`publish_snapshot.yml`): [LOW] GitHub-controlled value matrix.branch used in checkout ref and GIT_REF environment variable
- **apache/spark** (`release.yml`): [LOW] GitHub-controlled value github.actor used directly in GIT_NAME environment variable

</details>

## Detailed Results: Release & Snapshot Workflows

### apache/airflow

**2** release/snapshot workflows | Ecosystems: **docker_hub, ghcr** | Release Artifacts: 2

**`release_dockerhub_image.yml`** — Release PROD images [Release Artifacts]
- **Summary**: This workflow publishes production Apache Airflow Docker images to Docker Hub. It is manually triggered with an Airflow version parameter (supporting release, RC, and beta versions). The workflow builds images for multiple Python versions and platforms (amd64 and optionally arm64), then delegates to a reusable workflow (release_single_dockerhub_image.yml) that performs the actual Docker Hub publishing. Access is restricted to a whitelist of Apache Airflow committers.
- **Ecosystems**: docker_hub
- **Trigger**: workflow_dispatch with airflowVersion input (e.g. 3.0.1, 3.0.1rc1, 3.0.1b1)
- **Auth**: DOCKERHUB_USER and DOCKERHUB_TOKEN secrets
- **Confidence**: high

**`release_single_dockerhub_image.yml`** — Release single PROD image [Release Artifacts]
- **Summary**: Builds and publishes versioned Apache Airflow production Docker images to Docker Hub for multiple platforms (linux/amd64, linux/arm64) and Python versions. The workflow builds both regular and slim images, verifies them, then merges multi-platform manifests. Images are tagged with specific Airflow versions (e.g., 3.0.1, 3.0.1rc1) and optionally as 'latest'. Also logs into GHCR for intermediate operations.
- **Ecosystems**: docker_hub, ghcr
- **Trigger**: workflow_call
- **Auth**: DOCKERHUB_USER/DOCKERHUB_TOKEN secrets for Docker Hub, GITHUB_TOKEN for GHCR
- **Confidence**: high
- **Commands**: `breeze release-management release-prod-images`, `breeze release-management merge-prod-images`

### apache/kafka

**2** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 2

**`docker_promote.yml`** — Promote Release Candidate Docker Image [Release Artifacts]
- **Summary**: This workflow promotes Apache Kafka release candidate Docker images to final release versions on Docker Hub. It uses workflow_dispatch to manually trigger promotion, taking RC image names (e.g., apache/kafka:3.8.0-rc0) and promoted image names (e.g., apache/kafka:3.8.0) as inputs. The workflow authenticates to Docker Hub and uses docker buildx imagetools to copy/tag the RC image as the promoted release image. User inputs are safely passed through env variables before being used in shell commands.
- **Ecosystems**: docker_hub
- **Trigger**: workflow_dispatch
- **Auth**: secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@5e57cd118135c172c3672efd75eb46360885c0ef`
- **Commands**: `docker buildx imagetools create --tag $PROMOTED_DOCKER_IMAGE $RC_DOCKER_IMAGE`

**`docker_rc_release.yml`** — Build and Push Release Candidate Docker Image [Release Artifacts]
- **Summary**: This workflow builds and publishes Apache Kafka release candidate Docker images to Docker Hub. It supports both JVM and native image types, is manually triggered via workflow_dispatch, and uses a Python script (docker_release.py) to build and push multi-architecture images (via QEMU and Docker Buildx) to apache/kafka or apache/kafka-native repositories on Docker Hub.
- **Ecosystems**: docker_hub
- **Trigger**: workflow_dispatch
- **Auth**: secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@5e57cd118135c172c3672efd75eb46360885c0ef`
- **Commands**: `python docker/docker_release.py $RC_DOCKER_IMAGE --kafka-url $KAFKA_URL --image-type $IMAGE_TYPE`

### apache/spark

**2** release/snapshot workflows | Ecosystems: **apache_dist, maven_central, pypi** | Release Artifacts: 1, Snapshot / Nightly Artifacts: 1

**`release.yml`** — Release Apache Spark [Release Artifacts]
- **Summary**: This workflow orchestrates the Apache Spark release process, publishing release artifacts to Apache Distribution SVN (apache_dist), Maven Central (via ASF Nexus), and PyPI. It supports both RC creation and finalization modes. The workflow calls dev/create-release/do-release-docker.sh which handles the actual publishing. It includes dry-run capability and is designed to run in forked repositories with manual dispatch. The finalize mode converts RC artifacts to official releases (irreversible). Artifacts are signed with GPG and authenticated using ASF credentials and PyPI tokens.
- **Ecosystems**: apache_dist, maven_central, pypi
- **Trigger**: workflow_dispatch with inputs for branch, release-version, rc-count, and finalize; also scheduled cron
- **Auth**: ASF credentials (ASF_USERNAME, ASF_PASSWORD, ASF_NEXUS_TOKEN), GPG key signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE), PyPI API token (PYPI_API_TOKEN)
- **Confidence**: high
- **Commands**: `dev/create-release/do-release-docker.sh`

**`publish_snapshot.yml`** — Publish snapshot [Snapshot / Nightly Artifacts]
- **Summary**: Publishes Apache Spark snapshot builds to ASF Nexus repository on a daily schedule for multiple branches (master, branch-4.1, branch-4.0, branch-3.5). Uses Maven to build and deploy snapshot artifacts with ASF Nexus authentication.
- **Ecosystems**: maven_central
- **Trigger**: schedule (daily cron) and workflow_dispatch
- **Auth**: ASF Nexus credentials (NEXUS_USER, NEXUS_PW, NEXUS_TOKEN) stored in GitHub secrets
- **Confidence**: high
- **Commands**: `./dev/create-release/release-build.sh publish-snapshot`

---

*Cached in `ci-classification:apache`. Set `clear_cache` to `true` to force a fresh scan. Raw YAML stored in `ci-workflows:apache`.*