# CI Registry Publishing Analysis: apache

## Contents

- [Executive Summary](#executive-summary)
- [Package Ecosystem Distribution](#package-ecosystem-distribution-releases-snapshots-only)
- [Already Using Trusted Publishing](#already-using-trusted-publishing) (8)
- [Trusted Publishing Opportunities](#trusted-publishing-migration-opportunities) (79)
- [Release Artifact Workflows](#release-artifact-workflows) (190)
- [Snapshot / Nightly Workflows](#snapshot-nightly-artifact-workflows) (70)
- [CI Infrastructure Workflows](#ci-infrastructure-image-workflows) (37)
- [Documentation Workflows](#documentation-website-workflows) (154)
- [Security: Downgraded](#security-auto-downgraded-findings) (1)
- [Security: Low Risk](#security-low-risk) (373)
- [Detailed Results](#detailed-results-release-snapshot-workflows)
  - [apache/activemq](#apacheactivemq)
  - [apache/airavata](#apacheairavata)
  - [apache/airavata-mft](#apacheairavata-mft)
  - [apache/airflow](#apacheairflow)
  - [apache/airflow-publish](#apacheairflow-publish)
  - [apache/amoro](#apacheamoro)
  - [apache/answer](#apacheanswer)
  - [apache/apisix](#apacheapisix)
  - [apache/apisix-docker](#apacheapisix-docker)
  - [apache/apisix-helm-chart](#apacheapisix-helm-chart)
  - [apache/apisix-ingress-controller](#apacheapisix-ingress-controller)
  - [apache/arrow](#apachearrow)
  - [apache/arrow-adbc](#apachearrow-adbc)
  - [apache/arrow-dotnet](#apachearrow-dotnet)
  - [apache/arrow-flight-sql-postgresql](#apachearrow-flight-sql-postgresql)
  - [apache/arrow-go](#apachearrow-go)
  - [apache/arrow-java](#apachearrow-java)
  - [apache/arrow-js](#apachearrow-js)
  - [apache/arrow-nanoarrow](#apachearrow-nanoarrow)
  - [apache/arrow-swift](#apachearrow-swift)
  - [apache/avro](#apacheavro)
  - [apache/axis-axis2-java-core](#apacheaxis-axis2-java-core)
  - [apache/beam](#apachebeam)
  - [apache/bifromq](#apachebifromq)
  - [apache/buildstream](#apachebuildstream)
  - [apache/camel-k](#apachecamel-k)
  - [apache/camel-k-runtime](#apachecamel-k-runtime)
  - [apache/camel-kafka-connector](#apachecamel-kafka-connector)
  - [apache/camel-kameleon](#apachecamel-kameleon)
  - [apache/camel-kamelets](#apachecamel-kamelets)
  - [apache/camel-karavan](#apachecamel-karavan)
  - [apache/carbondata](#apachecarbondata)
  - [apache/casbin-Casbin.NET](#apachecasbin-casbinnet)
  - [apache/casbin-Casbin.NET-dotnet-cli](#apachecasbin-casbinnet-dotnet-cli)
  - [apache/casbin-Casbin.NET-ef-adapter](#apachecasbin-casbinnet-ef-adapter)
  - [apache/casbin-Casbin.NET-redis-adapter](#apachecasbin-casbinnet-redis-adapter)
  - [apache/casbin-Casbin.NET-redis-watcher](#apachecasbin-casbinnet-redis-watcher)
  - [apache/casbin-actix-casbin-auth](#apachecasbin-actix-casbin-auth)
  - [apache/casbin-admission-webhook](#apachecasbin-admission-webhook)
  - [apache/casbin-aspnetcore](#apachecasbin-aspnetcore)
  - [apache/casbin-axum-casbin](#apachecasbin-axum-casbin)
  - [apache/casbin-casbin.js](#apachecasbin-casbinjs)
  - [apache/casbin-core](#apachecasbin-core)
  - [apache/casbin-dart-casbin](#apachecasbin-dart-casbin)
  - [apache/casbin-docker_auth](#apachecasbin-docker_auth)
  - [apache/casbin-editor](#apachecasbin-editor)
  - [apache/casbin-efcore-adapter](#apachecasbin-efcore-adapter)
  - [apache/casbin-ex](#apachecasbin-ex)
  - [apache/casbin-gateway](#apachecasbin-gateway)
  - [apache/casbin-go-cli](#apachecasbin-go-cli)
  - [apache/casbin-jcasbin](#apachecasbin-jcasbin)
  - [apache/casbin-jcasbin-dynamodb-adapter](#apachecasbin-jcasbin-dynamodb-adapter)
  - [apache/casbin-jcasbin-hibernate-adapter](#apachecasbin-jcasbin-hibernate-adapter)
  - [apache/casbin-jcasbin-jdbc-adapter](#apachecasbin-jcasbin-jdbc-adapter)
  - [apache/casbin-jcasbin-jfinal-authz](#apachecasbin-jcasbin-jfinal-authz)
  - [apache/casbin-jcasbin-kafka-casbin](#apachecasbin-jcasbin-kafka-casbin)
  - [apache/casbin-jcasbin-kafka-watcher](#apachecasbin-jcasbin-kafka-watcher)
  - [apache/casbin-jcasbin-lettuce-redis-watcher](#apachecasbin-jcasbin-lettuce-redis-watcher)
  - [apache/casbin-jcasbin-mongo-adapter](#apachecasbin-jcasbin-mongo-adapter)
  - [apache/casbin-jcasbin-mybatis-adapter](#apachecasbin-jcasbin-mybatis-adapter)
  - [apache/casbin-jcasbin-mybatisplus-adapter](#apachecasbin-jcasbin-mybatisplus-adapter)
  - [apache/casbin-jcasbin-nutz-authz](#apachecasbin-jcasbin-nutz-authz)
  - [apache/casbin-jcasbin-play-authz](#apachecasbin-jcasbin-play-authz)
  - [apache/casbin-jcasbin-postgres-watcher](#apachecasbin-jcasbin-postgres-watcher)
  - [apache/casbin-jcasbin-pulsar-authz](#apachecasbin-jcasbin-pulsar-authz)
  - [apache/casbin-jcasbin-rabbitmq-watcher](#apachecasbin-jcasbin-rabbitmq-watcher)
  - [apache/casbin-jcasbin-redis-adapter](#apachecasbin-jcasbin-redis-adapter)
  - [apache/casbin-jcasbin-redis-watcher](#apachecasbin-jcasbin-redis-watcher)
  - [apache/casbin-jcasbin-redis-watcher-ex](#apachecasbin-jcasbin-redis-watcher-ex)
  - [apache/casbin-jcasbin-shiro-casbin](#apachecasbin-jcasbin-shiro-casbin)
  - [apache/casbin-jcasbin-spring-security-starter](#apachecasbin-jcasbin-spring-security-starter)
  - [apache/casbin-jcasbin-string-adapter](#apachecasbin-jcasbin-string-adapter)
  - [apache/casbin-jcasbin-vertx-authz](#apachecasbin-jcasbin-vertx-authz)
  - [apache/casbin-jcasbin-zookeeper-watcher](#apachecasbin-jcasbin-zookeeper-watcher)
  - [apache/casbin-js-vue-authz](#apachecasbin-js-vue-authz)
  - [apache/casbin-lego](#apachecasbin-lego)
  - [apache/casbin-lua-casbin](#apachecasbin-lua-casbin)
  - [apache/casbin-mcp-gateway](#apachecasbin-mcp-gateway)
  - [apache/casbin-mesh](#apachecasbin-mesh)
  - [apache/casbin-nest-authz](#apachecasbin-nest-authz)
  - [apache/casbin-node-casbin](#apachecasbin-node-casbin)
  - [apache/casbin-node-casbin-basic-adapter](#apachecasbin-node-casbin-basic-adapter)
  - [apache/casbin-node-casbin-couchdb-adapter](#apachecasbin-node-casbin-couchdb-adapter)
  - [apache/casbin-node-casbin-drizzle-adapter](#apachecasbin-node-casbin-drizzle-adapter)
  - [apache/casbin-node-casbin-etcd-watcher](#apachecasbin-node-casbin-etcd-watcher)
  - [apache/casbin-node-casbin-expression-eval](#apachecasbin-node-casbin-expression-eval)
  - [apache/casbin-node-casbin-file-adapter](#apachecasbin-node-casbin-file-adapter)
  - [apache/casbin-node-casbin-mongo-changestream-watcher](#apachecasbin-node-casbin-mongo-changestream-watcher)
  - [apache/casbin-node-casbin-mongoose-adapter](#apachecasbin-node-casbin-mongoose-adapter)
  - [apache/casbin-node-casbin-node-redis-adapter](#apachecasbin-node-casbin-node-redis-adapter)
  - [apache/casbin-node-casbin-prisma-adapter](#apachecasbin-node-casbin-prisma-adapter)
  - [apache/casbin-node-casbin-redis-watcher](#apachecasbin-node-casbin-redis-watcher)
  - [apache/casbin-node-casbin-session-role-manager](#apachecasbin-node-casbin-session-role-manager)
  - [apache/casbin-pycasbin](#apachecasbin-pycasbin)
  - [apache/casbin-python-async-django-orm-adapter](#apachecasbin-python-async-django-orm-adapter)
  - [apache/casbin-python-async-postgres-watcher](#apachecasbin-python-async-postgres-watcher)
  - [apache/casbin-python-async-sqlalchemy-adapter](#apachecasbin-python-async-sqlalchemy-adapter)
  - [apache/casbin-python-casbin-databases-adapter](#apachecasbin-python-casbin-databases-adapter)
  - [apache/casbin-python-django-casbin-auth](#apachecasbin-python-django-casbin-auth)
  - [apache/casbin-python-django-orm-adapter](#apachecasbin-python-django-orm-adapter)
  - [apache/casbin-python-etcd-watcher](#apachecasbin-python-etcd-watcher)
  - [apache/casbin-python-fastapi-casbin-auth](#apachecasbin-python-fastapi-casbin-auth)
  - [apache/casbin-python-flask-authz](#apachecasbin-python-flask-authz)
  - [apache/casbin-python-graphql-authz](#apachecasbin-python-graphql-authz)
  - [apache/casbin-python-postgresql-watcher](#apachecasbin-python-postgresql-watcher)
  - [apache/casbin-python-pymongo-adapter](#apachecasbin-python-pymongo-adapter)
  - [apache/casbin-python-rabbitmq-watcher](#apachecasbin-python-rabbitmq-watcher)
  - [apache/casbin-python-redis-adapter](#apachecasbin-python-redis-adapter)
  - [apache/casbin-python-redis-watcher](#apachecasbin-python-redis-watcher)
  - [apache/casbin-python-sanic-authz](#apachecasbin-python-sanic-authz)
  - [apache/casbin-python-sqlalchemy-adapter](#apachecasbin-python-sqlalchemy-adapter)
  - [apache/casbin-python-sqlobject-adapter](#apachecasbin-python-sqlobject-adapter)
  - [apache/casbin-rs](#apachecasbin-rs)
  - [apache/casbin-rust-actix-casbin](#apachecasbin-rust-actix-casbin)
  - [apache/casbin-rust-casbin-rust-cli](#apachecasbin-rust-casbin-rust-cli)
  - [apache/casbin-rust-diesel-adapter](#apachecasbin-rust-diesel-adapter)
  - [apache/casbin-rust-dufs-with-casbin](#apachecasbin-rust-dufs-with-casbin)
  - [apache/casbin-rust-postgres-adapter](#apachecasbin-rust-postgres-adapter)
  - [apache/casbin-rust-redis-watcher](#apachecasbin-rust-redis-watcher)
  - [apache/casbin-rust-rocket-authz](#apachecasbin-rust-rocket-authz)
  - [apache/casbin-rust-semantic-release-action-rust](#apachecasbin-rust-semantic-release-action-rust)
  - [apache/casbin-rust-string-adapter](#apachecasbin-rust-string-adapter)
  - [apache/casbin-rust-yaml-adapter](#apachecasbin-rust-yaml-adapter)
  - [apache/casbin-sequelize-adapter](#apachecasbin-sequelize-adapter)
  - [apache/casbin-server](#apachecasbin-server)
  - [apache/casbin-spring-boot-starter](#apachecasbin-spring-boot-starter)
  - [apache/casbin-sqlx-adapter](#apachecasbin-sqlx-adapter)
  - [apache/casbin-typeorm-adapter](#apachecasbin-typeorm-adapter)
  - [apache/casbin-vscode-plugin](#apachecasbin-vscode-plugin)
  - [apache/casbin-website-v3](#apachecasbin-website-v3)
  - [apache/cassandra-easy-stress](#apachecassandra-easy-stress)
  - [apache/cassandra-sidecar](#apachecassandra-sidecar)
  - [apache/causeway](#apachecauseway)
  - [apache/cayenne](#apachecayenne)
  - [apache/celeborn](#apacheceleborn)
  - [apache/cloudstack](#apachecloudstack)
  - [apache/cloudstack-kubernetes-provider](#apachecloudstack-kubernetes-provider)
  - [apache/commons-crypto](#apachecommons-crypto)
  - [apache/commons-io](#apachecommons-io)
  - [apache/commons-net](#apachecommons-net)
  - [apache/commons-numbers](#apachecommons-numbers)
  - [apache/cordova-android](#apachecordova-android)
  - [apache/cordova-coho](#apachecordova-coho)
  - [apache/cordova-eslint](#apachecordova-eslint)
  - [apache/cordova-ios](#apachecordova-ios)
  - [apache/cordova-plugin-camera](#apachecordova-plugin-camera)
  - [apache/couchdb-helm](#apachecouchdb-helm)
  - [apache/couchdb-mochiweb](#apachecouchdb-mochiweb)
  - [apache/daffodil](#apachedaffodil)
  - [apache/daffodil-sbt](#apachedaffodil-sbt)
  - [apache/daffodil-vscode](#apachedaffodil-vscode)
  - [apache/datafusion-ballista](#apachedatafusion-ballista)
  - [apache/datafusion-comet](#apachedatafusion-comet)
  - [apache/datafusion-ray](#apachedatafusion-ray)
  - [apache/directory-scimple](#apachedirectory-scimple)
  - [apache/dolphinscheduler](#apachedolphinscheduler)
  - [apache/doris-opentelemetry-demo](#apachedoris-opentelemetry-demo)
  - [apache/doris-operator](#apachedoris-operator)
  - [apache/doris-thirdparty](#apachedoris-thirdparty)
  - [apache/drill](#apachedrill)
  - [apache/dubbo-admin](#apachedubbo-admin)
  - [apache/dubbo-go-pixiu](#apachedubbo-go-pixiu)
  - [apache/dubbo-go-pixiu-samples](#apachedubbo-go-pixiu-samples)
  - [apache/dubbo-initializer](#apachedubbo-initializer)
  - [apache/dubbo-kubernetes](#apachedubbo-kubernetes)
  - [apache/echarts](#apacheecharts)
  - [apache/echarts-examples](#apacheecharts-examples)
  - [apache/eventmesh](#apacheeventmesh)
  - [apache/eventmesh-dashboard](#apacheeventmesh-dashboard)
  - [apache/fineract](#apachefineract)
  - [apache/flink-docker](#apacheflink-docker)
  - [apache/flink-kubernetes-operator](#apacheflink-kubernetes-operator)
  - [apache/fluss-rust](#apachefluss-rust)
  - [apache/fory](#apachefory)
  - [apache/gluten](#apachegluten)
  - [apache/gobblin](#apachegobblin)
  - [apache/grails-core](#apachegrails-core)
  - [apache/grails-forge-ui](#apachegrails-forge-ui)
  - [apache/grails-github-actions](#apachegrails-github-actions)
  - [apache/grails-gradle-publish](#apachegrails-gradle-publish)
  - [apache/grails-quartz](#apachegrails-quartz)
  - [apache/grails-redis](#apachegrails-redis)
  - [apache/grails-spring-security](#apachegrails-spring-security)
  - [apache/gravitino](#apachegravitino)
  - [apache/hamilton](#apachehamilton)
  - [apache/hertzbeat](#apachehertzbeat)
  - [apache/hive](#apachehive)
  - [apache/hudi-rs](#apachehudi-rs)
  - [apache/incubator-baremaps](#apacheincubator-baremaps)
  - [apache/incubator-devlake-helm-chart](#apacheincubator-devlake-helm-chart)
  - [apache/kafka](#apachekafka)
  - [apache/karaf-minho](#apachekaraf-minho)
  - [apache/knox](#apacheknox)
  - [apache/kvrocks](#apachekvrocks)
  - [apache/kyuubi](#apachekyuubi)
  - [apache/kyuubi-docker](#apachekyuubi-docker)
  - [apache/kyuubi-shaded](#apachekyuubi-shaded)
- [Non-publishing Repos](#repositories-with-workflows-no-publishing-detected)

---

Scanned **634** repositories, **633** had GitHub Actions workflow files, **2387** total workflows analyzed.

## Executive Summary

| Metric | Value |
|--------|-------|
| Repositories scanned | 634 |
| Repositories with workflows | 633 |
| Total workflow files | 2387 |
| **Repos publishing to registries** | **197** |
| Release artifact workflows | 190 |
| Snapshot / nightly workflows | 70 |
| CI infrastructure image workflows | 37 |
| Documentation / website workflows | 154 |
| Security notes flagged | 917 |

## Package Ecosystem Distribution (releases + snapshots only)

| Ecosystem | Workflows | Percentage |
|-----------|-----------|------------|
| github_releases | 107 | 28.6% |
| maven_central | 64 | 17.1% |
| docker_hub | 47 | 12.6% |
| pypi | 34 | 9.1% |
| npm | 26 | 7.0% |
| apache_dist | 18 | 4.8% |
| crates_io | 18 | 4.8% |
| ghcr | 16 | 4.3% |
| nuget | 10 | 2.7% |
| github_pages | 9 | 2.4% |
| gcr | 8 | 2.1% |
| github_packages | 7 | 1.9% |
| helm | 5 | 1.3% |
| hex | 2 | 0.5% |
| dart_pub | 1 | 0.3% |
| luarocks | 1 | 0.3% |
| gcs | 1 | 0.3% |

## Already Using Trusted Publishing

These workflows publish to OIDC-capable ecosystems and are already using Trusted Publishing — no stored secrets needed for publishing.

### crates.io

| Repository | Workflow | Auth Method | Category |
|------------|----------|------------|----------|
| fory | `release-rust.yaml` | OIDC via rust-lang/crates-io-auth-action with id-token: write permission | Release Artifacts |

### PyPI

| Repository | Workflow | Auth Method | Category |
|------------|----------|------------|----------|
| airflow-publish | `airflow-publish.yml` | OIDC trusted publishing (id-token: write permission) | Release Artifacts |
| airflow-publish | `providers-publish.yml` | OIDC trusted publishing (id-token: write permission) | Release Artifacts |
| airflow-publish | `test-pypi-airflow-publish.yml` | OIDC trusted publishing (id-token: write permission) | Release Artifacts |
| airflow-publish | `test-pypi-providers-publish.yml` | OIDC trusted publishing (id-token: write) | Snapshot / Nightly Artifacts |
| fory | `release-compiler.yaml` | OIDC (id-token: write permission for Trusted Publishing) | Release Artifacts |
| fory | `release-python.yaml` | OIDC (id-token: write permission for Trusted Publishing) | Release Artifacts |
| hamilton | `contrib-auto-build-publish.yml` | OIDC trusted publishing (id-token: write) | Release Artifacts |

## Trusted Publishing Migration Opportunities

These workflows publish to ecosystems that support OIDC Trusted Publishing but currently use long-lived API tokens or passwords. Migrating to Trusted Publishing eliminates stored secrets and reduces supply-chain risk.

### crates.io

**Available mechanism:** OIDC Trusted Publishing
**Documentation:** https://doc.rust-lang.org/cargo/reference/registry-authentication.html

| Repository | Workflow | Current Auth | Category |
|------------|----------|-------------|----------|
| casbin-actix-casbin-auth | `release.yml` | secrets.CARGO_TOKEN for crates.io, secrets.GITHUB_TOKEN for GitHub Releases | Release Artifacts |
| casbin-axum-casbin | `release.yml` | secrets.CARGO_TOKEN for crates.io, secrets.GITHUB_TOKEN for GitHub Releases | Release Artifacts |
| casbin-rs | `release.yml` | CARGO_TOKEN secret passed to reusable workflow | Release Artifacts |
| casbin-rust-actix-casbin | `release.yml` | CARGO_TOKEN secret for crates.io, GITHUB_TOKEN for releases | Release Artifacts |
| casbin-rust-casbin-rust-cli | `release.yml` | CARGO_TOKEN secret passed to reusable workflow | Release Artifacts |
| casbin-rust-diesel-adapter | `release.yml` | CARGO_TOKEN secret for crates.io, GITHUB_TOKEN for GitHub releases | Release Artifacts |
| casbin-rust-dufs-with-casbin | `release.yaml` | GITHUB_TOKEN for GitHub Releases, DOCKERHUB_USERNAME/DOCKERHUB_TOKEN for Docker Hub, CRATES_IO_API_TOKEN for crates.io | Release Artifacts |
| casbin-rust-postgres-adapter | `release.yml` | secrets.CARGO_TOKEN for crates.io, secrets.GITHUB_TOKEN for GitHub releases | Release Artifacts |
| casbin-rust-redis-watcher | `release.yml` | CARGO_TOKEN secret passed to reusable workflow | Release Artifacts |
| casbin-rust-rocket-authz | `release.yml` | secrets.CARGO_TOKEN for crates.io, secrets.GITHUB_TOKEN for GitHub Releases | Release Artifacts |
| casbin-rust-semantic-release-action-rust | `release-binary.yml` | cargo-registry-token secret | Release Artifacts |
| casbin-rust-semantic-release-action-rust | `release-library.yml` | cargo-registry-token secret | Release Artifacts |
| casbin-rust-string-adapter | `release.yml` | CARGO_TOKEN secret for crates.io, GITHUB_TOKEN for releases | Release Artifacts |
| casbin-rust-yaml-adapter | `release.yml` | CARGO_TOKEN secret for crates.io, GITHUB_TOKEN for releases | Release Artifacts |
| casbin-sqlx-adapter | `release.yml` | CARGO_TOKEN secret for crates.io authentication | Release Artifacts |
| fluss-rust | `release_rust.yml` | CARGO_REGISTRY_TOKEN secret | Release Artifacts |
| hudi-rs | `release.yml` | CARGO_REGISTRY_TOKEN secret for crates.io, MATURIN_PYPI_TOKEN secret for PyPI | Release Artifacts |

### npm

**Available mechanism:** npm provenance with OIDC
**Documentation:** https://docs.npmjs.com/generating-provenance-statements

| Repository | Workflow | Current Auth | Category |
|------------|----------|-------------|----------|
| arrow-adbc | `packaging.yml` | GEMFURY_PUSH_TOKEN, GEMFURY_API_TOKEN, ANACONDA_API_TOKEN, NPM_TOKEN | Snapshot / Nightly Artifacts |
| casbin-casbin.js | `ci.yml` | NPM_TOKEN secret | Release Artifacts |
| casbin-core | `ci.yml` | NPM_TOKEN secret for npm authentication, GITHUB_TOKEN for GitHub operations | Release Artifacts |
| casbin-js-vue-authz | `ci.yml` | NPM_TOKEN secret for npm registry, GITHUB_TOKEN for GitHub releases | Release Artifacts |
| casbin-nest-authz | `ci.yml` | NPM_TOKEN secret for npm registry, GITHUB_TOKEN for GitHub releases | Release Artifacts |
| casbin-node-casbin | `main.yml` | NPM_TOKEN secret | Release Artifacts |
| casbin-node-casbin-basic-adapter | `ci.yml` | NPM_TOKEN and GITHUB_TOKEN secrets | Release Artifacts |
| casbin-node-casbin-couchdb-adapter | `ci.yml` | NPM_TOKEN secret | Release Artifacts |
| casbin-node-casbin-drizzle-adapter | `ci.yml` | NPM_TOKEN secret | Release Artifacts |
| casbin-node-casbin-etcd-watcher | `main.yml` | NPM_TOKEN secret for npm registry, GITHUB_TOKEN for GitHub releases | Release Artifacts |
| casbin-node-casbin-expression-eval | `ci.yml` | NPM_TOKEN and GITHUB_TOKEN secrets | Release Artifacts |
| casbin-node-casbin-file-adapter | `ci.yml` | NPM_TOKEN and GITHUB_TOKEN secrets passed via environment variables | Release Artifacts |
| casbin-node-casbin-mongo-changestream-watcher | `main.yml` | NPM_TOKEN secret for npm registry authentication, GITHUB_TOKEN for GitHub releases | Release Artifacts |
| casbin-node-casbin-mongoose-adapter | `main.yml` | NPM_TOKEN secret | Release Artifacts |
| casbin-node-casbin-node-redis-adapter | `release.yml` | NPM_TOKEN and GITHUB_TOKEN secrets passed as environment variables | Release Artifacts |
| casbin-node-casbin-prisma-adapter | `ci.yml` | GITHUB_TOKEN and NPM_TOKEN secrets | Release Artifacts |
| casbin-node-casbin-redis-watcher | `ci.yml` | NPM_TOKEN secret | Release Artifacts |
| casbin-node-casbin-session-role-manager | `release.yml` | GITHUB_TOKEN and NPM_TOKEN secrets | Release Artifacts |
| casbin-sequelize-adapter | `ci.yml` | NPM_TOKEN secret | Release Artifacts |
| casbin-typeorm-adapter | `ci.yml` | NPM_TOKEN secret | Release Artifacts |
| casbin-vscode-plugin | `default.yml` | secrets.GITHUB_TOKEN, secrets.NPM_TOKEN, secrets.VS_MARKETPLACE_TOKEN | Release Artifacts |
| casbin-website-v3 | `release.yml` | GITHUB_TOKEN and NPM_TOKEN secrets | Release Artifacts |
| cordova-coho | `nightly.yml` | NODE_AUTH_TOKEN from secrets.CORDOVA_NPM_TOKEN | Snapshot / Nightly Artifacts |
| echarts | `nightly-next.yml` | NODE_AUTH_TOKEN secret | Snapshot / Nightly Artifacts |
| echarts | `nightly.yml` | NODE_AUTH_TOKEN secret | Snapshot / Nightly Artifacts |
| echarts-examples | `sync-nightly-mirror.yaml` | registry-url configured in actions/setup-node (likely uses NODE_AUTH_TOKEN secret) | Snapshot / Nightly Artifacts |

### NuGet

**Available mechanism:** Sigstore-based Trusted Publishing
**Documentation:** https://devblogs.microsoft.com/nuget/introducing-trusted-publishers/

| Repository | Workflow | Current Auth | Category |
|------------|----------|-------------|----------|
| arrow-dotnet | `rc.yaml` | GITHUB_TOKEN | Release Artifacts |
| casbin-Casbin.NET | `release.yml` | GITHUB_TOKEN for GitHub Packages, NUGET_API_TOKEN secret for NuGet.org | Release Artifacts |
| casbin-Casbin.NET-ef-adapter | `gitub-actions-build.yml` | MYGET_API_TOKEN secret | Snapshot / Nightly Artifacts |
| casbin-Casbin.NET-ef-adapter | `gitub-actions-release.yml` | NUGET_API_TOKEN secret | Release Artifacts |
| casbin-Casbin.NET-redis-adapter | `build.yml` | MYGET_API_TOKEN secret | Snapshot / Nightly Artifacts |
| casbin-Casbin.NET-redis-adapter | `release.yml` | MYGET_API_TOKEN, NUGET_API_TOKEN, GITHUB_TOKEN secrets | Release Artifacts |
| casbin-Casbin.NET-redis-watcher | `build.yml` | MYGET_API_TOKEN secret | Snapshot / Nightly Artifacts |
| casbin-Casbin.NET-redis-watcher | `release.yml` | MYGET_API_TOKEN, NUGET_API_TOKEN, GITHUB_TOKEN secrets | Release Artifacts |
| casbin-aspnetcore | `release.yml` | GITHUB_TOKEN for GitHub Packages, NUGET_API_TOKEN secret for NuGet.org | Release Artifacts |
| casbin-efcore-adapter | `release.yml` | GITHUB_TOKEN for GitHub Packages, NUGET_API_TOKEN secret for NuGet.org | Release Artifacts |

### PyPI

**Available mechanism:** OIDC Trusted Publisher via pypa/gh-action-pypi-publish
**Documentation:** https://docs.pypi.org/trusted-publishers/

| Repository | Workflow | Current Auth | Category |
|------------|----------|-------------|----------|
| arrow-adbc | `packaging.yml` | GEMFURY_PUSH_TOKEN, GEMFURY_API_TOKEN, ANACONDA_API_TOKEN, NPM_TOKEN | Snapshot / Nightly Artifacts |
| arrow-nanoarrow | `python-wheels.yaml` | NANOARROW_GEMFURY_TOKEN secret | Snapshot / Nightly Artifacts |
| beam | `deploy_release_candidate_pypi.yaml` | PyPI API token passed as workflow input | Release Artifacts |
| beam | `finalize_release.yml` | secrets (DOCKERHUB_USER, DOCKERHUB_TOKEN, PYPI_API_TOKEN) | Release Artifacts |
| buildstream | `release.yml` | PYPI_TOKEN secret for PyPI, GITHUB_TOKEN for GitHub Releases | Release Artifacts |
| casbin-pycasbin | `build.yml` | PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub releases | Release Artifacts |
| casbin-python-async-django-orm-adapter | `build.yml` | PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub Releases | Release Artifacts |
| casbin-python-async-postgres-watcher | `release.yml` | PYPI_TOKEN secret and GITHUB_TOKEN for semantic-release | Release Artifacts |
| casbin-python-async-sqlalchemy-adapter | `build.yml` | PYPI_TOKEN secret | Release Artifacts |
| casbin-python-casbin-databases-adapter | `build.yml` | PYPI_TOKEN secret for PyPI, GITHUB_TOKEN for GitHub releases | Release Artifacts |
| casbin-python-django-casbin-auth | `release.yml` | PYPI_TOKEN secret and GH_TOKEN for GitHub releases | Release Artifacts |
| casbin-python-django-orm-adapter | `build.yml` | PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub Releases | Release Artifacts |
| casbin-python-etcd-watcher | `release.yml` | PYPI_TOKEN secret and GITHUB_TOKEN for semantic-release | Release Artifacts |
| casbin-python-fastapi-casbin-auth | `release.yml` | GITHUB_TOKEN and PYPI_TOKEN secrets | Release Artifacts |
| casbin-python-flask-authz | `build.yml` | PYPI_TOKEN secret | Release Artifacts |
| casbin-python-graphql-authz | `build.yml` | PYPI_TOKEN secret | Release Artifacts |
| casbin-python-postgresql-watcher | `release.yml` | PYPI_TOKEN secret and GITHUB_TOKEN for semantic-release | Release Artifacts |
| casbin-python-pymongo-adapter | `main.yml` | PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub Releases | Release Artifacts |
| casbin-python-rabbitmq-watcher | `build.yml` | PYPI_TOKEN secret | Release Artifacts |
| casbin-python-redis-adapter | `build.yml` | PYPI_TOKEN secret | Release Artifacts |
| casbin-python-redis-watcher | `release.yml` | PYPI_TOKEN secret, GITHUB_TOKEN secret | Release Artifacts |
| casbin-python-sanic-authz | `build.yml` | PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub Releases | Release Artifacts |
| casbin-python-sqlalchemy-adapter | `build.yml` | PYPI_TOKEN secret | Release Artifacts |
| casbin-python-sqlobject-adapter | `build.yml` | PYPI_TOKEN secret | Release Artifacts |
| fluss-rust | `release_python.yml` | API token via secrets.PYPI_API_TOKEN and secrets.TEST_PYPI_API_TOKEN | Release Artifacts |
| hudi-rs | `release.yml` | CARGO_REGISTRY_TOKEN secret for crates.io, MATURIN_PYPI_TOKEN secret for PyPI | Release Artifacts |

## Release Artifact Workflows

These workflows publish versioned packages to public registries consumed by end users.

| Repository | Workflow | Ecosystems | Trigger | Auth |
|------------|----------|------------|---------|------|
| airavata | `build-and-publish.yml` | docker_hub | push to main/master branches, tags matching v*, or manual workflow_dispatch | Docker Hub username and access token from GitHub secrets |
| airavata-mft | `release_on_tag_push.yml` | github_releases | release published | GITHUB_TOKEN |
| airflow | `release_dockerhub_image.yml` | docker_hub | workflow_dispatch | DOCKERHUB_USER and DOCKERHUB_TOKEN secrets |
| airflow | `release_single_dockerhub_image.yml` | docker_hub | workflow_call | DOCKERHUB_USER and DOCKERHUB_TOKEN secrets |
| airflow-publish | `airflow-publish.yml` | pypi | workflow_dispatch with mode input (VERIFY or RELEASE) | OIDC trusted publishing (id-token: write permission) |
| airflow-publish | `providers-publish.yml` | pypi | workflow_dispatch with mode input (VERIFY or RELEASE) | OIDC trusted publishing (id-token: write permission) |
| airflow-publish | `test-pypi-airflow-publish.yml` | pypi | workflow_dispatch with mode input (VERIFY or RELEASE) | OIDC trusted publishing (id-token: write permission) |
| amoro | `docker-images.yml` | docker_hub | push to master branch or version tags (v*) | Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| answer | `build-binary-for-release.yml` | github_releases | push to tags matching v* | GITHUB_TOKEN (secrets.GITHUB_TOKEN) |
| answer | `build-image-for-latest-release.yml` | docker_hub | push to tags matching v2.*, v1.*, v0.* (excluding RC tags) | Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| answer | `build-image-for-manual.yml` | docker_hub | workflow_dispatch | secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| answer | `build-image-for-release.yml` | docker_hub | push to tags matching v2.*, v1.*, v0.* | DOCKERHUB_USER and DOCKERHUB_TOKEN secrets |
| apisix-docker | `apisix_push_docker_hub.yaml` | docker_hub | push to branches matching 'release/apisix-**' | Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| apisix-docker | `dashboard_push_docker_hub.yaml` | docker_hub | push to branches matching 'release/apisix-dashboard**' | Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| apisix-helm-chart | `release.yaml` | helm, github_releases | push to master, legacy, or dev branches | GITHUB_TOKEN (secrets.GITHUB_TOKEN) |
| apisix-ingress-controller | `push-docker.yaml` | docker_hub | push to tags or master branch | DOCKERHUB_USER and DOCKERHUB_TOKEN secrets |
| arrow | `package_linux.yml` | github_releases | push to tags matching apache-arrow-*-rc*, push to branches, pull_request, schedule | GITHUB_TOKEN |
| arrow | `release.yml` | github_releases | push to tags matching 'apache-arrow-*' (excluding RC tags) | GH_TOKEN (github.token) |
| arrow | `release_candidate.yml` | github_releases | push to tags matching apache-arrow-*-rc* | github.token |
| arrow-dotnet | `rc.yaml` | nuget, github_releases | push to tags matching *-rc* pattern | GITHUB_TOKEN |
| arrow-dotnet | `release.yaml` | github_releases | push to tags (excluding RC tags) | GITHUB_TOKEN |
| arrow-flight-sql-postgresql | `package.yaml` | github_releases, ghcr | push to tags matching *-rc* pattern, pull_request, push to any branch | github.token for GitHub Releases and GHCR |
| arrow-go | `rc.yml` | github_releases | push to tags matching 'v*-rc*' | GITHUB_TOKEN (automatic) |
| arrow-go | `release.yml` | github_releases | push to tags matching v* (excluding v*-rc*) | GITHUB_TOKEN secret |
| arrow-java | `release.yml` | github_releases, github_pages | push to tags (excluding RC tags) | GITHUB_TOKEN secret |
| arrow-js | `rc.yaml` | github_releases | push to tags matching *-rc* | GITHUB_TOKEN |
| arrow-js | `release.yaml` | github_releases | push to tags (excluding RC tags) | GITHUB_TOKEN |
| arrow-swift | `rc.yaml` | github_releases | push to tags matching *-rc* pattern | GITHUB_TOKEN |
| arrow-swift | `release.yaml` | github_releases | push to tags (excluding *-rc* tags) | GITHUB_TOKEN (secrets.GITHUB_TOKEN) |
| beam | `build_release_candidate.yml` | maven_central, apache_dist, docker_hub, github_releases | workflow_dispatch with manual inputs for RELEASE, RC, APACHE_ID, APACHE_PASSWORD, REPO_TOKEN, and STAGE configuration | Maven settings.xml with secrets.NEXUS_STAGE_DEPLOYER_USER/PW and secrets.NEXUS_USER/PW; Docker Hub login with secrets.DOCKERHUB_USER/TOKEN; Apache SVN with workflow_dispatch inputs APACHE_ID/APACHE_PASSWORD; GitHub token from workflow_dispatch input REPO_TOKEN |
| beam | `deploy_release_candidate_pypi.yaml` | pypi | workflow_dispatch | PyPI API token passed as workflow input |
| beam | `finalize_release.yml` | docker_hub, pypi | workflow_dispatch | secrets (DOCKERHUB_USER, DOCKERHUB_TOKEN, PYPI_API_TOKEN) |
| beam | `republish_released_docker_containers.yml` | gcr | workflow_dispatch with RELEASE and RC inputs, scheduled weekly on Mondays at 6 AM UTC | GCP service account authentication via google-github-actions/auth with credentials_json secret |
| bifromq | `docker-publish.yml` | docker_hub | workflow_dispatch | secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| buildstream | `release.yml` | pypi, github_releases | push tags matching '*.*.*' (semantic version tags) | PYPI_TOKEN secret for PyPI, GITHUB_TOKEN for GitHub Releases |
| camel-karavan | `docker-devmode.yml` | ghcr | push to main branch (paths: karavan-devmode/Dockerfile, .github/workflows/docker-devmode.yml) or workflow_dispatch | GITHUB_TOKEN secret for GHCR authentication |
| carbondata | `maven-publish.yml` | github_packages | release (types: [created]) | GITHUB_TOKEN (automatic token) |
| casbin-Casbin.NET | `release.yml` | nuget, github_packages | push to master/main/1.x branches or workflow_dispatch | GITHUB_TOKEN for GitHub Packages, NUGET_API_TOKEN secret for NuGet.org |
| casbin-Casbin.NET-dotnet-cli | `build.yml` | github_releases | push to master branch | GITHUB_TOKEN |
| casbin-Casbin.NET-ef-adapter | `gitub-actions-release.yml` | nuget | push to tags | NUGET_API_TOKEN secret |
| casbin-Casbin.NET-redis-adapter | `release.yml` | nuget, github_packages | workflow_dispatch | MYGET_API_TOKEN, NUGET_API_TOKEN, GITHUB_TOKEN secrets |
| casbin-Casbin.NET-redis-watcher | `release.yml` | nuget, github_packages | push | MYGET_API_TOKEN, NUGET_API_TOKEN, GITHUB_TOKEN secrets |
| casbin-actix-casbin-auth | `release.yml` | crates_io, github_releases | push to tags matching v* | secrets.CARGO_TOKEN for crates.io, secrets.GITHUB_TOKEN for GitHub Releases |
| casbin-admission-webhook | `release.yml` | docker_hub, github_releases | push to main/master branches | DOCKERHUB_USERNAME and DOCKERHUB_TOKEN secrets for Docker Hub; GITHUB_TOKEN for semantic-release |
| casbin-aspnetcore | `release.yml` | nuget, github_packages | push to master branch | GITHUB_TOKEN for GitHub Packages, NUGET_API_TOKEN secret for NuGet.org |
| casbin-axum-casbin | `release.yml` | crates_io, github_releases | push to tags matching v* | secrets.CARGO_TOKEN for crates.io, secrets.GITHUB_TOKEN for GitHub Releases |
| casbin-casbin.js | `ci.yml` | npm | push to casbin/casbin.js repository | NPM_TOKEN secret |
| casbin-core | `ci.yml` | npm | push to master branch only (github.repository == 'casbin/casbin-core' && github.event_name == 'push' && github.ref == 'refs/heads/master') | NPM_TOKEN secret for npm authentication, GITHUB_TOKEN for GitHub operations |
| casbin-dart-casbin | `dart.yml` | github_releases, dart_pub | push to master branch | PUB_CREDENTIALS secret stored in credentials.json file, GITHUB_TOKEN for semantic-release |
| casbin-editor | `release.yml` | github_releases | push to master branch or pull_request with title starting with 'feat:' | GITHUB_TOKEN secret |
| casbin-efcore-adapter | `release.yml` | nuget, github_packages | push to master branch | GITHUB_TOKEN for GitHub Packages, NUGET_API_TOKEN secret for NuGet.org |
| casbin-ex | `release.yml` | hex, github_releases | workflow_run on CI completion (master/main branches) | HEX_API_KEY secret for Hex.pm, GITHUB_TOKEN for semantic-release |
| casbin-gateway | `build.yml` | docker_hub | push to master branch with semantic version bump (major or minor) | Docker Hub username/password via secrets |
| casbin-go-cli | `build.yml` | github_releases | push | GITHUB_TOKEN |
| casbin-jcasbin | `maven-ci.yml` | maven_central, github_releases | push to master branch or pull_request | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured in setup-java action; credentials passed via environment variables to semantic-release |
| casbin-jcasbin-dynamodb-adapter | `release.yml` | maven_central, github_releases | push to master branch | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing key for Maven Central; GITHUB_TOKEN for GitHub Releases |
| casbin-jcasbin-hibernate-adapter | `maven-ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action and passed to semantic-release |
| casbin-jcasbin-jdbc-adapter | `maven-ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via actions/setup-java. GitHub token for GitHub releases. |
| casbin-jcasbin-jfinal-authz | `maven-ci.yml` | maven_central, github_releases | push, pull_request | Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via setup-java action; credentials passed as environment variables to semantic-release |
| casbin-jcasbin-kafka-casbin | `maven-ci.yml` | maven_central, github_releases | push, pull_request | Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via setup-java action; credentials passed as environment variables to semantic-release |
| casbin-jcasbin-kafka-watcher | `ci.yml` | maven_central, github_releases | push, pull_request, workflow_dispatch | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action; GITHUB_TOKEN for GitHub releases |
| casbin-jcasbin-lettuce-redis-watcher | `maven-ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (username/password) and GPG signing key for Maven Central; GITHUB_TOKEN for GitHub Releases |
| casbin-jcasbin-mongo-adapter | `maven-ci.yml` | maven_central, github_releases | push, pull_request | Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via setup-java action; credentials passed as environment variables to semantic-release |
| casbin-jcasbin-mybatis-adapter | `ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action. GitHub token for GitHub releases. |
| casbin-jcasbin-mybatisplus-adapter | `ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action. GitHub token for GitHub releases. |
| casbin-jcasbin-nutz-authz | `maven-ci.yml` | maven_central, github_releases | push, pull_request | Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via actions/setup-java. Semantic-release uses GITHUB_TOKEN for GitHub releases. |
| casbin-jcasbin-play-authz | `maven-ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured in setup-java action. GitHub token (GH_TOKEN) for GitHub releases. |
| casbin-jcasbin-postgres-watcher | `ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (OSSRH_USERNAME, OSSRH_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) for Maven Central; GITHUB_TOKEN for GitHub Releases |
| casbin-jcasbin-pulsar-authz | `maven-ci.yaml` | maven_central, github_releases | push, pull_request | Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via setup-java action; credentials passed as environment variables to semantic-release |
| casbin-jcasbin-rabbitmq-watcher | `ci.yml` | maven_central, github_releases | push to master branch | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action; GITHUB_TOKEN for GitHub releases |
| casbin-jcasbin-redis-adapter | `maven-ci.yml` | maven_central, github_releases | push, pull_request | Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via setup-java action. Secrets passed through env block to semantic-release. |
| casbin-jcasbin-redis-watcher | `maven-ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (username/password) and GPG signing key for Maven Central; GITHUB_TOKEN for GitHub Releases |
| casbin-jcasbin-redis-watcher-ex | `ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (username/password) and GPG signing key for Maven Central; GITHUB_TOKEN for GitHub Releases |
| casbin-jcasbin-shiro-casbin | `ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action and semantic-release environment variables |
| casbin-jcasbin-spring-security-starter | `gradle-ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action and passed to semantic-release |
| casbin-jcasbin-string-adapter | `ci.yml` | maven_central, github_releases | push, pull_request | Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via setup-java action. GitHub token for semantic-release. |
| casbin-jcasbin-vertx-authz | `maven-ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action. GitHub token (GH_TOKEN) for GitHub releases. |
| casbin-jcasbin-zookeeper-watcher | `maven-ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (username/password) and GPG signing key for Maven Central; GITHUB_TOKEN for GitHub Releases |
| casbin-js-vue-authz | `ci.yml` | npm, github_releases | push to casbin-js/vue-authz repository | NPM_TOKEN secret for npm registry, GITHUB_TOKEN for GitHub releases |
| casbin-lego | `main.yml` | github_pages, github_releases, docker_hub | push to master branch, push tags matching v*, pull_request | GITHUB_TOKEN for GitHub Pages and GoReleaser, DOCKER_USERNAME/DOCKER_PASSWORD for Docker Hub |
| casbin-lua-casbin | `release.yml` | luarocks, github_releases | push to master branch | LUAROCKS_API_KEY secret for LuaRocks, GITHUB_TOKEN for semantic-release |
| casbin-mcp-gateway | `release.yml` | github_releases | push to master/main branches | GITHUB_TOKEN (automatic) |
| casbin-mesh | `docker-publish.yml` | ghcr | push to main/master branches and semver tags (v*.*.*), pull_request (build only) | GITHUB_TOKEN with packages:write permission |
| casbin-nest-authz | `ci.yml` | npm, github_releases | push to node-casbin/nest-authz repository | NPM_TOKEN secret for npm registry, GITHUB_TOKEN for GitHub releases |
| casbin-node-casbin | `main.yml` | npm | push to master branch | NPM_TOKEN secret |
| casbin-node-casbin-basic-adapter | `ci.yml` | npm | push to node-casbin/basic-adapter repository | NPM_TOKEN and GITHUB_TOKEN secrets |
| casbin-node-casbin-couchdb-adapter | `ci.yml` | npm | push to node-casbin/couchdb-adapter repository | NPM_TOKEN secret |
| casbin-node-casbin-drizzle-adapter | `ci.yml` | npm | push to master branch (conditional on repository match) | NPM_TOKEN secret |
| casbin-node-casbin-etcd-watcher | `main.yml` | npm, github_releases | push to node-casbin/etcd-watcher repository | NPM_TOKEN secret for npm registry, GITHUB_TOKEN for GitHub releases |
| casbin-node-casbin-expression-eval | `ci.yml` | npm, github_releases | push | NPM_TOKEN and GITHUB_TOKEN secrets |
| casbin-node-casbin-file-adapter | `ci.yml` | npm, github_releases | push to main branch (semantic-release convention) | NPM_TOKEN and GITHUB_TOKEN secrets passed via environment variables |
| casbin-node-casbin-mongo-changestream-watcher | `main.yml` | npm | push to main branch (conditional: github.event_name == 'push' && github.repository == 'node-casbin/mongo-changestream-watcher') | NPM_TOKEN secret for npm registry authentication, GITHUB_TOKEN for GitHub releases |
| casbin-node-casbin-mongoose-adapter | `main.yml` | npm | push to master branch | NPM_TOKEN secret |
| casbin-node-casbin-node-redis-adapter | `release.yml` | npm, github_releases | push | NPM_TOKEN and GITHUB_TOKEN secrets passed as environment variables |
| casbin-node-casbin-prisma-adapter | `ci.yml` | npm, github_releases | push to node-casbin/prisma-adapter repository | GITHUB_TOKEN and NPM_TOKEN secrets |
| casbin-node-casbin-redis-watcher | `ci.yml` | npm | push to node-casbin/redis-watcher repository | NPM_TOKEN secret |
| casbin-node-casbin-session-role-manager | `release.yml` | npm, github_releases | push to master branch | GITHUB_TOKEN and NPM_TOKEN secrets |
| casbin-pycasbin | `build.yml` | pypi, github_releases | push to master branch (after tests pass) | PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub releases |
| casbin-python-async-django-orm-adapter | `build.yml` | pypi, github_releases | push to master branch (after tests pass) | PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub Releases |
| casbin-python-async-postgres-watcher | `release.yml` | pypi, github_releases | push to master branch (after tests pass) | PYPI_TOKEN secret and GITHUB_TOKEN for semantic-release |
| casbin-python-async-sqlalchemy-adapter | `build.yml` | pypi | push to master branch (after tests pass) | PYPI_TOKEN secret |
| casbin-python-casbin-databases-adapter | `build.yml` | pypi, github_releases | push to master branch (after tests pass) | PYPI_TOKEN secret for PyPI, GITHUB_TOKEN for GitHub releases |
| casbin-python-django-casbin-auth | `release.yml` | pypi, github_releases | push to master branch (after tests pass) | PYPI_TOKEN secret and GH_TOKEN for GitHub releases |
| casbin-python-django-orm-adapter | `build.yml` | pypi, github_releases | push to master branch (after tests pass) | PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub Releases |
| casbin-python-etcd-watcher | `release.yml` | pypi, github_releases | push to master branch | PYPI_TOKEN secret and GITHUB_TOKEN for semantic-release |
| casbin-python-fastapi-casbin-auth | `release.yml` | pypi, github_releases | push to master branch | GITHUB_TOKEN and PYPI_TOKEN secrets |
| casbin-python-flask-authz | `build.yml` | pypi | push to master branch | PYPI_TOKEN secret |
| casbin-python-graphql-authz | `build.yml` | pypi | push to master branch (after tests pass) | PYPI_TOKEN secret |
| casbin-python-postgresql-watcher | `release.yml` | pypi, github_releases | push to master branch (after tests pass) | PYPI_TOKEN secret and GITHUB_TOKEN for semantic-release |
| casbin-python-pymongo-adapter | `main.yml` | pypi, github_releases | push to master branch (after tests pass) | PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub Releases |
| casbin-python-rabbitmq-watcher | `build.yml` | pypi | push to master branch (after tests pass) | PYPI_TOKEN secret |
| casbin-python-redis-adapter | `build.yml` | pypi | push to master branch (after tests pass) | PYPI_TOKEN secret |
| casbin-python-redis-watcher | `release.yml` | pypi, github_releases | push to master branch, pull_request to master branch | PYPI_TOKEN secret, GITHUB_TOKEN secret |
| casbin-python-sanic-authz | `build.yml` | pypi, github_releases | push to master branch (after tests pass) | PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub Releases |
| casbin-python-sqlalchemy-adapter | `build.yml` | pypi | push to master branch (after tests pass) | PYPI_TOKEN secret |
| casbin-python-sqlobject-adapter | `build.yml` | pypi | push to master branch (after tests pass) | PYPI_TOKEN secret |
| casbin-rs | `release.yml` | crates_io | workflow_run (triggered after CI workflow completes successfully on push events) | CARGO_TOKEN secret passed to reusable workflow |
| casbin-rust-actix-casbin | `release.yml` | crates_io, github_releases | push to tags matching v* | CARGO_TOKEN secret for crates.io, GITHUB_TOKEN for releases |
| casbin-rust-casbin-rust-cli | `release.yml` | crates_io | push to master, next, next-major, beta, alpha, or version branches | CARGO_TOKEN secret passed to reusable workflow |
| casbin-rust-diesel-adapter | `release.yml` | crates_io, github_releases | push to tags matching v* | CARGO_TOKEN secret for crates.io, GITHUB_TOKEN for GitHub releases |
| casbin-rust-dufs-with-casbin | `release.yaml` | github_releases, docker_hub, crates_io | push to tags matching v[0-9]+.[0-9]+.[0-9]+* | GITHUB_TOKEN for GitHub Releases, DOCKERHUB_USERNAME/DOCKERHUB_TOKEN for Docker Hub, CRATES_IO_API_TOKEN for crates.io |
| casbin-rust-postgres-adapter | `release.yml` | crates_io, github_releases | push to tags matching v* | secrets.CARGO_TOKEN for crates.io, secrets.GITHUB_TOKEN for GitHub releases |
| casbin-rust-redis-watcher | `release.yml` | crates_io | workflow_run on CI completion (master branch only) | CARGO_TOKEN secret passed to reusable workflow |
| casbin-rust-rocket-authz | `release.yml` | crates_io, github_releases | push to tags matching v* | secrets.CARGO_TOKEN for crates.io, secrets.GITHUB_TOKEN for GitHub Releases |
| casbin-rust-semantic-release-action-rust | `release-binary.yml` | github_releases, crates_io | workflow_call | cargo-registry-token secret |
| casbin-rust-semantic-release-action-rust | `release-library.yml` | crates_io | workflow_call | cargo-registry-token secret |
| casbin-rust-string-adapter | `release.yml` | crates_io, github_releases | push to tags matching v* | CARGO_TOKEN secret for crates.io, GITHUB_TOKEN for releases |
| casbin-rust-yaml-adapter | `release.yml` | crates_io, github_releases | push to tags matching v* | CARGO_TOKEN secret for crates.io, GITHUB_TOKEN for releases |
| casbin-sequelize-adapter | `ci.yml` | npm | push to node-casbin/sequelize-adapter repository | NPM_TOKEN secret |
| casbin-server | `default.yml` | docker_hub | push to casbin/casbin-server repository | Docker Hub credentials via secrets.DOCKERHUB_USERNAME and secrets.DOCKERHUB_PASSWORD |
| casbin-spring-boot-starter | `maven-ci.yml` | maven_central, github_releases | push, pull_request | OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action and passed to semantic-release |
| casbin-sqlx-adapter | `release.yml` | crates_io | push to tags matching v* | CARGO_TOKEN secret for crates.io authentication |
| casbin-typeorm-adapter | `ci.yml` | npm | push to master branch (conditional on repository match) | NPM_TOKEN secret |
| casbin-vscode-plugin | `default.yml` | npm, github_releases | push to tags | secrets.GITHUB_TOKEN, secrets.NPM_TOKEN, secrets.VS_MARKETPLACE_TOKEN |
| casbin-website-v3 | `release.yml` | npm, github_releases | push to main/master branches | GITHUB_TOKEN and NPM_TOKEN secrets |
| cassandra-easy-stress | `gradle-publish-main-release.yml` | github_releases | push to main branch | GITHUB_TOKEN (secrets.GITHUB_TOKEN) |
| celeborn | `docker-build.yml` | docker_hub | release (published) and workflow_dispatch | Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| cordova-android | `draft-release.yml` | apache_dist | push to tags matching 'draft/**' | OIDC (id-token: write) and GPG signing with secrets.CORDOVA_GPG_SECRET_KEY |
| cordova-eslint | `draft-release.yml` | apache_dist | push to tags matching 'draft/**' | OIDC (id-token: write) and GPG signing with secrets.CORDOVA_GPG_SECRET_KEY |
| cordova-ios | `draft-release.yml` | apache_dist | push to tags matching 'draft/**' | OIDC (id-token: write) and GPG signing with secrets.CORDOVA_GPG_SECRET_KEY |
| cordova-plugin-camera | `draft-release.yml` | apache_dist | push to tags matching 'draft/**' | OIDC (id-token: write) and GPG signing with secrets.CORDOVA_GPG_SECRET_KEY |
| couchdb-helm | `chart-releaser.yaml` | helm, github_pages | push to main branch | GITHUB_TOKEN |
| couchdb-mochiweb | `release.yml` | hex | push to tags matching '*' (filtered to 'refs/tags/v*' in job condition) | HEX_API_KEY secret passed via env block |
| daffodil | `release-candidate.yml` | maven_central, apache_dist | push on tags v*-rc* | GPG signing key, SVN credentials, Nexus credentials passed to custom action |
| daffodil-sbt | `release-candidate.yml` | maven_central, apache_dist | push to tags matching 'v*-rc*' or workflow_dispatch | GPG signing key, SVN credentials, Nexus credentials via secrets |
| daffodil-vscode | `release-candidate.yml` | apache_dist, maven_central | push to tags matching 'v*-rc*' or workflow_dispatch | GPG signing key, SVN credentials, Nexus credentials via secrets |
| datafusion-ballista | `docker.yml` | ghcr | pull_request, push | docker login with github.actor and secrets.GITHUB_TOKEN |
| datafusion-comet | `docker-publish.yml` | ghcr | push on tags matching version patterns (*.*.*,  *.*.*-rc*, test-docker-publish-*) | GITHUB_TOKEN with packages:write permission |
| datafusion-ray | `k8s.yml` | ghcr | workflow_dispatch (manual trigger only; push/pull_request commented out) | GITHUB_TOKEN via docker/login-action to ghcr.io |
| directory-scimple | `release.yml` | maven_central, apache_dist | push to tags matching v*.** | Maven server credentials (NEXUS_USERNAME/NEXUS_PASSWORD) and SVN credentials (SVN_USERNAME/SVN_PASSWORD) |
| dolphinscheduler | `publish-docker.yaml` | docker_hub, maven_central | push to dev branch, release published | Docker Hub credentials via secrets (DOCKERHUB_USER, DOCKERHUB_TOKEN) |
| dolphinscheduler | `publish-helm-chart.yaml` | helm, docker_hub, ghcr | push to dev branch OR release published | Docker Hub credentials (secrets.DOCKERHUB_USER/TOKEN) for releases, GitHub token for dev branch |
| doris-opentelemetry-demo | `component-build-images.yml` | docker_hub, ghcr | workflow_call | GITHUB_TOKEN for GHCR, DOCKER_USERNAME/DOCKER_PASSWORD secrets for Docker Hub |
| doris-opentelemetry-demo | `release.yml` | docker_hub, ghcr | release (published) | secrets inherited from reusable workflow |
| doris-operator | `docker_action.yaml` | docker_hub | push to tags matching *.*.* | Docker Hub username/password via secrets.DOCKERHUB_USERNAME and secrets.DOCKERHUB_TOKEN |
| doris-operator | `helm-release.yaml` | helm | push to tags matching *.*.* | OSS credentials (secrets.OSS_KEY_ID, secrets.OSS_KEY_SECRET) |
| doris-thirdparty | `build-2.0.yml` | github_releases | schedule (every 30 minutes) | GITHUB_TOKEN with contents: write permission |
| doris-thirdparty | `manual-build.yml` | github_releases | workflow_dispatch | GITHUB_TOKEN |
| dubbo-admin | `release.yaml` | github_releases | push to tags matching 'v*' | GITHUB_TOKEN (automatic) |
| dubbo-go-pixiu | `release.yml` | github_releases | release (types: created) | GITHUB_TOKEN (secrets) |
| dubbo-go-pixiu-samples | `release.yml` | github_releases | release.created | GITHUB_TOKEN |
| dubbo-kubernetes | `release.yaml` | github_releases | push to tags matching '[0-9]+.[0-9]+.[0-9]+' | GITHUB_TOKEN (automatic) |
| eventmesh | `docker.yml` | docker_hub | release (types: [released]) | DockerHub username/password via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| eventmesh-dashboard | `docker.yml` | docker_hub | push to tags matching 'v*' | DockerHub username/password via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| fineract | `publish-dockerhub.yml` | docker_hub | push to develop branch or tags matching 1.* | DOCKERHUB_USER and DOCKERHUB_TOKEN secrets |
| fluss-rust | `release_python.yml` | pypi | push tags matching 'v*' pattern | API token via secrets.PYPI_API_TOKEN and secrets.TEST_PYPI_API_TOKEN |
| fluss-rust | `release_rust.yml` | crates_io | push to version tags (v*), excluding pre-release tags containing '-' | CARGO_REGISTRY_TOKEN secret |
| fory | `release-compiler.yaml` | pypi | push to tags matching 'v*' | OIDC (id-token: write permission for Trusted Publishing) |
| fory | `release-python.yaml` | pypi | workflow_run on completion of wheel build workflows | OIDC (id-token: write permission for Trusted Publishing) |
| fory | `release-rust.yaml` | crates_io | push to tags matching 'v*' | OIDC via rust-lang/crates-io-auth-action with id-token: write permission |
| gobblin | `docker_build_publish.yaml` | docker_hub | release (types: published, edited) | DOCKERHUB_USER and DOCKERHUB_TOKEN secrets |
| grails-core | `forge-deploy-release.yml` | gcr | workflow_dispatch with release version input | GCP service account credentials via secrets.GCP_CREDENTIALS |
| grails-core | `release.yml` | maven_central, github_releases, apache_dist | release published | secrets (NEXUS_STAGE_DEPLOYER_USER, NEXUS_STAGE_DEPLOYER_PW, GPG_KEY_ID, GRAILS_GPG_KEY, SVC_DIST_GRAILS_USERNAME, SVC_DIST_GRAILS_PASSWORD) |
| grails-forge-ui | `publish.yml` | github_releases | push to main branch | GITHUB_TOKEN secret |
| grails-github-actions | `release.yml` | apache_dist, github_releases | release published | SVN credentials (secrets.SVC_DIST_GRAILS_USERNAME, secrets.SVC_DIST_GRAILS_PASSWORD), GPG signing (secrets.GRAILS_GPG_KEY, secrets.GPG_KEY_ID), GitHub token |
| grails-gradle-publish | `release.yaml` | maven_central, apache_dist, github_releases, github_pages | release.published | secrets (NEXUS_STAGE_DEPLOYER_USER, NEXUS_STAGE_DEPLOYER_PW, GRAILS_GPG_KEY, GPG_KEY_ID, SVC_DIST_GRAILS_USERNAME, SVC_DIST_GRAILS_PASSWORD) |
| grails-quartz | `release.yml` | maven_central, apache_dist, github_releases | release published | Nexus credentials (NEXUS_STAGE_DEPLOYER_USER, NEXUS_STAGE_DEPLOYER_PW), GPG signing key (GRAILS_GPG_KEY, GPG_KEY_ID), SVN credentials (SVC_DIST_GRAILS_USERNAME, SVC_DIST_GRAILS_PASSWORD), GitHub token |
| grails-redis | `release.yml` | maven_central, apache_dist, github_releases, github_pages | release published | NEXUS_PUBLISH_USERNAME/PASSWORD secrets for Maven staging, SVN_USERNAME/PASSWORD for Apache dist, GITHUB_TOKEN for GitHub releases and pages, GPG signing with GRAILS_GPG_KEY |
| grails-spring-security | `release.yml` | maven_central, apache_dist, github_releases, github_pages | release published | secrets (NEXUS_STAGE_DEPLOYER_USER, NEXUS_STAGE_DEPLOYER_PW, GPG_KEY_ID, SVC_DIST_GRAILS_USERNAME, SVC_DIST_GRAILS_PASSWORD, GITHUB_TOKEN) |
| gravitino | `docker-image.yml` | docker_hub | workflow_dispatch | docker/login-action with username from workflow input and password from secrets.DOCKER_REPOSITORY_PASSWORD |
| hamilton | `contrib-auto-build-publish.yml` | pypi | push to main branch when contrib/** paths change | OIDC trusted publishing (id-token: write) |
| hamilton | `hamilton-ui-build-and-push.yml` | docker_hub | schedule (daily cron) and workflow_dispatch | Docker Hub username/password via secrets.DOCKER_USERNAME and secrets.DOCKER_TOKEN |
| hudi-rs | `release.yml` | crates_io, pypi | push to tags matching 'release-[0-9]+.[0-9]+.[0-9]+**' | CARGO_REGISTRY_TOKEN secret for crates.io, MATURIN_PYPI_TOKEN secret for PyPI |
| incubator-baremaps | `pre-release.yml` | github_releases | push to tags matching v*-alpha*, v*-beta*, v*-test* | GITHUB_TOKEN |
| incubator-baremaps | `release.yml` | github_releases, apache_dist | push to tags matching v[0-9]+.[0-9]+.[0-9]+-rc[0-9]+ | GitHub token (GITHUB_TOKEN), Apache SVN credentials (INCUBATOR_SVN_DEV_USERNAME/PASSWORD), GPG signing key |
| incubator-devlake-helm-chart | `release.yaml` | helm, ghcr | push to main/release-v* branches (charts/** paths) or workflow_dispatch | GITHUB_TOKEN for GHCR authentication |
| kafka | `docker_promote.yml` | docker_hub | workflow_dispatch | secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| kafka | `docker_rc_release.yml` | docker_hub | workflow_dispatch | DOCKERHUB_USER and DOCKERHUB_TOKEN secrets |
| knox | `docker-publish.yml` | docker_hub | push to master branch, push to tags matching 'v*', or manual workflow_dispatch | Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| kyuubi-docker | `docker-image.yml` | docker_hub | push to tags | Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |

## Snapshot / Nightly Artifact Workflows

These workflows publish snapshot or nightly builds to staging registries.

| Repository | Workflow | Ecosystems | Trigger | Auth |
|------------|----------|------------|---------|------|
| activemq | `deploy.yml` | maven_central | schedule (cron: '0 0 * * *') | Maven settings.xml (implicit) |
| airflow-publish | `test-pypi-providers-publish.yml` | pypi | workflow_dispatch | OIDC trusted publishing (id-token: write) |
| answer | `build-image-for-test.yml` | docker_hub | push to 'test' branch | DOCKERHUB_USER and DOCKERHUB_TOKEN secrets |
| apisix | `push-dev-image-on-commit.yml` | docker_hub | push to master branch (also pull_request and workflow_dispatch, but publishing only occurs on master) | Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| apisix-docker | `apisix_dev_push_docker_hub.yaml` | docker_hub | schedule (daily at 1:00 UTC) and push to master branch | Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| arrow | `r_nightly.yml` | apache_dist | schedule (cron: 0 14 * * *) and workflow_dispatch | SSH key authentication via secrets.NIGHTLIES_RSYNC_KEY |
| arrow-adbc | `packaging.yml` | maven_central, pypi, npm | schedule (nightly) or workflow_dispatch with upload_artifacts=true | GEMFURY_PUSH_TOKEN, GEMFURY_API_TOKEN, ANACONDA_API_TOKEN, NPM_TOKEN |
| arrow-nanoarrow | `python-wheels.yaml` | pypi | push to main branch | NANOARROW_GEMFURY_TOKEN secret |
| avro | `java-publish-snapshot.yml` | maven_central | workflow_dispatch, push to main branch (paths: .github/workflows/java-publish-snapshot.yml, lang/java/**, pom.xml) | Maven settings.xml with ASF_USERNAME and ASF_PASSWORD from GitHub secrets (NEXUS_USER, NEXUS_PW) |
| axis-axis2-java-core | `ci.yml` | maven_central | push to master branch | Maven server credentials (NEXUS_USER/NEXUS_PW) configured via setup-java server-id |
| beam | `beam_Publish_Beam_SDK_Snapshots.yml` | gcr | schedule (every 4 hours) and workflow_dispatch | GCP service account with credentials_json |
| beam | `beam_Publish_Docker_Snapshots.yml` | gcr | schedule (daily at 13:00 UTC) or workflow_dispatch | gcloud auth configure-docker |
| beam | `beam_Release_NightlySnapshot.yml` | maven_central | schedule (cron: '15 12 * * *') and workflow_dispatch | Maven settings.xml with username/password from secrets (NEXUS_USER, NEXUS_PW) |
| beam | `beam_Release_Python_NightlySnapshot.yml` | pypi | schedule (cron: '15 12 * * *') and workflow_dispatch | unknown (credentials likely in run_snapshot_publish.sh script or environment) |
| beam | `build_wheels.yml` | gcs | schedule (nightly), push to master/release branches, tags, pull_request, workflow_dispatch | Self-hosted runner with implicit GCP credentials |
| camel-k | `nightly-release.yml` | maven_central, docker_hub | schedule (cron: 15 0 * * *) and workflow_dispatch | secrets (NEXUS_USER, NEXUS_PW, TEST_DOCKER_HUB_USERNAME, TEST_DOCKER_HUB_PASSWORD) |
| camel-k-runtime | `ci-build.yml` | maven_central | push to main, camel-quarkus-3, or release-* branches | Maven settings.xml with NEXUS_DEPLOY_USERNAME and NEXUS_DEPLOY_PASSWORD from secrets |
| camel-kafka-connector | `asf-snapshots-deploy.yml` | maven_central | schedule (cron: 0 1 * * *) and workflow_dispatch | Maven settings.xml with NEXUS_DEPLOY_USERNAME and NEXUS_DEPLOY_PASSWORD from secrets |
| camel-kameleon | `main.yml` | ghcr | push to main branch, workflow_dispatch | GITHUB_TOKEN with github.actor username |
| camel-kamelets | `ci-build.yml` | maven_central | push to main or release branches | NEXUS_DEPLOY_USERNAME and NEXUS_DEPLOY_PASSWORD secrets |
| camel-karavan | `app.yml` | ghcr | push to main branch (paths: karavan-app/**, karavan-core/**, karavan-designer/**, .github/workflows/app.yml), workflow_dispatch, pull_request to main | GitHub token (secrets.GITHUB_TOKEN) with username github.actor |
| casbin-Casbin.NET-ef-adapter | `gitub-actions-build.yml` | nuget | push to master branch | MYGET_API_TOKEN secret |
| casbin-Casbin.NET-redis-adapter | `build.yml` | nuget | push | MYGET_API_TOKEN secret |
| casbin-Casbin.NET-redis-watcher | `build.yml` | nuget | push, pull_request | MYGET_API_TOKEN secret |
| casbin-docker_auth | `docker-nightly.yml` | docker_hub | push to master branch | DOCKER_USERNAME and DOCKER_PASSWORD secrets |
| cassandra-easy-stress | `ci.yml` | ghcr, github_releases | push to main branch | GITHUB_TOKEN |
| cassandra-sidecar | `publish-test-artifacts.yml` | ghcr, github_releases | workflow_run on CI completion (trunk branch) or workflow_dispatch | GITHUB_TOKEN for GHCR push and GitHub Releases |
| causeway | `ci-build-artifacts-push-maven.yml` | github_packages | schedule (weekly on Sunday 02:00 UTC) and workflow_dispatch | GITHUB_TOKEN (github.token) |
| cayenne | `verify-deploy-on-push.yml` | maven_central | push to master or STABLE-* branches | Maven settings.xml with NEXUS_USER and NEXUS_PW secrets |
| cloudstack | `docker-cloudstack-simulator.yml` | docker_hub | push to main branch or tags 4.*, 5.* | Docker registry credentials via secrets (DOCKERHUB_USER, DOCKERHUB_TOKEN) |
| cloudstack-kubernetes-provider | `build-docker-image.yml` | docker_hub | push to main branch, tags, or pull_request | Docker registry credentials via secrets (DOCKERHUB_USER, DOCKERHUB_TOKEN) |
| commons-crypto | `maven_crosstest.yml` | maven_central | workflow_dispatch, push (on native code changes), workflow_run (after Docker images workflow) | Maven settings.xml configured via actions/setup-java with NEXUS_USER and NEXUS_PW secrets |
| commons-io | `maven.yml` | maven_central | push to master branch, pull_request, workflow_dispatch | Maven settings.xml configured via actions/setup-java with server credentials from GitHub secrets |
| commons-net | `maven.yml` | maven_central | push to master branch in apache/commons-net repository | Maven settings.xml configured via actions/setup-java with server credentials from GitHub secrets (NEXUS_USER, NEXUS_PW) |
| commons-numbers | `maven.yml` | maven_central | push to master branch | Maven settings.xml configured via actions/setup-java with NEXUS_USER and NEXUS_PW secrets |
| cordova-coho | `nightly.yml` | npm | schedule (daily cron) and workflow_dispatch | NODE_AUTH_TOKEN from secrets.CORDOVA_NPM_TOKEN |
| directory-scimple | `snapshot.yml` | maven_central | push to develop branch | Maven server credentials (NEXUS_USERNAME/NEXUS_PASSWORD) configured via setup-java action, GPG signing key for artifact signing |
| doris-opentelemetry-demo | `nightly-release.yml` | docker_hub, ghcr | schedule (cron: '0 0 * * *') | secrets inherited from reusable workflow |
| doris-thirdparty | `build-1.2.yml` | github_releases | schedule (cron: '*/30 * * * *') | GITHUB_TOKEN |
| doris-thirdparty | `build-2.1.yml` | github_releases | schedule (every 30 minutes) | GITHUB_TOKEN with contents: write permission |
| doris-thirdparty | `build-3.0.yml` | github_releases | schedule (every 30 minutes) | GITHUB_TOKEN with contents: write permission |
| doris-thirdparty | `build-3.1.yml` | github_releases | schedule (every 30 minutes) | GITHUB_TOKEN with contents: write permission |
| doris-thirdparty | `build.yml` | github_releases | schedule (every 30 minutes) | GITHUB_TOKEN with contents: write permission |
| drill | `publish-snapshot.yml` | maven_central | push to master branch | Maven settings.xml with ASF_USERNAME and ASF_PASSWORD from GitHub secrets |
| dubbo-initializer | `deploy.yml` | docker_hub | schedule (cron: 0 0/6 * * *) and push to main branch | Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| echarts | `nightly-next.yml` | npm | schedule (cron: '10 9 * * *'), workflow_dispatch, repository_dispatch | NODE_AUTH_TOKEN secret |
| echarts | `nightly.yml` | npm | schedule (cron: 0 9 * * *), workflow_dispatch, repository_dispatch | NODE_AUTH_TOKEN secret |
| echarts-examples | `sync-nightly-mirror.yaml` | npm | schedule (cron: 30 9 * * *) and workflow_dispatch | registry-url configured in actions/setup-node (likely uses NODE_AUTH_TOKEN secret) |
| fineract | `mifos-fineract-client-publish.yml` | maven_central | push to develop-mifos branch | Username/password credentials stored in GitHub secrets (ARTIFACTORY_USERNAME, ARTIFACTORY_PASSWORD) |
| flink-docker | `snapshot.yml` | ghcr | schedule (daily cron) and workflow_dispatch | GITHUB_TOKEN with packages: write permission |
| flink-kubernetes-operator | `publish_snapshot.yml` | maven_central | schedule (daily cron) and workflow_dispatch | Maven settings.xml with ASF_USERNAME and ASF_PASSWORD from GitHub secrets |
| fory | `release-java-snapshot.yaml` | maven_central | push to main or release-java-snapshot branches | Maven server credentials (NEXUS_USERNAME/NEXUS_PASSWORD) configured via actions/setup-java with server-id apache.snapshots.https |
| gluten | `velox_nightly.yml` | apache_dist | schedule (nightly cron: '0 0 * * *') and push to main branch | SSH key authentication via secrets.NIGHTLIES_RSYNC_KEY |
| grails-core | `forge-deploy-next.yml` | gcr | workflow_dispatch | GCP service account credentials via secrets.GCP_CREDENTIALS |
| grails-core | `forge-deploy-prev-snapshot.yml` | gcr | workflow_dispatch | GCP service account credentials via secrets.GCP_CREDENTIALS |
| grails-core | `forge-deploy-prev.yml` | gcr | workflow_dispatch | GCP service account credentials via secrets.GCP_CREDENTIALS |
| grails-core | `forge-deploy-snapshot.yml` | gcr | workflow_dispatch | GCP service account credentials via secrets.GCP_CREDENTIALS |
| grails-core | `gradle.yml` | maven_central | push to version branches ([0-9]+.[0-9]+.x) or workflow_dispatch | Username/password credentials stored in GitHub secrets (NEXUS_USER, NEXUS_PW) |
| grails-gradle-publish | `ci.yaml` | maven_central | push to any branch (excluding tags) or workflow_dispatch, restricted to apache org | MAVEN_PUBLISH_USERNAME and MAVEN_PUBLISH_PASSWORD secrets |
| grails-quartz | `gradle.yml` | maven_central, github_pages | push to version branches or workflow_dispatch (only for apache org) | NEXUS_USER/NEXUS_PW secrets for Maven, GITHUB_TOKEN for GitHub Pages |
| grails-redis | `gradle.yml` | maven_central, github_pages | push to version branches or workflow_dispatch | secrets (NEXUS_USER, NEXUS_PW, GITHUB_TOKEN) |
| grails-spring-security | `gradle.yml` | maven_central, github_pages | push to version branches or workflow_dispatch | secrets.NEXUS_USER and secrets.NEXUS_PW for Maven; secrets.GITHUB_TOKEN for GitHub Pages |
| hertzbeat | `nightly-build.yml` | docker_hub | schedule (cron: '0 0 * * *') and push to action* branches | Docker Hub username/password via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| hive | `docker-images.yml` | docker_hub | workflow_dispatch, schedule (nightly at 3:17 AM), create (tags starting with 'rel/') | Docker Hub username/password via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| incubator-baremaps | `snapshot.yml` | maven_central | push to main branch | Maven server credentials (NEXUS_USER/NEXUS_PW) and GPG signing key configured via setup-java action |
| karaf-minho | `deploy.yml` | maven_central | schedule (cron: '30 2 * * *') and workflow_dispatch | secrets.NEXUS_USER and secrets.NEXUS_PW passed via environment variables |
| kvrocks | `nightly.yaml` | docker_hub | push to unstable branch or v2.** tags | Docker Hub credentials via secrets.DOCKER_USERNAME and secrets.DOCKER_PASSWORD |
| kyuubi | `publish-snapshot-docker.yml` | docker_hub | schedule (cron: '0 0 * * *') | Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN |
| kyuubi | `publish-snapshot-nexus.yml` | maven_central | schedule (daily cron: 0 0 * * *) | ASF_USERNAME and ASF_PASSWORD environment variables from secrets.NEXUS_USER and secrets.NEXUS_PW |
| kyuubi-shaded | `publish-snapshot-nexus.yml` | maven_central | schedule (daily cron: 0 0 * * *) | Maven settings.xml with ASF_USERNAME and ASF_PASSWORD environment variables from GitHub secrets |

## CI Infrastructure Image Workflows

These workflows push Docker images used only for CI build caching, test execution, or build acceleration. They do not publish end-user artifacts.

<details>
<summary>Show 37 CI infrastructure workflows</summary>

| Repository | Workflow | Target | Summary |
|------------|----------|--------|---------|
| airflow | `additional-ci-image-checks.yml` | ghcr | This workflow pushes early BuildX cache images to GitHub Container Registry (GHCR) to accelerate CI builds. The push-early-buildx-cache-to-github-registry job calls a reusable workflow that pushes CI cache images (not production images) to GHCR for the apache/airflow repository. This is purely CI infrastructure optimization - the images are used for build caching, not consumed by end users. The workflow also includes a validation step to ensure images build quickly after cache refresh. |
| airflow | `ci-image-build.yml` | ghcr | This workflow builds Apache Airflow CI Docker images for different Python versions and platforms (linux/amd64, linux/arm64). When push-image is true, it pushes these images to GitHub Container Registry (ghcr.io). The images are used for CI/CD infrastructure including build caching and testing, not as release artifacts for end users. The workflow also manages mount cache artifacts for build acceleration. |
| airflow | `finalize-tests.yml` | ghcr | This workflow finalizes test runs by updating constraints and pushing Docker build cache images to GHCR. The push-buildx-cache-to-github-registry job calls a reusable workflow (push-image-cache.yml) that pushes CI/build cache images to GitHub Container Registry. These are infrastructure images used for CI build acceleration, not release artifacts consumed by end users. The workflow is triggered via workflow_call and includes safety checks to prevent PRs from forks from pushing images. |
| airflow | `prod-image-build.yml` | ghcr | This workflow builds Apache Airflow production Docker images and pushes them to GitHub Container Registry (ghcr.io). It's a reusable workflow (workflow_call) that builds Airflow packages and provider distributions, then constructs production Docker images for multiple Python versions. The images are pushed to ghcr.io when push-image input is true. This is CI infrastructure because these are build/test images for the Airflow project itself (pushed to ghcr.io/apache/airflow), not release artifacts distributed to end users. The workflow authenticates using GITHUB_TOKEN and supports conditional pushing based on input parameters. |
| airflow | `push-image-cache.yml` | ghcr | This workflow pushes CI and PROD Docker image caches to GitHub Container Registry (ghcr.io) for build acceleration. It builds images using the 'breeze' tool with --push and --prepare-buildx-cache flags. The images are used for CI/CD build caching, not for end-user consumption. The workflow is triggered via workflow_call with configurable parameters for Python versions, platforms, and cache types (Early/Regular). |
| arrow | `cpp.yml` | docker_hub | This workflow builds and tests C++ components across multiple platforms (Linux, macOS, Windows). On successful builds to the main branch of apache/arrow, it pushes Docker images to Docker Hub using the 'archery docker push' command. The images pushed (conda-cpp, ubuntu-cpp-sanitizer, ubuntu-cpp) are CI infrastructure images used for building and testing, not release artifacts for end users. |
| arrow | `cpp_extra.yml` | docker_hub, ghcr | This workflow builds and tests C++ components across multiple platforms (Alpine, Ubuntu, Debian, macOS, Windows ARM64) and specialized configurations (JNI, ODBC). On successful builds to the main branch, it pushes Docker images to Docker Hub (alpine-linux-cpp, ubuntu-cpp, debian-cpp, conda-cpp, ubuntu-cpp-odbc) and GHCR (cpp-jni). These images appear to be used for CI/CD build environments rather than end-user consumption. The workflow also builds ODBC MSI installers and uploads them to nightlies server (not a package registry) and GitHub Releases for release candidates. |
| arrow | `cuda_extra.yml` | docker_hub | This workflow builds CUDA-enabled Docker images for CI testing purposes (ubuntu-cuda-cpp and ubuntu-cuda-python) and pushes them to Docker Hub when triggered by pushes to the main branch. The images are used for testing Apache Arrow with different CUDA and Ubuntu versions. This is CI infrastructure, not end-user consumable artifacts. |
| arrow | `docs.yml` | docker_hub | This workflow builds complete documentation for Apache Arrow using a Debian 12 Docker container. On successful builds pushed to the main branch of apache/arrow, it pushes the debian-docs Docker image to Docker Hub. This is a CI infrastructure image used for documentation building, not a release artifact consumed by end users. |
| arrow | `integration.yml` | docker_hub | This workflow runs integration tests across multiple Apache Arrow language implementations (Rust, Go, Java, JS, .NET, nanoarrow) using Docker containers. On successful completion of tests on the main branch, it pushes the 'conda-integration' Docker image to Docker Hub. This image is used for CI/CD integration testing infrastructure, not consumed by end users as a release artifact. |
| arrow | `python.yml` | docker_hub | This workflow builds and tests Python components of Apache Arrow across multiple platforms (Linux/Docker, macOS, Windows). The Docker job conditionally pushes built Docker images to Docker Hub when triggered by push events to the main branch of apache/arrow repository. These images (conda-python-docs, conda-python, conda-python-pandas, conda-python-no-numpy) are CI infrastructure images used for testing Python builds with various configurations, not release artifacts for end users. |
| arrow | `r.yml` | docker_hub | This workflow builds and tests R packages for Apache Arrow on Ubuntu and Windows. On successful builds to the main branch, it pushes Docker images (ubuntu-r and r) to Docker Hub. These images appear to be CI/test infrastructure images used for building and testing the R package, not release artifacts for end users to consume. |
| arrow | `r_extra.yml` | docker_hub | This workflow builds and tests R packages with various configurations using Docker containers. On successful builds pushed to the main branch of apache/arrow, it pushes the resulting Docker images to Docker Hub using the 'archery docker push' command. These images appear to be CI infrastructure images used for testing R packages with different R versions and configurations (Rocker, Rhub, RStudio variants), not release artifacts for end users. |
| arrow | `ruby.yml` | docker_hub | This workflow builds and tests C GLib and Ruby components across Ubuntu, macOS, and Windows platforms. On successful push to the main branch of apache/arrow, it pushes a Docker image 'ubuntu-ruby' to Docker Hub. This image appears to be used for CI/CD build and test purposes rather than as a release artifact for end users. |
| arrow-go | `test.yml` | ghcr | This workflow runs tests across multiple platforms (Debian, macOS, Windows) and Go versions. It pushes Docker images to GitHub Container Registry (ghcr.io) only when tests succeed on the main branch of apache/arrow-go. These images are used for CI build caching (docker compose pull/push pattern), not as release artifacts for end users. |
| arrow-java | `rc.yml` | ghcr | This workflow builds JNI libraries for Apache Arrow Java across multiple platforms (Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64). It pushes Docker images used for building JNI libraries to GHCR (GitHub Container Registry) when triggered by push to main branch. The workflow also creates GitHub Releases with artifacts when triggered by RC tags, but the Docker image push is purely for CI build infrastructure caching, not for end-user consumption. |
| arrow-nanoarrow | `docker-build.yaml` | ghcr | Builds and pushes Docker images for multiple platforms (ubuntu, fedora, alpine, archlinux, centos) and architectures (amd64, arm64, s390x) to GitHub Container Registry (ghcr.io/apache/arrow-nanoarrow). Images are used for CI verification across different Linux distributions. Pushes only occur on non-PR events in the apache/arrow-nanoarrow repository. Creates multi-arch manifests for ubuntu, fedora, and alpine images. |
| arrow-swift | `test.yaml` | ghcr | This workflow runs tests and linting for the Apache Arrow Swift project. It builds Docker images for testing with multiple Swift versions (5.10, 6.0, 6.1) and pushes these images to GitHub Container Registry (ghcr.io) when changes are pushed to the main branch. The Docker images are used for CI testing purposes, not as release artifacts for end users. |
| beam | `beam_Inference_Python_Benchmarks_Dataflow.yml` | gcr | This workflow builds and pushes a Docker image for VLLM testing to Google Artifact Registry (us-docker.pkg.dev/apache-beam-testing/beam-temp/beam-vllm-gpu-base). The image is used for running inference benchmarks on Dataflow, not for end-user consumption. The workflow runs scheduled daily benchmarks for various ML inference scenarios (PyTorch, VLLM) and publishes metrics to InfluxDB. |
| beam | `beam_PostCommit_Go.yml` | gcr | This workflow runs Go post-commit tests and pushes Docker images to GCR (us.gcr.io/apache-beam-testing/github-actions) for CI testing purposes. The images are used for integration testing of the Apache Beam Go SDK, not for end-user consumption. Authentication is handled via gcloud on self-hosted runners. |
| beam | `beam_PostCommit_Java_Examples_Dataflow_ARM.yml` | gcr | This workflow runs Java Examples integration tests on Google Cloud Dataflow ARM architecture. It builds multi-architecture Docker images (arm64, amd64) and pushes them to GCR at us.gcr.io/apache-beam-testing/github-actions with timestamp-based tags. The images are used for CI testing purposes, not for end-user consumption. The workflow tests multiple Java versions (8, 11, 17, 21, 25) and uses Gradle with the -Ppush-containers flag to publish the test containers. |
| beam | `beam_PostCommit_Python_Arm.yml` | gcr | This workflow builds and pushes multi-architecture (arm64, amd64) Docker images to GCR for Python post-commit testing on Arm. The images are pushed to us.gcr.io/apache-beam-testing/github-actions with timestamp-based tags via the Gradle task with -Ppush-containers flag. These are CI test infrastructure images, not release artifacts for end users. |
| beam | `beam_PreCommit_Flink_Container.yml` | gcr | This workflow builds and pushes Python SDK Docker images to GCR (gcr.io/apache-beam-testing) for CI testing purposes. The images are used to verify Flink container compatibility by running Go, Python, and Java Combine load tests against a temporary Flink cluster. For pull requests, images are pushed to a separate PR-specific repository (beam-sdk-pr) with timestamp-based tags and are deleted after tests complete. This is CI infrastructure, not release artifact publishing. |
| beam | `beam_Publish_BeamMetrics.yml` | gcr | This workflow deploys Apache Beam's metrics infrastructure (beam-test-infra-metrics) to a Kubernetes cluster on a daily schedule. It authenticates to Google Container Registry using gcloud, then runs Gradle tasks to get cluster credentials and deploy. This is CI infrastructure deployment - the metrics system is used for monitoring Beam's CI/CD pipeline performance, not for publishing end-user artifacts. |
| beam | `beam_Python_ValidatesContainer_Dataflow_ARM.yml` | gcr | This workflow validates Python SDK containers for Dataflow ARM architecture by building and pushing multi-architecture (arm64, amd64) Docker images to GCR at us.gcr.io/apache-beam-testing/github-actions. The images are tagged with timestamps and used for CI testing purposes, not for end-user consumption. The Gradle task validatesContainerARM with -Ppush-containers flag handles the container build and push operations. |
| beam | `build_runner_image.yml` | gcr | Builds and pushes Docker images for GitHub Actions self-hosted runners to Google Artifact Registry (us-central1-docker.pkg.dev/apache-beam-testing/beam-github-actions/beam-arc-runner). Images are tagged with 'latest' and commit SHA. Only pushes on master branch commits. This is CI infrastructure, not end-user consumable artifacts. |
| camel-k | `nightly-install-olm.yml` | docker_hub | Nightly workflow that builds and pushes an OLM bundle image to a test Docker Hub registry (docker.io/testcamelk/camel-k-bundle) for testing Operator Lifecycle Manager installation. The image is pushed to a staging registry solely for CI testing purposes, as noted in the comment that this is a workaround until operator-sdk supports local bundle testing. This is CI infrastructure, not a release artifact. |
| cloudberry | `docker-cbdb-build-containers.yml` | docker_hub | Builds and publishes multi-architecture (amd64/arm64) Docker images for Apache Cloudberry DB build environments to Docker Hub. Images are built for Rocky Linux 8/9 and Ubuntu 22.04/24.04, tested with TestInfra, and tagged as cbdb-build-{platform}-latest and cbdb-build-{platform}-{date}-{sha}. These are CI infrastructure images used for building Cloudberry DB, not end-user consumable artifacts. Only pushes on main branch; PR builds validate but do not push. |
| cloudberry | `docker-cbdb-test-containers.yml` | docker_hub | Builds and pushes multi-architecture (AMD64/ARM64) Docker test container images for Apache Cloudberry DB to Docker Hub. Images are tagged as 'cbdb-test-{platform}-latest' and 'cbdb-test-{platform}-{date}-{sha}' for Rocky Linux 8/9 and Ubuntu 22.04/24.04. These are CI/test infrastructure images used for testing Apache Cloudberry DB, not release artifacts for end users. Images are only pushed on main branch commits, not PRs. |
| commons-crypto | `docker_images.yml` | ghcr | Builds and pushes multi-architecture Docker images (linux/amd64, linux/aarch64, linux/riscv64) to GitHub Container Registry (ghcr.io). Images are tagged as 'latest' and used by maven_crosstest.yml workflow for cross-platform testing. Triggered manually or when Dockerfiles change. Uses GITHUB_TOKEN for authentication. |
| couchdb-ci | `image-builder.yml` | ghcr | Workflow builds and pushes Docker images to GHCR (ghcr.io/apache/couchdb-ci) with configurable Erlang/Elixir versions and target platforms. Images are tagged with dockerfile name and Erlang version. This is CI infrastructure for building test/build environments, not end-user consumable artifacts. Triggered manually by repository maintainers via workflow_dispatch. |
| dolphinscheduler-operator | `publish-docker.yaml` | ghcr | Publishes Docker images to GitHub Container Registry (ghcr.io/apache/dolphinscheduler-operator) on every push to master branch. Images are tagged with the commit SHA and 'latest'. This workflow builds and pushes the DolphinScheduler Operator controller image, which appears to be infrastructure for the project's Kubernetes operator rather than a release artifact for end users. The workflow uses make targets (docker-build, docker-push) and authenticates using GITHUB_TOKEN. |
| echarts | `pr-preview.yml` | surge_sh | Deploys PR preview builds to Surge.sh hosting platform. Triggered by workflow_run after 'Node CI' completes successfully. Downloads PR artifacts, extracts PR metadata from files (not event payload), and publishes to PR-specific Surge subdomain. Creates comment with preview link. This is CI infrastructure for PR previews, not end-user artifact distribution. |
| flink-docker | `docker_push.yml` | ghcr | Builds and pushes Apache Flink Docker images to GHCR (ghcr.io) for multiple Flink versions (1.20, 2.0, 2.1, 2.2) and Java versions (8, 11, 17, 21). Images are tagged with version, branch name, and git SHA. Push is skipped for pull requests. This appears to be CI infrastructure for testing/development rather than official release artifacts consumed by end users. |
| flink-kubernetes-operator | `docker_push.yml` | ghcr | Builds multi-platform Docker images for the Flink Kubernetes Operator and pushes them to GitHub Container Registry (ghcr.io). Images are tagged with 'main', commit SHA, and semver patterns. This is CI infrastructure for the operator itself, not release artifacts for end users to consume directly. Images are pushed on commits to main/release branches and RC tags, but only built (not pushed) on pull requests. |
| gluten | `docker_image.yml` | docker_hub | Builds and publishes multiple Docker images to Docker Hub (apache/gluten) for CI/build infrastructure. Images include vcpkg build environments (CentOS 7/8/9 with various GCC versions), CUDF-enabled images, and Maven cache images. Multi-architecture builds (amd64/arm64) use digest-based pushing with manifest merging. These are build/test environment images for the Apache Gluten project, not end-user release artifacts. |
| kafka-site | `build-docker-image.yml` | ghcr | Builds a multi-platform Docker image (linux/amd64, linux/arm64) containing a Hugo-generated static site and pushes it to GitHub Container Registry (ghcr.io). The workflow triggers on push and pull_request events to the markdown branch, uses GitHub Actions cache for Docker layer caching, and authenticates with GITHUB_TOKEN. This is CI infrastructure for building and caching the kafka-site documentation container, not a release artifact for end users. |

</details>

## Documentation / Website Workflows

<details>
<summary>Show 154 documentation workflows</summary>

| Repository | Workflow | Target | Summary |
|------------|----------|--------|---------|
| age-website | `build-documentation.yml` | github_pages | Builds Gatsby website and Sphinx documentation, then deploys both to GitHub Pages (asf-site branch). First deploys Gatsby build output to root, then deploys Sphinx multi-version docs to /age-manual subdirectory. |
| airflow | `ci-image-checks.yml` | s3 | This workflow builds Apache Airflow documentation and publishes it to AWS S3 (s3://apache-airflow-docs) during canary runs triggered by schedule or workflow_dispatch events. The publish-docs job builds documentation, generates SBOMs, validates doc versions, and syncs the generated docs to S3 using AWS CLI. It also includes static checks, mypy checks, and Python API client tests, but these do not publish artifacts. |
| airflow | `integration-system-tests.yml` | codecov | This is a reusable workflow that runs integration and system tests for Apache Airflow. It uploads code coverage reports to Codecov via the post_tests_success action in multiple jobs (tests-core-integration, tests-providers-integration, tests-system). The workflow does not publish any release artifacts or CI infrastructure images; it only uploads test coverage data for documentation purposes. |
| airflow | `publish-docs-to-s3.yml` | s3 | Builds Apache Airflow documentation from a specified ref and publishes it to S3 buckets (live or staging). The workflow builds docs using Breeze, optionally applies patch commits, generates SBOMs, adds watermarks for staging, and syncs the documentation to s3://live-docs-airflow-apache-org/docs/ or s3://staging-docs-airflow-apache-org/docs/. After publishing, it triggers a registry update workflow for provider documentation. |
| airflow | `registry-backfill.yml` | s3 | Publishes Apache Airflow provider registry documentation to S3 buckets (staging or live). Backfills specific provider versions by extracting metadata from git tags, building static registry site pages, and syncing HTML/JSON files to s3://staging-docs-airflow-apache-org/registry/ or s3://live-docs-airflow-apache-org/registry/. This is documentation publishing, not artifact distribution. |
| airflow | `registry-build.yml` | s3 | This workflow builds and publishes the Apache Airflow provider registry documentation site to S3. It extracts provider metadata using breeze, builds a static site with Eleventy (Node.js), and syncs the output to either a staging or live S3 bucket (live-docs-airflow-apache-org or staging-docs-airflow-apache-org). Supports incremental builds for specific providers by merging with existing S3 data. The workflow is restricted to trusted Apache Airflow committers via an explicit allowlist. |
| airflow-site | `build.yml` | s3, github_releases | This workflow builds the Apache Airflow documentation website and publishes it to S3 (live-docs-airflow-apache-org or staging-docs-airflow-apache-org) by pushing to a publish branch. It also creates GitHub releases with sphinx_airflow_theme packages. The workflow uploads built documentation to S3 via git push to a publish branch (which triggers ASF publishing tools), and creates GitHub releases with theme packages. This is primarily a documentation publishing workflow. |
| airflow-site-archive | `github-to-s3.yml` | s3 | This workflow syncs Apache Airflow documentation from GitHub to S3 buckets for hosting. It supports both live and staging destinations, can sync specific document packages or all packages, and handles both full syncs and single-commit syncs. The workflow uses AWS CLI and a custom Python script to upload documentation files to S3, and optionally syncs registry files. For staging deployments, it adds watermarks to CSS files. |
| airflow-site-archive | `s3-to-github.yml` | s3 | This workflow syncs Apache Airflow documentation from S3 buckets (live or staging) to GitHub, generates back-references for providers/components, and optionally syncs the updated back-references back to S3. The primary publishing action is uploading generated back-reference documentation to S3 using a custom Python script (github_to_s3.py). This is documentation publishing, not release artifacts. |
| ambari-website | `website.yml` | github_pages | Builds Apache Ambari documentation website using Node.js/Yarn and deploys to GitHub Pages via the asf-site branch using peaceiris/actions-gh-pages action. Also updates .asf.yaml configuration file on the asf-site branch. Triggered on push to main branch. |
| amoro | `core-hadoop2-ci.yml` | codecov | CI workflow that builds Amoro with Maven on JDK 11, validates checkstyle, runs tests with code coverage, and uploads coverage reports to Codecov. No release artifacts are published. |
| amoro | `site-deploy.yml` | github_pages | This workflow builds and deploys documentation and website content to the asf-site branch (Apache Software Foundation's GitHub Pages pattern). It has three jobs: deploy-site-page builds the main Amoro site, deploy-latest-docs-page builds the latest documentation, and deploy-versioned-docs-page builds version-specific documentation. All jobs use Hugo to generate static content and push the results to the asf-site branch via git push, which serves as the source for GitHub Pages hosting at amoro.apache.org. |
| amoro | `trino-ci.yml` | codecov | CI workflow that builds Trino module with Maven and uploads code coverage reports to Codecov. No release artifacts or packages are published. |
| answer-website | `deploy.yml` | github_pages | Builds a website using pnpm and Docusaurus-like tooling, then deploys the ./build directory to a GitHub Pages branch (dist-pages) using peaceiris/actions-gh-pages. Only publishes on push to main, not on pull requests. |
| apachecon-acasia | `build.yml` | github_pages | Builds Hugo documentation site on push to master and deploys to gh-pages branch for GitHub Pages hosting. On pull requests, only builds without deploying. |
| apachecon-eu | `build.yml` | github_pages | Builds Hugo documentation site and publishes to GitHub Pages via gh-pages branch on push to main. Pull requests only build without deploying. |
| apisix-go-plugin-runner | `unit-test-ci.yml` | — | This workflow runs unit tests on push/PR to master and uploads code coverage reports to Codecov. The coverage upload is classified as documentation publishing, not artifact release. |
| apisix-ingress-controller | `unit-test.yml` | codecov | Runs unit tests and uploads coverage reports to Codecov. This is documentation publishing (metrics/coverage data), not artifact release. |
| apisix-python-plugin-runner | `runner-unit.yml` | codecov | Unit test workflow that runs tests across Python 3.7-3.10 and uploads coverage reports to Codecov for the Python 3.7 matrix job. |
| apisix-website | `deploy.yml` | github_pages | Builds the Apache APISIX website using Docusaurus and deploys the static site to the asf-site branch for GitHub Pages hosting. The workflow syncs documentation from multiple repositories, builds the site with caching optimizations, and publishes to GitHub Pages on push to master or via scheduled runs. A Netlify deployment option exists but is currently disabled. |
| arrow-adbc | `nightly-website.yml` | github_pages | Builds documentation using Docker Compose, then publishes to the asf-site branch (Apache Software Foundation's standard documentation branch pattern). The workflow downloads built docs artifacts, processes them with sphobjinv, and pushes to the asf-site branch which typically serves as the source for GitHub Pages or Apache project websites. |
| arrow-cookbook | `deploy_development_cookbooks.yml` | github_pages | Builds Apache Arrow cookbook documentation (R, Python, Java, C++) and deploys to GitHub Pages (gh-pages branch) and Apache Software Foundation site (asf-site branch). Triggered on push to main branch. Uses nightly Arrow builds for development documentation. |
| arrow-cookbook | `deploy_stable_cookbooks.yml` | github_pages | Builds Apache Arrow cookbook documentation (R, Python, Java, C++) and deploys to GitHub Pages (gh-pages branch) and Apache Software Foundation site (asf-site branch). Triggered on push to stable branch. Uses GitHub Actions artifacts for intermediate storage between jobs, then force-pushes built documentation to gh-pages and asf-site branches. |
| arrow-flight-sql-postgresql | `doc.yaml` | github_pages | Builds documentation using rake doc:html and publishes it to the asf-site branch (GitHub Pages) via rake doc:publish. The workflow runs on both pull requests and pushes, but only publishes to the actual asf-site branch when running in the apache organization repository. For forks, it creates a local bare repository to test the publish workflow without pushing externally. |
| arrow-go | `benchmark.yml` | s3 | Workflow runs Go benchmarks and uploads results to Conbench (https://conbench.arrow-dev.org), a benchmark metrics dashboard service. The upload only occurs on pushes to main branch in the apache/arrow-go repository. This is categorized as documentation since it publishes benchmark metrics/dashboards rather than consumable artifacts. |
| arrow-julia | `ci.yml` | github_pages | This workflow runs CI tests for Apache Arrow Julia packages and deploys documentation using julia-actions/julia-docdeploy. The docs job publishes documentation (likely to GitHub Pages) using the DOCUMENTER_KEY secret. The workflow also includes license auditing, release verification, comprehensive testing across multiple Julia versions and operating systems, monorepo testing, and code formatting checks. No artifacts are published to package registries; only documentation deployment occurs. |
| arrow-julia | `ci_nightly.yml` | codecov | Nightly CI workflow that runs tests on Julia nightly builds and uploads coverage reports to Codecov. No release artifacts are published. |
| arrow-nanoarrow | `coverage.yaml` | codecov | Workflow calculates code coverage for C, R, and Python components using Docker, then uploads coverage reports to Codecov for visualization and tracking. Also uploads coverage artifacts to GitHub Actions artifact storage (ephemeral). |
| arrow-nanoarrow | `packaging.yaml` | github_pages | This workflow builds documentation from source archives and publishes it to the asf-site branch (GitHub Pages) when triggered on the main branch. It also creates GitHub releases with artifacts for tagged releases. The primary publishing activity is documentation deployment to GitHub Pages via git push to the asf-site branch. |
| arrow-rs | `docs.yml` | github_pages | Generates Rust documentation using cargo doc and deploys it to GitHub Pages (asf-site branch) on pushes to main. The workflow builds rustdocs for all workspace crates with private items included, uploads them as artifacts, then deploys to the asf-site branch using peaceiris/actions-gh-pages action. |
| arrow-site | `deploy.yml` | github_pages | Builds Jekyll-based Apache Arrow website and deploys to GitHub Pages. For apache/arrow-site repository, pushes built site to asf-site branch (Apache's hosting mechanism). For forks, deploys to GitHub Pages using actions/deploy-pages. Triggered on push to any branch except dependabot branches, and on pull requests. |
| arrow-site | `devdocs.yml` | github_pages | This workflow fetches nightly development documentation artifacts from Apache Arrow's Crossbow CI system, extracts them, and publishes them to the asf-site branch (GitHub Pages) at docs/dev/. It runs on a daily schedule and can be manually triggered. The workflow downloads pre-built docs from Crossbow artifacts, prepares them by extracting and organizing files, then commits and pushes changes to the asf-site branch if there are updates. |
| attic | `website.yml` | github_pages | Builds Apache Attic Jekyll website and publishes to GitHub branches (asf-site, cwiki-retired) for documentation hosting via GitHub Pages. Main branch pushes to production branches, while PR/feature branches push to staging branches for preview. |
| auron-sites | `deploy-website.yml` | github_pages | Builds VuePress documentation site and deploys to asf-site branch (Apache project GitHub Pages pattern). Triggered on push to master/branch-* branches and manual dispatch. Uses custom local action ./.github/actions/vuepress-build-and-deploy to build docs and push to TARGET_BRANCH (asf-site), which is the standard Apache Software Foundation pattern for GitHub Pages hosting. |
| avro | `deploy-docs.yml` | github_pages | Builds Hugo-based website and API documentation for multiple languages (C, C++, C#, Java, Python, Rust), then force-pushes the compiled static site to the asf-site branch for Apache Software Foundation GitHub Pages hosting. Also retrieves old documentation versions from Apache Subversion. |
| beam | `beam_PreCommit_Python_Coverage.yml` | codecov | This workflow runs Python coverage tests on pull requests and scheduled intervals, then uploads coverage reports to Codecov. The codecov-action publishes test coverage metrics/documentation, not release artifacts. The workflow also uploads test results as GitHub Actions artifacts (ephemeral storage) and publishes test result comments. |
| beam | `beam_PreCommit_SQL.yml` | codecov | This workflow runs SQL precommit tests for Apache Beam and uploads code coverage reports to Codecov. It does not publish any release or snapshot artifacts to package registries. The workflow uses actions/upload-artifact for ephemeral CI storage of test results, SpotBugs reports, and Jacoco coverage reports, but only the Codecov upload constitutes publishing to an external service. |
| beam | `beam_PreCommit_Website_Stage_GCS.yml` | gcs | This workflow publishes the Apache Beam website documentation to Google Cloud Storage (GCS) bucket 'apache-beam-website-pull-requests'. It stages website previews for pull requests and branch builds, making them accessible via HTTP URLs. The workflow is triggered on pushes to tags/branches, pull requests, comments, schedule, and manual dispatch. It uses GCP service account authentication to upload the staged website content. |
| beam | `beam_Publish_Website.yml` | github_pages | Scheduled workflow that publishes the Apache Beam website. Runs Gradle task ':website:publishWebsite' which likely pushes generated documentation to GitHub Pages or GCS. Authenticates with GCP service account and uses git remote to apache/beam repository. Runs on schedule (every 6 hours starting at 5:30 UTC) or manual dispatch. |
| bifromq-sites | `deploy.yml` | github_pages | Builds a static website using pnpm and deploys it to the asf-site branch using GitHub Pages action. The deployment is manually triggered via workflow_dispatch and can be toggled with the deploy input parameter. Uses GITHUB_TOKEN for authentication. |
| bookkeeper | `website-deploy.yaml` | github_pages | Builds and deploys the Apache BookKeeper website. Triggered on pushes to master branch affecting site3/** paths or manual dispatch. Uses build-website.sh and publish-website.sh scripts to build and publish the website to https://bookkeeper.apache.org/ (likely GitHub Pages for Apache project). Authenticates with GITHUB_TOKEN. |
| brpc-website | `build_and_deploy.yml` | github_pages | Builds Hugo-based documentation website and deploys to GitHub Pages (asf-site branch) on push to master. Uses peaceiris/actions-gh-pages action to publish static site content. |
| buildstream | `merge.yml` | github_pages | Builds BuildStream documentation using Docker Compose on master branch pushes, then force-pushes the generated HTML and tarball to the gh-pages branch for GitHub Pages hosting. The workflow resets gh-pages to its initial commit on each run to avoid polluting history with every docs build. |
| buildstream-plugins | `merge.yml` | github_pages | This workflow builds documentation and publishes it to GitHub Pages (gh-pages branch). Triggered on push to master, it builds HTML docs using Docker Compose, creates a tarball, and force-pushes the generated documentation to the gh-pages branch for hosting. |
| burr | `build-site.yml` | github_pages | Builds Next.js landing page and Sphinx documentation, then deploys the combined site to the asf-site branch (for main) or asf-staging branch (for other branches). This is a documentation publishing workflow using GitHub Pages-style branch deployment (asf-site branch). Includes HTML redirect fallbacks for Sphinx docs migration. |
| burr | `docs.yml` | github_pages | Builds Sphinx documentation and deploys to GitHub Pages. On main branch pushes, deploys to root of gh-pages branch. On pull requests, deploys preview to pull/{PR_NUMBER} subdirectory. Uses peaceiris/actions-gh-pages action with GITHUB_TOKEN for authentication. |
| calcite | `publish-non-release-website-updates.yml` | github_pages | This workflow publishes documentation website updates. When changes are pushed to the site/ folder on main branch, it cherry-picks the commit to the 'site' branch, builds the website using Docker, and pushes the generated static site to the apache/calcite-site repository (GitHub Pages). The workflow preserves existing javadoc and avatica content while updating other site files. |
| calcite | `publish-website-on-release.yml` | github_pages | Publishes Apache Calcite documentation website to apache/calcite-site repository on GitHub when a release tag is pushed. Builds site and javadoc using Docker Compose, then pushes generated content to the calcite-site repo's main branch. |
| calcite-avatica | `publish-non-release-website-updates.yml` | github_pages | This workflow builds the Avatica website using Docker Compose, then pushes the generated static site content to the apache/calcite-site repository (which hosts the project's GitHub Pages site). It is triggered on pushes to main branch when specific site files are modified. The workflow excludes most documentation files but includes specific ones like docker_images.md, history.md, howto.md, and index.md. Javadoc content is preserved during the update. |
| calcite-avatica | `publish-site-and-javadocs-on-release.yml` | github_pages | Publishes Apache Calcite Avatica website and javadocs to the apache/calcite-site repository when a release tag is pushed. Builds site and javadoc using Docker Compose, then commits and pushes the generated content to the calcite-site repository's main branch. |
| calcite-avatica-go | `publish-website.yml` | github_pages | Builds the Avatica Go client documentation site using Jekyll in Docker, then commits and pushes the generated static site to the apache/calcite-site repository (main branch) which hosts the project's public website. Triggered on version tags or main branch pushes affecting site files. |
| camel-website | `preview.yaml` | netlify | This workflow publishes documentation preview builds to Netlify. It is triggered after the 'Pull request checks' workflow completes successfully. The workflow downloads the website artifact from the previous workflow run, extracts the PR number from the artifact content, and deploys a preview to Netlify with a PR-specific alias. A comment with the preview URL is then posted to the pull request. |
| casbin-actix-casbin-auth | `coverage.yml` | codecov | Workflow runs cargo-tarpaulin to generate code coverage reports and uploads them to Codecov using codecov-action. Triggered on push and pull requests to master branch. |
| casbin-aspnetcore | `build.yml` | coveralls | This workflow builds, tests, and benchmarks a .NET project on pull requests. It uploads code coverage to Coveralls (documentation category) when triggered by push events. The workflow also packs NuGet packages with version suffixes but only uploads them to ephemeral GitHub Actions artifacts storage, not to any NuGet registry. The coverage upload is the only true external publishing action. |
| casbin-axum-casbin | `coverage.yml` | codecov | Workflow runs cargo-tarpaulin to generate code coverage reports and uploads them to Codecov using codecov-action. Triggered on push and pull requests to master branch. |
| casbin-editor | `master.yml` | github_pages | Builds a Node.js/Yarn project and deploys the output to the asf-site branch for GitHub Pages hosting. The workflow runs on push to master, pull requests (build only), and manual dispatch. Uses peaceiris/actions-gh-pages action to publish the ./out directory to the asf-site branch with force_orphan enabled. |
| casbin-lua-casbin | `build.yml` | coveralls | CI workflow that runs tests across multiple Lua versions (5.1-5.4, luajit-openresty), performs linting with Luacheck, and uploads test coverage reports to Coveralls. Also includes a benchmark job using LuaJIT. The coverage upload is the only publishing action, categorized as documentation. |
| casbin-mcp-gateway | `ci.yml` | codecov | This workflow runs tests and builds a Go backend with Node.js frontend. It uploads test coverage to Codecov (documentation category) and stores build artifacts in GitHub Actions ephemeral storage. The actions/upload-artifact step does not constitute registry publishing as it's internal CI storage. |
| casbin-python-fastapi-casbin-auth | `coverage.yml` | coveralls | Workflow runs test coverage using pytest and uploads coverage reports to Coveralls service. This is documentation/metrics publishing, not artifact distribution. |
| casbin-rs | `coverage.yml` | codecov | This workflow runs code coverage analysis using cargo-tarpaulin on pull requests and pushes to master, then uploads the coverage report to Codecov. This is classified as documentation publishing since coverage reports are metrics/documentation artifacts, not consumable software packages. |
| casbin-rust-actix-casbin | `coverage.yml` | codecov | Workflow runs cargo-tarpaulin to generate code coverage reports and uploads them to Codecov using codecov-action. Triggered on push and pull requests to master branch. |
| casbin-rust-diesel-adapter | `coverage.yml` | codecov | Workflow runs test coverage analysis using cargo-tarpaulin and uploads coverage reports to Codecov. This is a documentation/metrics publishing workflow, not artifact distribution. |
| casbin-rust-postgres-adapter | `coverage.yml` | codecov | Workflow runs code coverage tests using tarpaulin on a Rust project with PostgreSQL integration tests, then uploads coverage reports to Codecov. Triggered on push/PR to master branch. |
| casbin-rust-redis-watcher | `coverage.yml` | codecov | This workflow runs code coverage tests using cargo-tarpaulin on Rust code with Redis and Redis Cluster services, then uploads the coverage report to Codecov. This is a documentation/metrics publishing workflow, not artifact distribution. |
| casbin-rust-rocket-authz | `coverage.yml` | codecov | Workflow runs cargo-tarpaulin to generate code coverage reports and uploads them to Codecov for documentation/metrics purposes. Triggered on push and pull requests to master branch. |
| casbin-rust-salvo-casbin | `coverage.yml` | codecov | Workflow runs cargo-tarpaulin to generate code coverage reports and uploads them to Codecov for documentation/metrics tracking. Triggered on push and pull requests to master branch. |
| casbin-rust-string-adapter | `coverage.yml` | codecov | Workflow runs cargo-tarpaulin to generate code coverage reports and uploads them to Codecov for documentation/metrics tracking. Triggered on push and pull requests to master branch. |
| casbin-sqlx-adapter | `coverage.yml` | codecov | Workflow runs code coverage analysis using cargo-tarpaulin on a Rust project with PostgreSQL integration tests, then uploads coverage reports to Codecov. Triggered on push/PR to master branch. |
| casbin-ucon | `PerformancePush.yml` | github_pages | Runs Go benchmarks on push to master and publishes performance metrics to GitHub Pages (gh-pages branch) using benchmark-action/github-action-benchmark. This is a documentation/metrics publishing workflow, not artifact distribution. |
| casbin-website | `master.yml` | github_pages | Builds a Docusaurus/Node.js website, syncs translations with Crowdin, and deploys the static site to the asf-site branch for GitHub Pages hosting. Publishing only occurs on push to master or workflow_dispatch, not on pull requests. |
| casbin-website-v1-deprecated | `node-ci.yml` | github_pages | Workflow deploys Docusaurus documentation website to GitHub Pages. Triggered on push, it downloads translations from Crowdin, then publishes the website using Docusaurus's publish-gh-pages command with git authentication via GH_TOKEN. |
| celeborn | `maven.yml` | codecov | CI workflow that runs Maven tests across multiple Java versions, Spark versions, Flink versions, and MapReduce. Uploads coverage reports to Codecov for Java 8 service tests. Test logs are uploaded to GitHub Actions artifacts on failure (ephemeral storage, not a registry). |
| celeborn-website | `site.yaml` | github_pages | This workflow builds and deploys the Apache Celeborn project website documentation. It uses mkdocs to generate documentation from the main branch and multiple release versions (0.2.1 through 0.6.2), then pushes the generated static site to the asf-site branch. The asf-site branch is configured via .asf.yaml to be published through Apache Software Foundation's GitHub Pages infrastructure. This is a documentation publishing workflow, not artifact/package distribution. |
| celix | `coverage.yml` | codecov | This workflow generates code coverage reports for the Apache Celix project and uploads them to Codecov. It builds the project with coverage instrumentation enabled, runs tests with coverage collection using lcov, and publishes the coverage.info file to Codecov for visualization and tracking. The upload only occurs for the apache organization repository. |
| cloudberry-site | `publish-cloudberry-site.yml` | github_pages | Builds a Docusaurus website using Node.js and publishes it to the asf-site branch using peaceiris/actions-gh-pages action. The asf-site branch is served by Apache infrastructure at cloudberry.apache.org. Includes link checking validation. Only publishes on push to main branch; pull requests only build without publishing. |
| cloudstack | `ci.yml` | codecov | This workflow runs Apache CloudStack simulator integration tests and uploads code coverage reports to Codecov. It builds the project with Maven, sets up a MySQL database, starts a CloudStack management server with simulator, runs extensive integration tests across multiple test suites, generates Jacoco coverage reports, and publishes the coverage data to Codecov. No release artifacts or packages are published to any package registry. |
| cloudstack | `codecov.yml` | codecov | Workflow builds CloudStack with quality checks and uploads code coverage reports to Codecov using codecov-action. This is a documentation/metrics publishing workflow, not artifact distribution. |
| cloudstack | `ui.yml` | codecov | This workflow builds and tests the CloudStack UI on push and pull_request events. It uploads code coverage reports to Codecov using the codecov-action, which is classified as documentation publishing. The workflow only publishes coverage data when running on the apache/cloudstack repository. |
| cloudstack-kubernetes-provider | `build.yml` | codecov | This workflow runs tests on push and pull_request events, then uploads code coverage reports to Codecov. The coverage upload is classified as documentation publishing, not artifact release. The workflow uses the codecov-action with a CODECOV_TOKEN secret for authentication. |
| cloudstack-www | `deploy.yml` | github_pages | Builds a Node.js/Yarn-based website and publishes it to GitHub Pages via the asf-site branch using peaceiris/actions-gh-pages. Publishing only occurs on push to main branch when repository owner is 'apache'. Pull requests trigger builds but do not publish. |
| cloudstack-www | `stage.yml` | github_pages | Builds a static website using yarn and deploys it to GitHub Pages (staged-site branch) using peaceiris/actions-gh-pages. The workflow publishes documentation to a staging site at cloudstack.staged.apache.org when changes are pushed to the staging-site branch. |
| commons-geometry | `coverage.yml` | codecov | Workflow runs Maven tests with JaCoCo coverage reporting and uploads coverage reports to Codecov for documentation/metrics purposes. Triggered on push and pull_request events. |
| commons-math | `coverage.yml` | codecov | Workflow generates code coverage reports using JaCoCo and uploads them to Codecov for documentation/metrics purposes. Triggered on push, pull requests, and manual dispatch. Uses Maven to build and generate coverage reports, then publishes to Codecov. |
| commons-numbers | `coverage.yml` | codecov | Workflow runs Maven tests with JaCoCo coverage reporting and uploads coverage reports to Codecov for all commons-numbers modules. Triggered on push and pull request events. |
| commons-ognl | `coverage.yml` | codecov | This workflow generates code coverage reports using JaCoCo and uploads them to Codecov for documentation/metrics purposes. It runs on manual trigger (workflow_dispatch) and uses Java 8 to build and test the project before uploading coverage data. |
| commons-rng | `coverage.yml` | codecov | Workflow runs Maven tests with JaCoCo coverage reporting and uploads coverage data to Codecov. This is a documentation/metrics publishing workflow, not artifact distribution. |
| commons-statistics | `coverage.yml` | codecov | Workflow runs Maven tests with JaCoCo coverage reporting and uploads the coverage report to Codecov. This is a documentation/metrics publishing workflow, not artifact distribution. |
| cordova-docs | `deploy-prod.yml` | github_pages | Deploys production documentation site to GitHub Pages (asf-site branch) using JamesIves/github-pages-deploy-action. Builds documentation from master branch using Node.js and Ruby, then publishes the build-prod folder to the asf-site branch for Apache Cordova documentation hosting. |
| cordova-docs | `deploy-stage.yml` | github_pages | Builds Cordova documentation site and deploys it to the asf-staging branch using github-pages-deploy-action. This is a documentation deployment workflow that publishes the built static site from build-prod folder to a git branch for staging purposes. |
| cordova-ios | `docs.yml` | github_pages | Workflow builds DocC documentation for Cordova iOS library using xcodebuild and deploys it to GitHub Pages. Triggered on push to master branch. Uses standard GitHub Pages deployment actions with appropriate permissions. |
| ctakes-website | `jekyll.yml` | github_pages | This workflow builds a Jekyll static site and deploys it to GitHub Pages. The build job installs Ruby/Bundler, builds the Jekyll site with production environment settings, and uploads the artifact. The deploy job then publishes the artifact to GitHub Pages using the official deploy-pages action. |
| curator-site | `deploy.yml` | github_pages | Builds Javadoc from apache/curator repository and deploys a static website to GitHub Pages (asf-site branch). The workflow generates API documentation, builds a Node.js-based site with pnpm, and publishes to the asf-site branch using peaceiris/actions-gh-pages action. |
| daffodil | `main.yml` | codecov | This CI workflow builds and tests Apache Daffodil across multiple Java versions, Scala versions, and operating systems. It uploads coverage reports to Codecov and conditionally runs SonarCloud scans for code quality analysis. No release artifacts or snapshot builds are published to package registries. |
| daffodil-site | `build-publish.yml` | github_pages | Builds a Jekyll static site from the 'site' directory and publishes it to the 'asf-site' branch when changes are pushed to the main branch. The asf-site branch serves as the source for Apache's GitHub Pages hosting. The workflow uses docker://jekyll/jekyll for building and git push for publishing. |
| datafusion | `docs.yaml` | github_pages | Builds documentation using Python/uv and Sphinx, then commits and pushes the generated HTML to the asf-site branch for Apache project website hosting (GitHub Pages). Uses rsync to sync built docs, commits changes, and force-pushes if necessary. |
| datafusion-ballista | `docs.yaml` | github_pages | Builds documentation using Python/Sphinx and publishes to the asf-site branch (Apache Software Foundation's GitHub Pages pattern). Triggered on pushes to main branch affecting docs-related files. Uses rsync to sync built HTML to asf-site branch and force-pushes changes. |
| datafusion-comet | `docs.yaml` | github_pages | Builds documentation using Python/Sphinx, then commits and pushes the generated HTML to the asf-site branch for Apache project website hosting (GitHub Pages equivalent for ASF projects). |
| datafusion-python | `build.yml` | github_pages | This is a reusable workflow that builds Python wheels for multiple platforms (Linux x86_64/ARM64, macOS x86_64/ARM64, Windows) and generates documentation. The documentation build job downloads pre-built Linux wheels, builds HTML docs using Sphinx, and pushes the generated HTML to either the asf-staging branch (for main) or asf-site branch (for tags). The workflow also performs linting, generates license files, and archives build artifacts, but these are uploaded to GitHub Actions artifact storage (ephemeral), not published to external registries. The only external publishing is the documentation push to git branches for Apache project site hosting. |
| datafusion-sandbox | `docs.yaml` | github_pages | Builds documentation using Python/uv and Sphinx, then commits and pushes the generated HTML to the asf-site branch for GitHub Pages hosting. Uses rsync to sync built docs and pushes to asf-site branch with force push fallback. |
| datafusion-site | `publish-site.yml` | github_pages | This workflow builds the Apache DataFusion website using Pelican static site generator and publishes the result to the 'asf-site' branch, which is the standard Apache Software Foundation pattern for hosting project websites via GitHub Pages. |
| datafusion-site | `stage-site.yml` | github_pages | Publishes staged documentation site to asf-staging branch for Apache DataFusion project. Triggered by pull requests with branch names starting with 'site/'. The apache/infrastructure-actions/pelican action builds the Pelican static site and pushes to the asf-staging branch, which ASF infrastructure then publishes to datafusion.staged.apache.org for preview. |
| datasketches-cpp | `code_coverage.yml` | — | Workflow generates code coverage reports using lcov and uploads them to Coveralls for documentation/metrics tracking. This is a documentation publishing workflow, not artifact distribution. |
| datasketches-cpp | `doxygen.yml` | github_pages | Generates Doxygen documentation and publishes it to GitHub Pages (gh-pages branch) under docs/{branch_name} directory. Triggered on pushes to master or manually. |
| datasketches-go | `coverage.yml` | — | Workflow runs Go tests with coverage and uploads coverage reports to Coveralls.io. This is documentation publishing (coverage metrics), not artifact distribution. |
| datasketches-java | `javadoc.yml` | github_pages | This workflow publishes versioned Javadoc documentation to GitHub Pages. It is manually triggered with a Git tag as input, checks out that tag, generates Javadoc using Maven, and pushes the generated documentation to the gh-pages branch under docs/{TAG_NAME}. The workflow uses git worktree for safe branch manipulation and includes error handling. This is documentation publishing, not artifact release. |
| datasketches-memory | `javadoc.yml` | github_pages | This workflow publishes versioned Javadoc documentation to GitHub Pages. It is manually triggered with a Git tag as input, checks out that tag, generates Javadoc using Maven, and pushes the generated documentation to the gh-pages branch under docs/{TAG_NAME}. The workflow uses git worktree for safe branch manipulation and includes error handling. This is documentation publishing, not artifact release. |
| datasketches-python | `sphinx.yml` | github_pages | Builds Sphinx documentation and deploys it to GitHub Pages using peaceiris/actions-gh-pages action. Documentation is published to docs/{branch_name} directory on the gh-pages branch. |
| dolphinscheduler-sdk-python | `ci.yaml` | codecov | This CI workflow runs linting, testing, and documentation builds for the DolphinScheduler Python SDK. It uploads code coverage reports to Codecov after running pytest across multiple Python versions and operating systems. The workflow does not publish any release artifacts or packages to registries like PyPI. |
| dolphinscheduler-website | `website.yml` | github_pages | Builds DolphinScheduler documentation (main docs + Python SDK docs) and deploys to GitHub Pages (asf-site branch) on push/schedule events. Uses peaceiris/actions-gh-pages action to publish built documentation from ./build directory. |
| doris-website | `cron-deploy-website.yml` | s3, github_pages | This workflow builds and deploys the Apache Doris documentation website on an hourly schedule. It builds a Docusaurus site with multiple locales (en, zh-CN, ja), uploads static assets to Aliyun OSS (S3-compatible storage), and deploys the built website to GitHub Pages (asf-site branch). The workflow is designed for documentation publishing, not artifact distribution. |
| doris-website | `cron-generate-pdf.yml` | s3 | Scheduled workflow that generates PDF documentation from Apache Doris website (English and Chinese versions) and uploads them to Aliyun OSS storage. Runs three times daily via cron schedule. Uses a local composite action for OSS upload with credentials passed securely through secrets. |
| doris-website | `manual-deploy-website.yml` | s3, github_pages | This workflow builds a Docusaurus documentation website and publishes it to two destinations: (1) Aliyun OSS (S3-compatible object storage) for CDN hosting, and (2) GitHub Pages (asf-site branch) for Apache project hosting. The workflow is manually triggered with a branch parameter that determines the deployment path. It builds multi-locale documentation (en, zh-CN, ja), uploads static files to Aliyun OSS, and deploys to GitHub Pages with branch-specific paths. |
| doris-website | `manual-generate-pdf.yml` | s3 | Generates PDF documentation from Apache Doris website (English and Chinese versions) and uploads to Aliyun OSS (Object Storage Service). Uses vitpress-generate-pdf to crawl and convert docs to PDF, then uploads via custom Aliyun OSS action. Triggered manually via workflow_dispatch. |
| dubbo-admin | `ci.yml` | codecov | CI workflow that builds frontend (Vue3), runs Go tests, and uploads code coverage to Codecov. The Codecov upload is a documentation/metrics publishing action, not release artifact distribution. |
| dubbo-awesome | `benchmark.yml` | github_pages | Runs benchmark tests from apache/dubbo-benchmark repository and publishes results as markdown files to GitHub Pages (report/benchmark branch). Executes benchmarks for 8 different Dubbo serialization targets, collects output, and deploys to gh-pages for documentation purposes. |
| dubbo-go-pixiu | `github-actions.yml` | codecov | This CI workflow runs license checks, linting, unit tests, and integration tests. It uploads code coverage reports to Codecov using the codecov-action. No release artifacts or packages are published to any package registry. |
| dubbo-js | `node.js.yml` | codecov | This workflow runs CI tests for a Node.js project across multiple Node versions and operating systems. It builds packages, runs Jasmine tests, and uploads code coverage reports to Codecov. The Codecov upload is a documentation/metrics publishing activity, not a release artifact. |
| dubbo-kubernetes | `ci.yml` | codecov | CI workflow that runs unit tests, linting, builds, license checks, and Helm linting. Uploads test coverage to Codecov for documentation/metrics purposes. Does not publish any release or snapshot artifacts to package registries. |
| dubbo-website | `build_and_deploy.yml` | github_pages | Builds Hugo static website with Docsy theme and deploys to GitHub Pages branches. Two jobs: deploy_main publishes to asf-site-v2 branch, deploy_cn publishes Chinese version to cn-site branch along with benchmark data. Triggered on push to master. |
| echarts-handbook | `deploy.yml` | github_pages | Builds the ECharts handbook documentation and deploys it to GitHub Pages (gh-pages branch) on every push to master. The workflow uses the github-pages-deploy-action to publish the dist folder to the docs directory on the gh-pages branch. |
| echarts-theme-builder | `deploy.yml` | github_pages | Builds the project and deploys the dist folder to GitHub Pages (gh-pages branch) on every push to master. Uses the jamesives/github-pages-deploy-action to publish documentation. |
| echarts-website | `deploy.yml` | github_pages | Builds ECharts documentation website from multiple repositories (echarts-www, echarts-doc, echarts-examples, echarts-theme-builder, echarts-handbook) and deploys the compiled static site to the asf-site branch using GitHub Pages Deploy Action. This is a documentation publishing workflow triggered manually via workflow_dispatch. |
| eventmesh | `ci.yml` | codecov | CI workflow that builds EventMesh project on multiple OS/Java versions, runs tests with coverage, and uploads coverage reports to codecov.io. No release artifacts are published to package registries. |
| eventmesh-site | `publish.yml` | github_pages | Builds a Node.js-based website and publishes it to the asf-site branch using GitHub Pages action. Triggered on push to master. Uses the built-in GITHUB_TOKEN for authentication. |
| fesod | `deploy-docs.yml` | github_pages | Builds Docusaurus documentation site and deploys to GitHub Pages (gh-pages branch) on every push to main branch. Uses peaceiris/actions-gh-pages action with force_orphan to maintain only latest commit in publish branch. |
| fesod | `preview-docs.yml` | netlify | Deploys documentation preview builds to Netlify on pull requests that modify website files. Uses nwtgck/actions-netlify action to publish the built website to a preview URL with alias based on PR number. |
| flex-site | `build-pelican.yml` | github_pages | Builds a Pelican static site from the 'main' branch and publishes it to the 'asf-site' branch using Apache Infrastructure's Pelican action. The 'asf-site' branch is typically used by Apache projects to serve GitHub Pages documentation. |
| flink | `docs-legacy.yml` | s3 | Workflow builds legacy Flink documentation for historical release branches (1.0-1.18) and deploys it via rsync to a remote host (likely Apache nightlies server). Triggered manually via workflow_dispatch with branch selection. Uses Docker containers for building Jekyll and Maven-based docs, then uploads to remote server using SSH key authentication. |
| flink | `docs.yml` | s3 | Builds Flink documentation for multiple release branches (master, release-2.2, release-2.1, release-2.0, release-1.20, release-1.19) and deploys via rsync to Apache nightlies infrastructure. Runs daily via cron schedule. Documentation is built in Docker container and uploaded to remote host with branch-specific paths and aliases (e.g., master→release-2.3, release-2.2→stable, release-1.20→lts). |
| flink-agents | `docs.yml` | s3 | Builds Flink Agents documentation using Docker and deploys it via rsync to Apache nightlies infrastructure. Runs daily for main, release-0.2, and release-0.1 branches. Documentation is uploaded to remote paths with branch-specific naming, and some branches get aliased paths (main→release-0.3, release-0.2→latest). |
| flink-cdc | `build_docs.yml` | s3 | Builds Flink CDC documentation using Docker and deploys it via rsync to Apache nightlies infrastructure. The workflow checks for dead links in markdown files, builds documentation for multiple branches (master, release-3.6, release-3.5), and uploads the generated docs to a remote server using SSH/rsync. Pull requests only trigger the doc check job without deployment. Scheduled daily runs and manual triggers perform full build and deployment. |
| flink-kubernetes-operator | `docs.yaml` | apache_dist | Builds Hugo-based documentation and Javadocs for multiple branches (main, release-1.14, release-1.13) and uploads them to Apache nightlies infrastructure via rsync. Runs daily and on manual trigger. Documentation is published to remote paths like flink-kubernetes-operator-docs-{branch} with branch aliases (e.g., main→release-1.15, release-1.14→stable). |
| fluss | `docs-deploy.yaml` | github_pages | Triggers documentation deployment by sending a repository_dispatch event to apache/fluss-website repository, which then deploys the documentation (likely to GitHub Pages or similar). This is an indirect documentation publishing workflow. |
| fluss-rust | `deploy_documentation.yml` | github_pages | Builds a Node.js-based website and deploys it to the gh-pages branch for GitHub Pages hosting. Triggered manually via workflow_dispatch. Uses GITHUB_TOKEN for authentication. |
| fluss-website | `website-deploy.yaml` | github_pages | Workflow builds and deploys the Apache Fluss website documentation. Triggered by repository_dispatch event, it checks out the main repository, generates versioned docs, builds the website using npm, and deploys it using 'npm run deploy' (likely to GitHub Pages). Uses GITHUB_TOKEN for authentication. |
| fory-site | `deploy.yml` | github_pages | Builds documentation site using Python and Node.js, then deploys to GitHub Pages via the 'deploy' branch using peaceiris/actions-gh-pages action. Only runs on push to main (skipped for pull requests). |
| geaflow-website | `deploy.yml` | github_pages | Builds a website using yarn and deploys it to GitHub Pages (asf-site branch) using peaceiris/actions-gh-pages. Only deploys on push events, not pull requests. |
| gluten | `nightly_sync.yml` | apache_dist | This workflow publishes documentation to Apache's nightly distribution infrastructure. It builds Jekyll documentation pages and uses rsync to deploy them to a remote Apache server. Triggered on pushes to docs/ directory. Uses SSH key authentication to connect to Apache's nightlies server. |
| grails-core | `release-publish-docs.yml` | github_pages | Workflow generates Grails documentation using Gradle and publishes it to GitHub Pages (apache/grails-website repository, asf-site-production branch). Triggered manually via workflow_dispatch with a version input. Uses a custom Apache Grails action to deploy documentation to a separate website repository. |
| grails-static-website | `publish.yml` | github_pages | Publishes Grails static website and guides documentation. Runs a custom publish.sh script that builds the site using Gradle and pushes to GitHub Pages branches (asf-site-production for main site, gh-pages for guides). Uses GitHub tokens for authentication to push to separate repositories. |
| gravitino-site | `deploy.yml` | github_pages | Builds a Node.js/pnpm-based website and deploys it to GitHub Pages (asf-site branch) on pushes to main. Uses peaceiris/actions-gh-pages action with automatic GITHUB_TOKEN authentication. The .asf.yaml file is copied to the build directory, indicating this is an Apache Software Foundation project site deployment. |
| groovy | `groovy-build-coverage.yml` | codecov | This workflow runs Gradle tests with coverage enabled and uploads the coverage report to Codecov. It triggers on push and pull_request events. The coverage upload is classified as documentation publishing, not artifact release. |
| hadoop | `website.yml` | github_pages | Builds Apache Hadoop documentation using Maven site plugin and deploys the generated static site to GitHub Pages. Triggered on pushes to trunk branch. Uses peaceiris/actions-gh-pages action to publish the staged documentation from ./staging/hadoop-project directory. |
| hamilton | `docusaurus-gh-pages.yml` | github_pages | Builds a Docusaurus documentation site and deploys it to GitHub Pages. The workflow compiles documentation from Python code, builds the Docusaurus site with Node.js/Yarn, and publishes the static site to GitHub Pages using the official deploy-pages action. Only the 'deploy' job (triggered on main branch) actually publishes; the 'branch-build' job only builds without deploying. |
| hamilton | `sphinx-docs.yml` | github_pages | Builds Sphinx documentation (HTML and PDF) and deploys to GitHub Pages-style branches (asf-site for main, asf-staging for update_references). Uses git push to deploy documentation content to separate branches within the same repository. Only deploys on push events (not pull requests). |
| hertzbeat | `backend-build-test.yml` | codecov | This workflow builds and tests a Java backend project with Maven, uploads coverage reports to Codecov, builds a Docker image for testing (not pushed), runs E2E tests with docker-compose, and uploads test logs/reports to GitHub Actions artifacts. The only external publishing is coverage data to Codecov. |
| hertzbeat | `doc-deploy.yml` | github_pages | Builds documentation site from home/ directory using Node.js/pnpm and deploys to asf-site branch using peaceiris/actions-gh-pages action. This is a standard Apache project documentation deployment workflow where the asf-site branch serves GitHub Pages content. |
| hive-site | `gh-pages.yml` | github_pages | Builds a Hugo static site and deploys it to GitHub Pages via the asf-site branch. The build job generates the site from source, and the deploy job (triggered only on push to main) publishes the content using peaceiris/actions-gh-pages action. This is documentation publishing for the Apache Hive project website. |
| hugegraph-doc | `hugo.yml` | github_pages | Builds a Hugo static site and deploys it to GitHub Pages (asf-site branch) on push to master. Uses peaceiris/actions-gh-pages to publish the built site from ./public directory. Triggered on pull requests for validation but only deploys on master branch pushes. |
| incubator-baremaps-site | `publish.yml` | github_pages | Builds a Node.js-based website and deploys it to GitHub Pages (asf-site branch) on push to main. Uses peaceiris/actions-gh-pages action to publish the ./out directory. |
| kafka-site | `build-and-deploy.yml` | apache_dist | Builds Apache Kafka website documentation from markdown source and deploys it to Apache's asf-site (production) or asf-staging branches via git push. The asf-site branch is the standard Apache mechanism for publishing project websites. Triggered on push to markdown branch or manually with option to deploy to production. |
| kvrocks-controller | `ci.yaml` | codecov | This CI workflow performs license checks, linting (Go and Prettier), builds the Go application and web UI, runs tests, and uploads code coverage reports to Codecov. The coverage upload is the only publishing activity, categorized as documentation. |
| kvrocks-website | `deploy.yml` | github_pages | Builds a Node.js-based website (using Yarn) and deploys it to GitHub Pages via the asf-site branch using peaceiris/actions-gh-pages action. Deployment only occurs on pushes to main branch, not on pull requests. |
| kyuubi-website | `asf-site.yml` | github_pages | Builds a Hugo static website and deploys it to the asf-site branch using GitHub Pages action. The workflow also configures Apache Software Foundation publishing via .asf.yaml file. This is documentation publishing for the Apache Kyuubi project website. |

</details>

## Security: Auto-Downgraded Findings

Initially flagged but the note describes an env-mediated pattern (safe). Verify manually.

<details>
<summary>Show 1 downgraded findings</summary>

- **apache/beam** (`deploy_release_candidate_pypi.yaml`): [INFO-DOWNGRADED] github.event.inputs.PYPI_API_TOKEN directly interpolated in run block at step 'Deploy to Pypi'. This is untrusted user input from workflow_dispatch and creates a credential injection risk. Should be passed through env: block instead.

</details>

## Security: Low Risk

GitHub-controlled values used directly in `run:` blocks.

<details>
<summary>Show 373 low-risk findings</summary>

- **apache/airavata** (`build-and-publish.yml`): [LOW] secrets.DOCKER_HUB_USERNAME and secrets.DOCKER_HUB_ACCESS_TOKEN passed to docker/login-action. Standard practice for Docker authentication, values are trusted but handled by action.
- **apache/airavata-mft** (`release_on_tag_push.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at steps 'Upload file 1' and 'Upload file 2'. Trusted value but risks log leakage. Use env: block instead.
- **apache/airavata-mft** (`release_on_tag_push.yml`): [LOW] github.event.release.tag_name directly interpolated in run block at steps 'Upload file 1' and 'Upload file 2'. Trusted value (release tags are created by maintainers), but best practice is to pass through env: block.
- **apache/airflow** (`ci-image-checks.yml`): [LOW] secrets.DOCS_AWS_ACCESS_KEY_ID and secrets.DOCS_AWS_SECRET_ACCESS_KEY passed to aws-actions/configure-aws-credentials action via with: block. This is safe as secrets are passed to action inputs, not directly interpolated in run blocks.
- **apache/airflow** (`ci-image-checks.yml`): [LOW] secrets.SLACK_BOT_TOKEN used in env: block and passed to slackapi/slack-github-action. Safe pattern as it's passed through env: and to action inputs.
- **apache/airflow** (`publish-docs-to-s3.yml`): [LOW] secrets.DOCS_AWS_ACCESS_KEY_ID and secrets.DOCS_AWS_SECRET_ACCESS_KEY passed to aws-actions/configure-aws-credentials action via with: block. Safe pattern.
- **apache/airflow** (`publish-docs-to-s3.yml`): [LOW] Multiple workflow_dispatch inputs (ref, destination, include-docs, exclude-docs, apply-commits, airflow-base-version, airflow-version) are interpolated in run blocks. However, workflow is restricted to trusted committers via if: contains(fromJSON('[...approved users...]'), github.event.sender.login), so risk is limited to trusted users.
- **apache/airflow** (`registry-backfill.yml`): [LOW] secrets.DOCS_AWS_ACCESS_KEY_ID and secrets.DOCS_AWS_SECRET_ACCESS_KEY passed to aws-actions/configure-aws-credentials action via with: block. This is safe as secrets are passed to action inputs, not interpolated in shell.
- **apache/airflow** (`registry-backfill.yml`): [LOW] inputs.providers and inputs.versions are workflow_dispatch inputs from trusted committers (restricted by if: condition checking github.event.sender.login against allowlist). Values are interpolated in run: blocks via ${{ inputs.providers }}, ${{ inputs.versions }}, and ${{ matrix.provider }}. Risk is low due to committer restriction, but direct interpolation could allow command injection from malformed input.
- **apache/airflow** (`registry-build.yml`): [LOW] secrets.DOCS_AWS_ACCESS_KEY_ID and secrets.DOCS_AWS_SECRET_ACCESS_KEY passed through aws-actions/configure-aws-credentials action with: block. This is safe practice.
- **apache/airflow** (`registry-build.yml`): [LOW] inputs.destination interpolated in shell run block at 'Determine S3 destination' step. This is a workflow_dispatch input from trusted committers (restricted by sender.login allowlist) with constrained choice values (staging/live), so risk is low.
- **apache/airflow** (`registry-build.yml`): [LOW] inputs.provider interpolated in shell run blocks at 'Extract registry data' and 'Sync registry to S3' steps. This is free-form text from trusted committers (workflow restricted by sender.login allowlist). Main risk is accidental command injection from malformed provider IDs, not malicious exploitation.
- **apache/airflow** (`release_dockerhub_image.yml`): [LOW] github.event.inputs.airflowVersion directly interpolated in concurrency.group. Safe in this context (not shell execution), but used in env blocks and passed to reusable workflow.
- **apache/airflow** (`release_single_dockerhub_image.yml`): [LOW] secrets.DOCKERHUB_TOKEN directly interpolated in run block at step 'Login to hub.docker.com'. Trusted value but risks log leakage. Use env: block instead.
- **apache/airflow** (`release_single_dockerhub_image.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Login to ghcr.io'. Trusted value but risks log leakage. Use env: block instead.
- **apache/airflow-publish** (`airflow-publish.yml`): [LOW] inputs.release-config directly interpolated in with: block at step 'Config parser'. Trusted committer input (workflow_dispatch) but limited to predefined choice options, so risk is minimal.
- **apache/airflow-publish** (`airflow-publish.yml`): [LOW] inputs.mode directly interpolated in with: block at step 'Find packages' and in job condition. Trusted committer input limited to VERIFY/RELEASE choices.
- **apache/airflow-publish** (`providers-publish.yml`): [LOW] inputs.release-config directly interpolated in with: block at step 'Config parser'. Trusted committer input (workflow_dispatch) but limited to predefined choice options, so risk is minimal.
- **apache/airflow-publish** (`providers-publish.yml`): [LOW] inputs.mode directly interpolated in with: block at step 'Find packages' and in if: condition. Trusted committer input limited to VERIFY/RELEASE choices.
- **apache/airflow-publish** (`test-pypi-airflow-publish.yml`): [LOW] github.event.inputs.release-config and github.event.inputs.mode are interpolated in workflow contexts. These are workflow_dispatch inputs only triggerable by repository committers, so risk is low (trusted input).
- **apache/airflow-site** (`build.yml`): [LOW] secrets.DOCS_AWS_ACCESS_KEY_ID and secrets.DOCS_AWS_SECRET_ACCESS_KEY passed to aws-actions/configure-aws-credentials action via with: block. This is safe as secrets are passed to action inputs, not directly interpolated in run blocks.
- **apache/airflow-site** (`build.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Add commit to publish branch' (line with git remote set-url). Trusted value but risks log leakage. Use env: block instead.
- **apache/airflow-site** (`build.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Create releases on GitHub'. Trusted value but risks log leakage. Use env: block instead.
- **apache/airflow-site-archive** (`github-to-s3.yml`): [LOW] secrets.DOCS_AWS_ACCESS_KEY_ID and secrets.DOCS_AWS_SECRET_ACCESS_KEY directly interpolated in with: block of aws-actions/configure-aws-credentials step. While this is the standard pattern for this action and not a shell execution context, it's worth noting for completeness.
- **apache/airflow-site-archive** (`github-to-s3.yml`): [LOW] inputs.document-packages, inputs.commit-reference, inputs.destination, inputs.processes, and inputs.full-sync are workflow_dispatch inputs directly interpolated in run blocks. These are trusted values (only triggerable by repository committers) but represent free-form text that could cause command injection if malformed. All values are properly passed through env: blocks which mitigates the risk.
- **apache/airflow-site-archive** (`s3-to-github.yml`): [LOW] secrets.DOCS_AWS_ACCESS_KEY_ID and secrets.DOCS_AWS_SECRET_ACCESS_KEY directly interpolated in 'Configure AWS credentials' step with: block. While this is passed to an action (not a run: block), it's worth noting for credential management awareness.
- **apache/airflow-site-archive** (`s3-to-github.yml`): [LOW] inputs.document-packages directly interpolated in run blocks. This is a workflow_dispatch input controllable only by repository committers, so trusted but could cause issues with malformed input.
- **apache/airflow-site-archive** (`s3-to-github.yml`): [LOW] inputs.processes directly interpolated in run blocks. Workflow_dispatch input from trusted committers only.
- **apache/airflow-site-archive** (`s3-to-github.yml`): [LOW] inputs.source directly interpolated in run blocks. Workflow_dispatch input from trusted committers only.
- **apache/amoro** (`docker-images.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in docker/login-action@v2 'with:' block. While 'with:' blocks are safer than 'run:' blocks, best practice is to pass secrets through env: blocks.
- **apache/answer** (`build-image-for-latest-release.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN passed to docker/login-action via with: block. This is safe as secrets are passed to action inputs, not interpolated in shell commands.
- **apache/answer** (`build-image-for-manual.yml`): [LOW] inputs.tag_name directly interpolated in docker/build-push-action tags at step 'Build and push'. Workflow is workflow_dispatch restricted to apache org, so input is from trusted committers only. Risk is accidental malformed input rather than malicious injection.
- **apache/answer** (`build-image-for-release.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in docker/login-action 'with:' block. While 'with:' blocks are safer than 'run:' blocks, best practice is to use env: block for secrets.
- **apache/apisix-docker** (`apisix_dev_push_docker_hub.yaml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN passed to docker/login-action via with: block. This is safe as secrets are not directly interpolated in run blocks.
- **apache/apisix-docker** (`apisix_push_docker_hub.yaml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN passed to docker/login-action via with: block. This is safe as secrets are passed to action inputs, not interpolated in shell commands.
- **apache/apisix-docker** (`apisix_push_docker_hub.yaml`): [LOW] matrix.platform interpolated in run block for make push-multiarch-on-${{ matrix.platform }}. This is a controlled matrix value (ubuntu/debian/redhat), not user input, but direct interpolation in shell commands should ideally use env: block for consistency.
- **apache/apisix-docker** (`dashboard_push_docker_hub.yaml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in docker/login-action@v1 'with:' block. While 'with:' blocks are safer than 'run:' blocks, best practice is to use env: variables for secrets.
- **apache/apisix-go-plugin-runner** (`unit-test-ci.yml`): [LOW] The workflow downloads and executes a remote bash script from codecov.io without verification. While this is the official Codecov upload method, it introduces supply chain risk if codecov.io is compromised.
- **apache/apisix-helm-chart** (`release.yaml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block at 'Run chart-releaser' step. While env: block is used (best practice), note that this token has write access to releases.
- **apache/apisix-helm-chart** (`release.yaml`): [LOW] $GITHUB_ACTOR directly interpolated in run block at 'Configure Git' step. GitHub-controlled value, low risk.
- **apache/apisix-website** (`deploy.yml`): [LOW] github.event.pull_request.title directly interpolated in Netlify deploy-message (disabled step). If re-enabled, this would be untrusted input in action parameter (low risk as it's passed to action, not shell)
- **apache/arrow** (`cpp.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in env block at 'Docker Push' step. While env: block is safer than direct run: interpolation, these are trusted credential values.
- **apache/arrow** (`cpp_extra.yml`): [LOW] secrets.DOCKERHUB_TOKEN directly interpolated in env block at 'Docker Push' steps. Trusted value but risks log leakage. Use env: block instead.
- **apache/arrow** (`cuda_extra.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in env block at 'Docker Push' step. While env: block is used, these are credentials that should be handled carefully.
- **apache/arrow** (`docs.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in env blocks at 'Execute Docker Build' and 'Docker Push' steps. While env: block usage is safer than direct run: interpolation, these are still exposed as environment variables. This is acceptable for Docker authentication but should be noted.
- **apache/arrow** (`integration.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in env blocks at 'Execute Docker Build' and 'Docker Push' steps. While env: block usage is correct, these are passed to archery which may log them. Standard practice for Docker credentials.
- **apache/arrow** (`python.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in env block at 'Docker Push' step. While env: block usage is correct, these are credentials being passed to archery docker push command.
- **apache/arrow** (`r.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in env block for 'Execute Docker Build' and 'Docker Push' steps. While passed through env: block (best practice), these are used for authentication to Docker Hub.
- **apache/arrow** (`r_extra.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in env block at 'Docker Push' step. While env: block is safer than direct run: interpolation, these are credentials that should be handled carefully.
- **apache/arrow** (`r_nightly.yml`): [LOW] secrets.NIGHTLIES_RSYNC_PATH directly interpolated in with: block at 'Sync from Remote' and 'Sync to Remote' steps. While with: blocks are lower risk than run: blocks, consider using env: for consistency.
- **apache/arrow** (`r_nightly.yml`): [LOW] secrets.NIGHTLIES_RSYNC_HOST, secrets.NIGHTLIES_RSYNC_PORT, secrets.NIGHTLIES_RSYNC_USER, secrets.NIGHTLIES_RSYNC_KEY, secrets.NIGHTLIES_RSYNC_HOST_KEY directly interpolated in with: blocks. These are trusted values but represent credentials.
- **apache/arrow** (`r_nightly.yml`): [LOW] github.event.inputs.prefix and github.event.inputs.keep directly interpolated in run blocks. These are workflow_dispatch inputs from trusted committers only (apache/arrow repository), so risk is low but values should ideally be passed through env: blocks.
- **apache/arrow** (`release_candidate.yml`): [LOW] secrets.ARROW_GPG_SECRET_KEY directly interpolated in run block at step 'Create Release tarball'. Trusted value but risks log leakage. Use env: block instead.
- **apache/arrow** (`ruby.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in env block at 'Docker Push' step. While env: block is safer than direct run: interpolation, these are credentials that should be handled carefully.
- **apache/arrow-go** (`benchmark.yml`): [LOW] secrets.CONBENCH_EMAIL directly interpolated in env block at step 'Upload results'. Trusted value but risks log leakage. Use intermediate env: block pattern.
- **apache/arrow-go** (`benchmark.yml`): [LOW] secrets.CONBENCH_PASS directly interpolated in env block at step 'Upload results'. Trusted value but risks log leakage. Use intermediate env: block pattern.
- **apache/arrow-go** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block. While this is standard GitHub Actions pattern and the token is automatically masked, best practice is to use it only in action inputs or pass through env: in individual steps.
- **apache/arrow-java** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block. While this is standard GitHub practice and the token is scoped, best practice would be to pass it through env: in individual steps if needed.
- **apache/arrow-julia** (`ci.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block at 'Documentation' job. While env: block is safer than direct run: interpolation, this is a standard GitHub-provided token with appropriate scoping.
- **apache/arrow-julia** (`ci.yml`): [LOW] secrets.DOCUMENTER_KEY directly interpolated in env block at 'Documentation' job. This is a trusted secret for Julia documentation deployment.
- **apache/arrow-nanoarrow** (`python-wheels.yaml`): [LOW] secrets.NANOARROW_GEMFURY_TOKEN directly interpolated in run block at step 'Upload packages to Gemfury'. Trusted value but risks log leakage. Use env: block instead.
- **apache/auron-sites** (`deploy-website.yml`): [LOW] secrets.ACCESS_TOKEN directly interpolated in env block at step 'vuepress-deploy'. While env: block is used, this is a GitHub token that could be exposed if the custom action logs environment variables. Consider using GITHUB_TOKEN instead if possible.
- **apache/avro** (`java-publish-snapshot.yml`): [LOW] secrets.NEXUS_USER and secrets.NEXUS_PW directly interpolated in run block at step 'Deploy Maven snapshots'. Trusted values but risk log leakage. Use env: block instead of direct interpolation in echo command.
- **apache/beam** (`beam_Inference_Python_Benchmarks_Dataflow.yml`): [LOW] secrets.DEVELOCITY_ACCESS_KEY, secrets.GE_CACHE_USERNAME, secrets.GE_CACHE_PASSWORD, secrets.INFLUXDB_USER, secrets.INFLUXDB_USER_PASSWORD directly interpolated in env block. While env: block is safer than run: block, these are still exposed to all steps.
- **apache/beam** (`beam_PostCommit_Python_Arm.yml`): [LOW] secrets.GCP_SA_KEY directly interpolated in google-github-actions/auth action. Passed through with: block which is safe pattern.
- **apache/beam** (`beam_PostCommit_Python_Arm.yml`): [LOW] secrets.DEVELOCITY_ACCESS_KEY, secrets.GE_CACHE_USERNAME, secrets.GE_CACHE_PASSWORD directly interpolated in env block. Safe pattern for secrets.
- **apache/beam** (`beam_PreCommit_SQL.yml`): [LOW] secrets.DEVELOCITY_ACCESS_KEY directly interpolated in env block. While env: blocks are safer than run: blocks, this is a credential that could be exposed if mishandled.
- **apache/beam** (`beam_PreCommit_SQL.yml`): [LOW] secrets.GE_CACHE_USERNAME and secrets.GE_CACHE_PASSWORD directly interpolated in env block. Credentials should be passed through env: in individual steps when possible.
- **apache/beam** (`beam_Publish_BeamMetrics.yml`): [LOW] secrets.DEVELOCITY_ACCESS_KEY directly interpolated in env block. While env: is safer than run:, consider if this secret needs workflow-wide scope.
- **apache/beam** (`beam_Publish_BeamMetrics.yml`): [LOW] secrets.GE_CACHE_USERNAME and secrets.GE_CACHE_PASSWORD directly interpolated in env block. These are for Gradle Enterprise cache access.
- **apache/beam** (`beam_Publish_Beam_SDK_Snapshots.yml`): [LOW] secrets.DEVELOCITY_ACCESS_KEY directly interpolated in env block. Trusted value but risks log leakage.
- **apache/beam** (`beam_Publish_Beam_SDK_Snapshots.yml`): [LOW] secrets.GE_CACHE_USERNAME directly interpolated in env block. Trusted value but risks log leakage.
- **apache/beam** (`beam_Publish_Beam_SDK_Snapshots.yml`): [LOW] secrets.GE_CACHE_PASSWORD directly interpolated in env block. Trusted value but risks log leakage.
- **apache/beam** (`beam_Publish_Beam_SDK_Snapshots.yml`): [LOW] secrets.GCP_SA_EMAIL directly interpolated in with block. Trusted value but risks log leakage.
- **apache/beam** (`beam_Publish_Beam_SDK_Snapshots.yml`): [LOW] secrets.GCP_SA_KEY directly interpolated in with block. Trusted value but risks log leakage.
- **apache/beam** (`beam_Python_ValidatesContainer_Dataflow_ARM.yml`): [LOW] secrets.GCP_SA_KEY directly interpolated in google-github-actions/auth step. Trusted value but passed through with: block (safe pattern).
- **apache/beam** (`beam_Release_NightlySnapshot.yml`): [LOW] secrets.NEXUS_USER directly interpolated in run block at step 'Auth on snapshot repository'. Trusted value but risks log leakage. Use env: block instead.
- **apache/beam** (`beam_Release_NightlySnapshot.yml`): [LOW] secrets.NEXUS_PW directly interpolated in run block at step 'Auth on snapshot repository'. Trusted value but risks log leakage. Use env: block instead.
- **apache/beam** (`build_release_candidate.yml`): [LOW] secrets.NEXUS_STAGE_DEPLOYER_USER and secrets.NEXUS_STAGE_DEPLOYER_PW directly interpolated in run block at step 'Auth for nexus' in publish_java_artifacts job. Trusted values but risk log leakage. Use env: block instead.
- **apache/beam** (`build_release_candidate.yml`): [LOW] secrets.NEXUS_USER and secrets.NEXUS_PW directly interpolated in run block at step 'Auth for nexus' in publish_java_artifacts job. Trusted values but risk log leakage. Use env: block instead.
- **apache/beam** (`build_release_candidate.yml`): [LOW] github.event.inputs.APACHE_PASSWORD directly interpolated in svn commit commands across multiple jobs (stage_java_source, stage_python_artifacts, build_and_stage_prism). This is a workflow_dispatch input from trusted committers, but direct interpolation in shell commands risks accidental exposure. The workflow does mask it via add-mask, which mitigates log leakage.
- **apache/beam** (`build_release_candidate.yml`): [LOW] github.event.inputs.APACHE_ID directly interpolated in svn commit commands. Trusted committer input but could be passed through env: block for consistency.
- **apache/beam** (`deploy_release_candidate_pypi.yaml`): [LOW] github.event.inputs.RELEASE and github.event.inputs.RC directly interpolated in run blocks. These are workflow_dispatch inputs from trusted committers but should use env: block for safety.
- **apache/beam** (`finalize_release.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in docker/login-action 'with:' block at step 'Login to Docker Hub'. While 'with:' blocks are safer than 'run:' blocks, best practice is to use env: block.
- **apache/beam** (`finalize_release.yml`): [LOW] github.event.inputs.PYPI_API_TOKEN directly interpolated in run block at step 'Deploy to Pypi' in twine upload command. This is a workflow_dispatch input from trusted committers only, but risks log leakage. Use env: block instead.
- **apache/beam** (`finalize_release.yml`): [LOW] github.event.inputs.RELEASE and github.event.inputs.RC directly interpolated in multiple run blocks. These are workflow_dispatch inputs from trusted committers, but could cause command injection if malformed. Consider validation.
- **apache/beam** (`republish_released_docker_containers.yml`): [LOW] secrets.GCP_SA_KEY directly interpolated in with: block of google-github-actions/auth step. While with: blocks are generally safer than run: blocks, credentials should ideally be passed through env: for consistency.
- **apache/beam** (`republish_released_docker_containers.yml`): [LOW] github.event.inputs.RELEASE and github.event.inputs.RC interpolated in env: block and used in run: commands. These are workflow_dispatch inputs only triggerable by repository committers, so trusted input. Main risk is accidental command injection from malformed version strings.
- **apache/bifromq** (`docker-publish.yml`): [LOW] inputs.version directly interpolated in run blocks at steps 'Download and Verify Artifact' and 'Build and Push Multi-Arch Image'. Workflow is workflow_dispatch restricted to repository committers. Main risk is accidental command injection from malformed version strings, not malicious exploitation.
- **apache/bifromq** (`docker-publish.yml`): [LOW] inputs.artifact_url directly interpolated in run block at step 'Download and Verify Artifact'. Workflow is workflow_dispatch restricted to repository committers. Could allow arbitrary URL downloads but from trusted maintainers only.
- **apache/bookkeeper** (`website-deploy.yaml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Publish'. Trusted value but risks log leakage. Use env: block instead.
- **apache/buildstream** (`merge.yml`): [LOW] $GITHUB_TOKEN directly interpolated in run block at 'Update repo' step. While this is GitHub's automatic token (trusted), it risks log leakage if GitHub's masking fails. Best practice: pass through env: block.
- **apache/buildstream** (`release.yml`): [LOW] secrets.PYPI_TOKEN directly interpolated in run block at step 'Upload to PyPI'. Trusted value but risks log leakage. Use env: block instead.
- **apache/buildstream** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block at step 'Upload release assets'. While using env: block, GitHub's automatic masking should protect this.
- **apache/buildstream-plugins** (`merge.yml`): [LOW] $GITHUB_TOKEN directly interpolated in run block at 'Update repo' step. While this is the automatic GitHub token (trusted), best practice is to pass through env: block to prevent potential log leakage.
- **apache/burr** (`build-site.yml`): [LOW] github.token directly interpolated in git push URL at 'Deploy to asf-site / asf-staging' step. Trusted value but risks log leakage. Use env: block instead.
- **apache/calcite** (`publish-non-release-website-updates.yml`): [LOW] secrets.CALCITE_WEBSITE_BUILD directly interpolated in run block at step 'Push site'. Trusted value but risks log leakage. Use env: block instead.
- **apache/calcite** (`publish-non-release-website-updates.yml`): [LOW] github.actor directly interpolated in git config commands. GitHub-controlled value, low risk.
- **apache/calcite** (`publish-website-on-release.yml`): [LOW] secrets.CALCITE_WEBSITE_BUILD directly interpolated in run block at step 'Push site'. Trusted value but risks log leakage. Use env: block instead.
- **apache/calcite** (`publish-website-on-release.yml`): [LOW] github.actor directly interpolated in git config commands. GitHub-controlled value, low risk but could be passed through env: for consistency.
- **apache/calcite-avatica** (`publish-non-release-website-updates.yml`): [LOW] secrets.CALCITE_WEBSITE_BUILD directly interpolated in with: block at checkout step. While with: blocks are generally safer than run: blocks, this is a PAT token used for authentication.
- **apache/calcite-avatica** (`publish-non-release-website-updates.yml`): [LOW] github.actor directly interpolated in run block for git config user.email and user.name. GitHub-controlled value, low risk.
- **apache/calcite-avatica** (`publish-site-and-javadocs-on-release.yml`): [LOW] secrets.CALCITE_WEBSITE_BUILD directly interpolated in with: block at checkout step. While with: blocks are generally safer than run: blocks, this is a credential being passed directly. Standard practice for actions/checkout.
- **apache/calcite-avatica** (`publish-site-and-javadocs-on-release.yml`): [LOW] github.actor directly interpolated in run block for git config commands. GitHub-controlled value, low risk but could be passed through env: for consistency.
- **apache/calcite-avatica-go** (`publish-website.yml`): [LOW] secrets.CALCITE_WEBSITE_BUILD directly interpolated in with.token at checkout steps. Trusted value but best practice is to use env: block.
- **apache/camel-k** (`nightly-release.yml`): [LOW] secrets.NEXUS_PW directly interpolated in env block at workflow level. Trusted value but risks log leakage if referenced directly in run blocks. Best practice: pass through step-level env: block.
- **apache/camel-k** (`nightly-release.yml`): [LOW] secrets.NEXUS_USER directly interpolated in env block at workflow level. Trusted value but risks log leakage if referenced directly in run blocks.
- **apache/camel-k-runtime** (`ci-build.yml`): [LOW] secrets.NEXUS_USER directly interpolated in env block at 'deploy' job. While env: block is safer than direct run: interpolation, GitHub's secret masking should protect it.
- **apache/camel-k-runtime** (`ci-build.yml`): [LOW] secrets.NEXUS_PW directly interpolated in env block at 'deploy' job. While env: block is safer than direct run: interpolation, GitHub's secret masking should protect it.
- **apache/camel-kameleon** (`main.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Build application'. Trusted value but risks log leakage. Use env: block instead.
- **apache/camel-kamelets** (`ci-build.yml`): [LOW] secrets.NEXUS_USER and secrets.NEXUS_PW directly interpolated in env block at 'deploy' job. While env: block is safer than direct run: interpolation, these credentials are exposed as environment variables throughout the job. Best practice is to pass secrets only to the specific step that needs them.
- **apache/camel-karavan** (`app.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Build application'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-Casbin.NET** (`release.yml`): [LOW] secrets.NUGET_API_KEY directly interpolated in env block at workflow level as NUGET_API_TOKEN. While passed through env variable to shell, the initial interpolation pattern could be improved by setting it at step level.
- **apache/casbin-Casbin.NET** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block at workflow level. Standard pattern but could be scoped to step level for least privilege.
- **apache/casbin-Casbin.NET-ef-adapter** (`gitub-actions-release.yml`): [LOW] secrets.NUGET_API_TOKEN directly interpolated in env block at workflow level. While env: blocks are safer than direct run: interpolation, the secret is then exposed as an environment variable throughout the job. Best practice is to pass secrets directly to the step that needs them via env: at step level.
- **apache/casbin-Casbin.NET-redis-adapter** (`release.yml`): [LOW] secrets.MYGET_API_KEY directly interpolated in env block as MYGET_API_TOKEN. While env: block usage is safer, the secret is then referenced in run block as $MYGET_API_TOKEN which could risk log leakage.
- **apache/casbin-Casbin.NET-redis-adapter** (`release.yml`): [LOW] secrets.NUGET_API_KEY directly interpolated in env block as NUGET_API_TOKEN. While env: block usage is safer, the secret is then referenced in run block as $NUGET_API_TOKEN which could risk log leakage.
- **apache/casbin-Casbin.NET-redis-adapter** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block. While env: block usage is safer, the secret is then referenced in run block as $env:GITHUB_TOKEN which could risk log leakage.
- **apache/casbin-Casbin.NET-redis-watcher** (`build.yml`): [LOW] secrets.MYGET_API_KEY directly interpolated in env block at workflow level. While env: block is safer than direct run: interpolation, best practice is to pass secrets only to steps that need them.
- **apache/casbin-Casbin.NET-redis-watcher** (`build.yml`): [LOW] secrets.COVERALLS_REPO_TOKEN directly interpolated in env block at workflow level. Consider limiting scope to specific steps.
- **apache/casbin-Casbin.NET-redis-watcher** (`release.yml`): [LOW] secrets.MYGET_API_KEY directly interpolated in env block at workflow level. While env: blocks are safer than direct run: interpolation, consider passing to step-level env: for minimal scope.
- **apache/casbin-Casbin.NET-redis-watcher** (`release.yml`): [LOW] secrets.NUGET_API_TOKEN directly interpolated in env block at workflow level. While env: blocks are safer than direct run: interpolation, consider passing to step-level env: for minimal scope.
- **apache/casbin-Casbin.NET-redis-watcher** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block at workflow level. While env: blocks are safer than direct run: interpolation, consider passing to step-level env: for minimal scope.
- **apache/casbin-Casbin.NET-redis-watcher** (`release.yml`): [LOW] secrets.COVERALLS_REPO_TOKEN directly interpolated in env block at workflow level. While env: blocks are safer than direct run: interpolation, consider passing to step-level env: for minimal scope.
- **apache/casbin-actix-casbin-auth** (`coverage.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'Upload to codecov.io'. While with: blocks are generally safer than run: blocks, best practice is to pass secrets through env: block to minimize exposure risk.
- **apache/casbin-actix-casbin-auth** (`release.yml`): [LOW] secrets.CARGO_TOKEN directly interpolated in run block at step 'Cargo Login'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-aspnetcore** (`release.yml`): [LOW] secrets.NUGET_API_KEY directly interpolated in env block at workflow level. While env: blocks are safer than direct run: interpolation, consider passing secrets only to steps that need them.
- **apache/casbin-axum-casbin** (`coverage.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'Upload to codecov.io'. While with: blocks are generally safer than run: blocks, best practice is to pass secrets through env: block to minimize exposure risk.
- **apache/casbin-axum-casbin** (`release.yml`): [LOW] secrets.CARGO_TOKEN directly interpolated in run block at step 'Cargo Login'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-casbin.js** (`ci.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in run block at step 'Run semantic-release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-casbin.js** (`ci.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Run semantic-release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-core** (`ci.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block at step 'Run semantic-release'. While env: block is best practice, note for completeness.
- **apache/casbin-core** (`ci.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in env block at step 'Run semantic-release'. While env: block is best practice, note for completeness.
- **apache/casbin-dart-casbin** (`dart.yml`): [LOW] secrets.PUB_CREDENTIALS directly interpolated in run block at step 'Setup Pub Credentials'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-efcore-adapter** (`release.yml`): [LOW] secrets.NUGET_API_KEY directly interpolated in env block at workflow level. While env: block is safer than direct run: interpolation, consider passing to specific steps only.
- **apache/casbin-efcore-adapter** (`release.yml`): [LOW] secrets.COVERALLS_REPO_TOKEN directly interpolated in env block at workflow level for coverage upload.
- **apache/casbin-gateway** (`build.yml`): [LOW] secrets.DOCKERHUB_USERNAME and secrets.DOCKERHUB_PASSWORD directly interpolated in docker/login-action. Trusted values but best practice is to use env: block.
- **apache/casbin-lego** (`main.yml`): [LOW] secrets.DOCKER_PASSWORD directly interpolated in run block at step 'Docker Login'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-lua-casbin** (`build.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block at step 'Reporting test coverage'. While env: block is used, this is a trusted GitHub-provided token with limited scope for coverage reporting.
- **apache/casbin-lua-casbin** (`release.yml`): [LOW] secrets.LUAROCKS_API_KEY directly interpolated in run block at step 'Upload'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-lua-casbin** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Run semantic-release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-nest-authz** (`ci.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in env block at 'release' job. While env: block is safer than direct run: interpolation, ensure semantic-release handles token securely.
- **apache/casbin-node-casbin** (`main.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in env block at step 'Run semantic-release'. While env: block is used (best practice), note that semantic-release will use this token to publish to npm registry.
- **apache/casbin-node-casbin-basic-adapter** (`ci.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in run block at step 'Release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-node-casbin-basic-adapter** (`ci.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-node-casbin-couchdb-adapter** (`ci.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Run semantic-release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-node-casbin-couchdb-adapter** (`ci.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in run block at step 'Run semantic-release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-node-casbin-drizzle-adapter** (`ci.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in env block at step 'Run semantic-release'. While env: block is best practice, note this is passed to semantic-release which publishes to npm.
- **apache/casbin-node-casbin-drizzle-adapter** (`ci.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block at step 'Run semantic-release'. Best practice usage for semantic-release automation.
- **apache/casbin-node-casbin-etcd-watcher** (`main.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Run semantic-release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-node-casbin-etcd-watcher** (`main.yml`): [LOW] secrets.NPM_ACCESS_TOKEN directly interpolated in run block at step 'Run semantic-release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-node-casbin-expression-eval** (`ci.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Coveralls'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-node-casbin-expression-eval** (`ci.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in env block at step 'semantic-release'. While env: block is used, the secret is exposed to the command environment.
- **apache/casbin-node-casbin-prisma-adapter** (`ci.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Run semantic-release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-node-casbin-prisma-adapter** (`ci.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in run block at step 'Run semantic-release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-node-casbin-session-role-manager** (`release.yml`): [LOW] secrets.GITHUB_TOKEN and secrets.NPM_TOKEN passed through env: block (safe pattern). No direct interpolation in run commands detected.
- **apache/casbin-pycasbin** (`build.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-pycasbin** (`build.yml`): [LOW] secrets.PYPI_TOKEN_CASBIN directly interpolated in run block at step 'Release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-async-django-orm-adapter** (`build.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Upload coverage data to coveralls.io'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-async-django-orm-adapter** (`build.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Finished'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-async-postgres-watcher** (`release.yml`): [LOW] secrets.PYPI_TOKEN directly interpolated in run block at 'Release' step. Trusted value but risks log leakage. Use env: block instead (though semantic-release requires env vars, so this is acceptable pattern).
- **apache/casbin-python-async-postgres-watcher** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at 'Release' step. Standard pattern for semantic-release but direct interpolation could leak in logs.
- **apache/casbin-python-async-sqlalchemy-adapter** (`build.yml`): [LOW] secrets.PYPI_TOKEN directly interpolated in run block at 'Release' step. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-casbin-databases-adapter** (`build.yml`): [LOW] secrets.PYPI_TOKEN directly interpolated in run block at 'Release' step. Trusted value but risks log leakage. Use env: block instead (though semantic-release typically reads from env, so this is already following best practice).
- **apache/casbin-python-django-casbin-auth** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Upload coverage data to coveralls.io'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-django-casbin-auth** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Finished'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-django-orm-adapter** (`build.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Upload coverage data to coveralls.io'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-django-orm-adapter** (`build.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Finished'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-etcd-watcher** (`release.yml`): [LOW] secrets.PYPI_TOKEN directly interpolated in run block at 'Release' step. Trusted value but risks log leakage. Use env: block instead (though it is passed through env: here, so this is actually safe).
- **apache/casbin-python-fastapi-casbin-auth** (`release.yml`): [LOW] secrets.GITHUB_TOKEN and secrets.PYPI_TOKEN passed through env: block (correct pattern). No security issues detected.
- **apache/casbin-python-flask-authz** (`build.yml`): [LOW] secrets.PYPI_TOKEN directly interpolated in run block at step 'Release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-graphql-authz** (`build.yml`): [LOW] secrets.PYPI_TOKEN directly interpolated in run block at 'Release' step. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-postgresql-watcher** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Upload coverage data to coveralls.io'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-postgresql-watcher** (`release.yml`): [LOW] secrets.GITHUB_TOKEN and secrets.PYPI_TOKEN directly interpolated in env block at step 'Release'. While env: block is used, the secrets are exposed to the semantic-release command which could log them if misconfigured.
- **apache/casbin-python-pymongo-adapter** (`main.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Upload coverage data to coveralls.io'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-pymongo-adapter** (`main.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Finished' in coveralls job. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-pymongo-adapter** (`main.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Super-Linter'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-rabbitmq-watcher** (`build.yml`): [LOW] secrets.PYPI_TOKEN directly interpolated in run block at 'Release' step. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-redis-adapter** (`build.yml`): [LOW] secrets.PYPI_TOKEN directly interpolated in run block at 'Release' step. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-redis-watcher** (`release.yml`): [LOW] secrets.PYPI_TOKEN directly interpolated in run block at 'Release' step. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-redis-watcher** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at 'Release' step. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-sanic-authz** (`build.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Upload coverage data to coveralls.io'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-sanic-authz** (`build.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Finished'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-python-sqlalchemy-adapter** (`build.yml`): [LOW] secrets.PYPI_TOKEN passed through env: block to semantic-release. Proper pattern used.
- **apache/casbin-python-sqlalchemy-adapter** (`build.yml`): [LOW] secrets.GITHUB_TOKEN passed through env: blocks. Proper pattern used.
- **apache/casbin-python-sqlobject-adapter** (`build.yml`): [LOW] secrets.PYPI_TOKEN directly interpolated in run block at 'Release' step. Trusted value but risks log leakage. Use env: block instead (though it is passed through env: here, so this is actually safe).
- **apache/casbin-rs** (`coverage.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'Upload to codecov.io'. While with: blocks are generally safer than run: blocks, best practice is to pass secrets through env: block.
- **apache/casbin-rust-actix-casbin** (`coverage.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with block at step 'Upload to codecov.io'. While with: blocks are generally safer than run: blocks, best practice is to pass secrets through env: block to minimize exposure risk.
- **apache/casbin-rust-actix-casbin** (`release.yml`): [LOW] secrets.CARGO_TOKEN directly interpolated in run block at step 'Cargo Login'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-rust-diesel-adapter** (`coverage.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with block at step 'Upload to codecov.io'. While with: blocks are generally safer than run: blocks, best practice is to pass secrets through env: block to minimize exposure risk.
- **apache/casbin-rust-diesel-adapter** (`release.yml`): [LOW] secrets.CARGO_TOKEN directly interpolated in run block at step 'Cargo Login'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-rust-dufs-with-casbin** (`release.yaml`): [LOW] secrets.DOCKERHUB_USERNAME directly interpolated in docker/login-action with: block at step 'Login to DockerHub'. While with: blocks are generally safer than run: blocks, consider using env: pattern for consistency.
- **apache/casbin-rust-dufs-with-casbin** (`release.yaml`): [LOW] secrets.DOCKERHUB_TOKEN directly interpolated in docker/login-action with: block at step 'Login to DockerHub'. While with: blocks are generally safer than run: blocks, consider using env: pattern for consistency.
- **apache/casbin-rust-dufs-with-casbin** (`release.yaml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env: block at step 'Publish Archive'. This is acceptable as it's passed through env:, but note it's used in the action context.
- **apache/casbin-rust-dufs-with-casbin** (`release.yaml`): [LOW] secrets.CRATES_IO_API_TOKEN directly interpolated in env: block at step 'Publish'. This is the correct pattern - secret passed through env: block then used by cargo publish.
- **apache/casbin-rust-postgres-adapter** (`coverage.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with block at step 'Upload to codecov.io'. While with: blocks are generally safer than run: blocks, best practice is to pass secrets through env: block to minimize exposure risk.
- **apache/casbin-rust-postgres-adapter** (`release.yml`): [LOW] secrets.CARGO_TOKEN directly interpolated in run arguments at step 'Cargo Login'. Trusted value but risks log leakage if GitHub masking fails. Use env: block instead.
- **apache/casbin-rust-redis-watcher** (`coverage.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with block at step 'Upload to codecov.io'. While with: blocks are safer than run: blocks, best practice is to pass secrets through env: block.
- **apache/casbin-rust-rocket-authz** (`coverage.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'Upload to codecov.io'. While with: blocks are generally safer than run: blocks, best practice is to use env: block for secrets.
- **apache/casbin-rust-rocket-authz** (`release.yml`): [LOW] secrets.CARGO_TOKEN directly interpolated in run arguments at step 'Cargo Login'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-rust-salvo-casbin** (`coverage.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'Upload to codecov.io'. While with: blocks are generally safer than run: blocks, best practice is to pass secrets through env: to minimize exposure surface.
- **apache/casbin-rust-semantic-release-action-rust** (`release-library.yml`): [LOW] secrets.cargo-registry-token directly interpolated in with: block at step 'Release'. While with: blocks are safer than run: blocks, best practice is to pass secrets through env: blocks when possible.
- **apache/casbin-rust-string-adapter** (`coverage.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'Upload to codecov.io'. While with: blocks are generally safer than run: blocks, best practice is to use env: block for secrets.
- **apache/casbin-rust-string-adapter** (`release.yml`): [LOW] secrets.CARGO_TOKEN directly interpolated in run block at step 'Cargo Login'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-rust-yaml-adapter** (`release.yml`): [LOW] secrets.CARGO_TOKEN directly interpolated in run block at step 'Cargo Login'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-sequelize-adapter** (`ci.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block at step 'Run semantic-release'. Trusted value but best practice is to use $GITHUB_TOKEN shell variable reference.
- **apache/casbin-sequelize-adapter** (`ci.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in env block at step 'Run semantic-release'. Trusted value but best practice is to use $NPM_TOKEN shell variable reference.
- **apache/casbin-sqlx-adapter** (`coverage.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with block at step 'Upload to codecov.io'. While with: blocks are generally safer than run: blocks, best practice is to pass secrets through env: block.
- **apache/casbin-sqlx-adapter** (`release.yml`): [LOW] secrets.CARGO_TOKEN directly interpolated in run block at step 'Cargo Login'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-typeorm-adapter** (`ci.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in env block at step 'Run semantic-release'. While env: block is best practice, note this is passed to semantic-release which handles publishing.
- **apache/casbin-website** (`master.yml`): [LOW] secrets.CROWDIN_PERSONAL_TOKEN passed through env: block (safe pattern), used for translation sync
- **apache/casbin-website-v3** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/casbin-website-v3** (`release.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in run block at step 'Release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/cassandra-easy-stress** (`gradle-publish-main-release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in env block at steps 'Create Release' and 'Upload Release Artifact'. While env: block usage is correct pattern, note that GITHUB_TOKEN is automatically provided and trusted.
- **apache/cassandra-sidecar** (`publish-test-artifacts.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Build and push Docker image (latest tag)'. Trusted value but risks log leakage. Use env: block instead.
- **apache/cayenne** (`verify-deploy-on-push.yml`): [LOW] secrets.NEXUS_USER and secrets.NEXUS_PW directly interpolated in env block at 'Deploy snapshot' step. While env: block usage is best practice, note that these are passed to Maven settings.xml.
- **apache/celeborn** (`docker-build.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in docker/login-action@v3 'with:' block at step 'Login to Docker Hub'. While 'with:' blocks are safer than 'run:' blocks, best practice is to use env: block for secrets.
- **apache/celeborn** (`docker-build.yml`): [LOW] github.event.inputs.celeborn_version directly interpolated in run block at step 'Set Celeborn Version'. This is a workflow_dispatch input controllable by repository committers. Risk is low as only trusted maintainers can trigger, but malformed version strings could cause command issues.
- **apache/celeborn** (`docker-build.yml`): [LOW] github.event.release.tag_name directly interpolated in run block at step 'Set Celeborn Version'. This is a GitHub-controlled value from release events, but direct interpolation in shell commands should ideally use env: block for consistency.
- **apache/celix** (`coverage.yml`): [LOW] secrets.CODECOV_TOKEN passed through with: block to codecov-action. This is safe as it's not directly interpolated in a run block, but note the token is used for authentication.
- **apache/cloudberry** (`docker-cbdb-build-containers.yml`): [LOW] secrets.DOCKERHUB_TOKEN directly interpolated in docker/login-action with: block at step 'Login to Docker Hub'. Trusted value but passed to action parameter (safe pattern).
- **apache/cloudberry** (`docker-cbdb-test-containers.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in docker/login-action with: block. While passed to action (not run:), this is standard practice for this action.
- **apache/cloudstack** (`ci.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'uses: codecov/codecov-action@v4'. While this is passed to an action (not a run: block), it's worth noting for credential hygiene.
- **apache/cloudstack** (`codecov.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'codecov/codecov-action@v4'. While with: blocks are generally safe, this is a credential being passed to a third-party action.
- **apache/cloudstack** (`ui.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with block at step 'codecov/codecov-action@v4'. While with: blocks are generally safe, this is a credential being passed. Best practice is to use env: block for secrets.
- **apache/cloudstack-kubernetes-provider** (`build.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'Upload coverage to Codecov'. While with: blocks are generally safer than run: blocks, best practice is to pass secrets through env: blocks.
- **apache/cloudstack-www** (`stage.yml`): [LOW] github.event.inputs.branch directly interpolated in commit_message at step 'Publish PR change to staging site'. However, this workflow is triggered by push/pull_request events, not workflow_dispatch, so github.event.inputs.branch will always be empty/null. No actual injection risk in practice.
- **apache/commons-crypto** (`maven_crosstest.yml`): [LOW] secrets.NEXUS_USER directly interpolated in env block at step 'Package and deploy to Maven Central on macOS'. Trusted value but risks log leakage. Use env: block instead.
- **apache/commons-crypto** (`maven_crosstest.yml`): [LOW] secrets.NEXUS_PW directly interpolated in env block at step 'Package and deploy to Maven Central on macOS'. Trusted value but risks log leakage. Use env: block instead.
- **apache/commons-io** (`maven.yml`): [LOW] secrets.NEXUS_USER and secrets.NEXUS_PW passed through env: block correctly in 'Deploy SNAPSHOT using minimal build' step. Best practice followed.
- **apache/cordova-android** (`draft-release.yml`): [LOW] secrets.CORDOVA_GPG_SECRET_KEY directly interpolated in run block at step 'Create Sign and Checksum'. Trusted value but risks log leakage. Use env: block instead.
- **apache/cordova-coho** (`nightly.yml`): [LOW] github.event.inputs.dispatchReason directly interpolated in run block at step 'Dispatch Inputs'. Workflow_dispatch is restricted to committers, so this is trusted input with low risk.
- **apache/cordova-coho** (`nightly.yml`): [LOW] github.event.inputs.verbose directly interpolated in run block at step 'Cordova Coho - Create Nightlies'. Workflow_dispatch is restricted to committers, so this is trusted input with low risk.
- **apache/cordova-eslint** (`draft-release.yml`): [LOW] secrets.CORDOVA_GPG_SECRET_KEY directly interpolated in run block at step 'Create Sign and Checksum'. Trusted value but risks log leakage. Use env: block instead.
- **apache/cordova-ios** (`docs.yml`): [LOW] github.event.repository.name directly interpolated in run block at 'Build DocC' step. GitHub-controlled value, low risk.
- **apache/cordova-ios** (`docs.yml`): [LOW] github.repository directly interpolated in run block at 'Build DocC' step. GitHub-controlled value, low risk.
- **apache/cordova-ios** (`docs.yml`): [LOW] github.ref_name directly interpolated in run block at 'Build DocC' step. GitHub-controlled value, low risk.
- **apache/cordova-ios** (`docs.yml`): [LOW] github.workspace directly interpolated in run block at 'Build DocC' step. GitHub-controlled value, low risk.
- **apache/cordova-ios** (`draft-release.yml`): [LOW] secrets.CORDOVA_GPG_SECRET_KEY directly interpolated in run block at step 'Create Sign and Checksum'. Trusted value but risks log leakage. Use env: block instead.
- **apache/cordova-plugin-camera** (`draft-release.yml`): [LOW] secrets.CORDOVA_GPG_SECRET_KEY directly interpolated in run block at step 'Create Sign and Checksum'. Trusted value but risks log leakage. Use env: block instead.
- **apache/couchdb-ci** (`image-builder.yml`): [LOW] github.event.inputs.dockerfile directly interpolated in file path at 'Build and push' step. Trusted committer input (workflow_dispatch) but could cause path traversal if malformed. Consider validation.
- **apache/couchdb-ci** (`image-builder.yml`): [LOW] github.event.inputs.erlangVersion, elixirVersion, platforms directly interpolated in build-args and platforms. Trusted committer input but could inject unexpected Docker build arguments.
- **apache/daffodil** (`main.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'Upload Coverage Report'. While with: blocks are generally safe, this is a credential being passed to an action.
- **apache/daffodil** (`main.yml`): [LOW] secrets.GITHUB_TOKEN and secrets.SONAR_TOKEN directly interpolated in env: block at step 'Run SonarCloud Scan'. These are trusted values but represent credentials.
- **apache/daffodil** (`release-candidate.yml`): [LOW] secrets.DAFFODIL_GPG_SECRET_KEY directly interpolated in with: block at step 'ASF Release Candidate'. While with: blocks are safer than run: blocks, this is a credential being passed to a third-party action.
- **apache/daffodil** (`release-candidate.yml`): [LOW] secrets.DAFFODIL_SVN_DEV_USERNAME and secrets.DAFFODIL_SVN_DEV_PASSWORD directly interpolated in with: block at step 'ASF Release Candidate'. Credentials passed to custom action.
- **apache/daffodil** (`release-candidate.yml`): [LOW] secrets.NEXUS_STAGE_DEPLOYER_USER and secrets.NEXUS_STAGE_DEPLOYER_PW directly interpolated in with: block at step 'ASF Release Candidate'. Nexus credentials passed to custom action for Maven publishing.
- **apache/daffodil-sbt** (`release-candidate.yml`): [LOW] secrets.DAFFODIL_GPG_SECRET_KEY directly interpolated in with: block at step 'ASF Release Candidate'. Passed to action parameter, not shell execution - acceptable pattern.
- **apache/daffodil-sbt** (`release-candidate.yml`): [LOW] secrets.DAFFODIL_SVN_DEV_USERNAME and secrets.DAFFODIL_SVN_DEV_PASSWORD directly interpolated in with: block at step 'ASF Release Candidate'. Passed to action parameter, not shell execution - acceptable pattern.
- **apache/daffodil-sbt** (`release-candidate.yml`): [LOW] secrets.NEXUS_STAGE_DEPLOYER_USER and secrets.NEXUS_STAGE_DEPLOYER_PW directly interpolated in with: block at step 'ASF Release Candidate'. Passed to action parameter, not shell execution - acceptable pattern.
- **apache/daffodil-site** (`build-publish.yml`): [LOW] github.token directly interpolated in run block at step 'Publish'. GitHub-controlled value but best practice is to use env: block to avoid accidental exposure.
- **apache/daffodil-vscode** (`release-candidate.yml`): [LOW] secrets.DAFFODIL_GPG_SECRET_KEY directly interpolated in with: block. While with: blocks are safer than run: blocks, secrets should ideally be passed through env: blocks.
- **apache/daffodil-vscode** (`release-candidate.yml`): [LOW] secrets.DAFFODIL_SVN_DEV_USERNAME and secrets.DAFFODIL_SVN_DEV_PASSWORD directly interpolated in with: block for SVN authentication.
- **apache/daffodil-vscode** (`release-candidate.yml`): [LOW] secrets.NEXUS_STAGE_DEPLOYER_USER and secrets.NEXUS_STAGE_DEPLOYER_PW directly interpolated in with: block for Nexus staging authentication.
- **apache/datafusion** (`docs.yaml`): [LOW] ${{ github.sha }} interpolated in git commit message. GitHub-controlled value, low risk but could be passed through env: block for consistency.
- **apache/datafusion-ballista** (`docs.yaml`): [LOW] github.sha directly interpolated in git commit message at step 'Copy & push the generated HTML'. GitHub-controlled value, low risk.
- **apache/datafusion-comet** (`docs.yaml`): [LOW] github.sha directly interpolated in git commit message at step 'Copy & push the generated HTML'. GitHub-controlled value, low risk but could be passed through env: for consistency.
- **apache/datafusion-sandbox** (`docs.yaml`): [LOW] github.sha directly interpolated in git commit message at step 'Copy & push the generated HTML'. GitHub-controlled value, low risk.
- **apache/datasketches-java** (`javadoc.yml`): [LOW] github.event.inputs.tag_ref directly interpolated in run blocks at steps 'Checkout' and 'Deploy Javadoc via Worktree'. This is a workflow_dispatch input controllable only by repository committers. Main risk is accidental command injection from malformed tag strings, not malicious exploitation.
- **apache/datasketches-memory** (`javadoc.yml`): [LOW] github.event.inputs.tag_ref directly interpolated in run blocks at steps 'Checkout' and 'Deploy Javadoc via Worktree'. This is a workflow_dispatch input controllable only by repository committers. Main risk is accidental command injection from malformed tag strings, not malicious exploitation.
- **apache/directory-scimple** (`snapshot.yml`): [LOW] secrets.GPG_SECRET_KEY directly interpolated in setup-java gpg-private-key parameter. Trusted value but direct interpolation in action parameters.
- **apache/directory-scimple** (`snapshot.yml`): [LOW] secrets.NEXUS_USER and secrets.NEXUS_PW passed through env: block correctly, but workflow uses Apache Snapshots repository (server-id: apache.snapshots.https) for snapshot publishing.
- **apache/dolphinscheduler** (`publish-docker.yaml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in run block at step 'Set environment variables'. Trusted values but risk log leakage. Use env: block instead.
- **apache/dolphinscheduler** (`publish-helm-chart.yaml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in run block at 'Set environment variables' step. Trusted values but risk log leakage. Use env: block instead.
- **apache/dolphinscheduler** (`publish-helm-chart.yaml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at 'Set environment variables' step. Trusted value but risk log leakage. Use env: block instead.
- **apache/doris-opentelemetry-demo** (`component-build-images.yml`): [LOW] secrets.DOCKER_PASSWORD directly interpolated in docker/login-action at step 'Log in to Docker Hub'. Trusted value but passed through action 'with:' block which is safe pattern.
- **apache/doris-opentelemetry-demo** (`release.yml`): [LOW] github.event.release.tag_name interpolated in with: block passed to reusable workflow. This is safe as with: blocks are not shell execution contexts, but the called workflow should validate the tag_name if used in shell commands.
- **apache/doris-operator** (`helm-release.yaml`): [LOW] secrets.OSS_KEY_ID directly interpolated in with: block at step 'install ossutil'. While with: blocks are generally safer than run: blocks, consider using env: pattern for consistency.
- **apache/doris-operator** (`helm-release.yaml`): [LOW] secrets.OSS_KEY_SECRET directly interpolated in with: block at step 'install ossutil'. While with: blocks are generally safer than run: blocks, consider using env: pattern for consistency.
- **apache/doris-thirdparty** (`manual-build.yml`): [LOW] inputs.doris_ref directly interpolated in checkout action at step 'Checkout'. Workflow_dispatch inputs are from trusted committers only, but free-form text could cause issues with malformed refs.
- **apache/doris-website** (`cron-deploy-website.yml`): [LOW] secrets.ALIYUN_ACCESS_KEY_ID directly interpolated in with: block at step 'Upload files to OSS'. While with: blocks are safer than run: blocks, consider using env: pattern for consistency.
- **apache/doris-website** (`cron-deploy-website.yml`): [LOW] secrets.ALIYUN_ACCESS_KEY_SECRET directly interpolated in with: block at step 'Upload files to OSS'. While with: blocks are safer than run: blocks, consider using env: pattern for consistency.
- **apache/doris-website** (`manual-deploy-website.yml`): [LOW] secrets.ALIYUN_ACCESS_KEY_ID and secrets.ALIYUN_ACCESS_KEY_SECRET passed to action via with: block. This is safe practice.
- **apache/doris-website** (`manual-deploy-website.yml`): [LOW] github.event.inputs.branch interpolated in commit_message and destination_dir. Workflow_dispatch is restricted to repository committers, so this is trusted input with low risk.
- **apache/doris-website** (`manual-generate-pdf.yml`): [LOW] workflow_dispatch input 'branch' is defined but not used in the workflow. If it were used in run: blocks, it would be low risk as workflow_dispatch is committer-only
- **apache/drill** (`publish-snapshot.yml`): [LOW] secrets.NEXUS_USER directly interpolated in run block at step 'Deploy Maven snapshots'. Trusted value but risks log leakage. Use env: block instead.
- **apache/drill** (`publish-snapshot.yml`): [LOW] secrets.NEXUS_PW directly interpolated in run block at step 'Deploy Maven snapshots'. Trusted value but risks log leakage. Use env: block instead.
- **apache/dubbo-go-pixiu** (`github-actions.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'Upload coverage to Codecov'. While with: blocks are generally safer than run: blocks, consider using env: pattern for consistency.
- **apache/dubbo-go-pixiu** (`release.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in with: block at step using go-release-action. While with: blocks are generally safer than run: blocks, this is a secret value. However, this is standard practice for GitHub Actions and the token is scoped to the workflow.
- **apache/dubbo-initializer** (`deploy.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN passed to docker/login-action via with: block. This is safe as secrets are not interpolated in run: blocks.
- **apache/dubbo-js** (`node.js.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with block at step 'Code Coverage'. While with: blocks are generally safe, this is a credential being passed to a third-party action.
- **apache/echarts** (`nightly-next.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in run block at step 'Setup and publish nightly'. Trusted value but risks log leakage. Use env: block instead.
- **apache/echarts** (`nightly.yml`): [LOW] secrets.NPM_TOKEN directly interpolated in run block at step 'Setup and publish nightly'. Trusted value but risks log leakage. Use env: block instead.
- **apache/echarts-website** (`deploy.yml`): [LOW] github.actor interpolated directly in git-config-name at Deploy step. GitHub-controlled value, low risk but could be passed through env: block for consistency.
- **apache/fesod** (`preview-docs.yml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in with block at 'Deploy to Netlify' step. While with: blocks are generally safe, consider using env: pattern for consistency.
- **apache/fesod** (`preview-docs.yml`): [LOW] secrets.NETLIFY_AUTH_TOKEN and secrets.NETLIFY_SITE_ID passed through env block (correct pattern).
- **apache/fineract** (`publish-dockerhub.yml`): [LOW] secrets.DOCKERHUB_USER directly interpolated in run block at step 'Build the Apache Fineract image'. Trusted value but risks log leakage. Use env: block instead.
- **apache/fineract** (`publish-dockerhub.yml`): [LOW] secrets.DOCKERHUB_TOKEN directly interpolated in run block at step 'Build the Apache Fineract image'. Trusted value but risks log leakage. Use env: block instead.
- **apache/flink** (`docs-legacy.yml`): [LOW] inputs.branch directly interpolated in run block at step 'Set branch environment variable'. Trusted committer input (workflow_dispatch with restricted choice options) but could cause command injection if choice list is modified. Use env: block instead.
- **apache/flink** (`docs-legacy.yml`): [LOW] secrets.NIGHTLIES_RSYNC_KEY directly interpolated in with: block of rsync action. While with: blocks are generally safer than run: blocks, SSH keys should ideally be passed through environment variables to minimize exposure surface.
- **apache/flink-cdc** (`build_docs.yml`): [LOW] secrets.NIGHTLIES_RSYNC_PATH directly interpolated in with: block at 'Upload documentation' step. While with: blocks are generally safer than run: blocks, this is a secret value being passed to an action parameter.
- **apache/flink-cdc** (`build_docs.yml`): [LOW] secrets.NIGHTLIES_RSYNC_HOST, secrets.NIGHTLIES_RSYNC_PORT, secrets.NIGHTLIES_RSYNC_USER, secrets.NIGHTLIES_RSYNC_KEY directly interpolated in with: blocks. These are trusted credential values passed to the rsync action.
- **apache/flink-kubernetes-operator** (`publish_snapshot.yml`): [LOW] secrets.NEXUS_USER and secrets.NEXUS_PW directly interpolated in run block at step 'Publish snapshot'. Trusted values but risk log leakage. Use env: block instead (though they are passed to env: here, the pattern is acceptable).
- **apache/fluss** (`docs-deploy.yaml`): [LOW] secrets.GH_TOKEN directly interpolated in run block at step 'Send Event to Trigger Deploy'. Trusted value but risks log leakage. Use env: block instead.
- **apache/fluss-rust** (`release_rust.yml`): [LOW] secrets.CARGO_REGISTRY_TOKEN directly interpolated in run block at step 'Publish fluss-rs to crates.io'. Trusted value but risks log leakage. Use env: block instead.
- **apache/fluss-website** (`website-deploy.yaml`): [LOW] secrets.GITHUB_TOKEN directly interpolated in run block at step 'Deploy website'. Trusted value but risks log leakage. Use env: block instead.
- **apache/fory** (`release-compiler.yaml`): [LOW] github.ref_name directly interpolated in run block at step 'Bump compiler version'. GitHub-controlled value, but could be safer using env: block.
- **apache/fory** (`release-rust.yaml`): [LOW] secrets token from steps.crates-io-auth.outputs.token directly interpolated in run block at step 'Export crates.io token'. Trusted value but risks log leakage. Use env: block instead.
- **apache/fory** (`release-rust.yaml`): [LOW] github.ref_name directly interpolated in run block at step 'Bump rust version'. GitHub-controlled value, low risk.
- **apache/gluten** (`nightly_sync.yml`): [LOW] secrets.NIGHTLIES_RSYNC_PATH directly interpolated in with: block at step 'rsync'. While with: blocks are generally safer than run: blocks, this is a secret value being passed to a third-party action. Best practice would be to use env: block.
- **apache/gluten** (`nightly_sync.yml`): [LOW] secrets.NIGHTLIES_RSYNC_HOST directly interpolated in with: block at step 'rsync'. Same concern as above.
- **apache/gluten** (`nightly_sync.yml`): [LOW] secrets.NIGHTLIES_RSYNC_PORT directly interpolated in with: block at step 'rsync'. Same concern as above.
- **apache/gluten** (`nightly_sync.yml`): [LOW] secrets.NIGHTLIES_RSYNC_USER directly interpolated in with: block at step 'rsync'. Same concern as above.
- **apache/gluten** (`nightly_sync.yml`): [LOW] secrets.NIGHTLIES_RSYNC_KEY directly interpolated in with: block at step 'rsync'. SSH private key passed to third-party action. Ensure action is trusted and pinned to commit SHA (which it is).
- **apache/gluten** (`velox_nightly.yml`): [LOW] secrets.NIGHTLIES_RSYNC_KEY directly interpolated in with: block at steps 'rsync to apache nightly'. While with: blocks are lower risk than run: blocks, SSH keys should ideally be passed through env: for consistency.
- **apache/gluten** (`velox_nightly.yml`): [LOW] secrets.NIGHTLIES_RSYNC_PATH, secrets.NIGHTLIES_RSYNC_HOST, secrets.NIGHTLIES_RSYNC_PORT, secrets.NIGHTLIES_RSYNC_USER directly interpolated in with: blocks. These are trusted values but represent infrastructure configuration.
- **apache/gobblin** (`docker_build_publish.yaml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in docker/login-action@v1 'with:' block. While 'with:' blocks are safer than 'run:' blocks, best practice is to use env: block for secrets.
- **apache/grails-core** (`forge-deploy-next.yml`): [LOW] secrets.GH_OAUTH_SNAPSHOT_CLIENT_SECRET directly interpolated in run block at step 'Deploy Docker image'. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-core** (`forge-deploy-prev-snapshot.yml`): [LOW] secrets.GH_OAUTH_SNAPSHOT_CLIENT_SECRET directly interpolated in gcloud run deploy command at 'Deploy Docker image' step. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-core** (`forge-deploy-prev-snapshot.yml`): [LOW] secrets.GCLOUD_EMAIL directly interpolated in gcloud run deploy commands. Trusted value but could use env: block for consistency.
- **apache/grails-core** (`forge-deploy-prev.yml`): [LOW] secrets.GCP_CREDENTIALS directly interpolated in google-github-actions/auth step. Trusted value but passed through action 'with:' block (safe pattern).
- **apache/grails-core** (`forge-deploy-prev.yml`): [LOW] secrets.GH_OAUTH_SNAPSHOT_CLIENT_SECRET directly interpolated in gcloud run deploy command at 'Deploy Docker image' step. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-core** (`forge-deploy-release.yml`): [LOW] secrets.GCP_CREDENTIALS directly interpolated in google-github-actions/auth step. Trusted value but passed through with: block (safe pattern).
- **apache/grails-core** (`forge-deploy-release.yml`): [LOW] secrets.GH_OAUTH_LATEST_CLIENT_SECRET directly interpolated in gcloud run deploy command at 'Deploy Docker image' step. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-core** (`forge-deploy-release.yml`): [LOW] github.event.inputs.release directly interpolated in env.IMAGE_NAME and shell commands. Workflow_dispatch is committer-only, so trusted input, but free-form text could cause command injection if malformed.
- **apache/grails-core** (`forge-deploy-snapshot.yml`): [LOW] secrets.GCP_CREDENTIALS directly interpolated in auth action. Trusted value but passed through action with: block (safe pattern).
- **apache/grails-core** (`forge-deploy-snapshot.yml`): [LOW] secrets.GH_OAUTH_SNAPSHOT_CLIENT_SECRET directly interpolated in gcloud run deploy command at 'Deploy Docker image' step. Trusted value but risks log leakage. Use --set-env-vars with file or env: block instead.
- **apache/grails-core** (`gradle.yml`): [LOW] secrets.NEXUS_PW directly interpolated in env block at step 'Publish Gradle Snapshot Artifacts' in publishGradle job. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-core** (`gradle.yml`): [LOW] secrets.NEXUS_PW directly interpolated in env block at step 'Publish Grails-Core Snapshot Artifacts' in publish job. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-core** (`gradle.yml`): [LOW] secrets.NEXUS_PW directly interpolated in env block at step 'Publish Gradle Snapshot Artifacts' in publishForge job. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-core** (`release-publish-docs.yml`): [LOW] secrets.GRAILS_GHTOKEN directly interpolated in env block at step 'Publish to GitHub Pages'. Trusted value but risks log leakage. Use env: block instead (though this is already in env context, the pattern is acceptable).
- **apache/grails-core** (`release-publish-docs.yml`): [LOW] inputs.version directly interpolated in env block. Workflow_dispatch input from trusted committers only. Low risk of command injection from malformed version strings.
- **apache/grails-github-actions** (`release.yml`): [LOW] secrets.GRAILS_GPG_KEY directly interpolated in run block at step 'Set up GPG'. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-github-actions** (`release.yml`): [LOW] secrets.SVC_DIST_GRAILS_USERNAME and secrets.SVC_DIST_GRAILS_PASSWORD used directly in svn commands throughout the upload job. Trusted values but could be passed through env: block for consistency.
- **apache/grails-gradle-publish** (`ci.yaml`): [LOW] secrets.NEXUS_USER directly interpolated in env block at 'Publish Snapshot Artifacts' step. While env: block is used (best practice), note this is a credential.
- **apache/grails-gradle-publish** (`ci.yaml`): [LOW] secrets.NEXUS_PW directly interpolated in env block at 'Publish Snapshot Artifacts' step. While env: block is used (best practice), note this is a credential.
- **apache/grails-gradle-publish** (`release.yaml`): [LOW] secrets.GRAILS_GPG_KEY directly interpolated in run block at step 'Set up GPG for signing'. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-gradle-publish** (`release.yaml`): [LOW] secrets.GPG_KEY_ID directly interpolated in run block at step 'Publish to Staging Repository'. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-gradle-publish** (`release.yaml`): [LOW] secrets.GPG_KEY_ID directly interpolated in run block at step 'Sign source distribution ZIP'. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-quartz** (`release.yml`): [LOW] secrets.GRAILS_GPG_KEY directly interpolated in run block at step 'Set up GPG' in publish job. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-quartz** (`release.yml`): [LOW] secrets.GRAILS_GPG_KEY directly interpolated in run block at step 'Set up GPG' in source job. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-redis** (`gradle.yml`): [LOW] secrets.NEXUS_USER directly interpolated in env block at step 'Publish Snapshot Artifacts'. While env: block is used, the secret is exposed as an environment variable.
- **apache/grails-redis** (`gradle.yml`): [LOW] secrets.NEXUS_PW directly interpolated in env block at step 'Publish Snapshot Artifacts'. While env: block is used, the secret is exposed as an environment variable.
- **apache/grails-redis** (`release.yml`): [LOW] secrets.NEXUS_STAGE_DEPLOYER_USER directly interpolated in env block at step 'Create Staging Repository'. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-redis** (`release.yml`): [LOW] secrets.NEXUS_STAGE_DEPLOYER_PW directly interpolated in env block at step 'Create Staging Repository'. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-redis** (`release.yml`): [LOW] secrets.GPG_KEY_ID directly interpolated in env block at step 'Create Staging Repository'. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-redis** (`release.yml`): [LOW] secrets.GRAILS_GPG_KEY directly interpolated in run block at step 'Set up GPG'. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-redis** (`release.yml`): [LOW] secrets.SVC_DIST_GRAILS_USERNAME and secrets.SVC_DIST_GRAILS_PASSWORD directly interpolated in run blocks for SVN operations. Trusted values but risk log leakage.
- **apache/grails-spring-security** (`gradle.yml`): [LOW] secrets.NEXUS_PW directly interpolated in env block at step 'Publish Snapshot artifacts'. While env: block is used (best practice), the secret name is visible in workflow definition.
- **apache/grails-spring-security** (`release.yml`): [LOW] secrets.NEXUS_STAGE_DEPLOYER_USER and secrets.NEXUS_STAGE_DEPLOYER_PW directly interpolated in env blocks for multiple steps. While env: blocks are safer than direct run: interpolation, these are still credentials that could be exposed if mishandled.
- **apache/grails-spring-security** (`release.yml`): [LOW] secrets.GRAILS_GPG_KEY directly interpolated in run block at step 'Set up GPG' (publish job and source job). Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-spring-security** (`release.yml`): [LOW] secrets.SVC_DIST_GRAILS_PASSWORD directly interpolated in run blocks for SVN operations in upload job. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-static-website** (`publish.yml`): [LOW] secrets.GRAILS_GHTOKEN directly interpolated in run block at step 'Publish Main Site'. Trusted value but risks log leakage. Use env: block instead.
- **apache/grails-static-website** (`publish.yml`): [LOW] secrets.APACHE_GRAILS_BUILD_GH_TOKEN directly interpolated in run block at step 'Publish Guides Site'. Trusted value but risks log leakage. Use env: block instead.
- **apache/gravitino** (`docker-image.yml`): [LOW] github.event.inputs.username directly interpolated in docker/login-action 'with:' block. While 'with:' blocks are safer than 'run:' blocks, username is trusted committer input.
- **apache/gravitino** (`docker-image.yml`): [LOW] github.event.inputs.token directly interpolated in env block and compared in run block. This is a custom token validation mechanism where the token is exposed in the workflow environment. Should use GitHub secrets exclusively.
- **apache/gravitino** (`docker-image.yml`): [LOW] Multiple workflow_dispatch inputs (docker_repo_name, version, image) are directly interpolated in run blocks. These are trusted committer inputs (workflow_dispatch is restricted to repo maintainers) but could cause command injection if malformed. Consider validation or quoting.
- **apache/groovy** (`groovy-build-coverage.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'Upload coverage to Codecov'. While with: blocks are generally safe, this is a credential being passed to a third-party action.
- **apache/groovy** (`groovy-build-coverage.yml`): [LOW] secrets.DEVELOCITY_ACCESS_KEY directly interpolated in env: block. Trusted value but exposed as environment variable to all steps.
- **apache/hamilton** (`sphinx-docs.yml`): [LOW] github.token directly interpolated in env block then used in git push command. While passed through env:, the token is used in URL construction which could expose it in process listings. Standard practice for GitHub Pages deployment.
- **apache/hertzbeat** (`backend-build-test.yml`): [LOW] secrets.CODECOV_TOKEN directly interpolated in with: block at step 'Upload coverage reports to Codecov'. While with: blocks are generally safer than run: blocks, this is a credential being passed to a third-party action.
- **apache/hertzbeat** (`nightly-build.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in docker/login-action with: block. While this is standard practice for this action and values are passed to action inputs (not shell), it's worth noting for completeness.
- **apache/hive** (`docker-images.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in docker/login-action@v2 'with:' block. While 'with:' blocks are safer than 'run:' blocks, these are credentials being passed to an action.
- **apache/hive** (`docker-images.yml`): [LOW] github.event.inputs.hiveVersion, hadoopVersion, and tezVersion directly interpolated in run blocks for workflow_dispatch. These are trusted committer inputs (workflow_dispatch is restricted to maintainers), but free-form text could cause command injection if malformed. Risk is low as inputs are from trusted sources.
- **apache/hudi-rs** (`release.yml`): [LOW] secrets.CARGO_REGISTRY_TOKEN directly interpolated in env block at step 'cargo publish'. While env: block is used, this is a credential exposure pattern.
- **apache/hudi-rs** (`release.yml`): [LOW] secrets.PYPI_TOKEN directly interpolated in env block at multiple PyPI release steps. While env: block is used, this is a credential exposure pattern.
- **apache/hugegraph-doc** (`hugo.yml`): [LOW] github.event.head_commit.message directly interpolated in commit_message parameter at 'Deploy Site' step. This is GitHub-controlled metadata from committed changes, but could contain special characters. Low risk as it's from actual commits by authorized users, not external PR input.
- **apache/incubator-baremaps** (`pre-release.yml`): [LOW] secrets.BAREMAPS_GPG_SECRET_KEY directly interpolated in run block at step 'Set up GPG'. Trusted value but risks log leakage. Use env: block instead.
- **apache/incubator-baremaps** (`pre-release.yml`): [LOW] secrets.GPG_KEY_ID directly interpolated in run block at step 'Sign and hash pre-release'. Trusted value but risks log leakage. Use env: block instead.
- **apache/incubator-baremaps** (`release.yml`): [LOW] secrets.BAREMAPS_GPG_SECRET_KEY directly interpolated in run block at step 'Set up GPG'. Trusted value but risks log leakage. Use env: block instead.
- **apache/incubator-baremaps** (`release.yml`): [LOW] secrets.GPG_KEY_ID directly interpolated in run blocks at steps 'Sign and hash release candidate'. Trusted value but risks log leakage. Use env: block instead.
- **apache/incubator-baremaps** (`release.yml`): [LOW] secrets.INCUBATOR_SVN_DEV_USERNAME and secrets.INCUBATOR_SVN_DEV_PASSWORD directly interpolated in svn command at step 'Publish release candidate on Apache SVN'. Trusted values but risk log leakage. Use env: block instead.
- **apache/incubator-baremaps** (`snapshot.yml`): [LOW] secrets.BAREMAPS_GPG_SECRET_KEY directly interpolated in run block at step 'Set up GPG'. Trusted value but risks log leakage. Use env: block instead.
- **apache/kafka** (`docker_promote.yml`): [LOW] github.event.inputs.promoted_docker_image and github.event.inputs.rc_docker_image directly interpolated in run block at step 'Copy RC Image to promoted image'. These are workflow_dispatch inputs from trusted committers (workflow restricted to apache/kafka repository). Main risk is accidental command injection from malformed image names, not malicious exploitation.
- **apache/kafka** (`docker_rc_release.yml`): [LOW] github.event.inputs.rc_docker_image, github.event.inputs.kafka_url, and github.event.inputs.image_type are passed through env: block then used as shell variables. This is safe practice.
- **apache/knox** (`docker-publish.yml`): [LOW] secrets.DOCKERHUB_TOKEN directly interpolated in run block at step 'Login to Docker Hardened Images'. Trusted value but risks log leakage. Use env: block instead.
- **apache/knox** (`docker-publish.yml`): [LOW] secrets.DOCKERHUB_USER directly interpolated in run block at step 'Login to Docker Hardened Images'. Trusted value but risks log leakage. Use env: block instead.
- **apache/knox** (`docker-publish.yml`): [LOW] secrets.DOCKERHUB_TOKEN directly interpolated in run block at step 'Login to DockerHub'. Trusted value but risks log leakage. Use env: block instead.
- **apache/knox** (`docker-publish.yml`): [LOW] secrets.DOCKERHUB_USER directly interpolated in run block at step 'Login to DockerHub'. Trusted value but risks log leakage. Use env: block instead.
- **apache/kvrocks** (`nightly.yaml`): [LOW] secrets.DOCKER_USERNAME and secrets.DOCKER_PASSWORD directly interpolated in 'with:' blocks at 'Login to Docker Hub' steps. While 'with:' blocks are safer than 'run:' blocks, best practice is to use env: block for secrets.
- **apache/kyuubi** (`publish-snapshot-nexus.yml`): [LOW] secrets.NEXUS_USER directly interpolated in env block at step 'Publish Snapshot Jar to Nexus'. While env: block is used, the secret is exposed as an environment variable. This is acceptable practice but ensure the Maven settings file properly references these.
- **apache/kyuubi** (`publish-snapshot-nexus.yml`): [LOW] secrets.NEXUS_PW directly interpolated in env block at step 'Publish Snapshot Jar to Nexus'. While env: block is used, the secret is exposed as an environment variable. This is acceptable practice but ensure the Maven settings file properly references these.
- **apache/kyuubi-docker** (`docker-image.yml`): [LOW] secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN directly interpolated in docker/login-action with: block. While this is passed to an action (not a run: block), it's worth noting for credential handling awareness.

</details>

## Detailed Results: Release & Snapshot Workflows

### apache/activemq

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`deploy.yml`** — Deploy [Snapshot / Nightly Artifacts]
- **Summary**: Scheduled nightly workflow that deploys Maven artifacts using 'mvn deploy' with the 'deploy' profile. Runs daily at midnight UTC. This is a snapshot/nightly build deployment to a Maven repository (likely Apache Snapshots repository given the Apache project context).
- **Ecosystems**: maven_central
- **Trigger**: schedule (cron: '0 0 * * *')
- **Auth**: Maven settings.xml (implicit)
- **Confidence**: high
- **Commands**: `mvn -B -e deploy -Pdeploy -DskipTests`

### apache/airavata

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`build-and-publish.yml`** — Build and Push Airavata Docker Image [Release Artifacts]
- **Summary**: Builds Apache Airavata with Maven and Thrift, then publishes multi-architecture Docker images (linux/amd64, linux/arm64) to Docker Hub registry (docker.io/cybershuttle/airavata). Images are tagged with branch names, semantic versions from git tags, and commit SHAs. Publishes on pushes to main/master branches and version tags (v*), making this a release artifact workflow.
- **Ecosystems**: docker_hub
- **Trigger**: push to main/master branches, tags matching v*, or manual workflow_dispatch
- **Auth**: Docker Hub username and access token from GitHub secrets
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/build-push-action@v5`

### apache/airavata-mft

**1** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 1

**`release_on_tag_push.yml`** — GitHub Actions Demo [Release Artifacts]
- **Summary**: Workflow triggers on release publication, builds Maven artifacts, and uploads two binary zip files (MFT-Agent-0.01-bin.zip and Standalone-Service-0.01-bin.zip) to the GitHub Release using gh CLI. These are versioned release artifacts intended for end-user consumption.
- **Ecosystems**: github_releases
- **Trigger**: release published
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **Commands**: `gh release upload`

### apache/airflow

**2** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 2

**`release_dockerhub_image.yml`** — Release PROD images [Release Artifacts]
- **Summary**: Publishes versioned Apache Airflow Docker images to Docker Hub. Triggered manually via workflow_dispatch with airflowVersion input (e.g., 3.0.1, 3.0.1rc1). Builds multi-platform images (linux/amd64, linux/arm64) for multiple Python versions. Delegates actual publishing to reusable workflow release_single_dockerhub_image.yml using DOCKERHUB_USER and DOCKERHUB_TOKEN secrets. Access restricted to specific Apache Airflow committers.
- **Ecosystems**: docker_hub
- **Trigger**: workflow_dispatch
- **Auth**: DOCKERHUB_USER and DOCKERHUB_TOKEN secrets
- **Confidence**: high

**`release_single_dockerhub_image.yml`** — Release single PROD image [Release Artifacts]
- **Summary**: This workflow publishes versioned Apache Airflow production Docker images to Docker Hub. It builds multi-platform (amd64/arm64) images for specific Airflow and Python versions, creates both regular and slim variants, and merges them into multi-arch manifests. The workflow is triggered via workflow_call with version parameters (e.g., 3.0.1, 3.0.1rc1), indicating it's used for releasing official Airflow Docker images to Docker Hub for end-user consumption.
- **Ecosystems**: docker_hub
- **Trigger**: workflow_call
- **Auth**: DOCKERHUB_USER and DOCKERHUB_TOKEN secrets
- **Confidence**: high
- **Commands**: `breeze release-management release-prod-images`, `breeze release-management merge-prod-images`

### apache/airflow-publish

**4** release/snapshot workflows | Ecosystems: **pypi** | Release Artifacts: 3, Snapshot / Nightly Artifacts: 1

**`airflow-publish.yml`** — Dry run publish airflow packages [Release Artifacts]
- **Summary**: Apache Airflow release workflow that verifies SVN artifacts (checksums, signatures) and publishes Python packages to PyPI when mode is set to RELEASE. Uses OIDC trusted publishing for secure authentication. Workflow is manually triggered by repository maintainers with choice-based inputs for release config and mode.
- **Ecosystems**: pypi
- **Trigger**: workflow_dispatch with mode input (VERIFY or RELEASE)
- **Auth**: OIDC trusted publishing (id-token: write permission)
- **Confidence**: high
- **GitHub Actions**: `pypa/gh-action-pypi-publish@release/v1`

**`providers-publish.yml`** — Dry run publish airflow provider packages [Release Artifacts]
- **Summary**: This workflow publishes Apache Airflow provider packages to PyPI. It performs verification checks (SVN checkout, checksum, signature validation) on artifacts from Apache SVN distribution, then conditionally publishes to PyPI when mode is set to RELEASE. Uses OIDC trusted publishing for secure authentication. The workflow is manually triggered by repository maintainers via workflow_dispatch.
- **Ecosystems**: pypi
- **Trigger**: workflow_dispatch with mode input (VERIFY or RELEASE)
- **Auth**: OIDC trusted publishing (id-token: write permission)
- **Confidence**: high
- **GitHub Actions**: `pypa/gh-action-pypi-publish@release/v1`

**`test-pypi-airflow-publish.yml`** — Publish Airflow distribution 📦 to Test PyPI [Release Artifacts]
- **Summary**: This workflow publishes Apache Airflow Python packages to Test PyPI. It operates in two modes: VERIFY (validation only) and RELEASE (actual publication). The workflow checks out artifacts from Apache SVN distribution, validates checksums and signatures, uploads artifacts to GitHub Actions storage, then publishes to Test PyPI using OIDC trusted publishing. Despite the name 'Test PyPI', this is a release_artifact workflow as it publishes versioned Apache Airflow distributions to a public PyPI registry (test.pypi.org) that end users can consume.
- **Ecosystems**: pypi
- **Trigger**: workflow_dispatch with mode input (VERIFY or RELEASE)
- **Auth**: OIDC trusted publishing (id-token: write permission)
- **Confidence**: high
- **GitHub Actions**: `pypa/gh-action-pypi-publish@release/v1`

**`test-pypi-providers-publish.yml`** — Publish providers distribution 📦 to Test PyPI [Snapshot / Nightly Artifacts]
- **Summary**: Workflow publishes Apache Airflow provider packages to Test PyPI (test.pypi.org) after performing SVN checkout and validation checks (checksum, signature, artifact verification). Publishing is conditional on mode='RELEASE' input and requires environment approval. Uses OIDC trusted publishing for secure authentication.
- **Ecosystems**: pypi
- **Trigger**: workflow_dispatch
- **Auth**: OIDC trusted publishing (id-token: write)
- **Confidence**: high
- **GitHub Actions**: `pypa/gh-action-pypi-publish@release/v1`

### apache/amoro

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`docker-images.yml`** — Publish Docker Image [Release Artifacts]
- **Summary**: Publishes three Docker images to Docker Hub (apache/amoro, apache/amoro-flink-optimizer, apache/amoro-spark-optimizer) on pushes to master (snapshot builds) and version tags (releases). Images are built for multiple platforms (linux/amd64, linux/arm64) with various Hadoop, Flink, and Spark version matrices. Uses semantic versioning tags for releases and -snapshot suffix for master branch builds.
- **Ecosystems**: docker_hub
- **Trigger**: push to master branch or version tags (v*)
- **Auth**: Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v2`, `docker/build-push-action@v4`

### apache/answer

**5** release/snapshot workflows | Ecosystems: **docker_hub, github_releases** | Release Artifacts: 4, Snapshot / Nightly Artifacts: 1

**`build-binary-for-release.yml`** — Build Binary For Release [Release Artifacts]
- **Summary**: This workflow publishes release artifacts to GitHub Releases when version tags (v*) are pushed. It uses GoReleaser to build binaries for multiple platforms and automatically creates a GitHub Release with the built artifacts. The workflow builds the UI with Node.js, compiles Go binaries, and uses GoReleaser with the 'release' command to publish to GitHub Releases. The upload-artifact step is for CI storage only and does not constitute publishing to a registry.
- **Ecosystems**: github_releases
- **Trigger**: push to tags matching v*
- **Auth**: GITHUB_TOKEN (secrets.GITHUB_TOKEN)
- **Confidence**: high
- **GitHub Actions**: `goreleaser/goreleaser-action@v4`

**`build-image-for-latest-release.yml`** — Build Latest Docker Image For Release [Release Artifacts]
- **Summary**: Publishes Docker images to Docker Hub (apache/answer:latest) when version tags are pushed. Triggered on release tags (v0.*, v1.*, v2.*) excluding release candidates. Builds multi-platform images (linux/amd64, linux/arm64) and pushes to public Docker Hub registry for end-user consumption.
- **Ecosystems**: docker_hub
- **Trigger**: push to tags matching v2.*, v1.*, v0.* (excluding RC tags)
- **Auth**: Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/build-push-action@v4`

**`build-image-for-manual.yml`** — Manual Build Docker Image For Release [Release Artifacts]
- **Summary**: Manually triggered workflow that builds multi-platform Docker images (linux/amd64, linux/arm64) and publishes them to Docker Hub under apache/answer with a user-specified tag name. Restricted to apache organization repository owners.
- **Ecosystems**: docker_hub
- **Trigger**: workflow_dispatch
- **Auth**: secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/build-push-action@v4`

**`build-image-for-release.yml`** — Build Docker Image For Release [Release Artifacts]
- **Summary**: Publishes versioned Docker images to Docker Hub (apache/answer) when semantic version tags (v0.*, v1.*, v2.*) are pushed. Uses docker/build-push-action with multi-platform builds (linux/amd64, linux/arm64) and semantic versioning tags generated by docker/metadata-action.
- **Ecosystems**: docker_hub
- **Trigger**: push to tags matching v2.*, v1.*, v0.*
- **Auth**: DOCKERHUB_USER and DOCKERHUB_TOKEN secrets
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/build-push-action@v4`

**`build-image-for-test.yml`** — Build Docker Image For Test [Snapshot / Nightly Artifacts]
- **Summary**: Publishes Docker images to Docker Hub (apache/answer:test) when code is pushed to the 'test' branch. This is a snapshot/nightly build workflow for testing purposes, not a release artifact. The image is tagged with 'test' and pushed only for the linux/amd64 platform.
- **Ecosystems**: docker_hub
- **Trigger**: push to 'test' branch
- **Auth**: DOCKERHUB_USER and DOCKERHUB_TOKEN secrets
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/build-push-action@v4`

### apache/apisix

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Snapshot / Nightly Artifacts: 1

**`push-dev-image-on-commit.yml`** — Build and Push `apisix:dev` to DockerHub on Commit [Snapshot / Nightly Artifacts]
- **Summary**: Builds APISIX Docker images with embedded dashboard for amd64 and arm64 architectures, tests them, and pushes development images tagged 'master-debian-dev' to Docker Hub when commits are pushed to the master branch. This is a snapshot/nightly build workflow for development images, not release artifacts.
- **Ecosystems**: docker_hub
- **Trigger**: push to master branch (also pull_request and workflow_dispatch, but publishing only occurs on master)
- **Auth**: Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@b45d80f862d83dbcd57f89517bcf500b2ab88fb2`
- **Commands**: `make push-on-debian-dev`, `make merge-dev-tags`

### apache/apisix-docker

**3** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 2, Snapshot / Nightly Artifacts: 1

**`apisix_push_docker_hub.yaml`** — Docker image [Release Artifacts]
- **Summary**: Workflow builds Apache APISIX Docker images for multiple platforms (ubuntu, debian, redhat), tests them, and publishes to Docker Hub when triggered by pushes to release/apisix-** branches. Images are pushed as both platform-specific tags and latest tag (for ubuntu). Uses multi-architecture builds via Docker Buildx.
- **Ecosystems**: docker_hub
- **Trigger**: push to branches matching 'release/apisix-**'
- **Auth**: Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v1`
- **Commands**: `make push-multiarch-on-latest`, `make push-multiarch-on-${{ matrix.platform }}`

**`dashboard_push_docker_hub.yaml`** — Push apisix dashboard to Docker image [Release Artifacts]
- **Summary**: This workflow builds the Apache APISIX Dashboard Docker image on Alpine, runs smoke tests, and authenticates to Docker Hub using stored credentials. The workflow is triggered on pushes to release branches and sets up Docker Buildx with QEMU for multi-platform builds. While the YAML excerpt ends before showing the actual push command, the workflow name, Docker Hub authentication, and buildx setup clearly indicate this publishes release artifacts to Docker Hub.
- **Ecosystems**: docker_hub
- **Trigger**: push to branches matching 'release/apisix-dashboard**'
- **Auth**: Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v1`, `docker/setup-qemu-action@v1`, `docker/setup-buildx-action@v1`

**`apisix_dev_push_docker_hub.yaml`** — Build and Push apisix-dev to Docker DockerHub [Snapshot / Nightly Artifacts]
- **Summary**: Builds and publishes nightly development Docker images (apisix-dev) with tag 'master-debian-dev' to Docker Hub. Triggered daily via cron schedule and on pushes to master branch. Tests APISIX functionality before pushing multi-architecture images using buildx.
- **Ecosystems**: docker_hub
- **Trigger**: schedule (daily at 1:00 UTC) and push to master branch
- **Auth**: Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v1`
- **Commands**: `make push-multiarch-dev-on-debian`

### apache/apisix-helm-chart

**1** release/snapshot workflows | Ecosystems: **github_releases, helm** | Release Artifacts: 1

**`release.yaml`** — Release Charts [Release Artifacts]
- **Summary**: This workflow publishes Helm charts to GitHub Releases and the Apache APISIX Helm chart repository. It uses the chart-releaser-action (a local action at ./.github/actions/chart-releaser-action) to package and publish Helm charts on pushes to master, legacy, or dev branches. The chart-releaser tool typically creates GitHub Releases with packaged chart artifacts and updates the Helm repository index. Authentication uses the default GITHUB_TOKEN secret.
- **Ecosystems**: helm, github_releases
- **Trigger**: push to master, legacy, or dev branches
- **Auth**: GITHUB_TOKEN (secrets.GITHUB_TOKEN)
- **Confidence**: high
- **GitHub Actions**: `./.github/actions/chart-releaser-action`

### apache/apisix-ingress-controller

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`push-docker.yaml`** — push on dockerhub [Release Artifacts]
- **Summary**: Publishes multi-arch Docker images to Docker Hub. Triggered on tag pushes (release versions) and master branch pushes (dev builds). Uses docker/login-action for authentication and a Makefile target to build and push images. Tag releases use the git tag name as image tag, while master branch builds use 'dev' tag.
- **Ecosystems**: docker_hub
- **Trigger**: push to tags or master branch
- **Auth**: DOCKERHUB_USER and DOCKERHUB_TOKEN secrets
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`
- **Commands**: `make build-push-multi-arch-image`

### apache/arrow

**4** release/snapshot workflows | Ecosystems: **apache_dist, github_releases** | Release Artifacts: 3, Snapshot / Nightly Artifacts: 1

**`package_linux.yml`** — Package Linux [Release Artifacts]
- **Summary**: Builds Linux packages (APT/YUM) for Apache Arrow across multiple distributions and architectures. When triggered by release candidate tags (apache-arrow-*-rc*), uploads the packaged artifacts as .tar.gz files to GitHub Releases. Also pushes Docker build cache images to GHCR on main branch commits.
- **Ecosystems**: github_releases
- **Trigger**: push to tags matching apache-arrow-*-rc*, push to branches, pull_request, schedule
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **Commands**: `gh release upload ${GITHUB_REF_NAME} --clobber ${{ matrix.id }}.tar.gz*`

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes Apache Arrow release artifacts to GitHub Releases. It triggers on non-RC release tags, downloads artifacts from the corresponding release candidate, and creates a new GitHub Release with those artifacts attached. The workflow also cleans up draft releases.
- **Ecosystems**: github_releases
- **Trigger**: push to tags matching 'apache-arrow-*' (excluding RC tags)
- **Auth**: GH_TOKEN (github.token)
- **Confidence**: high
- **Commands**: `gh release create ${GITHUB_REF_NAME} --notes "TODO" --repo ${GITHUB_REPOSITORY} --title "${RELEASE_TITLE}" --verify-tag release_candidate_artifacts/*`

**`release_candidate.yml`** — RC [Release Artifacts]
- **Summary**: Publishes Apache Arrow release candidate tarballs to GitHub Releases. Triggered by tags matching apache-arrow-*-rc* pattern. Creates a signed tarball with GPG signature and checksum, then uploads to a draft GitHub Release marked as prerelease. The tarball is also uploaded to GitHub Actions artifacts for ephemeral storage.
- **Ecosystems**: github_releases
- **Trigger**: push to tags matching apache-arrow-*-rc*
- **Auth**: github.token
- **Confidence**: high
- **Commands**: `gh release create`

**`r_nightly.yml`** — Upload R Nightly builds [Snapshot / Nightly Artifacts]
- **Summary**: This workflow downloads nightly R binary packages from the Crossbow repository and uploads them to nightlies.apache.org via rsync. It runs on a schedule (daily at 14:00 UTC) and can be manually triggered. The workflow builds a CRAN-like repository structure with R packages and libarrow binaries for multiple platforms (Windows, macOS, Linux), prunes old versions (keeping 14 by default), updates repository indexes, and syncs the entire repository to Apache's nightly distribution server using SSH/rsync.
- **Ecosystems**: apache_dist
- **Trigger**: schedule (cron: 0 14 * * *) and workflow_dispatch
- **Auth**: SSH key authentication via secrets.NIGHTLIES_RSYNC_KEY
- **Confidence**: high
- **Commands**: `rsync -avzh --update --delete --progress repo to nightlies.apache.org`

### apache/arrow-adbc

**1** release/snapshot workflows | Ecosystems: **maven_central, npm, pypi** | Snapshot / Nightly Artifacts: 1

**`packaging.yml`** — Packaging [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds Apache Arrow ADBC packages (Java JARs, Python wheels, Node.js packages, C# NuGet, Conda packages, Linux packages) for multiple platforms. It publishes nightly/snapshot builds to Gemfury (for Java, Python, Node.js) and Anaconda.org (for Conda packages) when triggered by schedule or manual workflow_dispatch with upload_artifacts=true. For RC tags, it creates GitHub releases with artifacts but does not publish to public registries. The workflow also includes cleanup jobs to remove old packages from Gemfury and Anaconda.org.
- **Ecosystems**: maven_central, pypi, npm
- **Trigger**: schedule (nightly) or workflow_dispatch with upload_artifacts=true
- **Auth**: GEMFURY_PUSH_TOKEN, GEMFURY_API_TOKEN, ANACONDA_API_TOKEN, NPM_TOKEN
- **Confidence**: high
- **Commands**: `./ci/scripts/java_jar_upload.sh upload-staging/*.pom`, `./ci/scripts/python_wheel_upload.sh upload-staging/adbc_*.tar.gz upload-staging/*.whl`, `./ci/scripts/node_npm_upload.sh upload-staging`, `./ci/scripts/python_conda_upload.sh conda-packages/python-*-conda/*/*.tar.bz2`

### apache/arrow-dotnet

**2** release/snapshot workflows | Ecosystems: **github_releases, nuget** | Release Artifacts: 2

**`rc.yaml`** — RC [Release Artifacts]
- **Summary**: This workflow builds and publishes Apache Arrow .NET release candidate artifacts. It creates NuGet packages (.nupkg and symbol packages .snupkg) and uploads them to GitHub Releases when triggered by tags matching the *-rc* pattern. The workflow also builds source archives and documentation, performs verification across multiple platforms (macOS, Ubuntu, Windows), and optionally deploys documentation to GitHub Pages. The NuGet packages are intended for release candidate testing before final publication to NuGet.org.
- **Ecosystems**: nuget, github_releases
- **Trigger**: push to tags matching *-rc* pattern
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **Commands**: `gh release create ${GITHUB_REF_NAME} --generate-notes --prerelease --repo ${GITHUB_REPOSITORY} --title "Apache Arrow .NET ${VERSION} RC${RC}" --verify-tag release-*/*`

**`release.yaml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes Apache Arrow .NET release artifacts to GitHub Releases when a non-RC tag is pushed. It downloads artifacts from the corresponding RC release, creates a new GitHub Release with those artifacts, and updates documentation on the asf-site branch. The artifacts are downloadable binaries intended for end users.
- **Ecosystems**: github_releases
- **Trigger**: push to tags (excluding RC tags)
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **Commands**: `gh release create ${GITHUB_REF_NAME}`

### apache/arrow-flight-sql-postgresql

**1** release/snapshot workflows | Ecosystems: **ghcr, github_releases** | Release Artifacts: 1

**`package.yaml`** — Package [Release Artifacts]
- **Summary**: This workflow builds and publishes Apache Arrow Flight SQL PostgreSQL extension packages. On RC tags (*-rc*), it creates GitHub pre-releases with source archives and Linux distribution packages (.deb files). It also builds and pushes Docker images to GHCR (ghcr.io) tagged with version numbers for Debian Bookworm variants. The workflow builds packages for multiple PostgreSQL versions (15, 16, 17) across Debian and Ubuntu distributions. Docker images are pushed when the event is a push (not pull_request), and release artifacts are uploaded only on tag pushes.
- **Ecosystems**: github_releases, ghcr
- **Trigger**: push to tags matching *-rc* pattern, pull_request, push to any branch
- **Auth**: github.token for GitHub Releases and GHCR
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v4`, `docker/build-push-action@v7`
- **Commands**: `gh release create`, `gh release upload`, `rake docker:push`

### apache/arrow-go

**2** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 2

**`rc.yml`** — RC [Release Artifacts]
- **Summary**: Publishes Apache Arrow Go release candidate artifacts to GitHub Releases. Workflow archives source code, verifies it across multiple platforms, and uploads tar.gz archives with checksums to GitHub Releases as pre-release versions when tags matching 'v*-rc*' are pushed.
- **Ecosystems**: github_releases
- **Trigger**: push to tags matching 'v*-rc*'
- **Auth**: GITHUB_TOKEN (automatic)
- **Confidence**: high
- **Commands**: `gh release create`

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes Apache Arrow Go release artifacts to GitHub Releases. It triggers on version tags (v*), downloads artifacts from the corresponding RC release, creates a new GitHub Release with those artifacts attached, and updates documentation on the asf-site branch. The artifacts (dists/*) are downloadable binaries/packages for end users.
- **Ecosystems**: github_releases
- **Trigger**: push to tags matching v* (excluding v*-rc*)
- **Auth**: GITHUB_TOKEN secret
- **Confidence**: high
- **Commands**: `gh release create ${GITHUB_REF_NAME} --discussion-category Announcements --generate-notes --repo ${GITHUB_REPOSITORY} --title "Apache Arrow Go ${version}" --verify-tag dists/*`

### apache/arrow-java

**1** release/snapshot workflows | Ecosystems: **github_pages, github_releases** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes Apache Arrow Java release artifacts when a non-RC tag is pushed. It downloads artifacts from the corresponding RC release, creates a GitHub Release with generated notes and uploads the downloaded artifacts, then publishes documentation to either asf-site or gh-pages branch depending on the repository.
- **Ecosystems**: github_releases, github_pages
- **Trigger**: push to tags (excluding RC tags)
- **Auth**: GITHUB_TOKEN secret
- **Confidence**: high
- **Commands**: `gh release create`, `gh release upload`, `git push origin`

### apache/arrow-js

**2** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 2

**`rc.yaml`** — RC [Release Artifacts]
- **Summary**: This workflow creates release candidate artifacts for Apache Arrow JS. It builds source archives, documentation, and npm packages, then uploads them to a GitHub Release when triggered by an RC tag (e.g., v1.0.0-rc1). The workflow also publishes documentation to git branches (asf-site for apache/arrow-js, gh-pages for forks) but this is internal git operations, not registry publishing. The primary artifact publishing is the GitHub Release with downloadable tarballs and npm package files (.tgz) for release candidate distribution.
- **Ecosystems**: github_releases
- **Trigger**: push to tags matching *-rc*
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **Commands**: `gh release create`

**`release.yaml`** — Release [Release Artifacts]
- **Summary**: Publishes Apache Arrow JS releases to GitHub Releases by downloading artifacts from the latest RC tag, creating a GitHub Release with those artifacts, and updating documentation on the asf-site branch. Triggered on version tags (excluding RC tags).
- **Ecosystems**: github_releases
- **Trigger**: push to tags (excluding RC tags)
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **Commands**: `gh release create ${GITHUB_REF_NAME}`

### apache/arrow-nanoarrow

**1** release/snapshot workflows | Ecosystems: **pypi** | Snapshot / Nightly Artifacts: 1

**`python-wheels.yaml`** — python-wheels [Snapshot / Nightly Artifacts]
- **Summary**: Builds Python wheels and sdist for nanoarrow on multiple platforms (Linux, Windows, macOS, Pyodide) using cibuildwheel. On commits to main branch in the apache/arrow-nanoarrow repository, uploads nightly builds to Gemfury (arrow-nightlies) package registry. Sets dev version for main branch builds. Includes test execution during wheel building.
- **Ecosystems**: pypi
- **Trigger**: push to main branch
- **Auth**: NANOARROW_GEMFURY_TOKEN secret
- **Confidence**: high
- **Commands**: `fury push --api-token=${NANOARROW_GEMFURY_TOKEN} --as="arrow-nightlies" dist/*`

### apache/arrow-swift

**2** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 2

**`rc.yaml`** — RC [Release Artifacts]
- **Summary**: This workflow creates GitHub pre-releases for Apache Arrow Swift release candidates. When a tag matching *-rc* is pushed, it archives the source code, runs license audits, verifies the build across multiple Swift versions (5.10, 6.0, 6.1), and uploads the source tarball with checksums to GitHub Releases as a pre-release. The release artifacts include .tar.gz, .sha256, and .sha512 files.
- **Ecosystems**: github_releases
- **Trigger**: push to tags matching *-rc* pattern
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **Commands**: `gh release create ${GITHUB_REF_NAME} --generate-notes --prerelease --repo ${GITHUB_REPOSITORY} --title "Apache Arrow Swift ${VERSION} RC${RC}" --verify-tag *.tar.gz*`

**`release.yaml`** — Release [Release Artifacts]
- **Summary**: Creates a GitHub Release with downloadable artifacts when a non-RC tag is pushed. Downloads artifacts from the corresponding RC release tag and attaches them to the final release, making them available for end users to consume.
- **Ecosystems**: github_releases
- **Trigger**: push to tags (excluding *-rc* tags)
- **Auth**: GITHUB_TOKEN (secrets.GITHUB_TOKEN)
- **Confidence**: high
- **Commands**: `gh release create`

### apache/avro

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`java-publish-snapshot.yml`** — Publish Snapshot to Maven [Snapshot / Nightly Artifacts]
- **Summary**: Publishes Java Maven snapshot artifacts to Apache Snapshots repository (apache.snapshots.https) on push to main branch or manual trigger. Uses Maven deploy goal with credentials from GitHub secrets to authenticate to Nexus.
- **Ecosystems**: maven_central
- **Trigger**: workflow_dispatch, push to main branch (paths: .github/workflows/java-publish-snapshot.yml, lang/java/**, pom.xml)
- **Auth**: Maven settings.xml with ASF_USERNAME and ASF_PASSWORD from GitHub secrets (NEXUS_USER, NEXUS_PW)
- **Confidence**: high
- **Commands**: `mvn --settings ${{runner.temp}}/settings.xml -U -B -e -fae -ntp -PskipQuality deploy`

### apache/axis-axis2-java-core

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`ci.yml`** — Continuous Integration [Snapshot / Nightly Artifacts]
- **Summary**: This workflow deploys Maven snapshot artifacts to Apache Snapshots repository (apache.snapshots.https) when code is pushed to the master branch. The deploy job runs mvn deploy with the apache-release profile and skips GPG signing, indicating snapshot builds rather than release artifacts. Authentication uses Nexus credentials stored as GitHub secrets.
- **Ecosystems**: maven_central
- **Trigger**: push to master branch
- **Auth**: Maven server credentials (NEXUS_USER/NEXUS_PW) configured via setup-java server-id
- **Confidence**: high
- **Commands**: `mvn -B -e -Papache-release -Dgpg.skip=true -Dmaven.test.skip=true -Dmaven.compiler.release=${{ env.BASE_JAVA_VERSION }} deploy`

### apache/beam

**9** release/snapshot workflows | Ecosystems: **apache_dist, docker_hub, gcr, gcs, github_releases, maven_central, pypi** | Release Artifacts: 4, Snapshot / Nightly Artifacts: 5

**`build_release_candidate.yml`** — build_release_candidate [Release Artifacts]
- **Summary**: This workflow publishes Apache Beam release candidate artifacts across multiple ecosystems: Java artifacts to Maven Central (via Gradle publish to Nexus staging), source releases and Python/Prism artifacts to Apache dist SVN repository, SDK Docker images to Docker Hub, and Prism binaries to GitHub Releases. It is manually triggered via workflow_dispatch with configurable stages to selectively publish different artifact types. The workflow also creates documentation PRs to beam-site and managed-io docs. All artifacts are GPG-signed and include SHA512 checksums.
- **Ecosystems**: maven_central, apache_dist, docker_hub, github_releases
- **Trigger**: workflow_dispatch with manual inputs for RELEASE, RC, APACHE_ID, APACHE_PASSWORD, REPO_TOKEN, and STAGE configuration
- **Auth**: Maven settings.xml with secrets.NEXUS_STAGE_DEPLOYER_USER/PW and secrets.NEXUS_USER/PW; Docker Hub login with secrets.DOCKERHUB_USER/TOKEN; Apache SVN with workflow_dispatch inputs APACHE_ID/APACHE_PASSWORD; GitHub token from workflow_dispatch input REPO_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@b45d80f862d83dbcd57f89517bcf500b2ab88fb2`
- **Commands**: `./gradlew publish -Psigning.gnupg.keyName=${{steps.import_gpg.outputs.fingerprint}} -PisRelease -Pjava21Home=$JAVA_HOME_21_X64 --no-daemon --no-parallel`, `svn commit -m "Staging Java artifacts for Apache Beam ${{ github.event.inputs.RELEASE }} RC${{ github.event.inputs.RC }}" --non-interactive --username "${{ github.event.inputs.APACHE_ID }}" --password "${{ github.event.inputs.APACHE_PASSWORD }}"`, `./gradlew ${{ matrix.images_to_publish.gradle_task }} -PisRelease -Pdocker-pull-licenses -Pprune-images ${{ matrix.images_to_publish.include_skip_flags }} -Pdocker-tag=${{ github.event.inputs.RELEASE }}rc${{ github.event.inputs.RC }} --no-daemon --no-parallel`, `svn commit -m "Staging Python artifacts for Apache Beam ${RELEASE} RC${RC_NUM}" --non-interactive --username "${{ github.event.inputs.APACHE_ID }}" --password "${{ github.event.inputs.APACHE_PASSWORD }}"`, `gh release upload $RC_TAG $ZIP_NAME ${ZIP_NAME}.sha512 ${ZIP_NAME}.asc --clobber`, `svn commit -m "Staging Prism artifacts for Apache Beam ${RELEASE} RC${RC_NUM}" --non-interactive --username "${{ github.event.inputs.APACHE_ID }}" --password "${{ github.event.inputs.APACHE_PASSWORD }}"`

**`deploy_release_candidate_pypi.yaml`** — deploy_release_candidate_pypi [Release Artifacts]
- **Summary**: Publishes Apache Beam Python release candidate packages to PyPI. Downloads artifacts from GitHub Actions, verifies SHA512 checksums, and uploads wheels and source distribution to PyPI using twine. The workflow is manually triggered with release version, RC number, and PyPI API token as inputs.
- **Ecosystems**: pypi
- **Trigger**: workflow_dispatch
- **Auth**: PyPI API token passed as workflow input
- **Confidence**: high
- **Commands**: `twine upload * -u __token__ -p "${{ github.event.inputs.PYPI_API_TOKEN }}"`

**`finalize_release.yml`** — finalize_release [Release Artifacts]
- **Summary**: This workflow finalizes an Apache Beam release by publishing versioned Docker images to Docker Hub (tagging RC images as release versions and 'latest'), uploading Python wheels and source distributions to PyPI using twine, and creating Git tags for the release. It is manually triggered via workflow_dispatch with release version and RC number inputs. The workflow publishes end-user consumable artifacts to public registries.
- **Ecosystems**: docker_hub, pypi
- **Trigger**: workflow_dispatch
- **Auth**: secrets (DOCKERHUB_USER, DOCKERHUB_TOKEN, PYPI_API_TOKEN)
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@b45d80f862d83dbcd57f89517bcf500b2ab88fb2`
- **Commands**: `docker buildx imagetools create`, `twine upload`

**`republish_released_docker_containers.yml`** — Republish Released Docker Images [Release Artifacts]
- **Summary**: This workflow republishes Apache Beam released Docker images to GCR (gcr.io/apache-beam-testing/updated_released_container_images) to address vulnerabilities. It uses Gradle tasks to push various SDK and runner Docker images with release version tags. The workflow can be triggered manually with specific release/RC versions or runs weekly on a schedule. Images are tagged with the release version, commit SHA, and date.
- **Ecosystems**: gcr
- **Trigger**: workflow_dispatch with RELEASE and RC inputs, scheduled weekly on Mondays at 6 AM UTC
- **Auth**: GCP service account authentication via google-github-actions/auth with credentials_json secret
- **Confidence**: high
- **Commands**: `./gradlew :pushAllRunnersDockerImages -PisRelease -PpythonVersion=3.10 -Pdocker-pull-licenses -Pprune-images -Pinclude-ml -Pinclude-distroless -Pdocker-repository-root=gcr.io/apache-beam-testing/updated_released_container_images -Pdocker-tag-list=${{ env.release }},${{ github.sha }},$(date +'%Y-%m-%d') --no-daemon --no-parallel`, `./gradlew :sdks:python:container:push310 -PisRelease -PpythonVersion=3.10 -Pdocker-pull-licenses -Pprune-images -Pinclude-ml -Pinclude-distroless -Pdocker-repository-root=gcr.io/apache-beam-testing/updated_released_container_images -Pdocker-tag-list=${{ env.release }},${{ github.sha }},$(date +'%Y-%m-%d') --no-daemon --no-parallel`, `./gradlew :sdks:python:container:push311 -PisRelease -PpythonVersion=3.10 -Pdocker-pull-licenses -Pprune-images -Pinclude-ml -Pinclude-distroless -Pdocker-repository-root=gcr.io/apache-beam-testing/updated_released_container_images -Pdocker-tag-list=${{ env.release }},${{ github.sha }},$(date +'%Y-%m-%d') --no-daemon --no-parallel`, `./gradlew :sdks:python:container:push312 -PisRelease -PpythonVersion=3.10 -Pdocker-pull-licenses -Pprune-images -Pinclude-ml -Pinclude-distroless -Pdocker-repository-root=gcr.io/apache-beam-testing/updated_released_container_images -Pdocker-tag-list=${{ env.release }},${{ github.sha }},$(date +'%Y-%m-%d') --no-daemon --no-parallel`, `./gradlew :sdks:python:container:push313 -PisRelease -PpythonVersion=3.10 -Pdocker-pull-licenses -Pprune-images -Pinclude-ml -Pinclude-distroless -Pdocker-repository-root=gcr.io/apache-beam-testing/updated_released_container_images -Pdocker-tag-list=${{ env.release }},${{ github.sha }},$(date +'%Y-%m-%d') --no-daemon --no-parallel`, `./gradlew :sdks:python:container:pushAll -PisRelease -PpythonVersion=3.10 -Pdocker-pull-licenses -Pprune-images -Pinclude-ml -Pinclude-distroless -Pskip-python-39-images -Pskip-python-310-images -Pskip-python-311-images -Pskip-python-312-images -Pskip-python-313-images -Pdocker-repository-root=gcr.io/apache-beam-testing/updated_released_container_images -Pdocker-tag-list=${{ env.release }},${{ github.sha }},$(date +'%Y-%m-%d') --no-daemon --no-parallel`, `./gradlew :pushAllSdkDockerImages -PisRelease -PpythonVersion=3.10 -Pdocker-pull-licenses -Pprune-images -Pskip-python-images -Pdocker-repository-root=gcr.io/apache-beam-testing/updated_released_container_images -Pdocker-tag-list=${{ env.release }},${{ github.sha }},$(date +'%Y-%m-%d') --no-daemon --no-parallel`, `./gradlew :pushAllDockerImages -PisRelease -PpythonVersion=3.10 -Pdocker-pull-licenses -Pprune-images -Pskip-runner-images -Pskip-sdk-images -Pdocker-repository-root=gcr.io/apache-beam-testing/updated_released_container_images -Pdocker-tag-list=${{ env.release }},${{ github.sha }},$(date +'%Y-%m-%d') --no-daemon --no-parallel`

**`beam_Publish_Beam_SDK_Snapshots.yml`** — Publish Beam SDK Snapshots [Snapshot / Nightly Artifacts]
- **Summary**: This workflow publishes Apache Beam SDK snapshot Docker images to GCR (gcr.io/apache-beam-testing/beam-sdk) on a scheduled basis (every 4 hours) or manual trigger. It builds and pushes multi-architecture (arm64, amd64) container images for Go, Java, and Python (multiple versions including standard, distroless, and ML variants) SDKs. Images are tagged with the commit SHA, Beam version (extracted from gradle.properties), and 'latest' tag when running on master branch. This is clearly snapshot/nightly artifact publishing for testing purposes, not release artifacts for end users.
- **Ecosystems**: gcr
- **Trigger**: schedule (every 4 hours) and workflow_dispatch
- **Auth**: GCP service account with credentials_json
- **Confidence**: high
- **Commands**: `:sdks:go:container:docker`, `:sdks:java:container:pushAll`, `:sdks:python:container:py310:docker`, `:sdks:python:container:py311:docker`, `:sdks:python:container:py312:docker`, `:sdks:python:container:py313:docker`, `:sdks:python:container:py314:docker`, `:sdks:python:container:distroless:py310:docker`, `:sdks:python:container:distroless:py311:docker`, `:sdks:python:container:distroless:py312:docker`, `:sdks:python:container:distroless:py313:docker`, `:sdks:python:container:distroless:py314:docker`, `:sdks:python:container:ml:py310:docker`, `:sdks:python:container:ml:py311:docker`, `:sdks:python:container:ml:py312:docker`, `:sdks:python:container:ml:py313:docker`, `:sdks:java:expansion-service:container:docker`

**`beam_Publish_Docker_Snapshots.yml`** — Publish Docker Snapshots [Snapshot / Nightly Artifacts]
- **Summary**: Publishes nightly snapshot Docker images for Apache Beam Spark and Flink job servers to GCR (gcr.io/apache-beam-testing/beam_portability). Images are tagged with commit SHA and optionally 'latest' tag when running on master branch. Triggered daily via cron schedule or manually via workflow_dispatch.
- **Ecosystems**: gcr
- **Trigger**: schedule (daily at 13:00 UTC) or workflow_dispatch
- **Auth**: gcloud auth configure-docker
- **Confidence**: high
- **Commands**: `:runners:spark:3:job-server:container:dockerPush`, `:runners:flink:1.17:job-server-container:dockerPush`

**`beam_Release_NightlySnapshot.yml`** — Release Nightly Snapshot [Snapshot / Nightly Artifacts]
- **Summary**: This workflow publishes nightly snapshot builds of Apache Beam to the Apache Snapshots Maven repository. It runs on a daily schedule (12:15 UTC) and authenticates using Nexus credentials stored in GitHub secrets. The Gradle publish task is executed with the -Ppublishing flag to deploy artifacts to the snapshot repository configured as 'apache.snapshots.https'.
- **Ecosystems**: maven_central
- **Trigger**: schedule (cron: '15 12 * * *') and workflow_dispatch
- **Auth**: Maven settings.xml with username/password from secrets (NEXUS_USER, NEXUS_PW)
- **Confidence**: high
- **Commands**: `./gradlew publish --max-workers=8 -Ppublishing -PskipCheckerFramework -Pjava21Home=$JAVA_HOME_21_X64 --continue -Dorg.gradle.jvmargs=-Xms2g -Dorg.gradle.jvmargs=-Xmx6g -Dorg.gradle.vfs.watch=false -Pdocker-pull-licenses -Dorg.gradle.internal.http.connectionTimeout=60000 -Dorg.gradle.internal.http.socketTimeout=120000`

**`beam_Release_Python_NightlySnapshot.yml`** — Release Nightly Snapshot Python [Snapshot / Nightly Artifacts]
- **Summary**: Nightly scheduled workflow that builds and publishes Python snapshot artifacts. Runs buildSnapshot Gradle task then executes run_snapshot_publish.sh script to publish nightly Python packages. Triggered daily at 12:15 UTC or manually via workflow_dispatch.
- **Ecosystems**: pypi
- **Trigger**: schedule (cron: '15 12 * * *') and workflow_dispatch
- **Auth**: unknown (credentials likely in run_snapshot_publish.sh script or environment)
- **Confidence**: high
- **Commands**: `bash sdks/python/scripts/run_snapshot_publish.sh`

**`build_wheels.yml`** — Build python source distribution and wheels [Snapshot / Nightly Artifacts]
- **Summary**: Builds Python source distributions and wheels for multiple Python versions (3.10-3.14) across Linux (x86_64, aarch64), macOS, and Windows. Uploads built artifacts to a GCS bucket for snapshot/nightly distribution. Runs on schedule (nightly), pushes to master/release branches, tags, and pull requests. Does not publish to PyPI - only to GCS staging bucket.
- **Ecosystems**: gcs
- **Trigger**: schedule (nightly), push to master/release branches, tags, pull_request, workflow_dispatch
- **Auth**: Self-hosted runner with implicit GCP credentials
- **Confidence**: high
- **Commands**: `gsutil cp -r -a public-read source/* ${{ env.GCP_PATH }}`, `gsutil cp -r -a public-read wheelhouse/* ${{ env.GCP_PATH }}`, `gsutil cp -a public-read github_action_info ${{ env.GCP_PATH }}`, `gsutil cp -a public-read ${GITHUB_EVENT_PATH} ${{ env.GCP_PATH }}`

### apache/bifromq

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`docker-publish.yml`** — Docker Publish [Release Artifacts]
- **Summary**: Publishes multi-architecture Docker images (linux/amd64, linux/arm64) to Docker Hub under apache/bifromq repository. Triggered manually via workflow_dispatch with version input. Downloads Apache release artifacts from downloads.apache.org, verifies SHA512 checksums, builds Docker image, and pushes to Docker Hub with version tag. Restricted to apache/bifromq repository only.
- **Ecosystems**: docker_hub
- **Trigger**: workflow_dispatch
- **Auth**: secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`
- **Commands**: `docker buildx build --platform linux/amd64,linux/arm64 --build-arg BIFROMQ_VERSION=... -t apache/bifromq:... --push`

### apache/buildstream

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`release.yml`** — Release actions [Release Artifacts]
- **Summary**: This workflow publishes release artifacts to PyPI and GitHub Releases when semantic version tags are pushed. It builds Python wheels for multiple Python versions (3.10-3.14), creates a source distribution (sdist), and builds documentation. After testing the wheels, it uploads the sdist and wheels to PyPI using twine, and creates a GitHub Release with the documentation tarball attached. The workflow uses pipx to run build tools and cibuildwheel for cross-platform wheel building.
- **Ecosystems**: pypi, github_releases
- **Trigger**: push tags matching '*.*.*' (semantic version tags)
- **Auth**: PYPI_TOKEN secret for PyPI, GITHUB_TOKEN for GitHub Releases
- **Confidence**: high
- **Commands**: `twine upload --repository pypi`, `gh release create`

### apache/camel-k

**1** release/snapshot workflows | Ecosystems: **docker_hub, maven_central** | Snapshot / Nightly Artifacts: 1

**`nightly-release.yml`** — Nightly release [Snapshot / Nightly Artifacts]
- **Summary**: Scheduled nightly workflow that publishes snapshot builds of Apache Camel K. Authenticates to Nexus (Maven) using NEXUS_USER/NEXUS_PW secrets and Docker Hub using TEST_DOCKER_HUB credentials. Delegates actual publishing to a composite action ./.github/actions/release-nightly. Runs daily at 00:15 UTC on the main branch.
- **Ecosystems**: maven_central, docker_hub
- **Trigger**: schedule (cron: 15 0 * * *) and workflow_dispatch
- **Auth**: secrets (NEXUS_USER, NEXUS_PW, TEST_DOCKER_HUB_USERNAME, TEST_DOCKER_HUB_PASSWORD)
- **Confidence**: high
- **GitHub Actions**: `./.github/actions/release-nightly`

### apache/camel-k-runtime

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`ci-build.yml`** — Build [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds and tests the Apache Camel K Runtime project on push/PR events. The 'deploy' job publishes snapshot artifacts to the ASF Snapshots Repository (Nexus) when code is pushed to main, camel-quarkus-3, or release-* branches. It uses Maven deploy with credentials from GitHub secrets passed through environment variables. The workflow also runs native image builds and tests across multiple integration test modules.
- **Ecosystems**: maven_central
- **Trigger**: push to main, camel-quarkus-3, or release-* branches
- **Auth**: Maven settings.xml with NEXUS_DEPLOY_USERNAME and NEXUS_DEPLOY_PASSWORD from secrets
- **Confidence**: high
- **Commands**: `./mvnw ${MAVEN_ARGS} clean deploy -DskipTests -DskipITs --settings .github/asf-deploy-settings.xml`

### apache/camel-kafka-connector

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`asf-snapshots-deploy.yml`** — Deploy Camel Kafka Connector Snapshot [Snapshot / Nightly Artifacts]
- **Summary**: This workflow deploys snapshot builds of Apache Camel Kafka Connector to the ASF Snapshots Maven repository. It runs nightly at 1 AM UTC or on manual trigger, builds the project with Java 17, and deploys to Nexus using Maven with credentials stored in GitHub secrets. The deployment is restricted to the main branch only.
- **Ecosystems**: maven_central
- **Trigger**: schedule (cron: 0 1 * * *) and workflow_dispatch
- **Auth**: Maven settings.xml with NEXUS_DEPLOY_USERNAME and NEXUS_DEPLOY_PASSWORD from secrets
- **Confidence**: high
- **Commands**: `./mvnw ${MAVEN_ARGS} -U -B -e -fae -Dnoassembly -Dmaven.compiler.fork=true -Pdeploy -Dmaven.test.skip.exec=true --settings .github/asf-deploy-settings.xml clean deploy`

### apache/camel-kameleon

**1** release/snapshot workflows | Ecosystems: **ghcr** | Snapshot / Nightly Artifacts: 1

**`main.yml`** — Build and deploy [Snapshot / Nightly Artifacts]
- **Summary**: Builds a Quarkus application and pushes a Docker image tagged 'latest' to GitHub Container Registry (ghcr.io) on every push to main branch. This is a snapshot/nightly build pattern rather than versioned releases, as it always overwrites the 'latest' tag.
- **Ecosystems**: ghcr
- **Trigger**: push to main branch, workflow_dispatch
- **Auth**: GITHUB_TOKEN with github.actor username
- **Confidence**: high
- **Commands**: `mvn package with quarkus.container-image.push=true to ghcr.io/${GITHUB_REPOSITORY}:latest`

### apache/camel-kamelets

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`ci-build.yml`** — Build [Snapshot / Nightly Artifacts]
- **Summary**: CI workflow that builds camel-kamelets on push/PR and deploys snapshot artifacts to ASF Snapshots Repository (Nexus) when pushing to main or release branches. The deploy job uses Maven deploy goal with custom ASF settings to publish to Apache's snapshot Maven repository.
- **Ecosystems**: maven_central
- **Trigger**: push to main or release branches
- **Auth**: NEXUS_DEPLOY_USERNAME and NEXUS_DEPLOY_PASSWORD secrets
- **Confidence**: high
- **Commands**: `./mvnw ${MAVEN_ARGS} clean deploy -DskipTests -DskipITs --settings .github/asf-deploy-settings.xml`

### apache/camel-karavan

**2** release/snapshot workflows | Ecosystems: **ghcr** | Release Artifacts: 1, Snapshot / Nightly Artifacts: 1

**`docker-devmode.yml`** — DevMode container [Release Artifacts]
- **Summary**: Publishes a versioned DevMode Docker image (tag 4.18.0) to GitHub Container Registry (ghcr.io) for the apache/camel-karavan project. The image is built for multiple platforms (linux/amd64, linux/arm64) and pushed to ghcr.io/apache/camel-karavan-devmode:4.18.0. This appears to be a development mode container for the Camel Karavan project, likely consumed by developers or users of the project.
- **Ecosystems**: ghcr
- **Trigger**: push to main branch (paths: karavan-devmode/Dockerfile, .github/workflows/docker-devmode.yml) or workflow_dispatch
- **Auth**: GITHUB_TOKEN secret for GHCR authentication
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/build-push-action@v5`

**`app.yml`** — Application [Snapshot / Nightly Artifacts]
- **Summary**: Builds a Quarkus application and pushes a multi-platform Docker image (linux/amd64, linux/arm64) to GitHub Container Registry (ghcr.io) with tag 4.18.0. Publishing only occurs on push to main branch (not on pull requests). Uses Maven with Quarkus container-image extension to build and push the image.
- **Ecosystems**: ghcr
- **Trigger**: push to main branch (paths: karavan-app/**, karavan-core/**, karavan-designer/**, .github/workflows/app.yml), workflow_dispatch, pull_request to main
- **Auth**: GitHub token (secrets.GITHUB_TOKEN) with username github.actor
- **Confidence**: high
- **Commands**: `mvn package with -Dquarkus.container-image.push=true and -Dquarkus.container-image.image=ghcr.io/${GITHUB_REPOSITORY}:4.18.0`

### apache/carbondata

**1** release/snapshot workflows | Ecosystems: **github_packages** | Release Artifacts: 1

**`maven-publish.yml`** — Maven Package [Release Artifacts]
- **Summary**: Publishes Maven packages to GitHub Packages when a GitHub release is created. Uses the automatic GITHUB_TOKEN for authentication and deploys via 'mvn deploy' with a generated settings.xml file.
- **Ecosystems**: github_packages
- **Trigger**: release (types: [created])
- **Auth**: GITHUB_TOKEN (automatic token)
- **Confidence**: high
- **Commands**: `mvn deploy -s $GITHUB_WORKSPACE/settings.xml`

### apache/casbin-Casbin.NET

**1** release/snapshot workflows | Ecosystems: **github_packages, nuget** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow builds, tests, and publishes .NET NuGet packages to both NuGet.org (public registry) and GitHub Packages. It runs semantic-release to determine versioning, then packs and pushes packages to both registries. The workflow is triggered on pushes to master/main/1.x branches and only publishes if the repository owner is 'casbin'. Coverage reports are uploaded to Coveralls (documentation aspect), but the primary purpose is releasing versioned NuGet packages for end-user consumption.
- **Ecosystems**: nuget, github_packages
- **Trigger**: push to master/main/1.x branches or workflow_dispatch
- **Auth**: GITHUB_TOKEN for GitHub Packages, NUGET_API_TOKEN secret for NuGet.org
- **Confidence**: high
- **Commands**: `dotnet nuget push .\packages\*.nupkg -s github.com --skip-duplicate`, `dotnet nuget push .\packages\*.nupkg -s nuget.org -k $env:NUGET_API_TOKEN --skip-duplicate`

### apache/casbin-Casbin.NET-dotnet-cli

**1** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 1

**`build.yml`** — Build [Release Artifacts]
- **Summary**: This workflow builds cross-platform binaries for a .NET CLI tool (casbin-dotnet-cli) and publishes releases to GitHub Releases using semantic-release. On push to master, after tests pass and binaries are built for 6 platforms (linux/windows/macos x64/arm64), it downloads all artifacts, moves them to a dist directory, and runs semantic-release which creates GitHub Releases with the compiled binaries attached as downloadable assets.
- **Ecosystems**: github_releases
- **Trigger**: push to master branch
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **Commands**: `npx semantic-release@v19.0.2`

### apache/casbin-Casbin.NET-ef-adapter

**2** release/snapshot workflows | Ecosystems: **nuget** | Release Artifacts: 1, Snapshot / Nightly Artifacts: 1

**`gitub-actions-release.yml`** — Release [Release Artifacts]
- **Summary**: Publishes NuGet packages to nuget.org when tags are pushed. Builds, tests, packs, and pushes .nupkg files using dotnet CLI with API token authentication.
- **Ecosystems**: nuget
- **Trigger**: push to tags
- **Auth**: NUGET_API_TOKEN secret
- **Confidence**: high
- **Commands**: `dotnet nuget push .\packages\*.nupkg -s nuget.org -k $env:NUGET_API_TOKEN --skip-duplicate`

**`gitub-actions-build.yml`** — Build [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds, tests, and publishes snapshot NuGet packages to MyGet (myget.org/casbin-net) on every push to master. The packages are versioned with build numbers and commit SHAs (e.g., version-build.123.master.abc1234), indicating they are CI/snapshot builds rather than stable releases. Coverage reports are uploaded to Coveralls. The workflow uses GitHub Actions artifact storage for intermediate package transfer between jobs.
- **Ecosystems**: nuget
- **Trigger**: push to master branch
- **Auth**: MYGET_API_TOKEN secret
- **Confidence**: high
- **Commands**: `dotnet nuget push .\drop-ci-packages\*.nupkg -s myget.org -k $env:MYGET_API_TOKEN --skip-duplicate`

### apache/casbin-Casbin.NET-redis-adapter

**2** release/snapshot workflows | Ecosystems: **github_packages, nuget** | Release Artifacts: 1, Snapshot / Nightly Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes NuGet packages to three registries: myget.org (a NuGet feed), GitHub Packages, and nuget.org (the official public NuGet registry). It is manually triggered via workflow_dispatch, runs tests with coverage upload to Coveralls, uses semantic-release for version management, packs .NET packages with the version from git tags, and pushes them to all three registries. The primary target is nuget.org, making this a release_artifact workflow.
- **Ecosystems**: nuget, github_packages
- **Trigger**: workflow_dispatch
- **Auth**: MYGET_API_TOKEN, NUGET_API_TOKEN, GITHUB_TOKEN secrets
- **Confidence**: high
- **Commands**: `dotnet nuget push .\packages\*.nupkg -s myget.org -k $MYGET_API_TOKEN --skip-duplicate`, `dotnet nuget push .\packages\*.nupkg -s github.com --skip-duplicate`, `dotnet nuget push .\packages\*.nupkg -s nuget.org -k $NUGET_API_TOKEN --skip-duplicate`

**`build.yml`** — Build [Snapshot / Nightly Artifacts]
- **Summary**: Workflow builds .NET solution, runs tests with Redis service, uploads coverage to Coveralls, and publishes snapshot NuGet packages to MyGet registry. Package versions include build number, branch name, and commit SHA (e.g., 1.0.0-build.123.main.abc1234), indicating these are CI snapshot builds rather than release artifacts. Only triggers for casbin-net organization on push events.
- **Ecosystems**: nuget
- **Trigger**: push
- **Auth**: MYGET_API_TOKEN secret
- **Confidence**: high
- **Commands**: `dotnet nuget push ./packages/*.nupkg -s myget.org -k $MYGET_API_TOKEN --skip-duplicate`

### apache/casbin-Casbin.NET-redis-watcher

**2** release/snapshot workflows | Ecosystems: **github_packages, nuget** | Release Artifacts: 1, Snapshot / Nightly Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes NuGet packages to three registries: MyGet (myget.org), GitHub Packages (github.com), and NuGet.org. It runs on every push, performs build and test, uses semantic-release to create version tags, then packs and publishes versioned NuGet packages. The version is extracted from git tags created by semantic-release. Coverage reports are uploaded to Coveralls (documentation aspect), but the primary purpose is releasing versioned artifacts to public NuGet registries for end-user consumption.
- **Ecosystems**: nuget, github_packages
- **Trigger**: push
- **Auth**: MYGET_API_TOKEN, NUGET_API_TOKEN, GITHUB_TOKEN secrets
- **Confidence**: high
- **Commands**: `dotnet nuget push .\packages\*.nupkg -s myget.org -k $env:MYGET_API_TOKEN --skip-duplicate`, `dotnet nuget push .\packages\*.nupkg -s github.com --skip-duplicate`, `dotnet nuget push .\packages\*.nupkg -s nuget.org -k $env:NUGET_API_TOKEN --skip-duplicate`

**`build.yml`** — Build [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds, tests, and publishes snapshot NuGet packages to MyGet registry. It runs on push and pull_request events, but only publishes packages on push events when repository owner is 'casbin-net'. The package version includes build number, branch name, and commit SHA, indicating these are development/snapshot builds rather than official releases. Coverage reports are uploaded to Coveralls, and test results are stored as GitHub Actions artifacts.
- **Ecosystems**: nuget
- **Trigger**: push, pull_request
- **Auth**: MYGET_API_TOKEN secret
- **Confidence**: high
- **Commands**: `dotnet nuget push .\packages\*.nupkg -s myget.org -k $env:MYGET_API_TOKEN --skip-duplicate`

### apache/casbin-actix-casbin-auth

**1** release/snapshot workflows | Ecosystems: **crates_io, github_releases** | Release Artifacts: 1

**`release.yml`** — Auto Release [Release Artifacts]
- **Summary**: Publishes Rust crate to crates.io and creates GitHub Release when version tags (v*) are pushed. Uses cargo publish for crates.io deployment and actions/create-release for GitHub Releases.
- **Ecosystems**: crates_io, github_releases
- **Trigger**: push to tags matching v*
- **Auth**: secrets.CARGO_TOKEN for crates.io, secrets.GITHUB_TOKEN for GitHub Releases
- **Confidence**: high
- **GitHub Actions**: `actions/create-release@v1`
- **Commands**: `cargo login`, `cargo publish`

### apache/casbin-admission-webhook

**1** release/snapshot workflows | Ecosystems: **docker_hub, github_releases** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow performs semantic versioning releases on push to main/master. The 'release' job uses semantic-release to create GitHub releases with release notes and potentially attach build artifacts. The 'docker' job then builds and pushes multi-platform Docker images to Docker Hub (casbin/casbin-admission-webhook) with both 'latest' and version-specific tags derived from git tags. This is a release artifact workflow publishing versioned Docker images to a public registry for end-user consumption.
- **Ecosystems**: docker_hub, github_releases
- **Trigger**: push to main/master branches
- **Auth**: DOCKERHUB_USERNAME and DOCKERHUB_TOKEN secrets for Docker Hub; GITHUB_TOKEN for semantic-release
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/build-push-action@v6`
- **Commands**: `npx semantic-release`

### apache/casbin-aspnetcore

**1** release/snapshot workflows | Ecosystems: **github_packages, nuget** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes NuGet packages to both GitHub Packages and NuGet.org on pushes to master branch. It runs tests with coverage reporting to Coveralls, uses semantic-release to manage versioning, then packs and publishes .NET packages to two registries. The workflow is restricted to the casbin-net organization.
- **Ecosystems**: nuget, github_packages
- **Trigger**: push to master branch
- **Auth**: GITHUB_TOKEN for GitHub Packages, NUGET_API_TOKEN secret for NuGet.org
- **Confidence**: high
- **Commands**: `dotnet nuget push .\packages\*.nupkg -s github.com --skip-duplicate`, `dotnet nuget push .\packages\*.nupkg -s nuget.org -k $env:NUGET_API_TOKEN --skip-duplicate`

### apache/casbin-axum-casbin

**1** release/snapshot workflows | Ecosystems: **crates_io, github_releases** | Release Artifacts: 1

**`release.yml`** — Auto Release [Release Artifacts]
- **Summary**: Publishes Rust crate to crates.io and creates GitHub Release when version tags (v*) are pushed. Uses cargo publish for crates.io deployment and actions/create-release for GitHub Releases.
- **Ecosystems**: crates_io, github_releases
- **Trigger**: push to tags matching v*
- **Auth**: secrets.CARGO_TOKEN for crates.io, secrets.GITHUB_TOKEN for GitHub Releases
- **Confidence**: high
- **GitHub Actions**: `actions/create-release@v1`
- **Commands**: `cargo login`, `cargo publish`

### apache/casbin-casbin.js

**1** release/snapshot workflows | Ecosystems: **npm** | Release Artifacts: 1

**`ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow publishes release artifacts to npm using semantic-release. The semantic-release job runs after successful lint and test jobs, but only on push events to the casbin/casbin.js repository. It uses NPM_TOKEN for authentication to publish packages to the npm registry. The workflow follows a standard CI/CD pattern with linting, testing, and conditional release publishing.
- **Ecosystems**: npm
- **Trigger**: push to casbin/casbin.js repository
- **Auth**: NPM_TOKEN secret
- **Confidence**: high
- **Commands**: `yarn run release`

### apache/casbin-core

**1** release/snapshot workflows | Ecosystems: **npm** | Release Artifacts: 1

**`ci.yml`** — CI [Release Artifacts]
- **Summary**: This workflow publishes release artifacts to npm registry using semantic-release. The semantic-release job runs only on pushes to master branch in the casbin/casbin-core repository. It uses NPM_TOKEN for authentication to publish packages to npm. The workflow also includes coverage reporting to Coveralls (documentation category activity), but the primary publishing action is the npm release.
- **Ecosystems**: npm
- **Trigger**: push to master branch only (github.repository == 'casbin/casbin-core' && github.event_name == 'push' && github.ref == 'refs/heads/master')
- **Auth**: NPM_TOKEN secret for npm authentication, GITHUB_TOKEN for GitHub operations
- **Confidence**: high
- **Commands**: `yarn run release`

### apache/casbin-dart-casbin

**1** release/snapshot workflows | Ecosystems: **dart_pub, github_releases** | Release Artifacts: 1

**`dart.yml`** — Dart CI [Release Artifacts]
- **Summary**: This workflow publishes release artifacts to both GitHub Releases (via semantic-release) and pub.dev (Dart package registry). It triggers on pushes to master branch after passing analyze and test jobs. The publish job uses semantic-release to determine versioning and create GitHub releases, then publishes the Dart package to pub.dev using credentials stored in repository secrets.
- **Ecosystems**: github_releases, dart_pub
- **Trigger**: push to master branch
- **Auth**: PUB_CREDENTIALS secret stored in credentials.json file, GITHUB_TOKEN for semantic-release
- **Confidence**: high
- **Commands**: `dart pub publish --force`, `npx semantic-release@17`

### apache/casbin-docker_auth

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Snapshot / Nightly Artifacts: 1

**`docker-nightly.yml`** — docker-nightly [Snapshot / Nightly Artifacts]
- **Summary**: Publishes nightly Docker images to Docker Hub (cesanta/docker_auth:latest) on push to master branch. Pull requests build but do not push images. This is a snapshot/nightly build workflow as indicated by the workflow name and the 'latest' tag strategy.
- **Ecosystems**: docker_hub
- **Trigger**: push to master branch
- **Auth**: DOCKER_USERNAME and DOCKER_PASSWORD secrets
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v1`, `docker/build-push-action@v2`

### apache/casbin-editor

**1** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 1

**`release.yml`** — Build and Release Electron App [Release Artifacts]
- **Summary**: Builds Electron desktop application for macOS, Windows, and Linux, then uses semantic-release to publish versioned releases with downloadable binaries to GitHub Releases. The workflow creates end-user consumable artifacts (.dmg, .exe, .AppImage files) that are attached to GitHub releases.
- **Ecosystems**: github_releases
- **Trigger**: push to master branch or pull_request with title starting with 'feat:'
- **Auth**: GITHUB_TOKEN secret
- **Confidence**: high
- **Commands**: `yarn release`

### apache/casbin-efcore-adapter

**1** release/snapshot workflows | Ecosystems: **github_packages, nuget** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow builds, tests, and publishes NuGet packages to both GitHub Packages and NuGet.org. It runs on pushes to master, executes semantic-release for versioning, then packs and pushes .nupkg files to both registries. Coverage reports are uploaded to Coveralls.
- **Ecosystems**: nuget, github_packages
- **Trigger**: push to master branch
- **Auth**: GITHUB_TOKEN for GitHub Packages, NUGET_API_TOKEN secret for NuGet.org
- **Confidence**: high
- **Commands**: `dotnet nuget push .\packages\*.nupkg -s github.com --skip-duplicate`, `dotnet nuget push .\packages\*.nupkg -s nuget.org -k $env:NUGET_API_TOKEN --skip-duplicate`

### apache/casbin-ex

**1** release/snapshot workflows | Ecosystems: **github_releases, hex** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes Elixir packages to Hex.pm (the Elixir/Erlang package registry) and creates GitHub releases using semantic-release. It triggers after successful CI runs on master/main branches. The workflow uses semantic-release to create GitHub releases with version tags, then publishes the corresponding package version to Hex.pm using mix hex.publish. The version is extracted from git tags and updated in mix.exs before publishing.
- **Ecosystems**: hex, github_releases
- **Trigger**: workflow_run on CI completion (master/main branches)
- **Auth**: HEX_API_KEY secret for Hex.pm, GITHUB_TOKEN for semantic-release
- **Confidence**: high
- **Commands**: `mix hex.publish --yes`, `npx semantic-release`

### apache/casbin-gateway

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`build.yml`** — Build [Release Artifacts]
- **Summary**: CI workflow that builds Go backend and Node.js frontend, then conditionally publishes versioned Docker images to Docker Hub. Publishing is gated by repository check (casbin/caswaf), branch (master), and semantic version changes (major/minor only). Images are tagged with both the semantic version and 'latest'.
- **Ecosystems**: docker_hub
- **Trigger**: push to master branch with semantic version bump (major or minor)
- **Auth**: Docker Hub username/password via secrets
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v1`, `docker/build-push-action@v3`

### apache/casbin-go-cli

**1** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 1

**`build.yml`** — Build [Release Artifacts]
- **Summary**: This workflow runs tests on multiple Go versions, then on push events performs semantic versioning and uses GoReleaser to publish release artifacts (compiled binaries) to GitHub Releases. The semantic-release tool manages version bumping and changelog generation, while GoReleaser builds cross-platform binaries and attaches them to the GitHub Release.
- **Ecosystems**: github_releases
- **Trigger**: push
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `goreleaser/goreleaser-action@v6`
- **Commands**: `npx semantic-release@v19.0.2`

### apache/casbin-jcasbin

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow builds a Java project with Maven, runs tests with code coverage, uploads coverage to Codecov, and uses semantic-release with @conveyal/maven-semantic-release to automatically publish versioned releases to Maven Central (OSSRH) and GitHub Releases. The semantic-release tool handles version determination, changelog generation, and publishing to both Maven Central and GitHub. Credentials are properly configured through the setup-java action and passed securely via environment variables.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push to master branch or pull_request
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured in setup-java action; credentials passed via environment variables to semantic-release
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release`

### apache/casbin-jcasbin-dynamodb-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`release.yml`** — build [Release Artifacts]
- **Summary**: This workflow publishes versioned release artifacts to Maven Central (OSSRH) and GitHub Releases using semantic-release automation. Triggered on push to master branch after tests pass. Uses @conveyal/maven-semantic-release plugin to publish Maven artifacts to OSSRH/Maven Central with GPG signing, and @semantic-release/github to create GitHub releases. Also uploads code coverage to Codecov (documentation category but not primary purpose).
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push to master branch
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing key for Maven Central; GITHUB_TOKEN for GitHub Releases
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release`

### apache/casbin-jcasbin-hibernate-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow builds and tests a Java project with Maven, uploads code coverage to Codecov, and uses semantic-release with @conveyal/maven-semantic-release to automatically publish versioned releases to Maven Central (OSSRH) and GitHub Releases. The workflow is triggered on all pushes and pull requests, but semantic-release will only publish on qualifying commits (typically on main/master branch). Maven credentials are configured via setup-java with server-id 'ossrh' and GPG signing is enabled for artifact signing required by Maven Central.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action and passed to semantic-release
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-jdbc-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow builds and tests a Java JDBC adapter project against MySQL, PostgreSQL, and SQL Server databases. On successful builds (typically on push to main), it uses semantic-release with maven-semantic-release plugin to automatically version, build, sign with GPG, and publish artifacts to Maven Central (OSSRH) and create GitHub releases. The workflow also uploads code coverage to Codecov.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via actions/setup-java. GitHub token for GitHub releases.
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-jfinal-authz

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow uses semantic-release with maven-semantic-release plugin to automatically version, build, sign, and publish Java artifacts to OSSRH (Maven Central) and create GitHub releases. The workflow runs on push and pull_request events, but semantic-release typically only publishes on push to default branch. Maven credentials and GPG signing are properly configured through the setup-java action and passed securely via environment variables.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via setup-java action; credentials passed as environment variables to semantic-release
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-kafka-casbin

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — Java CI with Maven [Release Artifacts]
- **Summary**: This workflow builds, tests, and publishes Java artifacts to Maven Central (OSSRH) and creates GitHub releases using semantic-release. It runs on all pushes and pull requests. The semantic-release tool with @conveyal/maven-semantic-release plugin handles versioning and publishing to both Maven Central and GitHub Releases. Maven credentials are configured via setup-java action with OSSRH server credentials and GPG signing. Codecov is used for coverage reporting (documentation aspect). All secrets are properly passed through environment variables.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via setup-java action; credentials passed as environment variables to semantic-release
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-kafka-watcher

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow builds and tests a Java project with Maven, then uses semantic-release with maven-semantic-release plugin to automatically version and publish artifacts to Maven Central (OSSRH) and create GitHub releases. Publishing is triggered by conventional commit messages on push events. Authentication uses OSSRH Jira credentials and GPG signing for Maven Central, and GITHUB_TOKEN for GitHub releases.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request, workflow_dispatch
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action; GITHUB_TOKEN for GitHub releases
- **Confidence**: high
- **GitHub Actions**: `@conveyal/maven-semantic-release`, `@semantic-release/github`
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-lettuce-redis-watcher

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow builds and tests a Java project, then uses semantic-release with maven-semantic-release plugin to automatically publish versioned releases to Maven Central (via OSSRH) and GitHub Releases. The workflow runs on all pushes and pull requests, but semantic-release will only publish on pushes to the main branch when commits follow conventional commit format. Credentials are properly passed through env: blocks. Codecov upload is also present for code coverage reporting.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (username/password) and GPG signing key for Maven Central; GITHUB_TOKEN for GitHub Releases
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-mongo-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow builds, tests, and publishes Maven artifacts using semantic-release. On push/PR events, it runs tests with MongoDB, uploads coverage to Codecov, then uses @conveyal/maven-semantic-release to publish versioned releases to Maven Central (OSSRH) and GitHub Releases. The semantic-release tool handles version determination and publishing based on commit messages. Maven server credentials are configured via setup-java and passed to semantic-release along with GPG signing credentials.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via setup-java action; credentials passed as environment variables to semantic-release
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-mybatis-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`ci.yml`** — CI [Release Artifacts]
- **Summary**: This workflow runs tests with MySQL, uploads coverage to Codecov, and uses semantic-release with maven-semantic-release plugin to automatically publish versioned releases to Maven Central (OSSRH) and GitHub Releases. Publishing is triggered by semantic commits on push events. The workflow configures Maven server credentials and GPG signing for artifact publication to OSSRH.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action. GitHub token for GitHub releases.
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-mybatisplus-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`ci.yml`** — CI [Release Artifacts]
- **Summary**: This workflow runs tests with coverage reporting to Codecov, then uses semantic-release with maven-semantic-release plugin to automatically publish versioned releases to Maven Central (OSSRH) and create GitHub releases. Publishing is controlled by semantic-release's commit message analysis. Credentials are properly passed through env blocks.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action. GitHub token for GitHub releases.
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-nutz-authz

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — Java CI with Maven [Release Artifacts]
- **Summary**: This workflow uses semantic-release with @conveyal/maven-semantic-release to automatically publish versioned Maven artifacts to OSSRH (Maven Central) and create GitHub releases. It runs on all pushes and pull requests, but semantic-release only publishes on qualifying commits (typically main branch with conventional commits). Maven server credentials and GPG signing are configured for artifact signing and authentication.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via actions/setup-java. Semantic-release uses GITHUB_TOKEN for GitHub releases.
- **Confidence**: high
- **GitHub Actions**: `actions/setup-java@v1`
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-play-authz

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow builds and tests a Java project, then uses semantic-release with maven-semantic-release plugin to automatically publish versioned releases to Maven Central (via OSSRH) and create GitHub releases. The workflow is triggered on push and pull_request events. Publishing occurs through the semantic-release command which handles version determination, Maven artifact deployment to OSSRH/Maven Central, and GitHub release creation. Authentication uses OSSRH JIRA credentials for Maven Central and a GitHub token for releases, with GPG signing configured for artifact signing.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured in setup-java action. GitHub token (GH_TOKEN) for GitHub releases.
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-postgres-watcher

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow uses semantic-release with @conveyal/maven-semantic-release to automatically version, build, and publish Java artifacts to Maven Central (OSSRH) and create GitHub releases. The workflow sets up GPG signing for Maven artifacts and authenticates to OSSRH using Jira credentials. Publishing occurs when semantic-release detects releasable commits on the main branch.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (OSSRH_USERNAME, OSSRH_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) for Maven Central; GITHUB_TOKEN for GitHub Releases
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-pulsar-authz

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yaml`** — build [Release Artifacts]
- **Summary**: This workflow uses semantic-release with maven-semantic-release plugin to automatically version, build, and publish Maven artifacts to OSSRH (Maven Central) and create GitHub releases. It runs on all pushes and pull requests, but semantic-release will only publish on qualifying commits (typically main branch with conventional commit messages). Maven credentials are configured via setup-java action, and semantic-release handles both Maven deployment and GitHub release creation.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via setup-java action; credentials passed as environment variables to semantic-release
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-rabbitmq-watcher

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow builds a Java Maven project and publishes release artifacts to Maven Central (OSSRH) and GitHub Releases using semantic-release. The workflow runs on pushes to master and pull requests. For master branch pushes, it uses @conveyal/maven-semantic-release to publish versioned artifacts to Maven Central with GPG signing, and @semantic-release/github to create GitHub releases. Coverage reports are uploaded to Codecov for documentation purposes.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push to master branch
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action; GITHUB_TOKEN for GitHub releases
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-redis-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow builds a Java project with Maven and uses semantic-release with @conveyal/maven-semantic-release plugin to automatically publish versioned releases to Maven Central (OSSRH) and GitHub Releases. The workflow is triggered on push and pull_request events. Maven credentials are configured via setup-java action with server-id 'ossrh', and artifacts are signed with GPG. The semantic-release tool handles version determination, changelog generation, and publishing to both Maven Central and GitHub Releases.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via setup-java action. Secrets passed through env block to semantic-release.
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-redis-watcher

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow builds and tests a Java project, then uses semantic-release with @conveyal/maven-semantic-release to automatically publish versioned releases to Maven Central (via OSSRH) and GitHub Releases. Publishing is conditional based on semantic-release's analysis of commit messages. The workflow sets up GPG signing for Maven artifacts and authenticates to OSSRH using Jira credentials.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (username/password) and GPG signing key for Maven Central; GITHUB_TOKEN for GitHub Releases
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-redis-watcher-ex

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow publishes versioned release artifacts to Maven Central (via OSSRH) and GitHub Releases using semantic-release tooling. It runs on every push and pull request, but semantic-release only publishes when conditions are met (typically on main branch with proper commit messages). The workflow uses @conveyal/maven-semantic-release to publish to Maven Central with GPG signing, and @semantic-release/github to create GitHub releases. Codecov upload for coverage reporting is also present but is documentation-related, not artifact publishing.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (username/password) and GPG signing key for Maven Central; GITHUB_TOKEN for GitHub Releases
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-shiro-casbin

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow publishes Java artifacts to Maven Central (OSSRH) and creates GitHub releases using semantic-release with the @conveyal/maven-semantic-release plugin. It sets up Maven credentials via setup-java action with OSSRH server configuration and GPG signing. The semantic-release step handles versioning, Maven deployment to OSSRH/Maven Central, and GitHub release creation. Codecov upload is also present for documentation purposes.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action and semantic-release environment variables
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-spring-security-starter

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`gradle-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow builds and tests a Java Spring Security starter library, then uses semantic-release with maven-semantic-release plugin to automatically publish versioned releases to Maven Central (OSSRH) and GitHub Releases. The workflow is triggered on all pushes and pull requests, but semantic-release only publishes on pushes to the main branch when commits follow conventional commit format. Authentication uses OSSRH Jira credentials and GPG signing for Maven Central, and GITHUB_TOKEN for GitHub Releases.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action and passed to semantic-release
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-string-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`ci.yml`** — CI [Release Artifacts]
- **Summary**: This workflow publishes Maven artifacts to OSSRH (Maven Central) and creates GitHub releases using semantic-release. It runs on both push and pull_request events, builds with Maven, uploads coverage to Codecov, then uses semantic-release with maven-semantic-release plugin to automatically version, publish to Maven Central (via OSSRH), and create GitHub releases. Authentication uses OSSRH credentials and GPG signing.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: Maven server credentials (OSSRH_JIRA_USERNAME/PASSWORD) and GPG signing key configured via setup-java action. GitHub token for semantic-release.
- **Confidence**: high
- **GitHub Actions**: `codecov/codecov-action@v1`
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-vertx-authz

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow publishes Java artifacts to Maven Central (OSSRH) and creates GitHub releases using semantic-release with the @conveyal/maven-semantic-release plugin. It builds and tests the project with Maven, uploads coverage to Codecov, then uses semantic-release to automatically version, package, sign with GPG, and publish artifacts to OSSRH and GitHub releases based on conventional commits.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action. GitHub token (GH_TOKEN) for GitHub releases.
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-jcasbin-zookeeper-watcher

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow builds a Java project with Maven, runs tests with code coverage (Codecov upload), and uses semantic-release with @conveyal/maven-semantic-release to automatically publish versioned releases to Maven Central (OSSRH) and GitHub Releases. Publishing is triggered on push/pull_request events, though semantic-release typically restricts actual releases to protected branches. Artifacts are signed with GPG and authenticated to OSSRH using Jira credentials.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (username/password) and GPG signing key for Maven Central; GITHUB_TOKEN for GitHub Releases
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-js-vue-authz

**1** release/snapshot workflows | Ecosystems: **github_releases, npm** | Release Artifacts: 1

**`ci.yml`** — CI [Release Artifacts]
- **Summary**: This workflow runs tests and linting on multiple Node.js versions, uploads coverage to Codecov, then uses semantic-release to automatically publish versioned npm packages and create GitHub releases based on conventional commits. Publishing only occurs on push events to the main repository.
- **Ecosystems**: npm, github_releases
- **Trigger**: push to casbin-js/vue-authz repository
- **Auth**: NPM_TOKEN secret for npm registry, GITHUB_TOKEN for GitHub releases
- **Confidence**: high
- **Commands**: `yarn semantic-release`

### apache/casbin-lego

**1** release/snapshot workflows | Ecosystems: **docker_hub, github_pages, github_releases** | Release Artifacts: 1

**`main.yml`** — Main [Release Artifacts]
- **Summary**: This workflow publishes release artifacts when version tags (v*) are pushed. It deploys documentation to GitHub Pages on every push to master, creates GitHub releases with binaries via GoReleaser, and publishes multi-architecture Docker images to Docker Hub using Seihon. The Docker login step directly interpolates secrets.DOCKER_PASSWORD in a run command, which should use env: block pattern instead.
- **Ecosystems**: github_pages, github_releases, docker_hub
- **Trigger**: push to master branch, push tags matching v*, pull_request
- **Auth**: GITHUB_TOKEN for GitHub Pages and GoReleaser, DOCKER_USERNAME/DOCKER_PASSWORD for Docker Hub
- **Confidence**: high
- **GitHub Actions**: `crazy-max/ghaction-github-pages@v2`, `goreleaser/goreleaser-action@v2`
- **Commands**: `make publish-images`

### apache/casbin-lua-casbin

**1** release/snapshot workflows | Ecosystems: **github_releases, luarocks** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow performs semantic versioning releases and publishes Lua packages to LuaRocks registry. On push to master, it runs semantic-release to create GitHub releases, then dynamically generates a rockspec file based on the latest release tag and uploads it to LuaRocks using an API key. The workflow is protected by repository checks to only run on the official casbin/lua-casbin repository.
- **Ecosystems**: luarocks, github_releases
- **Trigger**: push to master branch
- **Auth**: LUAROCKS_API_KEY secret for LuaRocks, GITHUB_TOKEN for semantic-release
- **Confidence**: high
- **Commands**: `luarocks upload casbin-${rv}-1.rockspec --force --skip-pack --api-key=${{ secrets.LUAROCKS_API_KEY }}`

### apache/casbin-mcp-gateway

**1** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: Builds Go backend and Node.js frontend, packages them into a tarball (mcp-gateway-linux-amd64.tar.gz), and publishes to GitHub Releases using semantic-release. Triggered on pushes to master/main branches.
- **Ecosystems**: github_releases
- **Trigger**: push to master/main branches
- **Auth**: GITHUB_TOKEN (automatic)
- **Confidence**: high
- **GitHub Actions**: `semantic-release`
- **Commands**: `npx semantic-release`

### apache/casbin-mesh

**1** release/snapshot workflows | Ecosystems: **ghcr** | Release Artifacts: 1

**`docker-publish.yml`** — Docker [Release Artifacts]
- **Summary**: Publishes Docker images to GitHub Container Registry (ghcr.io) on pushes to main/master branches and semver tags. Images are built for linux/amd64 and linux/arm64 platforms. Pull requests trigger builds but do not push images. Uses docker/metadata-action to generate tags and labels from git refs.
- **Ecosystems**: ghcr
- **Trigger**: push to main/master branches and semver tags (v*.*.*), pull_request (build only)
- **Auth**: GITHUB_TOKEN with packages:write permission
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v1`, `docker/build-push-action@v2`

### apache/casbin-nest-authz

**1** release/snapshot workflows | Ecosystems: **github_releases, npm** | Release Artifacts: 1

**`ci.yml`** — Node.js CI [Release Artifacts]
- **Summary**: CI workflow that runs tests and linting on multiple Node.js versions, uploads coverage to Coveralls, and uses semantic-release to automatically publish versioned npm packages and create GitHub releases when pushed to the main repository.
- **Ecosystems**: npm, github_releases
- **Trigger**: push to node-casbin/nest-authz repository
- **Auth**: NPM_TOKEN secret for npm registry, GITHUB_TOKEN for GitHub releases
- **Confidence**: high
- **Commands**: `npx -p semantic-release -p @semantic-release/git -p @semantic-release/changelog semantic-release`

### apache/casbin-node-casbin

**1** release/snapshot workflows | Ecosystems: **npm** | Release Artifacts: 1

**`main.yml`** — main [Release Artifacts]
- **Summary**: This workflow runs tests on pull requests and pushes to master. On push to master (for the casbin/node-casbin repository only), it executes semantic-release which automatically publishes versioned npm packages based on commit messages. The workflow uses NPM_TOKEN for authentication to the npm registry.
- **Ecosystems**: npm
- **Trigger**: push to master branch
- **Auth**: NPM_TOKEN secret
- **Confidence**: high
- **Commands**: `yarn semantic-release`

### apache/casbin-node-casbin-basic-adapter

**1** release/snapshot workflows | Ecosystems: **npm** | Release Artifacts: 1

**`ci.yml`** — ci [Release Artifacts]
- **Summary**: This workflow runs tests across multiple database adapters (PostgreSQL, MySQL, SQLite, MSSQL) and performs linting/formatting checks. On push events to the main repository, it uses semantic-release to automatically publish versioned releases to npm based on commit messages. The release step is conditional on push events and repository ownership.
- **Ecosystems**: npm
- **Trigger**: push to node-casbin/basic-adapter repository
- **Auth**: NPM_TOKEN and GITHUB_TOKEN secrets
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-node-casbin-couchdb-adapter

**1** release/snapshot workflows | Ecosystems: **npm** | Release Artifacts: 1

**`ci.yml`** — ci [Release Artifacts]
- **Summary**: This workflow runs CI tests and uses semantic-release to automatically publish the Node.js CouchDB adapter package to npm. The semantic-release job is conditionally executed only on push events to the main repository (node-casbin/couchdb-adapter). It authenticates to npm using NPM_TOKEN and to GitHub using GITHUB_TOKEN. The workflow includes test coverage reporting to Coveralls but the primary publishing action is the npm package release via semantic-release.
- **Ecosystems**: npm
- **Trigger**: push to node-casbin/couchdb-adapter repository
- **Auth**: NPM_TOKEN secret
- **Confidence**: high
- **Commands**: `yarn run release`

### apache/casbin-node-casbin-drizzle-adapter

**1** release/snapshot workflows | Ecosystems: **npm** | Release Artifacts: 1

**`ci.yml`** — CI [Release Artifacts]
- **Summary**: This workflow runs linting, testing, and coverage checks on pull requests and pushes. On push to master (and only for the canonical repository 'node-casbin/drizzle-adapter'), it executes semantic-release which publishes versioned npm packages to the npm registry using the NPM_TOKEN secret. The 'yarn run release' command is semantic-release, which automates versioning and publishing based on conventional commits.
- **Ecosystems**: npm
- **Trigger**: push to master branch (conditional on repository match)
- **Auth**: NPM_TOKEN secret
- **Confidence**: high
- **Commands**: `yarn run release`

### apache/casbin-node-casbin-etcd-watcher

**1** release/snapshot workflows | Ecosystems: **github_releases, npm** | Release Artifacts: 1

**`main.yml`** — Main [Release Artifacts]
- **Summary**: This workflow runs tests across multiple Node.js and etcd versions, then uses semantic-release to automatically publish versioned npm packages and create GitHub releases. Publishing only occurs on push events to the node-casbin/etcd-watcher repository. Secrets are passed directly in the run block rather than through env variables.
- **Ecosystems**: npm, github_releases
- **Trigger**: push to node-casbin/etcd-watcher repository
- **Auth**: NPM_TOKEN secret for npm registry, GITHUB_TOKEN for GitHub releases
- **Confidence**: high
- **Commands**: `yarn semantic-release`

### apache/casbin-node-casbin-expression-eval

**1** release/snapshot workflows | Ecosystems: **github_releases, npm** | Release Artifacts: 1

**`ci.yml`** — Node.js CI [Release Artifacts]
- **Summary**: This workflow runs tests and coverage on multiple Node.js versions, then uses semantic-release to automatically publish versioned npm packages to the npm registry. The release job is triggered only on push events to the main repository (node-casbin/expression-eval). Semantic-release handles version bumping, changelog generation, git tagging, and npm publishing based on conventional commits.
- **Ecosystems**: npm, github_releases
- **Trigger**: push
- **Auth**: NPM_TOKEN and GITHUB_TOKEN secrets
- **Confidence**: high
- **Commands**: `npx -p semantic-release -p @semantic-release/git -p @semantic-release/changelog semantic-release`

### apache/casbin-node-casbin-file-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, npm** | Release Artifacts: 1

**`ci.yml`** — ci [Release Artifacts]
- **Summary**: CI workflow that runs tests, coverage, and linting on multiple Node.js versions. On push events to the canonical repository, it uses semantic-release to automatically publish versioned npm packages and create GitHub releases based on commit messages. The semantic-release tool handles version bumping, changelog generation, npm publishing, and GitHub release creation.
- **Ecosystems**: npm, github_releases
- **Trigger**: push to main branch (semantic-release convention)
- **Auth**: NPM_TOKEN and GITHUB_TOKEN secrets passed via environment variables
- **Confidence**: high
- **Commands**: `npx -p semantic-release -p @semantic-release/changelog -p @semantic-release/commit-analyzer -p @semantic-release/release-notes-generator -p @semantic-release/git -p @semantic-release/github semantic-release`

### apache/casbin-node-casbin-mongo-changestream-watcher

**1** release/snapshot workflows | Ecosystems: **npm** | Release Artifacts: 1

**`main.yml`** — main [Release Artifacts]
- **Summary**: This workflow runs tests and code coverage checks on multiple Node.js versions, then conditionally publishes the package to npm using semantic-release. The release step only executes on push events to the canonical repository (node-casbin/mongo-changestream-watcher). Semantic-release handles versioning, changelog generation, GitHub releases, and npm publishing based on conventional commits.
- **Ecosystems**: npm
- **Trigger**: push to main branch (conditional: github.event_name == 'push' && github.repository == 'node-casbin/mongo-changestream-watcher')
- **Auth**: NPM_TOKEN secret for npm registry authentication, GITHUB_TOKEN for GitHub releases
- **Confidence**: high
- **Commands**: `npx -p semantic-release -p @semantic-release/git -p @semantic-release/changelog -p @semantic-release/commit-analyzer -p @semantic-release/release-notes-generator -p @semantic-release/release-notes-generator -p @semantic-release/changelog -p @semantic-release/git -p @semantic-release/github semantic-release`

### apache/casbin-node-casbin-mongoose-adapter

**1** release/snapshot workflows | Ecosystems: **npm** | Release Artifacts: 1

**`main.yml`** — main [Release Artifacts]
- **Summary**: This workflow runs tests and code coverage on pull requests and pushes. On push to master branch in the node-casbin/mongoose-adapter repository, it uses semantic-release to automatically publish versioned releases to npm registry. The workflow includes test jobs, coverage reporting to Coveralls, and conditional release publishing using semantic-release with npm and GitHub plugins.
- **Ecosystems**: npm
- **Trigger**: push to master branch
- **Auth**: NPM_TOKEN secret
- **Confidence**: high
- **Commands**: `npx -p semantic-release -p @semantic-release/git -p @semantic-release/changelog -p @semantic-release/commit-analyzer -p @semantic-release/release-notes-generator -p @semantic-release/release-notes-generator -p @semantic-release/changelog -p @semantic-release/git -p @semantic-release/github semantic-release`

### apache/casbin-node-casbin-node-redis-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, npm** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes versioned releases to npm and GitHub Releases using semantic-release. It triggers on every push, builds the Node.js library, and runs semantic-release with npm and GitHub plugins. The NPM_TOKEN authenticates to npm registry for package publishing, while GITHUB_TOKEN creates GitHub releases. Publishing is restricted to the node-casbin/redis-adapter repository.
- **Ecosystems**: npm, github_releases
- **Trigger**: push
- **Auth**: NPM_TOKEN and GITHUB_TOKEN secrets passed as environment variables
- **Confidence**: high
- **Commands**: `npx -p semantic-release -p @semantic-release/git -p @semantic-release/changelog -p @semantic-release/commit-analyzer -p @semantic-release/release-notes-generator -p @semantic-release/release-notes-generator -p @semantic-release/changelog -p @semantic-release/git -p @semantic-release/github semantic-release`

### apache/casbin-node-casbin-prisma-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, npm** | Release Artifacts: 1

**`ci.yml`** — CI [Release Artifacts]
- **Summary**: This workflow runs linting, testing, and coverage checks on push and pull_request events. The semantic-release job publishes versioned releases to npm registry and creates GitHub releases when pushed to the node-casbin/prisma-adapter repository. Authentication uses NPM_TOKEN for npm publishing and GITHUB_TOKEN for GitHub releases. Secrets are directly interpolated in the run block rather than passed through env variables.
- **Ecosystems**: npm, github_releases
- **Trigger**: push to node-casbin/prisma-adapter repository
- **Auth**: GITHUB_TOKEN and NPM_TOKEN secrets
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-node-casbin-redis-watcher

**1** release/snapshot workflows | Ecosystems: **npm** | Release Artifacts: 1

**`ci.yml`** — CI [Release Artifacts]
- **Summary**: This workflow performs linting, testing, and coverage checks on push/PR events. On push to the main repository (node-casbin/redis-watcher), it runs semantic-release which publishes versioned npm packages. The semantic-release step uses NPM_TOKEN for authentication to publish to the npm registry.
- **Ecosystems**: npm
- **Trigger**: push to node-casbin/redis-watcher repository
- **Auth**: NPM_TOKEN secret
- **Confidence**: high
- **Commands**: `yarn run release`

### apache/casbin-node-casbin-session-role-manager

**1** release/snapshot workflows | Ecosystems: **github_releases, npm** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow uses semantic-release to automatically publish versioned npm packages to the npm registry and create GitHub releases. Triggered on push to master branch after running build, tests, and lint checks. Authentication uses NPM_TOKEN for npm publishing and GITHUB_TOKEN for GitHub releases.
- **Ecosystems**: npm, github_releases
- **Trigger**: push to master branch
- **Auth**: GITHUB_TOKEN and NPM_TOKEN secrets
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-pycasbin

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`build.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests, linters, and coverage reporting on push/PR to master. After successful tests, the 'release' job uses semantic-release to automatically publish Python packages to PyPI and create GitHub releases. The workflow uses PYPI_TOKEN_CASBIN for PyPI authentication and GITHUB_TOKEN for GitHub releases. Secrets are passed directly in run blocks rather than through env variables.
- **Ecosystems**: pypi, github_releases
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub releases
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-async-django-orm-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`build.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests and linting on PRs and pushes to master. On successful completion of tests on master branch, it uses semantic-release to automatically publish versioned releases to PyPI (using PYPI_TOKEN) and create GitHub Releases (using GH_TOKEN). The semantic-release tool handles version bumping, changelog generation, and publishing based on conventional commits.
- **Ecosystems**: pypi, github_releases
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub Releases
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-async-postgres-watcher

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`release.yml`** — tests [Release Artifacts]
- **Summary**: This workflow runs tests across multiple Python versions and OS platforms, uploads coverage to Coveralls, then uses semantic-release to automatically publish versioned releases to PyPI and create GitHub releases. The release job only runs on push to master after all tests pass. Semantic-release handles version bumping, changelog generation, and publishing to PyPI using the PYPI_TOKEN secret.
- **Ecosystems**: pypi, github_releases
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret and GITHUB_TOKEN for semantic-release
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-async-sqlalchemy-adapter

**1** release/snapshot workflows | Ecosystems: **pypi** | Release Artifacts: 1

**`build.yml`** — build [Release Artifacts]
- **Summary**: CI/CD workflow that runs tests and linters on pull requests and pushes to master. On master branch pushes (after tests pass), uses semantic-release with semantic-release-pypi plugin to automatically version and publish Python packages to PyPI. Coverage data is uploaded to coveralls.io for documentation purposes.
- **Ecosystems**: pypi
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-casbin-databases-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`build.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests and linters on pull requests and pushes to master. On successful completion of tests on master branch, it uses semantic-release with the semantic-release-pypi plugin to automatically publish versioned Python packages to PyPI and create GitHub releases. The release is gated behind test success and uses semantic versioning based on commit messages.
- **Ecosystems**: pypi, github_releases
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret for PyPI, GITHUB_TOKEN for GitHub releases
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-django-casbin-auth

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`release.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests and linting on PRs and pushes to master. On master branch pushes (after tests pass), it uses semantic-release to automatically publish versioned releases to PyPI and create GitHub releases. The PYPI_TOKEN secret is used for PyPI authentication, and GH_TOKEN for GitHub releases. Coverage data is uploaded to coveralls.io (documentation category activity, but primary purpose is release publishing).
- **Ecosystems**: pypi, github_releases
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret and GH_TOKEN for GitHub releases
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-django-orm-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`build.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests and linting on PRs and pushes to master. On successful completion of tests on master branch, it uses semantic-release to automatically publish versioned releases to PyPI and create GitHub Releases. The semantic-release tool handles version bumping, changelog generation, and publishing based on conventional commits. Coverage data is uploaded to coveralls.io (documentation category, but primary purpose is release_artifact).
- **Ecosystems**: pypi, github_releases
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub Releases
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-etcd-watcher

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`release.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests and linting on pull requests and pushes to master. On master branch pushes (after tests pass), it uses semantic-release to automatically publish the Python package to PyPI and create GitHub releases based on commit messages. The PYPI_TOKEN secret is used for PyPI authentication.
- **Ecosystems**: pypi, github_releases
- **Trigger**: push to master branch
- **Auth**: PYPI_TOKEN secret and GITHUB_TOKEN for semantic-release
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-fastapi-casbin-auth

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`release.yml`** — release [Release Artifacts]
- **Summary**: Automated release workflow using semantic-release that publishes Python packages to PyPI and creates GitHub releases. Triggered on push to master branch. Uses semantic-release-pypi plugin to handle PyPI publishing with twine, and @semantic-release/github for GitHub releases. Credentials properly passed through environment variables.
- **Ecosystems**: pypi, github_releases
- **Trigger**: push to master branch
- **Auth**: GITHUB_TOKEN and PYPI_TOKEN secrets
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-flask-authz

**1** release/snapshot workflows | Ecosystems: **pypi** | Release Artifacts: 1

**`build.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests, linters, and coverage reporting on pull requests and pushes to master. On push events to master, it uses semantic-release with the semantic-release-pypi plugin to automatically publish versioned releases to PyPI. The release is authenticated using a PYPI_TOKEN secret.
- **Ecosystems**: pypi
- **Trigger**: push to master branch
- **Auth**: PYPI_TOKEN secret
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-graphql-authz

**1** release/snapshot workflows | Ecosystems: **pypi** | Release Artifacts: 1

**`build.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests and linters on pull requests and pushes to master. On successful completion of tests on master branch, it uses semantic-release with the semantic-release-pypi plugin to automatically publish versioned Python packages to PyPI. The release is triggered by commit messages following semantic versioning conventions.
- **Ecosystems**: pypi
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-postgresql-watcher

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`release.yml`** — tests [Release Artifacts]
- **Summary**: This workflow runs tests across multiple Python versions and operating systems, uploads coverage to Coveralls, and then uses semantic-release to automatically publish versioned releases to PyPI and create GitHub releases. The release job only runs on master branch pushes after all tests pass. The semantic-release tool with semantic-release-pypi plugin handles the PyPI publishing using twine under the hood.
- **Ecosystems**: pypi, github_releases
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret and GITHUB_TOKEN for semantic-release
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-pymongo-adapter

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`main.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests, linting, and coverage reporting on push/PR to master. After successful tests, the 'release' job uses semantic-release to automatically publish versioned Python packages to PyPI and create GitHub Releases. The semantic-release-pypi plugin handles PyPI publishing using the PYPI_TOKEN secret. Coverage data is uploaded to coveralls.io (documentation category activity, but primary purpose is release_artifact).
- **Ecosystems**: pypi, github_releases
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub Releases
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-rabbitmq-watcher

**1** release/snapshot workflows | Ecosystems: **pypi** | Release Artifacts: 1

**`build.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests and linters on pull requests and pushes to master. On master branch pushes (after tests pass), it uses semantic-release with the semantic-release-pypi plugin to automatically publish Python packages to PyPI. The release is triggered by commit messages following conventional commit format. Authentication uses PYPI_TOKEN secret.
- **Ecosystems**: pypi
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-redis-adapter

**1** release/snapshot workflows | Ecosystems: **pypi** | Release Artifacts: 1

**`build.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests and linters on pull requests and pushes to master. On master branch pushes (after tests pass), it uses semantic-release with the semantic-release-pypi plugin to automatically publish versioned Python packages to PyPI. Authentication is via PYPI_TOKEN secret.
- **Ecosystems**: pypi
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-redis-watcher

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`release.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests, linting, and coverage reporting on push/PR to master. The 'release' job uses semantic-release to publish Python packages to PyPI and create GitHub releases. The PYPI_TOKEN and GH_TOKEN are passed directly in the run block environment, which is functional but not best practice for secret handling.
- **Ecosystems**: pypi, github_releases
- **Trigger**: push to master branch, pull_request to master branch
- **Auth**: PYPI_TOKEN secret, GITHUB_TOKEN secret
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-sanic-authz

**1** release/snapshot workflows | Ecosystems: **github_releases, pypi** | Release Artifacts: 1

**`build.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests and linting on PRs and pushes to master. On successful completion of tests on master branch, it uses semantic-release to automatically publish versioned releases to PyPI and create GitHub Releases. The semantic-release tool determines version bumps based on commit messages and handles the publishing process.
- **Ecosystems**: pypi, github_releases
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret for PyPI, GH_TOKEN for GitHub Releases
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-sqlalchemy-adapter

**1** release/snapshot workflows | Ecosystems: **pypi** | Release Artifacts: 1

**`build.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests and linters on pull requests and pushes to master. On master branch pushes (after tests pass), it uses semantic-release with the semantic-release-pypi plugin to automatically publish versioned Python packages to PyPI. The release job installs twine and setuptools, then runs semantic-release which handles version bumping, changelog generation, and PyPI publishing using the PYPI_TOKEN secret.
- **Ecosystems**: pypi
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-python-sqlobject-adapter

**1** release/snapshot workflows | Ecosystems: **pypi** | Release Artifacts: 1

**`build.yml`** — build [Release Artifacts]
- **Summary**: This workflow runs tests on multiple Python versions, uploads coverage to Coveralls, and uses semantic-release with the semantic-release-pypi plugin to automatically publish versioned releases to PyPI when changes are pushed to the master branch. The release job depends on successful test and coverage jobs.
- **Ecosystems**: pypi
- **Trigger**: push to master branch (after tests pass)
- **Auth**: PYPI_TOKEN secret
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/casbin-rs

**1** release/snapshot workflows | Ecosystems: **crates_io** | Release Artifacts: 1

**`release.yml`** — Auto Release [Release Artifacts]
- **Summary**: Automated release workflow that publishes Rust library to crates.io using semantic-release. Triggered after successful CI workflow completion on push events. Uses a reusable workflow from casbin-rs/semantic-release-action-rust with cargo registry token authentication.
- **Ecosystems**: crates_io
- **Trigger**: workflow_run (triggered after CI workflow completes successfully on push events)
- **Auth**: CARGO_TOKEN secret passed to reusable workflow
- **Confidence**: high
- **GitHub Actions**: `casbin-rs/semantic-release-action-rust/.github/workflows/release-library.yml@master`

### apache/casbin-rust-actix-casbin

**1** release/snapshot workflows | Ecosystems: **crates_io, github_releases** | Release Artifacts: 1

**`release.yml`** — Auto Release [Release Artifacts]
- **Summary**: Publishes Rust crate to crates.io and creates GitHub release when version tags (v*) are pushed. Uses cargo publish for crates.io deployment and actions/create-release for GitHub releases.
- **Ecosystems**: crates_io, github_releases
- **Trigger**: push to tags matching v*
- **Auth**: CARGO_TOKEN secret for crates.io, GITHUB_TOKEN for releases
- **Confidence**: high
- **GitHub Actions**: `actions/create-release@v1`
- **Commands**: `cargo login`, `cargo publish`

### apache/casbin-rust-casbin-rust-cli

**1** release/snapshot workflows | Ecosystems: **crates_io** | Release Artifacts: 1

**`release.yml`** — Auto Release [Release Artifacts]
- **Summary**: This workflow publishes Rust crates to crates.io using semantic-release automation. It triggers on pushes to release branches (master, next, beta, alpha, and version branches) and delegates to a reusable workflow that handles the actual cargo publish operation using the CARGO_TOKEN secret.
- **Ecosystems**: crates_io
- **Trigger**: push to master, next, next-major, beta, alpha, or version branches
- **Auth**: CARGO_TOKEN secret passed to reusable workflow
- **Confidence**: high
- **GitHub Actions**: `casbin-rs/semantic-release-action-rust/.github/workflows/release-binary.yml@master`

### apache/casbin-rust-diesel-adapter

**1** release/snapshot workflows | Ecosystems: **crates_io, github_releases** | Release Artifacts: 1

**`release.yml`** — Auto Release [Release Artifacts]
- **Summary**: Publishes Rust crate to crates.io and creates GitHub release when version tags (v*) are pushed. Uses cargo publish for crates.io deployment and actions/create-release for GitHub releases.
- **Ecosystems**: crates_io, github_releases
- **Trigger**: push to tags matching v*
- **Auth**: CARGO_TOKEN secret for crates.io, GITHUB_TOKEN for GitHub releases
- **Confidence**: high
- **GitHub Actions**: `actions/create-release@v1`
- **Commands**: `cargo login`, `cargo publish`

### apache/casbin-rust-dufs-with-casbin

**1** release/snapshot workflows | Ecosystems: **crates_io, docker_hub, github_releases** | Release Artifacts: 1

**`release.yaml`** — Release [Release Artifacts]
- **Summary**: Multi-ecosystem release workflow triggered by version tags. Builds Rust binaries for 14 target platforms, publishes compiled archives to GitHub Releases, pushes multi-platform Docker images to Docker Hub (only for stable releases), and publishes the crate to crates.io (only for stable releases, not release candidates). The workflow distinguishes between stable releases (x.y.z) and release candidates (x.y.z-rc) using tag pattern matching.
- **Ecosystems**: github_releases, docker_hub, crates_io
- **Trigger**: push to tags matching v[0-9]+.[0-9]+.[0-9]+*
- **Auth**: GITHUB_TOKEN for GitHub Releases, DOCKERHUB_USERNAME/DOCKERHUB_TOKEN for Docker Hub, CRATES_IO_API_TOKEN for crates.io
- **Confidence**: high
- **GitHub Actions**: `softprops/action-gh-release@v0.1.5`, `docker/login-action@v1`, `docker/build-push-action@v2`
- **Commands**: `cargo publish`

### apache/casbin-rust-postgres-adapter

**1** release/snapshot workflows | Ecosystems: **crates_io, github_releases** | Release Artifacts: 1

**`release.yml`** — Auto Release [Release Artifacts]
- **Summary**: Publishes versioned Rust crate to crates.io and creates GitHub release when tags matching v* are pushed. Uses cargo login with CARGO_TOKEN secret, then cargo publish --no-verify. Also creates a GitHub release with the tag name.
- **Ecosystems**: crates_io, github_releases
- **Trigger**: push to tags matching v*
- **Auth**: secrets.CARGO_TOKEN for crates.io, secrets.GITHUB_TOKEN for GitHub releases
- **Confidence**: high
- **GitHub Actions**: `actions-rs/cargo@v1`
- **Commands**: `cargo login`, `cargo publish`

### apache/casbin-rust-redis-watcher

**1** release/snapshot workflows | Ecosystems: **crates_io** | Release Artifacts: 1

**`release.yml`** — Auto Release [Release Artifacts]
- **Summary**: Automated release workflow that publishes Rust library to crates.io via a reusable semantic-release workflow. Triggered only after successful CI runs on master branch. Uses cargo-registry-token for authentication.
- **Ecosystems**: crates_io
- **Trigger**: workflow_run on CI completion (master branch only)
- **Auth**: CARGO_TOKEN secret passed to reusable workflow
- **Confidence**: high
- **GitHub Actions**: `casbin-rs/semantic-release-action-rust/.github/workflows/release-library.yml@master`

### apache/casbin-rust-rocket-authz

**1** release/snapshot workflows | Ecosystems: **crates_io, github_releases** | Release Artifacts: 1

**`release.yml`** — Auto Release [Release Artifacts]
- **Summary**: Publishes Rust crate to crates.io and creates GitHub Release when version tags (v*) are pushed. Uses cargo login with CARGO_TOKEN secret, then cargo publish to release the package. Also creates a GitHub Release entry for the tag.
- **Ecosystems**: crates_io, github_releases
- **Trigger**: push to tags matching v*
- **Auth**: secrets.CARGO_TOKEN for crates.io, secrets.GITHUB_TOKEN for GitHub Releases
- **Confidence**: high
- **GitHub Actions**: `actions-rs/cargo@v1`
- **Commands**: `cargo login`, `cargo publish`

### apache/casbin-rust-semantic-release-action-rust

**2** release/snapshot workflows | Ecosystems: **crates_io, github_releases** | Release Artifacts: 2

**`release-binary.yml`** — Release Binary [Release Artifacts]
- **Summary**: This workflow publishes Rust release artifacts to both GitHub Releases and crates.io. It compiles binaries for multiple target platforms (aarch64-apple-darwin, x86_64-apple-darwin, x86_64-pc-windows-gnu, x86_64-unknown-linux-gnu, etc.), runs tests, creates checksums, and delegates final publishing to the semantic-release-action-rust action. The action receives cargo-registry-token for crates.io publishing and handles both binary releases to GitHub and package publishing to the Cargo registry. The workflow is triggered via workflow_call and uses concurrency controls to prevent simultaneous releases.
- **Ecosystems**: github_releases, crates_io
- **Trigger**: workflow_call
- **Auth**: cargo-registry-token secret
- **Confidence**: high
- **GitHub Actions**: `casbin-rs/semantic-release-action-rust/semantic-release-binary@master`

**`release-library.yml`** — Release Library [Release Artifacts]
- **Summary**: Reusable workflow that publishes Rust library crates to a cargo registry (typically crates.io) using semantic-release. The workflow accepts a cargo-registry-token secret for authentication and uses a custom semantic-release action that handles Rust library releases. The disable-semantic-release-cargo input allows bypassing cargo publishing if needed.
- **Ecosystems**: crates_io
- **Trigger**: workflow_call
- **Auth**: cargo-registry-token secret
- **Confidence**: high
- **GitHub Actions**: `casbin-rs/semantic-release-action-rust/semantic-release-library@master`

### apache/casbin-rust-string-adapter

**1** release/snapshot workflows | Ecosystems: **crates_io, github_releases** | Release Artifacts: 1

**`release.yml`** — Auto Release [Release Artifacts]
- **Summary**: Publishes Rust crate to crates.io and creates GitHub release when version tags (v*) are pushed. Uses cargo publish for crates.io deployment and actions/create-release for GitHub releases.
- **Ecosystems**: crates_io, github_releases
- **Trigger**: push to tags matching v*
- **Auth**: CARGO_TOKEN secret for crates.io, GITHUB_TOKEN for releases
- **Confidence**: high
- **GitHub Actions**: `actions/create-release@v1`
- **Commands**: `cargo login`, `cargo publish`

### apache/casbin-rust-yaml-adapter

**1** release/snapshot workflows | Ecosystems: **crates_io, github_releases** | Release Artifacts: 1

**`release.yml`** — Auto Release [Release Artifacts]
- **Summary**: Publishes Rust crate to crates.io and creates GitHub release when version tags (v*) are pushed. Uses cargo publish for crates.io deployment and actions/create-release for GitHub releases.
- **Ecosystems**: crates_io, github_releases
- **Trigger**: push to tags matching v*
- **Auth**: CARGO_TOKEN secret for crates.io, GITHUB_TOKEN for releases
- **Confidence**: high
- **GitHub Actions**: `actions/create-release@v1`
- **Commands**: `cargo login`, `cargo publish`

### apache/casbin-sequelize-adapter

**1** release/snapshot workflows | Ecosystems: **npm** | Release Artifacts: 1

**`ci.yml`** — ci [Release Artifacts]
- **Summary**: This workflow runs CI tests and uses semantic-release to automatically publish versioned npm packages. The semantic-release job only runs on push events to the node-casbin/sequelize-adapter repository, authenticating to npm using NPM_TOKEN. The workflow includes MySQL service for testing, runs linting/formatting checks, executes tests with coverage reporting to Coveralls, and then performs automated semantic versioning and npm publishing.
- **Ecosystems**: npm
- **Trigger**: push to node-casbin/sequelize-adapter repository
- **Auth**: NPM_TOKEN secret
- **Confidence**: high
- **Commands**: `yarn run release`

### apache/casbin-server

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`default.yml`** — Build [Release Artifacts]
- **Summary**: This workflow runs tests with coverage reporting to Coveralls, then performs semantic versioning release and publishes Docker images to Docker Hub. On push events to the main casbin/casbin-server repository, it uses semantic-release to create GitHub releases, then conditionally pushes multi-platform Docker images (linux/amd64, linux/arm64) tagged with the version and 'latest' to Docker Hub (casbin/casbin-server). The push only occurs if there's a major or minor version bump.
- **Ecosystems**: docker_hub
- **Trigger**: push to casbin/casbin-server repository
- **Auth**: Docker Hub credentials via secrets.DOCKERHUB_USERNAME and secrets.DOCKERHUB_PASSWORD
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v1`, `docker/build-push-action@v3`
- **Commands**: `npx semantic-release`

### apache/casbin-spring-boot-starter

**1** release/snapshot workflows | Ecosystems: **github_releases, maven_central** | Release Artifacts: 1

**`maven-ci.yml`** — build [Release Artifacts]
- **Summary**: This workflow uses semantic-release with @conveyal/maven-semantic-release plugin to automatically publish Maven artifacts to OSSRH/Maven Central and create GitHub releases. The workflow is triggered on both push and pull_request events. It builds the project with Maven, then runs semantic-release which analyzes commit messages to determine version bumps and publishes artifacts to Maven Central (via OSSRH) and GitHub releases. Authentication uses OSSRH JIRA credentials and GPG signing for Maven Central publication.
- **Ecosystems**: maven_central, github_releases
- **Trigger**: push, pull_request
- **Auth**: OSSRH credentials (OSSRH_JIRA_USERNAME, OSSRH_JIRA_PASSWORD) and GPG signing (GPG_PRIVATE_KEY, GPG_PASSPHRASE) configured via setup-java action and passed to semantic-release
- **Confidence**: high
- **Commands**: `semantic-release --prepare @conveyal/maven-semantic-release --publish @semantic-release/github,@conveyal/maven-semantic-release --verify-conditions @semantic-release/github,@conveyal/maven-semantic-release --verify-release @conveyal/maven-semantic-release`

### apache/casbin-sqlx-adapter

**1** release/snapshot workflows | Ecosystems: **crates_io** | Release Artifacts: 1

**`release.yml`** — Auto Release [Release Artifacts]
- **Summary**: Publishes Rust crate to crates.io when version tags (v*) are pushed. Uses cargo publish with CARGO_TOKEN authentication. Also creates a GitHub Release (notes only, no downloadable artifacts attached).
- **Ecosystems**: crates_io
- **Trigger**: push to tags matching v*
- **Auth**: CARGO_TOKEN secret for crates.io authentication
- **Confidence**: high
- **GitHub Actions**: `actions/create-release@v1`
- **Commands**: `cargo login`, `cargo publish`

### apache/casbin-typeorm-adapter

**1** release/snapshot workflows | Ecosystems: **npm** | Release Artifacts: 1

**`ci.yml`** — CI [Release Artifacts]
- **Summary**: This workflow runs linting, testing, and coverage checks on push/PR. On push to master (and only for the node-casbin/typeorm-adapter repository), it runs semantic-release which publishes versioned npm packages based on conventional commits. The semantic-release step uses NPM_TOKEN for authentication to npm registry.
- **Ecosystems**: npm
- **Trigger**: push to master branch (conditional on repository match)
- **Auth**: NPM_TOKEN secret
- **Confidence**: high
- **Commands**: `yarn run release`

### apache/casbin-vscode-plugin

**1** release/snapshot workflows | Ecosystems: **github_releases, npm** | Release Artifacts: 1

**`default.yml`** — Deploy To GitHub Releases and VSCode Extension Marketplace [Release Artifacts]
- **Summary**: Publishes VSCode extension to Visual Studio Marketplace and runs semantic-release (likely publishing to npm and creating GitHub releases). Triggered on tag push. Uses semantic-release for automated versioning and GitHub releases, and HaaLeo/publish-vscode-extension action for marketplace deployment.
- **Ecosystems**: npm, github_releases
- **Trigger**: push to tags
- **Auth**: secrets.GITHUB_TOKEN, secrets.NPM_TOKEN, secrets.VS_MARKETPLACE_TOKEN
- **Confidence**: high
- **GitHub Actions**: `HaaLeo/publish-vscode-extension@v1`
- **Commands**: `yarn semantic-release`

### apache/casbin-website-v3

**1** release/snapshot workflows | Ecosystems: **github_releases, npm** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow uses semantic-release to automatically publish versioned npm packages and create GitHub releases. Triggered on pushes to main/master branches, it runs semantic-release which analyzes commits, determines version bumps, publishes to npm registry using NPM_TOKEN, and creates GitHub releases using GITHUB_TOKEN. Both secrets are directly interpolated in the run block rather than passed through env variables.
- **Ecosystems**: npm, github_releases
- **Trigger**: push to main/master branches
- **Auth**: GITHUB_TOKEN and NPM_TOKEN secrets
- **Confidence**: high
- **Commands**: `npx semantic-release`

### apache/cassandra-easy-stress

**2** release/snapshot workflows | Ecosystems: **ghcr, github_releases** | Release Artifacts: 1, Snapshot / Nightly Artifacts: 1

**`gradle-publish-main-release.yml`** — Release Workflow [Release Artifacts]
- **Summary**: Publishes release artifacts to GitHub Releases. Triggered on push to main branch, builds a distribution ZIP using Gradle, creates a GitHub release, and uploads the cassandra-easy-stress-6.0.0.zip artifact. Uses github.ref for tagging which may be problematic since trigger is branch push rather than tag push.
- **Ecosystems**: github_releases
- **Trigger**: push to main branch
- **Auth**: GITHUB_TOKEN (secrets.GITHUB_TOKEN)
- **Confidence**: high
- **GitHub Actions**: `actions/create-release@v1`, `actions/upload-release-asset@v1`

**`ci.yml`** — CI [Snapshot / Nightly Artifacts]
- **Summary**: This workflow publishes snapshot/nightly artifacts from the main branch. It builds a Docker image and pushes it to GitHub Container Registry (ghcr.io) using Gradle Jib, and creates a GitHub Release tagged 'latest' with a downloadable tarball. The release explicitly states these are 'Test Artifacts - Not an Official Release' for testing and development purposes only. The workflow is triggered on pushes to main and pull requests, but publishing only occurs on main branch pushes.
- **Ecosystems**: ghcr, github_releases
- **Trigger**: push to main branch
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `softprops/action-gh-release@v2`
- **Commands**: `./gradlew jib`

### apache/cassandra-sidecar

**1** release/snapshot workflows | Ecosystems: **ghcr, github_releases** | Snapshot / Nightly Artifacts: 1

**`publish-test-artifacts.yml`** — Publish Test Artifacts [Snapshot / Nightly Artifacts]
- **Summary**: Publishes snapshot test artifacts after successful CI runs on trunk branch. Builds a distribution tarball and pushes it to a GitHub Release tagged 'test-artifacts' (prerelease). Also builds and pushes a Docker image to ghcr.io/apache/cassandra-sidecar:latest using Gradle Jib. These are explicitly marked as test artifacts (not official releases) with version format like '1.0.0-test-20240101-abc1234'. The workflow deletes and recreates the 'test-artifacts' release on each run to maintain a single rolling snapshot.
- **Ecosystems**: ghcr, github_releases
- **Trigger**: workflow_run on CI completion (trunk branch) or workflow_dispatch
- **Auth**: GITHUB_TOKEN for GHCR push and GitHub Releases
- **Confidence**: high
- **GitHub Actions**: `softprops/action-gh-release@v2`
- **Commands**: `./gradlew :server:jib -Djib.to.image=ghcr.io/apache/cassandra-sidecar:latest -Djib.to.auth.username=${{ github.actor }} -Djib.to.auth.password=${{ secrets.GITHUB_TOKEN }} --stacktrace`

### apache/causeway

**1** release/snapshot workflows | Ecosystems: **github_packages** | Snapshot / Nightly Artifacts: 1

**`ci-build-artifacts-push-maven.yml`** — Apache Causeway Weekly Build [Snapshot / Nightly Artifacts]
- **Summary**: Weekly scheduled workflow that calculates a new revision number based on timestamp, builds Apache Causeway artifacts, and deploys them to GitHub Packages Maven registry. The -Dgithub flag and MVN_STAGES=deploy indicate Maven deployment. This is a snapshot/nightly build workflow (runs weekly, calculates dynamic revision) rather than a release workflow.
- **Ecosystems**: github_packages
- **Trigger**: schedule (weekly on Sunday 02:00 UTC) and workflow_dispatch
- **Auth**: GITHUB_TOKEN (github.token)
- **Confidence**: high
- **Commands**: `bash scripts/ci/build-artifacts.sh with MVN_STAGES=deploy and -Dgithub flag`

### apache/cayenne

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`verify-deploy-on-push.yml`** — verify and deploy 5.0 [Snapshot / Nightly Artifacts]
- **Summary**: Workflow runs tests across multiple JDK versions and database profiles on every push. For pushes to master or STABLE-* branches in the apache/cayenne repository, it conditionally deploys SNAPSHOT artifacts to Apache Nexus repository using Maven deploy with credentials from GitHub secrets.
- **Ecosystems**: maven_central
- **Trigger**: push to master or STABLE-* branches
- **Auth**: Maven settings.xml with NEXUS_USER and NEXUS_PW secrets
- **Confidence**: high
- **Commands**: `mvn deploy -DskipTests --settings .github/maven-settings.xml`

### apache/celeborn

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`docker-build.yml`** — Build and Push Celeborn Docker Images [Release Artifacts]
- **Summary**: Publishes official Apache Celeborn Docker images to Docker Hub (apache/celeborn) on release events or manual workflow dispatch. Downloads the official Apache release tarball, builds multi-platform images (amd64/arm64), and pushes to Docker Hub with version tags.
- **Ecosystems**: docker_hub
- **Trigger**: release (published) and workflow_dispatch
- **Auth**: Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`
- **Commands**: `docker buildx build --push -f docker/Dockerfile --platform=linux/amd64,linux/arm64 -t apache/celeborn:${VERSION} .`

### apache/cloudstack

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Snapshot / Nightly Artifacts: 1

**`docker-cloudstack-simulator.yml`** — Docker Image Build [Snapshot / Nightly Artifacts]
- **Summary**: Builds and publishes cloudstack-simulator Docker images to Docker Hub (apache/cloudstack-simulator) on pushes to main branch or version tags. Images are tagged with version from pom.xml or tag name, with timestamp suffix for SNAPSHOT versions. This is a snapshot/nightly build workflow for development versions of the CloudStack simulator.
- **Ecosystems**: docker_hub
- **Trigger**: push to main branch or tags 4.*, 5.*
- **Auth**: Docker registry credentials via secrets (DOCKERHUB_USER, DOCKERHUB_TOKEN)
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v2`
- **Commands**: `docker push ${FULL_TAG}`

### apache/cloudstack-kubernetes-provider

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Snapshot / Nightly Artifacts: 1

**`build-docker-image.yml`** — Docker Image Build [Snapshot / Nightly Artifacts]
- **Summary**: Builds multi-architecture Docker images (amd64/arm64) for cloudstack-kubernetes-provider and publishes to Docker Hub (apache/cloudstack-kubernetes-provider). Pushes snapshot builds on main branch commits (tagged with version file content), release builds on git tags, and PR builds (tagged with PR number) from non-fork PRs. Also pushes registry cache images for build optimization.
- **Ecosystems**: docker_hub
- **Trigger**: push to main branch, tags, or pull_request
- **Auth**: Docker registry credentials via secrets (DOCKERHUB_USER, DOCKERHUB_TOKEN)
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/build-push-action@v6`

### apache/commons-crypto

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`maven_crosstest.yml`** — Java Cross Test [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds native binaries for Apache Commons Crypto across multiple architectures (Linux x86_64/x86/aarch64/riscv64, Windows, macOS x86_64/aarch64) using Docker and native builds. The package-macos job conditionally deploys to Maven Central (Apache Snapshots repository) when running on the master branch of apache/commons-crypto. The deployment uses 'mvn deploy' with credentials from GitHub secrets (NEXUS_USER, NEXUS_PW) configured via Maven settings.xml. This is a snapshot_artifact workflow as it deploys to Apache's snapshot repository (server-id: apache.snapshots.https) from the master branch, not a versioned release.
- **Ecosystems**: maven_central
- **Trigger**: workflow_dispatch, push (on native code changes), workflow_run (after Docker images workflow)
- **Auth**: Maven settings.xml configured via actions/setup-java with NEXUS_USER and NEXUS_PW secrets
- **Confidence**: high
- **Commands**: `mvn -V -B -ntp deploy -DskipTests -Drat.skip -Djacoco.skip -DbuildNumber.skip -Danimal.sniffer.skip -Dcyclonedx.skip -Dspdx.skip`

### apache/commons-io

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`maven.yml`** — Java CI [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds and tests Apache Commons IO across multiple OS and Java versions. On the master branch of the apache/commons-io repository, it deploys SNAPSHOT artifacts to Apache's Nexus snapshot repository using Maven. The deploy step uses Java 21 on Ubuntu, skips GPG signing and tests, and authenticates using NEXUS_USER and NEXUS_PW secrets configured through Maven settings.xml.
- **Ecosystems**: maven_central
- **Trigger**: push to master branch, pull_request, workflow_dispatch
- **Auth**: Maven settings.xml configured via actions/setup-java with server credentials from GitHub secrets
- **Confidence**: high
- **Commands**: `mvn --show-version --batch-mode --no-transfer-progress deploy -Dgpg.skip -DskipTests -Drat.skip -Djacoco.skip -Dcyclonedx.skip -Dspotbugs.skip -Dspdx.skip -Dpmd.skip`

### apache/commons-net

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`maven.yml`** — Java CI [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds and tests Apache Commons Net across multiple Java versions and operating systems. When triggered on the master branch with Java 8 on Ubuntu, it deploys SNAPSHOT artifacts to the Apache Snapshots Maven repository (apache.snapshots.https). The deployment uses Maven's deploy goal with GPG signing disabled and test execution skipped.
- **Ecosystems**: maven_central
- **Trigger**: push to master branch in apache/commons-net repository
- **Auth**: Maven settings.xml configured via actions/setup-java with server credentials from GitHub secrets (NEXUS_USER, NEXUS_PW)
- **Confidence**: high
- **Commands**: `mvn --show-version --batch-mode --no-transfer-progress deploy -Dgpg.skip -DskipTests -Drat.skip -Djacoco.skip -Dcyclonedx.skip -Dspotbugs.skip -Dspdx.skip -Dpmd.skip`

### apache/commons-numbers

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`maven.yml`** — Java CI [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds Apache Commons Numbers with Maven across multiple Java versions (8, 11, 17, 21). When running on Java 8 in the apache/commons-numbers repository on the master branch, it deploys SNAPSHOT artifacts to the Apache Snapshots Maven repository (apache.snapshots.https). The deployment uses Maven credentials stored in GitHub secrets and configured via actions/setup-java.
- **Ecosystems**: maven_central
- **Trigger**: push to master branch
- **Auth**: Maven settings.xml configured via actions/setup-java with NEXUS_USER and NEXUS_PW secrets
- **Confidence**: high
- **Commands**: `mvn --show-version --batch-mode --no-transfer-progress deploy -Dgpg.skip -DskipTests -Drat.skip -Djacoco.skip -Dcyclonedx.skip -Dspotbugs.skip -Dspdx.skip -Dpmd.skip`

### apache/cordova-android

**1** release/snapshot workflows | Ecosystems: **apache_dist** | Release Artifacts: 1

**`draft-release.yml`** — Draft Release [Release Artifacts]
- **Summary**: Publishes Apache Cordova Android release artifacts to Apache Trusted Release (ATR) repository. Triggered on draft tags, creates source archives (tar.gz, zip) and npm convenience package (tgz), signs them with GPG, generates SHA512 checksums, and uploads to ATR using OIDC authentication.
- **Ecosystems**: apache_dist
- **Trigger**: push to tags matching 'draft/**'
- **Auth**: OIDC (id-token: write) and GPG signing with secrets.CORDOVA_GPG_SECRET_KEY
- **Confidence**: high
- **GitHub Actions**: `apache/tooling-actions/upload-to-atr@b7e972c11790ee16eca101900af1b3c7fd1b106e`

### apache/cordova-coho

**1** release/snapshot workflows | Ecosystems: **npm** | Snapshot / Nightly Artifacts: 1

**`nightly.yml`** — Cordova Nightly [Snapshot / Nightly Artifacts]
- **Summary**: Publishes nightly builds of 10 Cordova packages (cordova-cli, cordova-lib, cordova-common, cordova-fetch, cordova-serve, cordova-create, cordova-node-xcode, cordova-android, cordova-electron, cordova-ios) to npm with the 'nightly' tag. Runs daily via cron schedule or manual dispatch. Uses coho tool to prepare nightly versions before publishing.
- **Ecosystems**: npm
- **Trigger**: schedule (daily cron) and workflow_dispatch
- **Auth**: NODE_AUTH_TOKEN from secrets.CORDOVA_NPM_TOKEN
- **Confidence**: high
- **Commands**: `npm publish --tag nightly`

### apache/cordova-eslint

**1** release/snapshot workflows | Ecosystems: **apache_dist** | Release Artifacts: 1

**`draft-release.yml`** — Draft Release [Release Artifacts]
- **Summary**: Workflow publishes Apache Cordova release artifacts to Apache Trusted Release (ATR) repository. Triggered by draft tags, it creates source archives (tar.gz, zip) and npm convenience packages (tgz), signs them with GPG, generates SHA512 checksums, and uploads to ATR using OIDC authentication. This is a release artifact workflow for Apache Software Foundation distribution.
- **Ecosystems**: apache_dist
- **Trigger**: push to tags matching 'draft/**'
- **Auth**: OIDC (id-token: write) and GPG signing with secrets.CORDOVA_GPG_SECRET_KEY
- **Confidence**: high
- **GitHub Actions**: `apache/tooling-actions/upload-to-atr@b7e972c11790ee16eca101900af1b3c7fd1b106e`

### apache/cordova-ios

**1** release/snapshot workflows | Ecosystems: **apache_dist** | Release Artifacts: 1

**`draft-release.yml`** — Draft Release [Release Artifacts]
- **Summary**: Workflow publishes Apache Cordova iOS release artifacts to Apache Trusted Release (ATR) repository. Triggered on draft tags, it creates source archives (tar.gz, zip) and npm convenience packages (tgz), signs them with GPG, generates SHA512 checksums, and uploads to ATR using OIDC authentication. This is a release artifact workflow for Apache Software Foundation distribution.
- **Ecosystems**: apache_dist
- **Trigger**: push to tags matching 'draft/**'
- **Auth**: OIDC (id-token: write) and GPG signing with secrets.CORDOVA_GPG_SECRET_KEY
- **Confidence**: high
- **GitHub Actions**: `apache/tooling-actions/upload-to-atr@b7e972c11790ee16eca101900af1b3c7fd1b106e`

### apache/cordova-plugin-camera

**1** release/snapshot workflows | Ecosystems: **apache_dist** | Release Artifacts: 1

**`draft-release.yml`** — Draft Release [Release Artifacts]
- **Summary**: Publishes Apache Cordova plugin release artifacts to Apache Trusted Release (ATR) repository. Triggered by draft/** tags, the workflow creates source archives (tar.gz, zip) and npm convenience packages (tgz), signs them with GPG, generates SHA512 checksums, and uploads to ATR using OIDC authentication. This is a release artifact workflow for Apache Software Foundation distribution.
- **Ecosystems**: apache_dist
- **Trigger**: push to tags matching 'draft/**'
- **Auth**: OIDC (id-token: write) and GPG signing with secrets.CORDOVA_GPG_SECRET_KEY
- **Confidence**: high
- **GitHub Actions**: `apache/tooling-actions/upload-to-atr@b7e972c11790ee16eca101900af1b3c7fd1b106e`

### apache/couchdb-helm

**1** release/snapshot workflows | Ecosystems: **github_pages, helm** | Release Artifacts: 1

**`chart-releaser.yaml`** — Release Charts [Release Artifacts]
- **Summary**: Publishes Helm charts to GitHub Pages (https://apache.github.io/couchdb-helm) on every push to main branch using chart-releaser-action. This is a standard Helm chart release workflow that packages charts and publishes them to a Helm repository hosted on GitHub Pages for end-user consumption.
- **Ecosystems**: helm, github_pages
- **Trigger**: push to main branch
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `./.github/actions/chart-releaser-action`

### apache/couchdb-mochiweb

**1** release/snapshot workflows | Ecosystems: **hex** | Release Artifacts: 1

**`release.yml`** — release.yml [Release Artifacts]
- **Summary**: Publishes Erlang/Elixir package to Hex.pm registry when version tags (v*) are pushed. Uses erlangpack/github-action with HEX_API_KEY authentication.
- **Ecosystems**: hex
- **Trigger**: push to tags matching '*' (filtered to 'refs/tags/v*' in job condition)
- **Auth**: HEX_API_KEY secret passed via env block
- **Confidence**: high
- **GitHub Actions**: `erlangpack/github-action@v3`

### apache/daffodil

**1** release/snapshot workflows | Ecosystems: **apache_dist, maven_central** | Release Artifacts: 1

**`release-candidate.yml`** — Release Candidate [Release Artifacts]
- **Summary**: This workflow builds and publishes Apache Daffodil release candidates when rc tags are pushed. It uses a custom Apache Daffodil infrastructure action to handle the release candidate process, which publishes signed Maven artifacts to Nexus staging repository and uploads binary artifacts (tgz, zip, rpm, exe) to Apache SVN dist. The workflow builds JVM artifacts via sbt publishSigned and creates platform-specific binaries (RPM, Windows installer, universal packages). Publishing is controlled by the 'publish: true' parameter and is disabled for workflow_dispatch triggers.
- **Ecosystems**: maven_central, apache_dist
- **Trigger**: push on tags v*-rc*
- **Auth**: GPG signing key, SVN credentials, Nexus credentials passed to custom action
- **Confidence**: high
- **GitHub Actions**: `apache/daffodil-infrastructure/actions/release-candidate@main`
- **Commands**: `sbt +publishSigned`

### apache/daffodil-sbt

**1** release/snapshot workflows | Ecosystems: **apache_dist, maven_central** | Release Artifacts: 1

**`release-candidate.yml`** — Release Candidate [Release Artifacts]
- **Summary**: Publishes Apache Daffodil SBT Plugin release candidates to Apache SVN dist and Maven staging repository (Nexus). Triggered by rc tags (v*-rc*). Uses custom Apache infrastructure action to handle SVN publishing and sbt publishSigned for Maven artifacts. Includes GPG signing. When triggered via workflow_dispatch, publishing is disabled for testing purposes.
- **Ecosystems**: maven_central, apache_dist
- **Trigger**: push to tags matching 'v*-rc*' or workflow_dispatch
- **Auth**: GPG signing key, SVN credentials, Nexus credentials via secrets
- **Confidence**: high
- **GitHub Actions**: `apache/daffodil-infrastructure/actions/release-candidate@main`
- **Commands**: `sbt ^compile ^publishSigned`

### apache/daffodil-vscode

**1** release/snapshot workflows | Ecosystems: **apache_dist, maven_central** | Release Artifacts: 1

**`release-candidate.yml`** — Release Candidate [Release Artifacts]
- **Summary**: Builds and publishes Apache Daffodil VS Code release candidates to Apache distribution infrastructure (SVN) and Maven/Nexus staging repositories. Triggered by pushing tags matching 'v*-rc*' pattern. Uses a custom Apache Daffodil infrastructure action that handles GPG signing, SVN upload to Apache dist/dev, and Nexus staging. Creates VSIX binary artifacts and copies them to the artifact directory. The publish flag is set to true, enabling actual deployment to registries.
- **Ecosystems**: apache_dist, maven_central
- **Trigger**: push to tags matching 'v*-rc*' or workflow_dispatch
- **Auth**: GPG signing key, SVN credentials, Nexus credentials via secrets
- **Confidence**: high
- **GitHub Actions**: `apache/daffodil-infrastructure/actions/release-candidate@main`

### apache/datafusion-ballista

**1** release/snapshot workflows | Ecosystems: **ghcr** | Release Artifacts: 1

**`docker.yml`** — Docker [Release Artifacts]
- **Summary**: Builds Ballista Docker images (standalone, executor, scheduler) and conditionally publishes them to GHCR when a release tag matching pattern ^[0-9\.]+(-rc[0-9]+)?$ is detected. Publishes both versioned tags and 'latest' tags. These are end-user consumable runtime images for the Apache DataFusion Ballista distributed query engine.
- **Ecosystems**: ghcr
- **Trigger**: pull_request, push
- **Auth**: docker login with github.actor and secrets.GITHUB_TOKEN
- **Confidence**: high
- **Commands**: `docker push ghcr.io/apache/datafusion-ballista-standalone:$DOCKER_TAG`, `docker push ghcr.io/apache/datafusion-ballista-executor:$DOCKER_TAG`, `docker push ghcr.io/apache/datafusion-ballista-scheduler:$DOCKER_TAG`, `docker push ghcr.io/apache/datafusion-ballista-standalone:latest`, `docker push ghcr.io/apache/datafusion-ballista-executor:latest`, `docker push ghcr.io/apache/datafusion-ballista-scheduler:latest`

### apache/datafusion-comet

**1** release/snapshot workflows | Ecosystems: **ghcr** | Release Artifacts: 1

**`docker-publish.yml`** — Publish Docker images [Release Artifacts]
- **Summary**: Publishes versioned Docker images to GitHub Container Registry (ghcr.io) for Apache DataFusion Comet. Triggered by version tags including release candidates. Images are tagged with Spark/Scala version and Comet version extracted from git tags. Builds multi-platform images (amd64/arm64) intended for end-user consumption.
- **Ecosystems**: ghcr
- **Trigger**: push on tags matching version patterns (*.*.*,  *.*.*-rc*, test-docker-publish-*)
- **Auth**: GITHUB_TOKEN with packages:write permission
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v4`, `docker/build-push-action@v7`

### apache/datafusion-ray

**1** release/snapshot workflows | Ecosystems: **ghcr** | Release Artifacts: 1

**`k8s.yml`** — Kubernetes [Release Artifacts]
- **Summary**: Builds and publishes Docker images to GitHub Container Registry (ghcr.io/apache/datafusion-ray) when tags are pushed. The workflow uses docker/metadata-action to generate semantic version tags and SHA-based tags. Images are only pushed to GHCR when the workflow is triggered by a tag (refs/tags/*). The workflow also tests the built image by deploying it to a local Kind Kubernetes cluster with Ray/KubeRay Helm charts and submitting a test job. This is a release artifact workflow as the images are published to a public registry (GHCR) under the Apache organization namespace for end-user consumption of the DataFusion Ray project.
- **Ecosystems**: ghcr
- **Trigger**: workflow_dispatch (manual trigger only; push/pull_request commented out)
- **Auth**: GITHUB_TOKEN via docker/login-action to ghcr.io
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/build-push-action@v6`

### apache/directory-scimple

**2** release/snapshot workflows | Ecosystems: **apache_dist, maven_central** | Release Artifacts: 1, Snapshot / Nightly Artifacts: 1

**`release.yml`** — Release Build [Release Artifacts]
- **Summary**: Apache release workflow that publishes versioned artifacts to Maven Central (via Nexus staging) and Apache distribution SVN repository. Triggered on version tags (v*.**). Performs Maven deploy with apache-release profile, stages to Nexus, and uploads source release zip with signatures to Apache dist SVN (dist.apache.org/repos/dist/dev/directory/scimple). Includes GPG signing and checksum generation (SHA-512, SHA-1, MD5). Generates changelog using JReleaser.
- **Ecosystems**: maven_central, apache_dist
- **Trigger**: push to tags matching v*.**
- **Auth**: Maven server credentials (NEXUS_USERNAME/NEXUS_PASSWORD) and SVN credentials (SVN_USERNAME/SVN_PASSWORD)
- **Confidence**: high
- **Commands**: `./mvnw -V deploy -Papache-release -Pci --threads=1`, `svn commit`

**`snapshot.yml`** — Snapshot Build [Snapshot / Nightly Artifacts]
- **Summary**: This workflow publishes snapshot builds to Apache Maven Snapshots repository. Triggered on pushes to the develop branch, it builds the project with Maven, signs artifacts with GPG, and deploys to the Apache Snapshots repository using Nexus credentials. The workflow also generates a changelog using JReleaser and outputs build summaries.
- **Ecosystems**: maven_central
- **Trigger**: push to develop branch
- **Auth**: Maven server credentials (NEXUS_USERNAME/NEXUS_PASSWORD) configured via setup-java action, GPG signing key for artifact signing
- **Confidence**: high
- **Commands**: `./mvnw -V deploy -Papache-release -Pci --threads=1 -Daether.checksums.algorithms=SHA-512,SHA-1,MD5`

### apache/dolphinscheduler

**2** release/snapshot workflows | Ecosystems: **docker_hub, ghcr, helm, maven_central** | Release Artifacts: 2

**`publish-docker.yaml`** — publish-docker [Release Artifacts]
- **Summary**: Publishes Docker images to Docker Hub (apache organization) and Maven artifacts. Triggered on push to dev branch (publishes 'dev' tag) and on release events (publishes versioned tag). Uses Maven deploy goal with docker profile to build and push multi-architecture images. Authenticates to Docker Hub using organization secrets.
- **Ecosystems**: docker_hub, maven_central
- **Trigger**: push to dev branch, release published
- **Auth**: Docker Hub credentials via secrets (DOCKERHUB_USER, DOCKERHUB_TOKEN)
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`
- **Commands**: `./mvnw -B clean deploy -Dmaven.test.skip -Dspotless.skip=true -Ddocker.tag=${{ env.DOCKER_TAG }} -Ddocker.hub=${{ env.HUB }} -Pdocker,release`

**`publish-helm-chart.yaml`** — publish-helm-chart [Release Artifacts]
- **Summary**: Publishes Helm charts to OCI registries. On release events, pushes versioned charts to Docker Hub (registry-1.docker.io/apache). On dev branch pushes, publishes snapshot charts with git SHA version (0.0.0-<sha>) to GHCR (ghcr.io/apache/dolphinscheduler). Uses helm push to OCI-compatible registries.
- **Ecosystems**: helm, docker_hub, ghcr
- **Trigger**: push to dev branch OR release published
- **Auth**: Docker Hub credentials (secrets.DOCKERHUB_USER/TOKEN) for releases, GitHub token for dev branch
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v2`
- **Commands**: `helm push dolphinscheduler-helm-*.tgz oci://${{ env.HUB }}`

### apache/doris-opentelemetry-demo

**3** release/snapshot workflows | Ecosystems: **docker_hub, ghcr** | Release Artifacts: 2, Snapshot / Nightly Artifacts: 1

**`component-build-images.yml`** — component-build-images.yml [Release Artifacts]
- **Summary**: Reusable workflow that builds and publishes multi-component Docker images for the OpenTelemetry demo application to both Docker Hub (otel/demo) and GitHub Container Registry (ghcr.io/open-telemetry/demo). Builds 20 different service images across multiple platforms (amd64/arm64) with version-specific and 'latest' tags. Publishing is controlled by the 'push' input parameter. This is a release artifact workflow as it publishes versioned demo application components to public registries for end-user consumption.
- **Ecosystems**: docker_hub, ghcr
- **Trigger**: workflow_call
- **Auth**: GITHUB_TOKEN for GHCR, DOCKER_USERNAME/DOCKER_PASSWORD secrets for Docker Hub
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/build-push-action@v6.15.0`

**`release.yml`** — Build and Publish [Release Artifacts]
- **Summary**: Release workflow triggered on GitHub release publication. Calls reusable workflow component-build-images.yml with push: true and the release tag name. The reusable workflow likely builds and publishes Docker images to registries (typically Docker Hub and GHCR for OpenTelemetry projects). Secrets are inherited by the called workflow for authentication. Repository guard ensures it only runs on the canonical open-telemetry/opentelemetry-demo repository.
- **Ecosystems**: docker_hub, ghcr
- **Trigger**: release (published)
- **Auth**: secrets inherited from reusable workflow
- **Confidence**: high

**`nightly-release.yml`** — Nightly Release [Snapshot / Nightly Artifacts]
- **Summary**: Scheduled nightly workflow that builds and pushes Docker images with nightly version tags. Delegates to reusable workflow component-build-images.yml with push: true. The 'nightly-' prefix and daily cron schedule indicate this publishes snapshot/nightly artifacts rather than stable releases. Likely publishes to Docker Hub and/or GHCR based on OpenTelemetry project conventions.
- **Ecosystems**: docker_hub, ghcr
- **Trigger**: schedule (cron: '0 0 * * *')
- **Auth**: secrets inherited from reusable workflow
- **Confidence**: high

### apache/doris-operator

**2** release/snapshot workflows | Ecosystems: **docker_hub, helm** | Release Artifacts: 2

**`docker_action.yaml`** — docker [Release Artifacts]
- **Summary**: Publishes two Docker images (selectdb/doris.k8s-operator and selectdb/doris-debug-ubuntu) to Docker Hub when semantic version tags are pushed. Builds multi-platform images (linux/amd64, linux/arm64) using docker/build-push-action with push: true.
- **Ecosystems**: docker_hub
- **Trigger**: push to tags matching *.*.*
- **Auth**: Docker Hub username/password via secrets.DOCKERHUB_USERNAME and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/build-push-action@v5`

**`helm-release.yaml`** — Release Charts [Release Artifacts]
- **Summary**: Publishes Helm charts to Alibaba Cloud OSS (Object Storage Service) at oss://selectdb-charts when version tags are pushed. Packages two charts (doris and doris-operator), generates Helm repository index, and uploads to OSS using ossutil CLI. This is a public Helm chart repository accessible at https://charts.selectdb.com for end-user consumption.
- **Ecosystems**: helm
- **Trigger**: push to tags matching *.*.*
- **Auth**: OSS credentials (secrets.OSS_KEY_ID, secrets.OSS_KEY_SECRET)
- **Confidence**: high
- **GitHub Actions**: `manyuanrong/setup-ossutil@v2.0`
- **Commands**: `helm package doris -d package`, `helm package doris-operator -d package`, `helm repo index ./package --url https://charts.selectdb.com --merge ./index.yaml`, `ossutil cp helm-charts/package oss://selectdb-charts -rf`

### apache/doris-thirdparty

**7** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 2, Snapshot / Nightly Artifacts: 5

**`build-2.0.yml`** — Build (2.0) [Release Artifacts]
- **Summary**: This workflow builds and publishes Apache Doris third-party prebuilt binaries to GitHub Releases. It runs on a schedule (every 30 minutes), checks for changes in the thirdparty directory of apache/doris branch-2.0, and if changes are detected, builds binaries for macOS (x86_64 and arm64) and Linux. The workflow uploads source archives and platform-specific prebuilt binaries (tar.xz files) to a GitHub Release tagged 'automation-2.0'. These are release artifacts intended for end-user consumption as dependencies for building Apache Doris.
- **Ecosystems**: github_releases
- **Trigger**: schedule (every 30 minutes)
- **Auth**: GITHUB_TOKEN with contents: write permission
- **Confidence**: high
- **Commands**: `gh release upload --clobber "${tag_name}" doris-thirdparty-source.tgz`, `gh release upload --clobber "${tag_name}" "doris-thirdparty-prebuilt-${kernel}-${arch}.tar.xz"`

**`manual-build.yml`** — Manual Build [Release Artifacts]
- **Summary**: This workflow builds Apache Doris third-party dependencies for multiple platforms (macOS x86_64, macOS arm64, Linux) and publishes prebuilt artifacts to GitHub Releases. It creates/updates a release tagged 'automation', uploads source tarballs and platform-specific prebuilt binaries (.tar.xz files), and updates release notes with build status and SHA256 checksums. The workflow is manually triggered with an optional doris_ref input to specify which branch/tag/commit to build from.
- **Ecosystems**: github_releases
- **Trigger**: workflow_dispatch
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **Commands**: `gh release create -t 'Apache Doris Third Party Prebuilt' automation`, `gh release upload --clobber automation doris-thirdparty-source.tgz`, `gh release upload --clobber automation "doris-thirdparty-prebuilt-${kernel}-${arch}.tar.xz"`

**`build-1.2.yml`** — Build (1.2-lts) [Snapshot / Nightly Artifacts]
- **Summary**: Automated workflow that runs every 30 minutes to check for changes in the apache/doris thirdparty directory. When changes are detected, it downloads third-party source code, builds prebuilt binaries for macOS (x86_64 and arm64) and Linux, and uploads them to a GitHub Release tagged 'automation-1.2-lts'. The release notes are dynamically updated with build status and SHA256 checksums. This is a snapshot/nightly build system for third-party dependencies, not a versioned release for end users.
- **Ecosystems**: github_releases
- **Trigger**: schedule (cron: '*/30 * * * *')
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **Commands**: `gh release create`, `gh release upload --clobber`, `gh release edit`

**`build-2.1.yml`** — Build (2.1) [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds Apache Doris third-party dependencies on a schedule (every 30 minutes) and publishes prebuilt binaries to GitHub Releases. It checks for changes in the thirdparty/ directory of the apache/doris repository (branch-2.1), downloads source dependencies, builds them for Linux (x86_64), macOS (x86_64), and macOS (arm64), then uploads the resulting tar.xz archives to a GitHub release tagged 'automation-2.1'. This is a snapshot/nightly build workflow that provides prebuilt dependencies for CI/development use rather than end-user consumption.
- **Ecosystems**: github_releases
- **Trigger**: schedule (every 30 minutes)
- **Auth**: GITHUB_TOKEN with contents: write permission
- **Confidence**: high
- **Commands**: `gh release create`, `gh release upload --clobber`, `gh release edit`

**`build-3.0.yml`** — Build (3.0) [Snapshot / Nightly Artifacts]
- **Summary**: Automated workflow that runs every 30 minutes to build Apache Doris third-party dependencies for multiple platforms (macOS x86_64, macOS arm64, Linux). It checks for changes in the thirdparty/ directory of the apache/doris repository (branch-3.0), downloads source code, builds prebuilt binaries, and uploads them to a GitHub release tagged 'automation-3.0'. The workflow creates tar.xz archives of compiled dependencies for each platform and updates release notes with build status and SHA256 checksums. This is a snapshot/nightly build system for CI infrastructure dependencies.
- **Ecosystems**: github_releases
- **Trigger**: schedule (every 30 minutes)
- **Auth**: GITHUB_TOKEN with contents: write permission
- **Confidence**: high
- **Commands**: `gh release create`, `gh release upload --clobber`, `gh release edit`

**`build-3.1.yml`** — Build (3.1) [Snapshot / Nightly Artifacts]
- **Summary**: Automated workflow that builds Apache Doris third-party dependencies for multiple platforms (macOS x86_64, macOS arm64, Linux) and publishes prebuilt binaries to GitHub Releases. Runs every 30 minutes, checks for changes in the thirdparty directory of apache/doris branch-3.1, downloads source dependencies, builds them, and uploads platform-specific tarballs (doris-thirdparty-prebuilt-{kernel}-{arch}.tar.xz) to a GitHub release tagged 'automation-3.1'. This is a snapshot/nightly build workflow for CI acceleration and developer convenience.
- **Ecosystems**: github_releases
- **Trigger**: schedule (every 30 minutes)
- **Auth**: GITHUB_TOKEN with contents: write permission
- **Confidence**: high
- **Commands**: `gh release create`, `gh release upload --clobber`, `gh release edit`

**`build.yml`** — Build [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds Apache Doris third-party dependencies on a schedule (every 30 minutes). It checks for changes in the thirdparty directory of the apache/doris repository, and if changes are detected, builds prebuilt binaries for macOS (x86_64 and arm64) and Linux. The artifacts (source tarball and prebuilt binaries) are uploaded to a GitHub Release tagged 'automation'. This is a snapshot/nightly build pattern for CI infrastructure dependencies, not end-user release artifacts.
- **Ecosystems**: github_releases
- **Trigger**: schedule (every 30 minutes)
- **Auth**: GITHUB_TOKEN with contents: write permission
- **Confidence**: high
- **Commands**: `gh release upload --clobber automation doris-thirdparty-source.tgz`, `gh release upload --clobber automation doris-thirdparty-prebuilt-${kernel}-${arch}.tar.xz`

### apache/drill

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`publish-snapshot.yml`** — Publish snapshot artifacts [Snapshot / Nightly Artifacts]
- **Summary**: Publishes Maven snapshot artifacts to Apache Snapshots repository on every push to master branch. Uses Maven deploy goal with credentials from GitHub secrets to authenticate to apache.snapshots.https repository. Secrets are passed through env variables but then directly interpolated in shell command to construct settings.xml.
- **Ecosystems**: maven_central
- **Trigger**: push to master branch
- **Auth**: Maven settings.xml with ASF_USERNAME and ASF_PASSWORD from GitHub secrets
- **Confidence**: high
- **Commands**: `mvn --settings settings.xml -U -B -e -fae -ntp -DskipTests deploy`

### apache/dubbo-admin

**1** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 1

**`release.yaml`** — dubboctl Release [Release Artifacts]
- **Summary**: This workflow publishes release artifacts to GitHub Releases. Triggered by version tags (v*), it creates a GitHub Release and uploads compiled Go binaries (dubboctl and dubbo-cp) for multiple OS/architecture combinations (Linux, macOS, Windows across 386, amd64, arm64). The binaries are packaged as tar.gz or zip files and attached as downloadable release assets. This is a standard release artifact publishing workflow for distributing end-user binaries.
- **Ecosystems**: github_releases
- **Trigger**: push to tags matching 'v*'
- **Auth**: GITHUB_TOKEN (automatic)
- **Confidence**: high
- **GitHub Actions**: `actions/create-release@v1`, `actions/upload-release-asset@v1`

### apache/dubbo-go-pixiu

**1** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: Publishes Go binary artifacts (dubbo-go-pixiu) to GitHub Releases for multiple OS/architecture combinations (linux/386, linux/amd64, linux/arm64, windows/386, windows/amd64, darwin/amd64, darwin/arm64) when a GitHub release is created. Uses go-release-action to build and attach binaries with LICENSE and README files.
- **Ecosystems**: github_releases
- **Trigger**: release (types: created)
- **Auth**: GITHUB_TOKEN (secrets)
- **Confidence**: high
- **GitHub Actions**: `wangyoucao577/go-release-action@v1`

### apache/dubbo-go-pixiu-samples

**1** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: Publishes Go binary artifacts (dubbo-go-pixiu) to GitHub Releases for multiple OS/architecture combinations (linux, windows, darwin with 386, amd64, arm64 variants). Triggered on release creation events. Uses wangyoucao577/go-release-action to build and attach binaries to the GitHub Release.
- **Ecosystems**: github_releases
- **Trigger**: release.created
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `wangyoucao577/go-release-action@v1`

### apache/dubbo-initializer

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Snapshot / Nightly Artifacts: 1

**`deploy.yml`** — Deploy Docker [Snapshot / Nightly Artifacts]
- **Summary**: Publishes a Docker image tagged 'apache/dubbo-initializer:dev' to Docker Hub on a schedule (every 6 hours) and on pushes to main branch. This is a snapshot/nightly build workflow as indicated by the 'dev' tag and scheduled trigger pattern, not a versioned release.
- **Ecosystems**: docker_hub
- **Trigger**: schedule (cron: 0 0/6 * * *) and push to main branch
- **Auth**: Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v2`, `docker/build-push-action@v2`

### apache/dubbo-kubernetes

**1** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 1

**`release.yaml`** — Dubbo Kubernetes Release [Release Artifacts]
- **Summary**: Creates GitHub releases with downloadable binary artifacts for dubboctl and dubbo tools. Triggered on semantic version tags, builds Go binaries for multiple OS/architecture combinations (linux/darwin/windows × 386/amd64/arm64), packages them with documentation and samples, and uploads as release assets to GitHub Releases.
- **Ecosystems**: github_releases
- **Trigger**: push to tags matching '[0-9]+.[0-9]+.[0-9]+'
- **Auth**: GITHUB_TOKEN (automatic)
- **Confidence**: high
- **GitHub Actions**: `actions/create-release@v1`, `actions/upload-release-asset@v1`

### apache/echarts

**2** release/snapshot workflows | Ecosystems: **npm** | Snapshot / Nightly Artifacts: 2

**`nightly-next.yml`** — Publish Nightly Next [Snapshot / Nightly Artifacts]
- **Summary**: Publishes nightly snapshot builds of Apache ECharts to npm with the 'next' tag. Runs on a daily schedule after zrender nightly is published, or can be manually triggered. Uses the 'next' branch and publishes to npm registry with NODE_AUTH_TOKEN authentication.
- **Ecosystems**: npm
- **Trigger**: schedule (cron: '10 9 * * *'), workflow_dispatch, repository_dispatch
- **Auth**: NODE_AUTH_TOKEN secret
- **Confidence**: high
- **Commands**: `npm publish --tag next`

**`nightly.yml`** — Publish Nightly [Snapshot / Nightly Artifacts]
- **Summary**: Publishes nightly builds of Apache ECharts to npm registry. Runs on a daily schedule (9:00 UTC), can be manually triggered by committers, or triggered via repository_dispatch. Uses zrender-nightly dependency and publishes after running tests.
- **Ecosystems**: npm
- **Trigger**: schedule (cron: 0 9 * * *), workflow_dispatch, repository_dispatch
- **Auth**: NODE_AUTH_TOKEN secret
- **Confidence**: high
- **Commands**: `npm publish`

### apache/echarts-examples

**1** release/snapshot workflows | Ecosystems: **npm** | Snapshot / Nightly Artifacts: 1

**`sync-nightly-mirror.yaml`** — Synchronize Nightly Mirror [Snapshot / Nightly Artifacts]
- **Summary**: This workflow publishes nightly snapshot builds of zrender-nightly and echarts-nightly packages to npm registry. It runs daily via cron schedule (9:30 UTC) and can be manually triggered. The sync-nightly-mirror.js script handles the publishing logic, with actions/setup-node providing npm registry authentication.
- **Ecosystems**: npm
- **Trigger**: schedule (cron: 30 9 * * *) and workflow_dispatch
- **Auth**: registry-url configured in actions/setup-node (likely uses NODE_AUTH_TOKEN secret)
- **Confidence**: high
- **Commands**: `node --unhandled-rejections=strict sync-nightly-mirror.js zrender-nightly`, `node --unhandled-rejections=strict sync-nightly-mirror.js echarts-nightly`

### apache/eventmesh

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`docker.yml`** — Docker [Release Artifacts]
- **Summary**: Publishes Apache EventMesh Docker images to Docker Hub (apache/eventmesh) when a GitHub release is published. Uses docker/build-push-action with push: true to deploy versioned release images based on tags generated from release metadata.
- **Ecosystems**: docker_hub
- **Trigger**: release (types: [released])
- **Auth**: DockerHub username/password via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/build-push-action@v6`

### apache/eventmesh-dashboard

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`docker.yml`** — Docker [Release Artifacts]
- **Summary**: Publishes Docker images to Docker Hub (apache/eventmesh-dashboard) when version tags (v*) are pushed. Uses docker/build-push-action with push: true to publish release artifacts.
- **Ecosystems**: docker_hub
- **Trigger**: push to tags matching 'v*'
- **Auth**: DockerHub username/password via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/build-push-action@v5`

### apache/fineract

**2** release/snapshot workflows | Ecosystems: **docker_hub, maven_central** | Release Artifacts: 1, Snapshot / Nightly Artifacts: 1

**`publish-dockerhub.yml`** — Fineract Publish to DockerHub [Release Artifacts]
- **Summary**: Publishes Apache Fineract Docker images to Docker Hub using Gradle Jib plugin. Triggered on pushes to develop branch (tagged with branch name and git hashes) and on version tags matching 1.* pattern (tagged with version number). Builds multi-platform images for linux/amd64 and linux/arm64.
- **Ecosystems**: docker_hub
- **Trigger**: push to develop branch or tags matching 1.*
- **Auth**: DOCKERHUB_USER and DOCKERHUB_TOKEN secrets
- **Confidence**: high
- **Commands**: `./gradlew --no-daemon --console=plain :fineract-provider:jib -x test -x cucumber -Djib.to.auth.username=${{secrets.DOCKERHUB_USER}} -Djib.to.auth.password=${{secrets.DOCKERHUB_TOKEN}} -Djib.from.platforms=linux/amd64,linux/arm64 -Djib.to.image=apache/fineract -Djib.to.tags=$TAGS`

**`mifos-fineract-client-publish.yml`** — Publish Fineract client to Mifos Artifactory [Snapshot / Nightly Artifacts]
- **Summary**: Publishes Fineract client library to Mifos Artifactory (Maven repository) on pushes to develop-mifos branch. Uses Gradle publish task with dynamically generated build numbers. Credentials are passed from GitHub secrets through environment variables to Gradle properties.
- **Ecosystems**: maven_central
- **Trigger**: push to develop-mifos branch
- **Auth**: Username/password credentials stored in GitHub secrets (ARTIFACTORY_USERNAME, ARTIFACTORY_PASSWORD)
- **Confidence**: high
- **Commands**: `./gradlew publish -Pfineract.config.username=$ARTIFACTORY_USERNAME -Pfineract.config.password=$ARTIFACTORY_PASSWORD -Pfineract.release.version=${BUILD_NUMBER}`

### apache/flink-docker

**1** release/snapshot workflows | Ecosystems: **ghcr** | Snapshot / Nightly Artifacts: 1

**`snapshot.yml`** — Publish SNAPSHOTs [Snapshot / Nightly Artifacts]
- **Summary**: This workflow publishes nightly snapshot Docker images of Apache Flink to GitHub Container Registry (ghcr.io). It runs daily via cron schedule and builds multi-platform images for various Java versions (8, 11, 17, 21) and Flink SNAPSHOT versions (2.2, 2.1, 2.0, 1.20). Images are tagged with version identifiers like '2.2-SNAPSHOT-scala_2.12-java11-debian' and pushed to ghcr.io/apache/flink-docker. The workflow uses docker/bake-action for building and pushing, authenticates with GITHUB_TOKEN, and is restricted to the apache organization.
- **Ecosystems**: ghcr
- **Trigger**: schedule (daily cron) and workflow_dispatch
- **Auth**: GITHUB_TOKEN with packages: write permission
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`, `docker/bake-action@v4`

### apache/flink-kubernetes-operator

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`publish_snapshot.yml`** — Publish Snapshot [Snapshot / Nightly Artifacts]
- **Summary**: Publishes nightly snapshot builds of Apache Flink Kubernetes Operator to Apache Maven Snapshots repository. Runs daily via cron schedule and can be manually triggered. Uses Maven deploy with apache-release profile to push to apache.snapshots.https repository.
- **Ecosystems**: maven_central
- **Trigger**: schedule (daily cron) and workflow_dispatch
- **Auth**: Maven settings.xml with ASF_USERNAME and ASF_PASSWORD from GitHub secrets
- **Confidence**: high
- **Commands**: `mvn -B --settings $tmp_settings clean deploy -Dgpg.skip -Drat.skip -DskipTests -Papache-release`

### apache/fluss-rust

**2** release/snapshot workflows | Ecosystems: **crates_io, pypi** | Release Artifacts: 2

**`release_python.yml`** — Release Python [Release Artifacts]
- **Summary**: Publishes Python wheels and sdist for fluss Python bindings to PyPI on version tag push. Pre-release versions (tags containing '-') are published to TestPyPI, while release versions go to production PyPI. Builds wheels for multiple platforms (Windows, macOS x86_64/aarch64, Linux x86_64/aarch64) and Python versions (3.9-3.12) using maturin. Includes version verification step before publishing.
- **Ecosystems**: pypi
- **Trigger**: push tags matching 'v*' pattern
- **Auth**: API token via secrets.PYPI_API_TOKEN and secrets.TEST_PYPI_API_TOKEN
- **Confidence**: high
- **GitHub Actions**: `pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e`

**`release_rust.yml`** — Release Rust [Release Artifacts]
- **Summary**: Publishes the fluss-rs Rust crate to crates.io when a release version tag (v*) is pushed, excluding pre-release tags containing '-'. Uses cargo publish with CARGO_REGISTRY_TOKEN for authentication.
- **Ecosystems**: crates_io
- **Trigger**: push to version tags (v*), excluding pre-release tags containing '-'
- **Auth**: CARGO_REGISTRY_TOKEN secret
- **Confidence**: high
- **Commands**: `cargo publish -p fluss-rs`

### apache/fory

**4** release/snapshot workflows | Ecosystems: **crates_io, maven_central, pypi** | Release Artifacts: 3, Snapshot / Nightly Artifacts: 1

**`release-compiler.yaml`** — Publish Compiler [Release Artifacts]
- **Summary**: Publishes Python compiler package to PyPI on version tags. Tags containing '-' are published to TestPyPI (pre-releases), while clean version tags go to production PyPI. Uses OIDC Trusted Publishing for authentication.
- **Ecosystems**: pypi
- **Trigger**: push to tags matching 'v*'
- **Auth**: OIDC (id-token: write permission for Trusted Publishing)
- **Confidence**: high
- **GitHub Actions**: `pypa/gh-action-pypi-publish@release/v1`

**`release-python.yaml`** — Publish Python [Release Artifacts]
- **Summary**: Publishes Python wheels to PyPI and TestPyPI. Triggered by completion of wheel build workflows. Downloads wheel artifacts from the triggering workflow run, then publishes to TestPyPI for release candidate branches (v*-*) or to PyPI for release branches (v* without hyphen). Uses OIDC Trusted Publishing for secure authentication.
- **Ecosystems**: pypi
- **Trigger**: workflow_run on completion of wheel build workflows
- **Auth**: OIDC (id-token: write permission for Trusted Publishing)
- **Confidence**: high
- **GitHub Actions**: `pypa/gh-action-pypi-publish@release/v1`

**`release-rust.yaml`** — Publish Rust [Release Artifacts]
- **Summary**: Publishes three Rust crates (fory-core, fory-derive, fory) to crates.io when version tags (v*) are pushed. Uses OIDC authentication via rust-lang/crates-io-auth-action. Bumps version numbers before publishing with --allow-dirty flag. Restricted to apache/fory repository.
- **Ecosystems**: crates_io
- **Trigger**: push to tags matching 'v*'
- **Auth**: OIDC via rust-lang/crates-io-auth-action with id-token: write permission
- **Confidence**: high
- **GitHub Actions**: `rust-lang/crates-io-auth-action@b7e9a28eded4986ec6b1fa40eeee8f8f165559ec`
- **Commands**: `cargo publish -p fory-core --allow-dirty`, `cargo publish -p fory-derive --allow-dirty`, `cargo publish -p fory --allow-dirty`

**`release-java-snapshot.yaml`** — Publish Fory Java Snapshot [Snapshot / Nightly Artifacts]
- **Summary**: Publishes Java snapshot artifacts to Apache Snapshots Maven repository on pushes to main or release-java-snapshot branches. Uses Maven with credentials for apache.snapshots.https server-id, executing a Python CI script with --release flag to perform the deployment.
- **Ecosystems**: maven_central
- **Trigger**: push to main or release-java-snapshot branches
- **Auth**: Maven server credentials (NEXUS_USERNAME/NEXUS_PASSWORD) configured via actions/setup-java with server-id apache.snapshots.https
- **Confidence**: high
- **GitHub Actions**: `actions/setup-java@v4`
- **Commands**: `python ./ci/run_ci.py java --version 11 --release`

### apache/gluten

**1** release/snapshot workflows | Ecosystems: **apache_dist** | Snapshot / Nightly Artifacts: 1

**`velox_nightly.yml`** — Velox backend nightly release [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds nightly snapshot releases of Apache Gluten Velox backend bundles for multiple JDK versions (8, 17, 21) and architectures (x86, ARM64). It compiles native libraries, packages them with Maven, and uploads the resulting JAR artifacts to Apache's nightly distribution server (nightly.apache.org) via rsync. The workflow runs on a daily schedule and publishes to paths like /gluten/nightly-release-jdk8, /gluten/nightly-release-jdk17, /gluten/nightly-release-jdk21, and /gluten/nightly-release-jdk17-enhanced.
- **Ecosystems**: apache_dist
- **Trigger**: schedule (nightly cron: '0 0 * * *') and push to main branch
- **Auth**: SSH key authentication via secrets.NIGHTLIES_RSYNC_KEY
- **Confidence**: high
- **GitHub Actions**: `burnett01/rsync-deployments@0dc935cdecc5f5e571865e60d2a6cdc673704823`

### apache/gobblin

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`docker_build_publish.yaml`** — Build and Publish Docker image [Release Artifacts]
- **Summary**: Builds Apache Gobblin Docker images and publishes them to DockerHub (apache/gobblin) on release events. Images are tagged with SHA, release tag name, and 'latest'. Pull requests and pushes to master only build images without publishing.
- **Ecosystems**: docker_hub
- **Trigger**: release (types: published, edited)
- **Auth**: DOCKERHUB_USER and DOCKERHUB_TOKEN secrets
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v1`, `docker/build-push-action@v2`

### apache/grails-core

**7** release/snapshot workflows | Ecosystems: **apache_dist, gcr, github_releases, maven_central** | Release Artifacts: 2, Snapshot / Nightly Artifacts: 5

**`forge-deploy-release.yml`** — Forge - Release GCP Deploy [Release Artifacts]
- **Summary**: Workflow builds Docker native images for Grails Forge application and analytics service, pushes them to Google Cloud Artifact Registry (us-docker.pkg.dev), and deploys to Google Cloud Run. Triggered manually with a release version input. Two separate Docker images are published: main application and analytics service, both tagged with the release version and deployed to versioned Cloud Run services.
- **Ecosystems**: gcr
- **Trigger**: workflow_dispatch with release version input
- **Auth**: GCP service account credentials via secrets.GCP_CREDENTIALS
- **Confidence**: high
- **Commands**: `docker push ${{ env.IMAGE_NAME }}`, `gcloud run deploy`

**`release.yml`** — Release [Release Artifacts]
- **Summary**: Apache Grails release workflow that publishes versioned release artifacts to Maven Central (via Nexus staging), GitHub Releases (signed binaries and source distributions), and Apache dist.apache.org. Triggered on GitHub release publication. Includes multi-stage process: (1) publish JARs to Nexus staging repository, (2) create and upload signed source/binary distributions to GitHub Releases, (3) upload distributions to Apache SVN dev area, (4) manual vote confirmation, (5) manual promotion to Maven Central and Apache release area, (6) documentation publishing, (7) SDKMAN release. Uses environment protection for release-critical steps.
- **Ecosystems**: maven_central, github_releases, apache_dist
- **Trigger**: release published
- **Auth**: secrets (NEXUS_STAGE_DEPLOYER_USER, NEXUS_STAGE_DEPLOYER_PW, GPG_KEY_ID, GRAILS_GPG_KEY, SVC_DIST_GRAILS_USERNAME, SVC_DIST_GRAILS_PASSWORD)
- **Confidence**: high
- **GitHub Actions**: `softprops/action-gh-release@v2.6.1`
- **Commands**: `./gradlew initializeSonatypeStagingRepository`, `./gradlew publishToSonatype aggregateChecksums aggregatePublishedArtifacts`, `./gradlew closeSonatypeStagingRepository`, `svn commit -m "Upload ${PROJECT_NAME} distribution files for ${VERSION}"`, `.github/scripts/releaseJarFiles.sh`, `.github/scripts/releaseDistributions.sh`

**`forge-deploy-next.yml`** — Forge - Next GCP Deploy [Snapshot / Nightly Artifacts]
- **Summary**: Builds and deploys snapshot Docker images (tagged 'next') to Google Artifact Registry (us-docker.pkg.dev) and Google Cloud Run. Two separate images are deployed: the main grails-forge-web-netty application and grails-forge-analytics-postgres. These are snapshot/nightly builds for the 'next' environment (next.grails.org), not production releases. Uses GraalVM native image compilation.
- **Ecosystems**: gcr
- **Trigger**: workflow_dispatch
- **Auth**: GCP service account credentials via secrets.GCP_CREDENTIALS
- **Confidence**: high
- **Commands**: `docker push ${{ env.IMAGE_NAME }}`, `gcloud run deploy`

**`forge-deploy-prev-snapshot.yml`** — Forge - Prev Snapshot GCP Deploy [Snapshot / Nightly Artifacts]
- **Summary**: Builds and deploys snapshot Docker images (prev-snapshot tag) of Grails Forge application and analytics service to Google Cloud Artifact Registry (us-docker.pkg.dev) and Google Cloud Run. Two separate images are built using GraalVM native compilation: the main web application and an analytics service. Both are deployed to Cloud Run with environment-specific configuration.
- **Ecosystems**: gcr
- **Trigger**: workflow_dispatch
- **Auth**: GCP service account credentials via secrets.GCP_CREDENTIALS
- **Confidence**: high
- **Commands**: `docker push ${{ env.IMAGE_NAME }}`, `gcloud run deploy`

**`forge-deploy-prev.yml`** — Forge - Prev GCP Deploy [Snapshot / Nightly Artifacts]
- **Summary**: Workflow builds and deploys two Docker images (grails-forge-web-netty and grails-forge-analytics-postgres) to Google Cloud Artifact Registry (us-docker.pkg.dev) with 'prev' tag, then deploys them to Google Cloud Run. This is a snapshot/preview deployment triggered manually via workflow_dispatch, not a versioned release to a public registry for end-user consumption.
- **Ecosystems**: gcr
- **Trigger**: workflow_dispatch
- **Auth**: GCP service account credentials via secrets.GCP_CREDENTIALS
- **Confidence**: high
- **Commands**: `docker push ${{ env.IMAGE_NAME }}`, `gcloud run deploy`

**`forge-deploy-snapshot.yml`** — Forge - Snapshot GCP Deploy [Snapshot / Nightly Artifacts]
- **Summary**: Builds Grails Forge application and analytics service as Docker native images, pushes them to Google Cloud Artifact Registry (us-docker.pkg.dev) with 'snapshot' tags, and deploys to Google Cloud Run. Two separate deployments: main forge application and analytics service. This is a snapshot deployment workflow triggered manually for pre-release/development versions.
- **Ecosystems**: gcr
- **Trigger**: workflow_dispatch
- **Auth**: GCP service account credentials via secrets.GCP_CREDENTIALS
- **Confidence**: high
- **Commands**: `docker push ${{ env.IMAGE_NAME }}`, `gcloud run deploy`

**`gradle.yml`** — CI [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds and tests Grails Core across multiple Java versions and platforms, then publishes snapshot artifacts to Apache Nexus snapshot repository. Three separate publish jobs handle grails-gradle, grails-core, and grails-forge components. Publishing is triggered only on push to version branches or workflow_dispatch, and only when running in the apache organization. The workflow also builds documentation and deploys it to GitHub Pages (apache/grails-website repository). Artifacts are uploaded to GitHub Actions for workflow summary pages but these are ephemeral CI storage, not registry publishing.
- **Ecosystems**: maven_central
- **Trigger**: push to version branches ([0-9]+.[0-9]+.x) or workflow_dispatch
- **Auth**: Username/password credentials stored in GitHub secrets (NEXUS_USER, NEXUS_PW)
- **Confidence**: high
- **Commands**: `./gradlew publish aggregateChecksums aggregatePublishedArtifacts`, `./gradlew publish aggregateChecksums aggregatePublishedArtifacts`

### apache/grails-forge-ui

**1** release/snapshot workflows | Ecosystems: **github_releases** | Release Artifacts: 1

**`publish.yml`** — Publish [Release Artifacts]
- **Summary**: Workflow publishes Grails Forge UI artifacts on push to main branch. Executes ./publish.sh script with GITHUB_TOKEN authentication. The script name and environment variables (GITHUB_SLUG, GH_TOKEN) suggest publishing to GitHub infrastructure (likely GitHub Releases or GitHub Packages). Classified as release_artifact based on trigger (main branch push) and naming convention indicating production releases rather than CI infrastructure or snapshots.
- **Ecosystems**: github_releases
- **Trigger**: push to main branch
- **Auth**: GITHUB_TOKEN secret
- **Confidence**: medium
- **Commands**: `./publish.sh`

### apache/grails-github-actions

**1** release/snapshot workflows | Ecosystems: **apache_dist, github_releases** | Release Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes Apache Grails GitHub Actions release artifacts to Apache's official distribution system (dist.apache.org) and GitHub Releases. Triggered on release publication, it: (1) runs tests, (2) creates signed source distribution ZIP with checksums, (3) uploads artifacts to GitHub Releases, (4) publishes to Apache SVN dev repository at dist.apache.org/repos/dist/dev/grails/actions, and (5) provides manual steps for PMC vote completion and final promotion to Apache release repository. The workflow follows Apache Software Foundation release procedures including GPG signing and checksum generation.
- **Ecosystems**: apache_dist, github_releases
- **Trigger**: release published
- **Auth**: SVN credentials (secrets.SVC_DIST_GRAILS_USERNAME, secrets.SVC_DIST_GRAILS_PASSWORD), GPG signing (secrets.GRAILS_GPG_KEY, secrets.GPG_KEY_ID), GitHub token
- **Confidence**: high
- **GitHub Actions**: `softprops/action-gh-release@v2`
- **Commands**: `svn commit -m "Upload ${PROJECT_NAME} distribution files for ${VERSION}"`

### apache/grails-gradle-publish

**2** release/snapshot workflows | Ecosystems: **apache_dist, github_pages, github_releases, maven_central** | Release Artifacts: 1, Snapshot / Nightly Artifacts: 1

**`release.yaml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes the Grails Publish Gradle Plugin release artifacts to multiple registries: (1) Maven artifacts to Sonatype/Nexus staging repository (Maven Central), (2) signed source distributions to Apache dist.apache.org via SVN, (3) release assets to GitHub Releases, and (4) documentation to GitHub Pages. The workflow is triggered on release publication and includes manual approval steps for final promotion after PMC vote.
- **Ecosystems**: maven_central, apache_dist, github_releases, github_pages
- **Trigger**: release.published
- **Auth**: secrets (NEXUS_STAGE_DEPLOYER_USER, NEXUS_STAGE_DEPLOYER_PW, GRAILS_GPG_KEY, GPG_KEY_ID, SVC_DIST_GRAILS_USERNAME, SVC_DIST_GRAILS_PASSWORD)
- **Confidence**: high
- **GitHub Actions**: `softprops/action-gh-release@v2`, `apache/grails-github-actions/deploy-github-pages@asf`
- **Commands**: `./gradlew initializeSonatypeStagingRepository`, `./gradlew findSonatypeStagingRepository publishToSonatype aggregateChecksums aggregatePublishedArtifacts`, `./gradlew findSonatypeStagingRepository closeSonatypeStagingRepository`, `svn commit`

**`ci.yaml`** — CI [Snapshot / Nightly Artifacts]
- **Summary**: This workflow publishes snapshot artifacts to Apache Maven repository (repository.apache.org/content/repositories/snapshots) on push or workflow_dispatch events when triggered from the apache organization. It builds the project with Java 17/21, then publishes snapshots using Gradle with Maven credentials. Additionally, it deploys snapshot documentation to GitHub Pages. The workflow explicitly sets GRAILS_PUBLISH_RELEASE=false, confirming snapshot (not release) publishing.
- **Ecosystems**: maven_central
- **Trigger**: push to any branch (excluding tags) or workflow_dispatch, restricted to apache org
- **Auth**: MAVEN_PUBLISH_USERNAME and MAVEN_PUBLISH_PASSWORD secrets
- **Confidence**: high
- **GitHub Actions**: `apache/grails-github-actions/deploy-github-pages@asf`
- **Commands**: `./gradlew publish aggregateChecksums aggregatePublishedArtifacts`

### apache/grails-quartz

**2** release/snapshot workflows | Ecosystems: **apache_dist, github_pages, github_releases, maven_central** | Release Artifacts: 1, Snapshot / Nightly Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes versioned release artifacts for the Apache Grails Quartz Plugin. It stages and closes JAR files to a Nexus/Maven staging repository (maven_central ecosystem), creates signed source distributions and uploads them to GitHub Releases, and uploads source distributions to Apache SVN dist repository (apache_dist ecosystem). The workflow is triggered on release publication and includes manual approval steps for final release promotion after PMC vote. Documentation is published to GitHub Pages in a separate job.
- **Ecosystems**: maven_central, apache_dist, github_releases
- **Trigger**: release published
- **Auth**: Nexus credentials (NEXUS_STAGE_DEPLOYER_USER, NEXUS_STAGE_DEPLOYER_PW), GPG signing key (GRAILS_GPG_KEY, GPG_KEY_ID), SVN credentials (SVC_DIST_GRAILS_USERNAME, SVC_DIST_GRAILS_PASSWORD), GitHub token
- **Confidence**: high
- **GitHub Actions**: `softprops/action-gh-release@153bb8e04406b158c6c84fc1615b65b24149a1fe`
- **Commands**: `./gradlew initializeSonatypeStagingRepository`, `./gradlew findSonatypeStagingRepository publishToSonatype aggregateChecksums aggregatePublishedArtifacts`, `./gradlew findSonatypeStagingRepository closeSonatypeStagingRepository`, `svn commit -m "Upload ${PROJECT_NAME} distribution files for ${VERSION}"`

**`gradle.yml`** — Java CI [Snapshot / Nightly Artifacts]
- **Summary**: Publishes snapshot artifacts to Maven repository (likely Apache Snapshots) and documentation to GitHub Pages. The publish_snapshot job runs on push to version branches or manual dispatch, but only for the apache organization. Maven artifacts are published via Gradle with credentials from Nexus secrets. Documentation is generated and deployed to GitHub Pages using a custom Apache Grails action.
- **Ecosystems**: maven_central, github_pages
- **Trigger**: push to version branches or workflow_dispatch (only for apache org)
- **Auth**: NEXUS_USER/NEXUS_PW secrets for Maven, GITHUB_TOKEN for GitHub Pages
- **Confidence**: high
- **GitHub Actions**: `apache/grails-github-actions/deploy-github-pages@asf`
- **Commands**: `./gradlew --no-build-cache publish`

### apache/grails-redis

**2** release/snapshot workflows | Ecosystems: **apache_dist, github_pages, github_releases, maven_central** | Release Artifacts: 1, Snapshot / Nightly Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes versioned release artifacts of the Apache Grails Redis Plugin to multiple registries: (1) Maven JARs to Nexus staging repository (Maven Central path), (2) signed source distributions to Apache SVN dist dev repository, (3) release assets to GitHub Releases, and (4) documentation to GitHub Pages. Triggered on GitHub release publication. Includes manual approval gates and vote confirmation steps following Apache release process. All artifacts are GPG-signed and checksummed for integrity verification.
- **Ecosystems**: maven_central, apache_dist, github_releases, github_pages
- **Trigger**: release published
- **Auth**: NEXUS_PUBLISH_USERNAME/PASSWORD secrets for Maven staging, SVN_USERNAME/PASSWORD for Apache dist, GITHUB_TOKEN for GitHub releases and pages, GPG signing with GRAILS_GPG_KEY
- **Confidence**: high
- **GitHub Actions**: `softprops/action-gh-release@153bb8e04406b158c6c84fc1615b65b24149a1fe`, `apache/grails-github-actions/deploy-github-pages@asf`
- **Commands**: `./gradlew initializeSonatypeStagingRepository`, `./gradlew findSonatypeStagingRepository publishToSonatype aggregateChecksums aggregatePublishedArtifacts`, `./gradlew findSonatypeStagingRepository closeSonatypeStagingRepository`, `svn commit -m "Upload ${PROJECT_NAME} distribution files for ${VERSION}"`, `svnmucc --username "$SVN_USERNAME" --password "$SVN_PASSWORD" --non-interactive mkdir https://dist.apache.org/repos/dist/dev/grails`

**`gradle.yml`** — Java CI [Snapshot / Nightly Artifacts]
- **Summary**: This workflow runs tests against Redis 6 and 7, then publishes snapshot artifacts to a Maven repository (Nexus) and documentation to GitHub Pages. Publishing only occurs on push/workflow_dispatch events from the apache organization repository. The GRAILS_PUBLISH_RELEASE=false flag and GRAILS_NEXUS_PUBLISH_SNAPSHOT_URL secret indicate this publishes snapshot builds, not releases.
- **Ecosystems**: maven_central, github_pages
- **Trigger**: push to version branches or workflow_dispatch
- **Auth**: secrets (NEXUS_USER, NEXUS_PW, GITHUB_TOKEN)
- **Confidence**: high
- **GitHub Actions**: `apache/grails-github-actions/deploy-github-pages@asf`
- **Commands**: `./gradlew --no-build-cache publish`

### apache/grails-spring-security

**2** release/snapshot workflows | Ecosystems: **apache_dist, github_pages, github_releases, maven_central** | Release Artifacts: 1, Snapshot / Nightly Artifacts: 1

**`release.yml`** — Release [Release Artifacts]
- **Summary**: This workflow publishes Apache Grails Spring Security release artifacts to multiple registries: (1) Maven/Gradle artifacts to Nexus staging repository (Maven Central path) via Gradle Nexus Publish plugin, (2) signed source distributions to Apache SVN dist/dev repository for PMC voting, (3) signed source ZIP files to GitHub Releases, and (4) documentation to GitHub Pages. The workflow is triggered on GitHub release publication and includes manual approval gates for final release promotion and documentation publishing. It follows Apache Software Foundation release procedures including GPG signing, checksum generation, and PMC vote coordination.
- **Ecosystems**: maven_central, apache_dist, github_releases, github_pages
- **Trigger**: release published
- **Auth**: secrets (NEXUS_STAGE_DEPLOYER_USER, NEXUS_STAGE_DEPLOYER_PW, GPG_KEY_ID, SVC_DIST_GRAILS_USERNAME, SVC_DIST_GRAILS_PASSWORD, GITHUB_TOKEN)
- **Confidence**: high
- **GitHub Actions**: `softprops/action-gh-release@153bb8e04406b158c6c84fc1615b65b24149a1fe`, `apache/grails-github-actions/deploy-github-pages@asf`
- **Commands**: `./gradlew initializeSonatypeStagingRepository`, `./gradlew findSonatypeStagingRepository publishToSonatype aggregateChecksums aggregatePublishedArtifacts`, `./gradlew findSonatypeStagingRepository closeSonatypeStagingRepository`, `svn commit -m "Upload ${PROJECT_NAME} distribution files for ${VERSION}" --username "$SVN_USERNAME" --password "$SVN_PASSWORD" --non-interactive`

**`gradle.yml`** — CI [Snapshot / Nightly Artifacts]
- **Summary**: This workflow runs tests on pull requests and pushes, then publishes snapshot artifacts to a Maven repository (likely Apache Snapshots Nexus) and documentation to GitHub Pages when tests pass on push/workflow_dispatch events. The GRAILS_PUBLISH_RELEASE: 'false' environment variable confirms this is snapshot publishing, not release artifacts. Publishing is restricted to the apache organization only.
- **Ecosystems**: maven_central, github_pages
- **Trigger**: push to version branches or workflow_dispatch
- **Auth**: secrets.NEXUS_USER and secrets.NEXUS_PW for Maven; secrets.GITHUB_TOKEN for GitHub Pages
- **Confidence**: high
- **GitHub Actions**: `apache/grails-github-actions/deploy-github-pages@asf`
- **Commands**: `./gradlew publish --no-build-cache --rerun-tasks`

### apache/gravitino

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`docker-image.yml`** — Publish Docker Image [Release Artifacts]
- **Summary**: Publishes Apache Gravitino Docker images to Docker Hub (default: apache/* namespace). Supports multiple image types including main gravitino image, CI images (hive, trino, doris, ranger), playground images, and REST server images. Triggered manually via workflow_dispatch with version tagging and optional 'latest' tag update for official releases. Uses custom token validation mechanism.
- **Ecosystems**: docker_hub
- **Trigger**: workflow_dispatch
- **Auth**: docker/login-action with username from workflow input and password from secrets.DOCKER_REPOSITORY_PASSWORD
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@b45d80f862d83dbcd57f89517bcf500b2ab88fb2`
- **Commands**: `./dev/docker/build-docker.sh --platform all --type ${image_type} --image ${image_name} --tag ${full_tag_name} --latest`, `./dev/docker/build-docker.sh --platform all --type ${image_type} --image ${image_name} --tag ${full_tag_name}`

### apache/hamilton

**2** release/snapshot workflows | Ecosystems: **docker_hub, pypi** | Release Artifacts: 2

**`contrib-auto-build-publish.yml`** — Publish SF Hamilton Contrib Python Package [Release Artifacts]
- **Summary**: Publishes the SF Hamilton Contrib Python package to PyPI on pushes to main branch that modify contrib/** paths. Uses OIDC trusted publishing for secure authentication and includes a version check to ensure only new versions are published. The workflow builds the package using python -m build and publishes via the official pypa/gh-action-pypi-publish action.
- **Ecosystems**: pypi
- **Trigger**: push to main branch when contrib/** paths change
- **Auth**: OIDC trusted publishing (id-token: write)
- **Confidence**: high
- **GitHub Actions**: `pypa/gh-action-pypi-publish@release/v1`

**`hamilton-ui-build-and-push.yml`** — Building and pushing UI frontend and backend images [Release Artifacts]
- **Summary**: This workflow checks PyPI for new versions of sf-hamilton-ui, compares against existing Docker Hub tags for dagworks/ui-frontend, and if a new version is detected, builds and pushes Docker images to Docker Hub using a shell script (buildx_and_push.sh). The workflow runs daily via cron schedule and can be manually triggered. It authenticates to Docker Hub using stored credentials and executes a build script that pushes versioned release images.
- **Ecosystems**: docker_hub
- **Trigger**: schedule (daily cron) and workflow_dispatch
- **Auth**: Docker Hub username/password via secrets.DOCKER_USERNAME and secrets.DOCKER_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v2`
- **Commands**: `./ui/buildx_and_push.sh`

### apache/hertzbeat

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Snapshot / Nightly Artifacts: 1

**`nightly-build.yml`** — Nightly CI [Snapshot / Nightly Artifacts]
- **Summary**: Nightly build workflow that compiles frontend (pnpm) and backend (Maven), then builds and pushes multi-platform Docker images (linux/amd64, linux/arm64) to Docker Hub with 'nightly' tags for both apache/hertzbeat and apache/hertzbeat-collector. Triggered daily at midnight UTC and on pushes to action* branches.
- **Ecosystems**: docker_hub
- **Trigger**: schedule (cron: '0 0 * * *') and push to action* branches
- **Auth**: Docker Hub username/password via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/build-push-action@d08e5c354a6adb9ed34480a06d141179aa583294`

### apache/hive

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Snapshot / Nightly Artifacts: 1

**`docker-images.yml`** — Build and Publish docker images for Hive GA [Snapshot / Nightly Artifacts]
- **Summary**: This workflow builds and publishes Apache Hive Docker images to Docker Hub. It runs on three triggers: manual workflow_dispatch with version parameters, nightly schedule (cron), and on tag creation (rel/* tags). The workflow builds two images: a main Hive image and a standalone metastore image. For scheduled runs, images are tagged as 'nightly'. For other triggers, images are tagged with the Hive version. Images are tested in a Kubernetes cluster before being pushed to Docker Hub with multi-platform support (linux/amd64, linux/arm64). The namespace defaults to 'apache' but can be configured via repository variables. This is categorized as snapshot_artifact because it publishes nightly builds and pre-release versions to Docker Hub, not just stable releases consumed by end users.
- **Ecosystems**: docker_hub
- **Trigger**: workflow_dispatch, schedule (nightly at 3:17 AM), create (tags starting with 'rel/')
- **Auth**: Docker Hub username/password via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/build-push-action@v4`

### apache/hudi-rs

**1** release/snapshot workflows | Ecosystems: **crates_io, pypi** | Release Artifacts: 1

**`release.yml`** — Publish artifacts [Release Artifacts]
- **Summary**: This workflow publishes release artifacts to crates.io and PyPI when a release tag is pushed. It validates the tag matches the Cargo.toml version, then publishes three Rust crates sequentially to crates.io, followed by Python wheels to PyPI for multiple platforms (macOS x86_64/aarch64, Windows x86_64, Linux x86_64/aarch64). The PyPI releases use maturin to build and publish Python bindings.
- **Ecosystems**: crates_io, pypi
- **Trigger**: push to tags matching 'release-[0-9]+.[0-9]+.[0-9]+**'
- **Auth**: CARGO_REGISTRY_TOKEN secret for crates.io, MATURIN_PYPI_TOKEN secret for PyPI
- **Confidence**: high
- **GitHub Actions**: `PyO3/maturin-action@v1`
- **Commands**: `cargo publish -p ${{ matrix.package }} --all-features`

### apache/incubator-baremaps

**3** release/snapshot workflows | Ecosystems: **apache_dist, github_releases, maven_central** | Release Artifacts: 2, Snapshot / Nightly Artifacts: 1

**`pre-release.yml`** — Release [Release Artifacts]
- **Summary**: Publishes pre-release artifacts (alpha/beta/test versions) to GitHub Releases. Builds Apache Baremaps source and binary tarballs, signs them with GPG, generates SHA512 checksums, and uploads all artifacts to a draft pre-release on GitHub. Triggered by version tags with alpha/beta/test suffixes.
- **Ecosystems**: github_releases
- **Trigger**: push to tags matching v*-alpha*, v*-beta*, v*-test*
- **Auth**: GITHUB_TOKEN
- **Confidence**: high
- **Commands**: `gh release create`, `gh release upload`

**`release.yml`** — Release [Release Artifacts]
- **Summary**: Publishes Apache Baremaps release candidate artifacts (source and binary tarballs with GPG signatures and SHA512 checksums) to GitHub Releases and Apache SVN dist/dev repository. Triggered by release candidate tags (e.g., v1.0.0-rc1). Artifacts are signed with GPG and uploaded to both GitHub Releases (as draft prerelease) and Apache Incubator SVN for voting.
- **Ecosystems**: github_releases, apache_dist
- **Trigger**: push to tags matching v[0-9]+.[0-9]+.[0-9]+-rc[0-9]+
- **Auth**: GitHub token (GITHUB_TOKEN), Apache SVN credentials (INCUBATOR_SVN_DEV_USERNAME/PASSWORD), GPG signing key
- **Confidence**: high
- **Commands**: `gh release create`, `gh release upload`, `svn import`

**`snapshot.yml`** — Nexus [Snapshot / Nightly Artifacts]
- **Summary**: Publishes Maven snapshot artifacts to Apache Nexus snapshot repository on every push to main branch. Uses Maven deploy goal with GPG signing. Configured with server-id 'apache.snapshots.https' pointing to Apache's snapshot repository.
- **Ecosystems**: maven_central
- **Trigger**: push to main branch
- **Auth**: Maven server credentials (NEXUS_USER/NEXUS_PW) and GPG signing key configured via setup-java action
- **Confidence**: high
- **Commands**: `./mvnw deploy -DskipTests -Dmaven.javadoc.skip=true -B -V`

### apache/incubator-devlake-helm-chart

**1** release/snapshot workflows | Ecosystems: **ghcr, helm** | Release Artifacts: 1

**`release.yaml`** — Release Charts [Release Artifacts]
- **Summary**: Publishes Helm charts to GitHub Container Registry (GHCR) as OCI artifacts. Triggered on pushes to main/release branches affecting charts/** paths. Uses chart-releaser-action to package charts, then pushes them to oci://ghcr.io/apache/incubator-devlake-helm-chart using helm push. Authenticates to GHCR using GITHUB_TOKEN. This is a release artifact workflow as it publishes versioned Helm charts to a public registry for end-user consumption.
- **Ecosystems**: helm, ghcr
- **Trigger**: push to main/release-v* branches (charts/** paths) or workflow_dispatch
- **Auth**: GITHUB_TOKEN for GHCR authentication
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`
- **Commands**: `helm push "${pkg}" oci://ghcr.io/${{ github.repository }}`

### apache/kafka

**2** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 2

**`docker_promote.yml`** — Promote Release Candidate Docker Image [Release Artifacts]
- **Summary**: This workflow promotes release candidate Docker images to final release versions on Docker Hub. It is manually triggered via workflow_dispatch with inputs for the RC image name and the promoted image name. The workflow uses docker buildx imagetools to copy/tag the RC image to the final release tag on Docker Hub. This is a release artifact workflow as it publishes versioned release packages (Docker images) to a public registry (Docker Hub) that end users consume.
- **Ecosystems**: docker_hub
- **Trigger**: workflow_dispatch
- **Auth**: secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@5e57cd118135c172c3672efd75eb46360885c0ef`
- **Commands**: `docker buildx imagetools create --tag $PROMOTED_DOCKER_IMAGE $RC_DOCKER_IMAGE`

**`docker_rc_release.yml`** — Build and Push Release Candidate Docker Image [Release Artifacts]
- **Summary**: This workflow builds and publishes Apache Kafka release candidate Docker images to Docker Hub. It is manually triggered with inputs for image type (jvm/native), RC docker image tag (e.g., apache/kafka:3.8.0-rc0), and Kafka URL. The workflow uses docker/login-action to authenticate to Docker Hub and executes a Python script (docker_release.py) to build and push multi-architecture images. This is a release artifact workflow as it publishes versioned RC images to the public Docker Hub registry for end-user consumption.
- **Ecosystems**: docker_hub
- **Trigger**: workflow_dispatch
- **Auth**: DOCKERHUB_USER and DOCKERHUB_TOKEN secrets
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@5e57cd118135c172c3672efd75eb46360885c0ef`
- **Commands**: `python docker/docker_release.py $RC_DOCKER_IMAGE --kafka-url $KAFKA_URL --image-type $IMAGE_TYPE`

### apache/karaf-minho

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`deploy.yml`** — Deploy [Snapshot / Nightly Artifacts]
- **Summary**: Scheduled nightly workflow that deploys Maven artifacts to Apache Nexus repository (likely snapshots). Runs daily at 02:30 UTC on the main branch using Maven deploy goal with custom ASF settings. Credentials are properly passed through environment variables.
- **Ecosystems**: maven_central
- **Trigger**: schedule (cron: '30 2 * * *') and workflow_dispatch
- **Auth**: secrets.NEXUS_USER and secrets.NEXUS_PW passed via environment variables
- **Confidence**: high
- **Commands**: `mvn -U -B -e -fae clean deploy --settings .github/asf-deploy-settings.xml`

### apache/knox

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`docker-publish.yml`** — Docker Publish [Release Artifacts]
- **Summary**: This workflow publishes Apache Knox Docker images to Docker Hub (apache/knox). It builds multi-architecture images (linux/amd64, linux/arm64) and pushes them with version-based tags. When triggered by a version tag (v*), it creates multiple tags including major and minor version tags plus 'latest'. The workflow builds the Knox project with Maven, extracts the version, and uses Docker Buildx to create and push multi-platform images.
- **Ecosystems**: docker_hub
- **Trigger**: push to master branch, push to tags matching 'v*', or manual workflow_dispatch
- **Auth**: Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **Commands**: `docker buildx build --push --platform linux/amd64,linux/arm64`

### apache/kvrocks

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Snapshot / Nightly Artifacts: 1

**`nightly.yaml`** — Nightly [Snapshot / Nightly Artifacts]
- **Summary**: Publishes nightly Docker images to Docker Hub (apache/kvrocks) triggered by pushes to the 'unstable' branch or v2.** tags. Multi-platform builds (linux/amd64, linux/arm64) are created with digest-based push, then merged into manifest lists with tags like 'nightly' and 'nightly-YYYYMMDD-{sha}'. This is a snapshot/nightly build workflow, not a stable release.
- **Ecosystems**: docker_hub
- **Trigger**: push to unstable branch or v2.** tags
- **Auth**: Docker Hub credentials via secrets.DOCKER_USERNAME and secrets.DOCKER_PASSWORD
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9`, `docker/build-push-action@d08e5c354a6adb9ed34480a06d141179aa583294`
- **Commands**: `docker buildx imagetools create`

### apache/kyuubi

**2** release/snapshot workflows | Ecosystems: **docker_hub, maven_central** | Snapshot / Nightly Artifacts: 2

**`publish-snapshot-docker.yml`** — Publish Snapshot Docker Image [Snapshot / Nightly Artifacts]
- **Summary**: Scheduled nightly workflow that builds and publishes a multi-platform (linux/amd64, linux/arm64) Docker image tagged 'apache/kyuubi:master-snapshot' to Docker Hub. This is a snapshot build triggered daily at midnight UTC, not a versioned release artifact.
- **Ecosystems**: docker_hub
- **Trigger**: schedule (cron: '0 0 * * *')
- **Auth**: Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@b45d80f862d83dbcd57f89517bcf500b2ab88fb2`, `docker/build-push-action@d08e5c354a6adb9ed34480a06d141179aa583294`

**`publish-snapshot-nexus.yml`** — Publish Snapshot Nexus [Snapshot / Nightly Artifacts]
- **Summary**: Scheduled daily workflow that publishes snapshot builds to Apache Nexus repository for multiple branches (master, branch-1.8, branch-1.9) with various Spark/Flink/Hive profile combinations. Uses Maven deploy with ASF settings file and authenticates via NEXUS_USER/NEXUS_PW secrets. Runs only on apache/* repositories.
- **Ecosystems**: maven_central
- **Trigger**: schedule (daily cron: 0 0 * * *)
- **Auth**: ASF_USERNAME and ASF_PASSWORD environment variables from secrets.NEXUS_USER and secrets.NEXUS_PW
- **Confidence**: high
- **Commands**: `build/mvn clean deploy -s build/release/asf-settings.xml -DskipTests`

### apache/kyuubi-docker

**1** release/snapshot workflows | Ecosystems: **docker_hub** | Release Artifacts: 1

**`docker-image.yml`** — Publish Docker image [Release Artifacts]
- **Summary**: Publishes official Apache Kyuubi Docker images to Docker Hub when tags are pushed. Builds multiple image variants (base, spark, flink, all) from Apache release source tarballs and pushes them to apache/kyuubi repository on Docker Hub with version tags.
- **Ecosystems**: docker_hub
- **Trigger**: push to tags
- **Auth**: Docker Hub credentials via secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN
- **Confidence**: high
- **GitHub Actions**: `docker/login-action@v3`
- **Commands**: `docker push apache/kyuubi:$(cat release/release_version)${{ matrix.suffix-name }}`

### apache/kyuubi-shaded

**1** release/snapshot workflows | Ecosystems: **maven_central** | Snapshot / Nightly Artifacts: 1

**`publish-snapshot-nexus.yml`** — Publish Snapshot Nexus [Snapshot / Nightly Artifacts]
- **Summary**: Scheduled daily workflow that publishes snapshot builds to Apache Nexus repository. Runs Maven deploy with ASF credentials for the master branch. This is a snapshot artifact workflow publishing to Apache's Maven snapshot repository (part of maven_central ecosystem).
- **Ecosystems**: maven_central
- **Trigger**: schedule (daily cron: 0 0 * * *)
- **Auth**: Maven settings.xml with ASF_USERNAME and ASF_PASSWORD environment variables from GitHub secrets
- **Confidence**: high
- **Commands**: `build/mvn clean deploy -s build/release/asf-settings.xml -DskipTests`

## Repositories with Workflows (No Publishing Detected)

352 repositories had workflow files but no publishing of any kind.

<details>
<summary>Show 352 repos</summary>

- **accumulo**: maven-full-its.yaml, maven-on-demand.yaml, maven.yaml, scripts.yaml
- **accumulo-access**: maven-on-demand.yaml, maven.yaml, scripts.yaml
- **accumulo-classloaders**: maven-on-demand.yaml, maven.yaml
- **accumulo-examples**: maven.yaml
- **accumulo-fluo**: maven.yaml
- **accumulo-fluo-bytes**: maven.yaml
- **accumulo-fluo-examples**: maven.yaml
- **accumulo-fluo-muchos**: ci.yaml
- **accumulo-fluo-recipes**: maven.yaml
- **accumulo-fluo-uno**: shellcheck.yaml
- **accumulo-fluo-website**: jekyll.yaml
- **accumulo-fluo-yarn**: maven.yaml
- **accumulo-instamo-archetype**: maven.yaml
- **accumulo-maven-plugin**: maven.yaml, scripts.yaml
- **accumulo-proxy**: maven.yaml
- **accumulo-testing**: maven.yaml
- **accumulo-website**: jekyll.yaml
- **accumulo-wikisearch**: maven.yaml
- **activemq-nms-amqp**: build.yml
- **activemq-nms-openwire**: build.yml
- **age**: go-driver.yml, installcheck.yaml, jdbc-driver.yaml, nodejs-driver.yaml, python-driver.yaml
- **age-viewer**: node.js.yml
- **airavata-django-portal**: build-and-test.yaml
- **airflow-client-go**: ci.yml
- **airflow-client-python**: ci.yml, stale.yml
- **allura**: codeql.yml
- **ambari-metrics**: ambari.yml
- **amoro-shade**: ci.yaml
- **answer-plugins**: check-asf-header.yml, sync-info.yml
- **apisix-control-plane**: ci.yml, golangci-lint.yml, license_ci.yml
- **apisix-dashboard**: codeql-analysis.yml, e2e.yml, gitleaks.yml, license-checker.yml, lint.yml
- **apisix-java-plugin-runner**: ci.yaml, runner-e2e.yml
- **apr**: linux.yml, macos.yml, windows-vcpkg.yml, windows.yml
- **apr-util**: linux.yml, windows-vcpkg.yml, windows.yml
- **aries**: async.yml, blueprint-maven-plugin.yml, blueprint.yml, esa-ant-task.yml, esa-maven-plugin.yml, jmx.yml, jndi.yml, labeler.yml, pmd.yml, proxy.yml, pushstream.yml, quiesce.yml, samples.yml, spi-fly.yml, subsystem.yml, testsupport.yml, transaction.yml, tutorials.yml, util.yml, versioning.yml, web.yml
- **aries-cdi**: maven.yml
- **aries-component-dsl**: maven.yml
- **aries-jax-rs-whiteboard**: maven.yml
- **aries-jpa**: build.yml
- **arrow-rs-object-store**: audit.yml, ci.yml, dev.yml, rust.yml, take.yml, typos.yml
- **artemis**: build.yml
- **artemis-console**: audit.yml, build.yml
- **artemis-examples**: build.yml
- **artemis-native**: build.yml
- **atlas**: ci.yml
- **auron**: build-amd64-releases.yml, build-arm-releases.yml, celeborn.yml, delete-workflow-runs.yml, flink.yml, hudi.yml, iceberg.yml, labeler.yml, license.yml, paimon.yml, pr-title-check.yml, rust-test.yml, stale.yml, style.yml, tpcds-reusable.yml, tpcds.yml, uniffle.yml
- **avro-rs**: test-lang-rust-audit.yml, test-lang-rust-ci.yml, test-lang-rust-clippy.yml
- **axis-axis1-java**: ci.yml
- **axis-axis2-c-core**: cve-check.yml
- **axis-axis2-java-rampart**: ci.yml
- **beam-starter-go**: test.yaml
- **beam-starter-java**: test.yaml
- **beam-starter-java-provider**: validate-pipeline.yml
- **beam-starter-kotlin**: test.yaml
- **beam-starter-python**: test.yaml
- **beam-starter-typescript**: test.yaml
- **bigtop-manager**: check_chinese_character.yml, ci.yml, codeql.yaml, pr.yml
- **brpc**: ci-linux.yml, ci-macos.yml, cifuzz.yml, license-eyes.yml
- **bval**: bval-ci.yml
- **camel**: alternative-os-build-main.yml, check-container-versions.yml, depsreview.yaml, generate-sbom-main.yml, main-build.yml, pr-build-main.yml, pr-cleanup-branches.yml, pr-commenter.yml, pr-doc-validation.yml, pr-id.yml, pr-labeler.yml, pr-manual-component-test.yml, pr-test-commenter.yml, pr-update-branch.yml, security-scan.yml, sonar-build.yml, sonar-scan.yml
- **camel-examples**: master-pr-build.yml, master-push-build.yml
- **camel-jbang-examples**: build.yml
- **camel-karaf**: main.yml
- **camel-performance-tests**: depsreview.yaml, pr-build-main.yml
- **camel-quarkus**: assign-issue-milestone.yaml, assign-wontfix-issue-milestone.yaml, camel-master-cron.yaml, check-dependency-convergence.yml, ci-build.yaml, ci-semeru-jdk.yaml, generate-sbom-main.yml, jdk25-build.yaml, label-issue.yaml, pr-doc-validation.yml, pr-validate.yml, quarkus-lts-ci-build.yaml, quarkus-master-cron.yaml, synchronize-dependabot-branch.yaml
- **camel-quarkus-examples**: ci-build.yaml
- **camel-spring-boot**: automatic-sync-main.yml, depsreview.yaml, generate-sbom-main.yml, pr-build-main.yml, pr-doc-validation.yml
- **camel-spring-boot-examples**: master-pr-build.yml, master-push-build.yml
- **camel-upgrade-recipes**: ci-build.yaml, comment-pr.yml, github-release.yml, receive-pr.yml
- **casbin**: comment.yml, default.yml, golangci-lint.yml, performance-pr.yml
- **casbin-3rd-party-casbin-pg-adapter**: ci.yml
- **casbin-SwiftCasbin**: test.yml
- **casbin-beego-orm-adapter**: ci.yml
- **casbin-confita**: build.yml
- **casbin-cpp**: benchmark.yml, ci.yml, memcheck.yml, python_binding.yml, release.yml
- **casbin-cpp-Cvaluate**: ci.yml
- **casbin-cpp-casbin-CMake-setup**: ci.yml
- **casbin-cpp-sqlpp11-adapter**: ci.yml
- **casbin-crd-adapter**: ci.yml
- **casbin-docker-plugin**: ci.yml
- **casbin-ent-adapter**: ci.yml
- **casbin-etcd-watcher**: ci.yml
- **casbin-express-authz**: main.yml
- **casbin-fasthttp-auth**: ci.yml, release.yml
- **casbin-go-client**: ci.yml
- **casbin-gorm-adapter**: ci.yml
- **casbin-gorm-adapter-ex**: ci.yml
- **casbin-govaluate**: build.yml
- **casbin-hraft-dispatcher**: main.yml
- **casbin-informer-watcher**: ci.yml
- **casbin-jcasbin-java-cli**: maven-ci.yml
- **casbin-jcasbin-menu-permission**: maven-ci.yml
- **casbin-json-adapter**: default.yml
- **casbin-k8s-gatekeeper**: ci.yml
- **casbin-kubesphere-authz**: ci.yml
- **casbin-laravel-rbac**: build.yml
- **casbin-ldap-role-manager**: ci.yml
- **casbin-lua-4daysorm-adapter**: test.yml
- **casbin-lua-apisix-authz**: test.yml
- **casbin-lua-kong-authz**: release.yml, test.yml
- **casbin-lua-luasql-adapter**: test.yml
- **casbin-mongodb-adapter**: ci.yml
- **casbin-node-casbin-examples**: main.yml
- **casbin-node-casbin-graphql-authz**: ci.yml
- **casbin-node-casbin-node-pubsub-watcher**: ci.yml
- **casbin-okta-role-manager**: ci.yml
- **casbin-opentelemetry-logger**: ci.yml
- **casbin-pg-adapter**: ci.yml
- **casbin-policyguard**: build.yml
- **casbin-prometheus-logger**: ci.yml
- **casbin-python-cli**: release.yml
- **casbin-python-django-casbin**: build.yml
- **casbin-raft**: default.yml
- **casbin-redis-adapter**: ci.yml
- **casbin-redis-watcher**: ci.yml
- **casbin-rust-actix-file-adapter-rbac**: ci.yml
- **casbin-rust-actix-middleware-example**: CI.yml
- **casbin-rust-actix-postgresql-simple**: CI.yml
- **casbin-rust-axum-middleware-example**: CI.yml
- **casbin-rust-casbin-grpc**: CI.yml
- **casbin-rust-json-adapter**: ci.yml, coverage.yml
- **casbin-rust-ntex-file-adapter-acl**: CI.yml
- **casbin-rust-poem-casbin**: ci.yml
- **casbin-rust-poem-todo**: CI.yml
- **casbin-tikv-watcher**: go.yml
- **casbin-xorm-adapter**: ci.yml
- **casbin-zap-logger**: build.yml, ci.yml
- **cassandra**: code-check.yaml
- **cassandra-analytics**: test.yaml
- **cassandra-builds**: jenkins-agent-install.yaml
- **cassandra-ccm**: main-python-2-7.yml, main.yml
- **cassandra-diff**: maven.yml
- **cassandra-gocql-driver**: main.yml
- **cassandra-spark-connector**: main.yml
- **cassandra-website**: site-content.yaml
- **cloudberry-backup**: apache-rat-audit.yml, build_and_unit_test.yml, cloudberry-backup-ci.yml
- **cloudberry-go-libs**: code-check.yml
- **cloudberry-pxf**: apache-rat-audit.yml, dependency-submission.yml, pxf-ci.yml
- **cloudstack-cloudmonkey**: build-pr-cmk.yml, build.yml, ci.yml, comment-pr-build.yml, lint.yml, rat.yaml
- **cloudstack-csbench**: build.yml
- **cloudstack-documentation**: gen-docs.yaml
- **cloudstack-go**: build.yml, ci.yml, rat.yaml
- **cloudstack-terraform-provider**: acceptance.yml, build.yml, rat.yaml
- **comdev-events-site**: getcalendar.yml
- **commons-bcel**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-beanutils**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-bsf**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-build-plugin**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-chain**: maven.yml
- **commons-cli**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-codec**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-collections**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-compress**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-configuration**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-csv**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-daemon**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml, windows.yml
- **commons-dbcp**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-dbutils**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-digester**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-email**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-exec**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-fileupload**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-graph**: maven.yml
- **commons-imaging**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-jci**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-jcs**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-jelly**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-jexl**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-jxpath**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-lang**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-logging**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-parent**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-pool**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-rdf**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-release-plugin**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-scxml**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-skin**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-text**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-validator**: codeql-analysis.yml, data-source-check.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-vfs**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **commons-weaver**: codeql-analysis.yml, dependency-review.yml, maven.yml, scorecards-analysis.yml
- **cordova**: twitter-together.yml
- **cordova-app-hello-world**: release-audit.yml
- **cordova-browser**: ci.yml, release-audit.yml
- **cordova-cli**: ci.yml, release-audit.yml
- **cordova-common**: ci.yml, release-audit.yml
- **cordova-create**: ci.yml, release-audit.yml
- **cordova-electron**: ci.yml, release-audit.yml
- **cordova-fetch**: ci.yml, release-audit.yml
- **cordova-js**: ci.yml, release-audit.yml
- **cordova-lib**: ci.yml, release-audit.yml
- **cordova-mobile-spec**: release-audit.yml
- **cordova-node-xcode**: ci.yml, release-audit.yml
- **cordova-paramedic**: android.yml, chrome.yml, ci.yml, ios.yml, lint.yml, release-audit.yml
- **cordova-plugin-battery-status**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugin-device**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugin-device-motion**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugin-device-orientation**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugin-dialogs**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugin-file**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugin-file-transfer**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugin-geolocation**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugin-inappbrowser**: android.yml, chrome.yml, ios.yml, lint.yml, release-audit.yml
- **cordova-plugin-media**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugin-media-capture**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugin-network-information**: android.yml, chrome.yml, ci.yml, ios.yml, lint.yml, release-audit.yml
- **cordova-plugin-screen-orientation**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugin-splashscreen**: chrome.yml, lint.yml
- **cordova-plugin-statusbar**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugin-test-framework**: ci.yml, release-audit.yml
- **cordova-plugin-vibration**: android.yml, chrome.yml, ios.yml, lint.yml
- **cordova-plugman**: ci.yml, release-audit.yml
- **cordova-serve**: ci.yml, release-audit.yml
- **couchdb-erlfdb**: ci.yml
- **couchdb-fast-pbkdf2**: ci.yml
- **couchdb-fauxton**: main.yml
- **couchdb-jiffy**: ci.yml
- **couchdb-meck**: erlang.yml
- **couchdb-nano**: ci.yaml
- **couchdb-recon**: ci.yml
- **creadur-rat**: maven.yml, sonarcloud.yml
- **creadur-tentacles**: maven.yml
- **creadur-whisker**: maven.yml
- **curator**: ci.yml
- **cxf**: codeql-analysis.yml, pull-request-build.yml, scorecards.yml
- **cxf-build-utils**: codeql.yml, pull-request-build.yml
- **cxf-fediz**: codeql.yml, pull-request-build.yml, scorecards.yml
- **cxf-xjc-utils**: codeql.yml, pull-request-build.yml
- **daffodil-infrastructure**: check-dist.yml
- **daffodil-schema.g8**: main.yml
- **datafu**: codeql-analysis.yml, tests.yml
- **datafusion-ballista-python**: cancel.yml, comment_bot.yml, dev.yml, dev_pr.yml, python_build.yml, python_test.yaml, rust.yml
- **datafusion-benchmarks**: codeql.yml
- **datafusion-sqlparser-rs**: license.yml, rust.yml, stale.yml
- **datafusion-testing**: codeql.yml
- **datasketches-hive**: maven.yml
- **datasketches-memory16**: maven.yml
- **datasketches-memory17**: codeql-analysis.yml, maven.yml
- **datasketches-pig**: maven.yml
- **datasketches-postgresql**: c-cpp.yml
- **datasketches-rust**: ci.yml
- **datasketches-spark**: ci.yaml, python_ci.yaml
- **datasketches-website**: codeql.yml
- **db-jdo**: build.yml
- **db-jdo-site**: build-site.yml, deploy-site.yml, recreate-site-branch.yml
- **db-site**: build-site.yml, deploy-site.yml, recreate-site-branch.yml
- **deltaspike**: ci.yml, integration.yml
- **directory-kerby**: codeql.yml, pull-request-build.yaml, scorecards.yml
- **directory-ldap-api**: codeql-analysis.yml, pull-request-build.yaml, scorecards.yml
- **directory-server**: codeql-analysis.yml, pull-request-build.yaml, scorecards.yml
- **directory-studio**: codeql-analysis.yml, pull-request-build-openjdk11.yml, pull-request-build-openjdk17.yml, pull-request-build-openjdk21.yml, pull-request-build.yml, scorecards.yml
- **doris**: approve-label-trigger.yml, approve-label.yml, auto-cherry-pick.yml, be-ut-mac.yml, build-extension.yml, build-thirdparty.yml, checkstyle.yaml, clang-format.yml, code-checks.yml, comment-to-trigger-teamcity.yml, gitleaks-pr-check.yml, lfs-warning.yml, license-eyes.yml, opencode-review.yml, pr-approve-status.yml, scope-label.yml, stale.yml, third_party_review.yml, title-checker.yml
- **doris-flink-connector**: approve-label-trigger.yml, approve-label.yml, build-connector.yml, checkstyle.yaml, license-eyes.yml, run-e2ecase-flink1.yml, run-e2ecase-flink2.yml, run-itcase-flink1.yml, run-itcase-flink2.yml
- **doris-kafka-connector**: build-doris-kafka-connector.yml, checkstyle.yaml, kafka2doris-e2ecase.yaml, license-eyes.yml
- **doris-sdk**: build-extension.yaml, license.yaml
- **doris-shade**: license.yaml
- **doris-spark-connector**: approve-label-trigger.yml, approve-label.yml, build-extension.yml, license-eyes.yml, run-e2ecase.yml, run-itcase.yml
- **doris-streamloader**: go.yml, license-eyes.yml
- **druid**: backport.yml, ci.yml, codeql.yml, cron-job-its.yml, docker-tests.yml, labeler.yml, pr-checks.yml, pr-merged.yml, stale.yml, static-checks.yml, unit-and-integration-tests-unified.yml, worker.yml
- **druid-operator**: docker-image.yml
- **dubbo**: build-and-test-pr.yml, build-and-test-scheduled-3.1.yml, build-and-test-scheduled-3.2.yml, build-and-test-scheduled-3.3.yml, release-test.yml
- **dubbo-benchmark**: ci.yml
- **dubbo-getty**: github-actions.yml
- **dubbo-go**: codeql-analysis.yml, github-actions.yml, release-drafter.yml
- **dubbo-go-contrib**: license.yml
- **dubbo-go-extensions**: github-actions.yml
- **dubbo-go-hessian2**: github-actions.yml
- **dubbo-go-samples**: github-actions.yml, golangci-lint.yml
- **dubbo-hessian-lite**: maven.yml
- **dubbo-integration-cases**: dubbo-3_2.yml, dubbo-3_3.yml, license.yml, nightly-dubbo-3.yml
- **dubbo-python**: license-check.yaml, test-suite.yaml
- **dubbo-rust**: github-actions.yml, licence-checker.yml
- **dubbo-samples**: dubbo-3_2.yml, dubbo-3_3.yml, license.yml, nightly-dubbo-3.yml
- **dubbo-spi-extensions**: build-and-test-pr.yml, conformance.yml, release-test.yml
- **dubbo-spi-samples**: dubbo-3_2.yml, license.yml
- **dubbo-spring-boot-project**: dubbo-2.yml
- **dubbo-test-tools**: build-error-code-inspector.yml, license-check.yml, unit-test.yml
- **echarts-bot**: bot-wakup.yml
- **echarts-doc**: nodejs.yml
- **eventmesh-catalog**: ci.yml
- **eventmesh-go**: ci.yml
- **eventmesh-workflow**: ci.yml
- **felix-atomos**: maven.yml
- **felix-dev**: maven-ci.yml
- **fineract-backoffice-ui**: ci.yml
- **fineract-chat-archive**: test.yml, verify-commits.yml
- **fineract-credit-scorecard**: django-build.yml, java-build.yml
- **fineract-site**: site-pr-check.yml, site-publish.yml, verify-commits.yml, whimsy-daily-check.yml
- **flagon**: distill_ci.yml, license.yml, site.yml, userale_ci.yml
- **flink-benchmarks**: ci.yml
- **flink-connector-aws**: common.yml, nightly.yml, push_pr.yml
- **flink-connector-cassandra**: push_pr.yml, weekly.yml
- **flink-connector-elasticsearch**: push_pr.yml, weekly.yml
- **flink-connector-gcp-pubsub**: push_pr.yml, weekly.yml
- **flink-connector-hbase**: push_pr.yml, weekly.yml
- **flink-connector-hive**: push_pr.yml, weekly.yml
- **flink-connector-http**: push_pr.yml, weekly.yml
- **flink-connector-jdbc**: backwards_compatibility.yml, push_pr.yml, stale.yml, weekly.yml
- **flink-connector-kafka**: push_pr.yml, stale.yml, weekly.yml
- **flink-connector-kudu**: push_pr.yml, weekly.yml
- **flink-connector-mongodb**: push_pr.yml, weekly.yml
- **flink-connector-opensearch**: push_pr.yml, weekly.yml
- **flink-connector-prometheus**: common.yml, nightly.yml, push_pr.yml
- **flink-connector-pulsar**: push_pr.yml, weekly.yml
- **flink-connector-rabbitmq**: push_pr.yml, weekly.yml
- **flink-connector-redis-streams**: push_pr.yml, weekly.yml
- **flink-jira-bot**: actions.yaml
- **flink-ml**: java-tests.yml, python-tests.yml
- **flink-shaded**: ci.yml
- **flink-statefun**: doc-check.yml, java8-build.yml
- **flink-training**: ci.yml
- **fluss-blog**: blog-check.yaml, blog-deploy.yaml
- **fluss-shaded**: ci.yml
- **freemarker**: ci.yml
- **geaflow**: ci-jdk11.yml, ci-py311.yml, ci.yml
- **geode**: codeql.yml, gradle.yml
- **geode-benchmarks**: gradle.yml
- **geode-examples**: gradle.yml
- **geode-kafka-connector**: mvn-package-all-os.yml
- **geode-site**: gradle.yml
- **geronimo-arthur**: maven.yml
- **geronimo-batchee**: ci.yml
- **geronimo-mail**: ci.yml
- **geronimo-txmanager**: maven.yml
- **gora**: master-pr-build.yml, master-push-build.yml
- **grails-plugins-metadata**: syncVersion.yml, updateIndex.yml
- **groovy-geb**: build-check.yml, check-manual.yml, dockerised-cross-browser.yml, gradle-wrapper-validation.yml, license-check.yml, local-browser.yml
- **guacamole-client**: pr-build.yml
- **guacamole-manual**: pr-build.yml
- **guacamole-server**: pr-build.yml
- **guacamole-website**: pr-build.yml
- **hadoop-api-shim**: maven.yml
- **hadoop-thirdparty**: build.yml, dependency_check.yml, license_check.yml
- **hbase**: yetus-general-check.yml, yetus-jdk17-hadoop3-compile-check.yml, yetus-jdk17-hadoop3-unit-check.yml
- **helix**: Helix-CI.yml, Helix-Manual-CI.yml, Helix-PR-CI.yml, Helix-PR-Premerge-Check.yml, helix-front.yml
- **hertzbeat-collector-go**: build-and-test.yml, invalid-issue-check.yml, license-check.yml, lint-pr-title.yml, linter.yml, pull-request-robot.yml, secret-check.yml
- **hertzbeat-helm-chart**: ci.yaml, license-checker.yml
- **hop**: issue_tagger.yml, pr_assign_milestone.yml, pr_build_code.yml, pr_build_docs.yml, pr_tagger.yml, self_assign.yml
- **httpcomponents-client**: codeql-analysis.yml, depsreview.yaml, maven.yml
- **httpcomponents-core**: codeql-analysis.yml, depsreview.yaml, maven.yml
- **httpd**: linux.yml, windows.yml
- **httpd-tests**: httpd-build.yml
- **hudi**: azure_ci_check.yml, bot.yml, maven_artifact_validation.yml, pr_compliance.yml, pr_title_validation.yml, release_candidate_validation.yml, scheduled_workflow.yml, update_pr_compliance.yml
- **hugegraph**: auto-pr-review.yml, check-dependencies.yml, cluster-test-ci.yml, codeql-analysis.yml, commons-ci.yml, licence-checker.yml, pd-store-ci.yml, server-ci.yml, stale.yml
- **hugegraph-ai**: auto-pr-comment.yml, check-dependencies.yml, codeql.yml, hugegraph-llm.yml, hugegraph-python-client.yml, labeler.yml, ruff.yml, sync.yml
- **hugegraph-computer**: codeql-analysis.yml, computer-ci.yml, license-checker.yml, stale.yml
- **hugegraph-toolchain**: client-ci.yml, client-go-ci.yml, codeql-analysis.yml, hubble-ci.yml, labeler.yml, license-checker.yml, loader-ci.yml, spark-connector-ci.yml, stale.yml, tools-ci.yml
- **kafka-merge-queue-sandbox**: build.yml, ci.yml, merge.yml, pr.yml
- **karaf**: ci-test-results.yml, ci.yml
- **karaf-cellar**: build.yml
- **karaf-decanter**: ci-test-results.yml, ci.yml
- **karaf-winegrower**: maven.yml

</details>

---

*Cached in `ci-classification:apache`.*