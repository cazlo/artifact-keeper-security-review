# AGENTS.md

## Purpose

This workspace is for a focused security review of the `artifact-keeper` project, with the intent to determine whether it is defensible for internal use and whether we can productively contribute security improvements upstream.

The preferred workflow is:
1. All repositories from the [artifact-keeper org](https://github.com/artifact-keeper) are cloned as **git subtrees** (full history, no squash):  
   | Prefix | Repo | Pinned SHA |
   |---|---|---|
   | `artifact-keeper/` | artifact-keeper/artifact-keeper | `fb2fcd799c9a87b49f2170f1f46bc26bb902500f` |
   | `artifact-keeper-web/` | artifact-keeper/artifact-keeper-web | `10fd8569b6e91ad174867b45a971a55880029964` |
   | `artifact-keeper-iac/` | artifact-keeper/artifact-keeper-iac | `583adb7d3f885ccb0b5e77a894ef89af374f1f96` |
   | `artifact-keeper-api/` | artifact-keeper/artifact-keeper-api | `4d7d207f839b81ca4e11b6fb70fc7efd35d85a7d` |
   | `artifact-keeper-example-plugin/` | artifact-keeper/artifact-keeper-example-plugin | `23d495209d8761dd14b71c2468c570a8b5156d28` |

2. Inspect the code locally. Do not browse GitHub per-file when the subtree is available.
3. Write findings under the `findings/` directory — one markdown file per topic, numbered (e.g. `001-ssrf-redirects.md`).
4. Every finding must include **receipts**: links to specific source files at the pinned commit SHA.  
   Link format: `https://github.com/artifact-keeper/<repo>/blob/<SHA>/path/to/file`  
   Use the pinned SHA from the table above for the relevant repo.
5. Favor concrete proof over speculation.

**Tech stack notes:**
- **artifact-keeper** (backend): Rust (Cargo.toml, Cargo.lock). Not Go. See `README.md` for Rust tooling setup.
- **artifact-keeper-web** (frontend): TypeScript / Next.js 15 / React 19 / Tailwind CSS 4
- **artifact-keeper-iac** (infra): Terraform (AWS) / Helm 3 / ArgoCD / kube-prometheus
- **artifact-keeper-api** (spec): OpenAPI 3.1 (auto-generated from backend annotations via utoipa) + SDK generators
- **artifact-keeper-example-plugin** (plugins): Rust → WASM Component Model (wasm32-wasip2)

This repository review is **not** a generic audit of every feature. The review should stay tightly aligned to the actual intended use cases below.

---

## User context and intended use cases

### Use case 1: private home cluster
The user wants an internal package proxy/cache for a home lab / private cluster. Main desired ecosystems:
- PyPI
- npm
- Java / Maven
- maybe Rust / Cargo

Other relevant home-lab context:
- Harbor already exists for OCI/container artifacts
- Gitea already exists
- the desire is to avoid direct dependency pulls from the public internet where possible
- the user wants more control over caching, continuity, and possibly scanning
- simplicity matters; unnecessary feature surface is a downside

### Use case 2: startup environment
The user expects to buy Chainguard for secure PyPI/npm packages and wants an internal artifact proxy/cache in front of upstreams.

Desired properties:
- internal/private deployment only
- likely VPC-only or Teleport-gated access
- SSO for write/admin paths at minimum
- read access may be more open internally
- can cache and retain artifacts already in use
- can preserve continuity during upstream outages, vendor issues, or contract changes
- can reduce or eliminate direct public internet pulls by developers and CI

The user explicitly does **not** want Nexus or Artifactory for this effort. Reasons include:
- philosophical disagreement with freemium/rug-pull behavior
- unacceptable business continuity concerns around limits stopping the service
- cost is high for a small startup
- prior operational experience with those products was negative

So this review assumes Artifact Keeper is being seriously considered and may be worth contributing to if the security posture is acceptable.

---

## Current high-level assessment

Current conclusion from the first pass:
- no obvious signs of malicious intent were found
- no obvious encrypted payloads, embedded binaries, or glaring hidden update mechanisms were identified
- the main risk appears to be **youth + broad scope**, not obvious malice
- the product does more than is needed for the actual use case, which increases attack surface and review burden

Main risk areas identified so far:
- outbound fetch / proxy logic
- SSRF and redirect handling
- authn/authz boundaries
- package path normalization for PyPI/npm/Maven/Cargo
- large upload / disk exhaustion behavior
- plugin system, especially remote plugin acquisition and execution
- optional SSO integration paths and configuration sharp edges

Important nuance:
- if a claim is not proven from local code or local testing, do not present it as fact
- distinguish clearly between:
  - confirmed issue
  - plausible issue worth testing
  - deployment risk / operational concern

---

## Scope of review

### In scope — backend (`artifact-keeper/`)
Primary review target. Focus heavily on:
- PyPI proxy/repository behavior
- npm proxy/repository behavior
- Maven proxy/repository behavior
- Cargo proxy/repository behavior
- common auth middleware and repo visibility rules
- outbound HTTP client configuration
- URL validation and SSRF controls
- upload and download handlers
- cache/proxy semantics and continuity concerns
- deployment hardening for private/internal-only use

### In scope — frontend (`artifact-keeper-web/`)
Secondary review. Focus on:
- client-side auth token handling and storage
- API URL configuration and CORS implications
- any client-side secrets or credentials in code/config
- XSS vectors in artifact metadata display
- dependency supply chain (npm packages)

### In scope — infrastructure (`artifact-keeper-iac/`)
Review for deployment security posture:
- Helm chart defaults (RBAC, NetworkPolicy, PodSecurityStandards)
- Terraform module defaults (security groups, IAM, RDS config)
- Secrets management approach (Secrets Manager, IRSA)
- Default exposure (ingress, service types, public endpoints)
- Monitoring/alerting gaps

### In scope — API spec (`artifact-keeper-api/`)
Light review:
- API surface area assessment (277 operations across 24 groups)
- Auth requirements per endpoint (missing auth on sensitive operations?)
- SDK generation safety (no credential leaks in generated code)

### In scope — example plugins (`artifact-keeper-example-plugin/`)
Review in context of WASM plugin surface (finding 005):
- WIT interface contract (what host capabilities are exposed)
- Plugin install/load mechanism security
- Reference implementation patterns that downstream plugin authors will copy

### Deprioritized
Do not spend much time here unless findings force us to:
- ecosystems the user does not care about
- UI polish / UX issues
- generalized feature comparison against enterprise products
- plugin development workflows as a product feature

### Treat as high-risk optional surface
These should be reviewed, but the likely recommendation is to disable or avoid them unless clearly needed:
- WASM plugin system
- replication / peer sync
- any external scanner/plugin integrations not required for the first deployment

---

## Review principles

1. **Local-first analysis**
   Clone locally and use local grep/search/indexing. Avoid per-file GitHub browsing once the repo is cloned.

2. **Proof over vibes**
   Do not label something a vulnerability unless there is a concrete code-path argument or a working reproduction.

3. **Threat-model alignment**
   Always tie findings back to the actual deployment model: internal artifact proxy/cache for a small startup or home lab.

4. **Prefer narrow, high-value findings**
   Good examples:
   - SSRF via redirects or token realm abuse
   - authz bypass between repositories
   - cache poisoning or path confusion
   - package name/path traversal or normalization bugs
   - storage exhaustion or unbounded upload paths

5. **Separate product risk from code bugs**
   Examples of product/deployment risk:
   - feature sprawl
   - immature project processes
   - dangerous optional features enabled by default

6. **Capture upstream contribution ideas**
   If a hardening improvement is small and actionable, write it down as a potential PR even if it is not a confirmed vulnerability.

---

## Recommended work order

1. bootstrap local repo and identify the exact files for:
   - proxy service
   - shared HTTP client setup
   - URL validation
   - auth middleware
   - PyPI/npm/Maven/Cargo handlers

2. do a targeted static review of common code paths

3. stand up a local test harness and attempt hostile cases:
   - redirect-based SSRF
   - weird package/path names
   - oversized uploads
   - repo-scope auth bypass attempts
   - cache poisoning attempts

4. capture findings as:
   - confirmed bug
   - plausible issue needing more work
   - deployment hardening recommendation

5. propose small upstream patches where possible

---

## Deliverables expected from future agents

Good deliverables include:
- a threat model focused on internal artifact proxy/cache use
- a file/function map of the important code paths
- a shortlist of confirmed findings with reproduction steps
- a shortlist of hardening recommendations
- candidate upstream PRs

Avoid bloated deliverables that try to audit every feature in the product.

---

## Communication style

- be precise
- be skeptical
- state uncertainty clearly
- do not guess when local code or testing can answer the question
- if something is an inference, label it as an inference
- if a finding depends on configuration, say so explicitly

---

## Suggested first commands

These are examples only; adapt to the local environment.

```bash
git clone https://github.com/artifact-keeper/artifact-keeper.git
cd artifact-keeper
rg -n "reqwest|Client::builder|redirect|proxy|validate.*url|ssrf|auth|middleware|cargo|pypi|npm|maven|plugin|wasm"
```

Then build a local file map before going deeper.
