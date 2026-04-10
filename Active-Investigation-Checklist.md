# Active Investigation Checklist

Priority order: SSRF/fetch → format handlers → authz → resource exhaustion → plugins.
Check items off as completed. Reference findings by number where written up.

---

## 1. Shared Outbound Request Path (SSRF / Redirects)

> Central to the proxy/cache use case. One bug here turns the service into an internal pivot point.

### 1a. Map the outbound fetch infrastructure

- [x] Locate shared HTTP client construction (`reqwest::Client`, `Client::builder`) → [000-code-map](findings/000-code-map.md)
- [x] Locate proxy service / upstream fetch helper
- [x] Locate URL validation helpers (`validate_url`, SSRF guard)
- [x] Identify redirect policy
- [x] Review DNS resolution handling
- [ ] Review custom CA / TLS options
- [ ] Check env proxy usage (`HTTP_PROXY` / `HTTPS_PROXY` behavior in server mode)

### 1b. Answer key SSRF questions

- [x] Does it validate only the original URL, or also the final redirect target? → **Original only; redirects not re-validated** → [001-ssrf-via-redirects](findings/001-ssrf-via-redirects.md)
- [x] Does it block private IPs only by hostname string, or after DNS resolution too? → **Hostname string only; no post-resolution check**
- [x] IPv6 private ranges blocked? → **No** → [002-ipv6-private-ranges](findings/002-ipv6-private-ranges.md)
- [ ] Can an upstream return a token realm / secondary URL / metadata URL fetched without equivalent validation?
- [ ] Does it honor `HTTP_PROXY` / `HTTPS_PROXY` unexpectedly in server mode?
- [x] K8s service-name allowance reviewed → [004-k8s-service-name-allowance](findings/004-k8s-service-name-allowance.md)

### 1c. Draw the full outbound fetch path

- [ ] Document end-to-end: request in → handler constructs upstream URL → validation → client sends → redirects → auth challenge / token realm → response streamed/rewritten back to client

---

## 2. Format Handlers (PyPI / npm / Maven / Cargo)

> If the shared fetch path is okay, format-specific URL construction and name handling are the next likely bug class.

### 2a. PyPI

- [ ] Path normalization review
- [ ] URL joining / construction bugs
- [ ] Package name encoding (PEP 503 normalization)
- [ ] Checksum handling / cache poisoning
- [ ] Metadata rewriting safety
- [ ] Public read vs authenticated write path differences
- [ ] Private authenticated upstream (Chainguard use case) — see §2e below

### 2b. npm

- [ ] Path normalization review
- [ ] Scoped package name handling (`@scope/pkg`)
- [ ] URL joining / construction bugs
- [ ] Checksum / integrity field handling
- [ ] Metadata rewriting safety
- [ ] Public read vs authenticated write path differences

### 2c. Maven

- [ ] Path normalization review (GAV coordinates → path)
- [ ] URL joining / construction bugs
- [ ] Checksum handling (`.sha1`, `.md5`, `.sha256`)
- [ ] Metadata rewriting safety (`maven-metadata.xml`)
- [ ] Snapshot version handling
- [ ] Public read vs authenticated write path differences

### 2d. Cargo

- [ ] Path normalization review
- [ ] URL joining / construction bugs
- [ ] Crate name encoding
- [ ] Checksum handling
- [ ] Index metadata rewriting safety
- [ ] Public read vs authenticated write path differences

### 2e. Private Authenticated Upstream (Chainguard)

> Chainguard upstreams use Basic auth where the username may contain special characters and the password is a JWT. Verify this works end-to-end.

- [ ] Confirm `upstream_auth` API accepts and stores arbitrary special chars in username
- [ ] Confirm JWT-length passwords (long, with dots/base64 chars) survive encrypt → store → decrypt → apply round-trip
- [ ] Verify `apply_upstream_auth()` delegates to reqwest `basic_auth()` (RFC 7617 base64, not URL-encoded) — no truncation or mangling
- [ ] Test: configure a PyPI proxy repo with Chainguard-style credentials and verify upstream fetch succeeds
- [ ] Check whether credential errors (401 from upstream) are surfaced clearly vs silently cached as failures
- [ ] Review: are upstream credentials ever logged, leaked in error messages, or included in audit log entries?

---

## 3. Authz on Repo Boundaries

> Multi-tenant internal cache needs repo isolation. More tedious than SSRF but critical.

- [ ] Review shared auth middleware and identify all bypass points
- [ ] Verify: public repo reads vs private repo reads enforced correctly
- [ ] Verify: write operations always require auth
- [ ] Verify: token scoped to repo A cannot read or write repo B
- [ ] Verify: admin endpoints do not accidentally inherit weaker repo-reader semantics
- [ ] Verify: per-format handlers do not special-case around common auth checks
- [ ] Check SSO/OIDC integration paths for auth bypass or misconfiguration risks

---

## 4. Upload / Resource Exhaustion Controls

> A registry that can be trivially disk-killed is a real business continuity issue.

- [x] Request body / upload size limits reviewed → **quota_bytes field exists but is not enforced** → [003-upload-no-quota-enforcement](findings/003-upload-no-quota-enforcement.md)
- [ ] Per-format upload limit enforcement
- [ ] Temp file handling and cleanup on failure
- [ ] Partial upload cleanup
- [ ] Streaming vs buffering behavior
- [ ] Decompression / archive expansion paths (zip bombs, tar bombs)
- [ ] Disk quota assumptions documented

---

## 5. WASM Plugin System (High-Risk Optional Surface)

> For our use case, plugins are "extra risk until proven needed." Review enough to decide whether to disable.

- [x] Surface area reviewed → [005-wasm-plugin-surface](findings/005-wasm-plugin-surface.md)
- [x] Can we disable them cleanly? → **Yes, do not configure; but no explicit kill switch**
- [x] Are they installable from arbitrary remote sources? → **Yes, reviewed in finding**
- [x] Is source pinning / verification present? → **No, reviewed in finding**
- [x] What host capabilities are exposed to WASM? → **Reviewed in finding**
- [ ] Recommendation: confirm "disable by policy" is sufficient or propose upstream kill-switch PR

---

## 6. Contribution Ideas / Upstream PRs

- [x] Format allowlist (per-format enable/disable) → [006-format-allowlist-contribution](findings/006-format-allowlist-contribution.md)
- [ ] SSRF redirect re-validation patch
- [ ] IPv6 private range blocking patch
- [ ] Upload quota enforcement wiring
- [ ] WASM plugin explicit disable config flag

---

## Cross-Cutting Notes

- Findings live in `findings/` — one file per topic, numbered
- Every finding must include receipts: links to source at the pinned SHA
- Distinguish: **confirmed issue** vs **plausible issue** vs **deployment risk**

### Pinned subtree commits

| Subtree | Pinned SHA |
|---|---|
| `artifact-keeper/` | `fb2fcd799c9a87b49f2170f1f46bc26bb902500f` |
| `artifact-keeper-web/` | `10fd8569b6e91ad174867b45a971a55880029964` |
| `artifact-keeper-iac/` | `583adb7d3f885ccb0b5e77a894ef89af374f1f96` |
| `artifact-keeper-api/` | `4d7d207f839b81ca4e11b6fb70fc7efd35d85a7d` |
| `artifact-keeper-example-plugin/` | `23d495209d8761dd14b71c2468c570a8b5156d28` |

---

## 7. Frontend — artifact-keeper-web (Next.js / TypeScript)

> Secondary review target. Focus on auth token handling, XSS, and client-side config.

- [ ] Auth token storage mechanism (localStorage? cookies? httpOnly?)
- [ ] API URL configuration — CORS and origin validation implications
- [ ] XSS vectors in artifact metadata display (package names, descriptions, versions)
- [ ] Client-side secrets or credentials in code/config/env
- [ ] npm dependency review (supply chain risk, outdated packages)
- [ ] CSP headers and other security headers in Next.js config

---

## 8. Infrastructure — artifact-keeper-iac (Helm / Terraform / ArgoCD)

> Review for deployment security defaults. These templates define the actual attack surface in production.

- [ ] Helm chart defaults: RBAC roles, NetworkPolicy, PodSecurityStandards
- [ ] Terraform defaults: security groups, IAM policies, RDS encryption, public access
- [ ] Secrets management: how are DB creds, API keys, TLS certs provisioned?
- [ ] IRSA (IAM Roles for Service Accounts): properly scoped?
- [ ] Default service exposure: ingress config, service type, TLS termination
- [ ] Monitoring: are security-relevant events (auth failures, SSRF attempts) alerted on?
- [ ] Container image provenance and scanning config (Trivy, Dependency-Track)

---

## 9. API Spec — artifact-keeper-api (OpenAPI 3.1)

> Light review. The spec is auto-generated from backend annotations.

- [ ] Audit auth requirements per endpoint group — any sensitive ops missing auth?
- [ ] Review API surface area (277 operations / 24 groups) — excessively broad?
- [ ] SDK generation: no credential leaks in generated client code
- [ ] Spectral linting rules: do they catch security-relevant API patterns?

---

## 10. WASM Plugin Examples — artifact-keeper-example-plugin

> Review in context of finding 005 (WASM plugin surface).

- [ ] WIT interface contract: what host capabilities are exposed to plugins?
- [ ] Plugin install endpoint: auth required? Source validation?
- [ ] Reference implementations: do they demonstrate insecure patterns that plugin authors will copy?
- [ ] PyPI plugin: PEP 503 normalization correctness (relevant to format handler review §2a)
