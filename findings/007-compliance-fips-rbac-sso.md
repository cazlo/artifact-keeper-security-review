# Finding 007 — Compliance Posture: FIPS, RBAC, SSO, Encryption, and Audit Logging

**Status:** Mixed — confirmed application code issues, IaC default gaps, deployment hardening recommendations  
**Severity:** Critical (OIDC signature bypass), High (RBAC not enforced, gRPC reflection), Medium–Low (others)  
**Subtree commits:**
- artifact-keeper: `fb2fcd799c9a87b49f2170f1f46bc26bb902500f`
- artifact-keeper-iac: `583adb7d3f885ccb0b5e77a894ef89af374f1f96`
- artifact-keeper-web: `10fd8569b6e91ad174867b45a971a55880029964`

**IaC license note:** The `artifact-keeper-iac` repo does not currently have a license file ([issue #59](https://github.com/artifact-keeper/artifact-keeper-iac/issues/59)). All IaC references below should be treated as **inspiration for your own deployment templates**, not as directly usable code, until a license is granted.

---

## Context

This finding covers compliance-relevant features — FIPS, STIG hardening, RBAC, SSO (OIDC/SAML/LDAP), encryption, audit logging, gRPC security, credential bootstrapping, and Kubernetes/Terraform defaults — assessed against realistic deployment in a FedRAMP-adjacent or high-security startup environment.

The project demonstrates intentional security awareness that's uncommon for young open-source projects. However, several gaps exist between the aspirational infrastructure and actual enforcement.

Findings are clearly separated into:
- **Application issues** (artifact-keeper backend/frontend — MIT-licensed, directly reviewable)
- **IaC observations** (artifact-keeper-iac — unlicensed, treat as reference/inspiration only)

---

# Part A: Application Issues (artifact-keeper backend)

These are code-level findings in the MIT-licensed backend. They represent bugs or gaps in the application itself, independent of how it's deployed.

---

## A1. OIDC ID Token Signature Not Verified — CRITICAL

**Status:** Confirmed code-path issue

The OIDC service decodes ID tokens by manually base64-decoding the JWT payload **without verifying the cryptographic signature** against the IdP's JWKS (JSON Web Key Set).

**File:** [`backend/src/services/oidc_service.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/services/oidc_service.rs)

```rust
// Line 324:
// Decode JWT without verification (validation should use JWKS in production)
// The token format is: header.payload.signature
let parts: Vec<&str> = id_token.split('.').collect();
// ...
let decoded = base64_decode_url_safe(&padded)
    .map_err(|e| AppError::Authentication(format!("Failed to decode ID token: {}", e)))?;
let claims: IdTokenClaims = serde_json::from_slice(&decoded).map_err(|e| {
    AppError::Authentication(format!("Failed to parse ID token claims: {}", e))
})?;
```

**What IS validated:**
- Issuer match (line ~352)
- Audience contains `client_id` (line ~358)
- Token expiration (line ~363)

**What IS NOT validated:**
- JWT signature (no JWKS fetch, no `jsonwebtoken::decode()` with `DecodingKey`)
- The code even has a comment acknowledging this: *"validation should use JWKS in production"*
- The `jwks_uri` is retrieved from discovery (line 78) but never used for token verification

**Impact:** An attacker who can inject a crafted JWT into the OIDC callback flow (e.g., via a compromised or spoofed IdP, or a man-in-the-middle if TLS is misconfigured) can forge a valid-looking token that will be accepted. This is a fundamental break in the OIDC trust chain.

**FedRAMP relevance:** Fails NIST SP 800-63B (authentication assurance) and AC-17 (remote access). OIDC without signature verification is equivalent to trusting unsigned assertions.

**Recommendation:** Use `jsonwebtoken::decode()` with keys fetched from the IdP's JWKS endpoint. Cache the JWKS with appropriate TTL. The discovery document already provides `jwks_uri`.

---

## A2. RBAC Model Exists But Is Not Enforced — HIGH

**Status:** Confirmed code-path gap

The database schema and Rust models define a proper RBAC system with roles, permission grants (Read/Write/Delete/Admin), and per-repository scoping. However, **no middleware or handler code checks these permission grants**.

**Models defined in:** [`backend/src/models/role.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/models/role.rs)

```rust
pub enum PermissionType { Read, Write, Delete, Admin }

pub struct PermissionGrant {
    pub role_id: Uuid,
    pub repository_id: Option<Uuid>,  // Repo-scoped or global
    pub permission: PermissionType,
}

pub struct RoleAssignment {
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub repository_id: Option<Uuid>,
}
```

**Role assignment is wired up** — admin endpoints exist at `PUT /api/v1/users/{id}/roles` and `DELETE /api/v1/users/{id}/roles/{role_id}` (see [`backend/src/api/handlers/users.rs`, lines 538–600](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/api/handlers/users.rs)).

**What actually enforces authorization:**
- Binary `is_admin` flag on the User model (coarse-grained)
- `admin_middleware` checks `is_admin == true`
- `auth_middleware` checks token validity (any authenticated user)
- `repo_visibility_middleware` checks public/private repo status + token scopes
- API token scopes (e.g., `read:artifacts`, `write:artifacts`)

**What does NOT happen:**
- No middleware or handler queries the `permission_grants` table
- No code checks whether a user's assigned role grants the required `PermissionType` for the current operation on the current repository
- Searching for `check_permission`, `has_permission`, `enforce_permission`, `permission_grant` across the entire backend source yields **zero hits** outside the model definition

**Impact:** The auth model is effectively: admin (full access) vs. authenticated user (all repos of matching visibility) vs. anonymous (public repos only). There is no way to grant a user write access to repo A but not repo B — the RBAC tables exist but are decoration.

**FedRAMP relevance:** Fails AC-3 (access enforcement), AC-6 (least privilege). FedRAMP requires role-based access control with per-resource granularity, not just admin/non-admin.

**Workaround for near-term deployment:** API token scopes + `repo_selector` restrictions are enforced at the middleware level and can approximate per-repo least-privilege for CI/CD service accounts. This does not help for human users authenticating via SSO/password.

---

## A3. gRPC Reflection Exposed Without Authentication — HIGH

**Status:** Confirmed code-path issue

The gRPC server (port 9090) exposes 3 services with 17 RPC methods (SBOM lifecycle, CVE tracking, security policy CRUD). All RPC methods require admin JWT authentication via an interceptor. However, **the gRPC reflection service is added without an interceptor**, allowing unauthenticated enumeration.

**File:** [`backend/src/main.rs`, lines 559–573](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/main.rs)

```rust
if let Err(e) = TonicServer::builder()
    .add_service(reflection_service)  // ← NO interceptor
    .add_service(SbomServiceServer::with_interceptor(
        sbom_server,
        sbom_interceptor,
    ))
    // ...
```

**Impact:** An unauthenticated attacker on the network can:
1. Enumerate all gRPC services via `grpcurl -plaintext backend:9090 list`
2. Discover all RPC methods and message schemas via `grpcurl -plaintext backend:9090 describe`
3. Learn exact field names (artifact_id, sbom_id, repository_id) for crafting requests

The project's own [red team test #06](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/scripts/redteam/tests/06-grpc-unauth.sh) confirms this finding — it tests for and flags the enumeration.

**Additional gRPC concerns:**
- No TLS on gRPC (plaintext TCP on 0.0.0.0:9090)
- No per-method or per-repository authorization — all admin users have equal access to all gRPC operations
- `DeleteSbom`, `UpdateCveStatus`, `UpsertLicensePolicy` are destructive operations accessible to any admin

**Recommendation:** Conditionally enable reflection (e.g., `GRPC_ENABLE_REFLECTION=false` in production). Alternatively, wrap the reflection service with the auth interceptor.

**Istio mTLS mitigation note:** Deploying with Istio auto-mTLS addresses the plaintext TCP concern — all pod-to-pod traffic including gRPC would be encrypted with mutual TLS and identity-bound via SPIFFE. However, Istio mTLS does **not** prevent reflection enumeration: any pod within the mesh with a valid sidecar certificate can still reach `backend:9090` and call the reflection API. An Istio `AuthorizationPolicy` restricting source workloads on port 9090 would further limit this, but the correct fix remains disabling reflection in production or wrapping it with the auth interceptor.

---

## A4. FIPS Configuration — Aspirational But Not Validated

**Status:** Deployment hardening observation

All production Dockerfiles configure OpenSSL FIPS mode:

**Files:**
- [`docker/Dockerfile.backend`, line 87–89](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/docker/Dockerfile.backend)
- [`docker/Dockerfile.openscap`, line 33–35](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/docker/Dockerfile.openscap)
- [`Dockerfile` (web)](https://github.com/artifact-keeper/artifact-keeper-web/blob/10fd8569b6e91ad174867b45a971a55880029964/Dockerfile)

```dockerfile
# Crypto policy: FIPS-grade defaults for OpenSSL
RUN if [ -f /mnt/rootfs/etc/pki/tls/openssl.cnf ]; then \
      echo -e "\n[algorithm_sect]\ndefault_properties = fips=yes" >> /mnt/rootfs/etc/pki/tls/openssl.cnf; \
    fi
```

**What this does:** Tells OpenSSL to prefer FIPS-validated algorithms when the FIPS provider is available.

**What this does NOT do:**
- Validate that the FIPS module is actually present and operational
- Fail if FIPS mode cannot be activated (the `if` guard silently skips if the config file is missing)
- Cover Rust-native crypto (the backend uses `bcrypt` and `jsonwebtoken` crates, which use their own crypto implementations, not OpenSSL)
- Guarantee FIPS compliance — that requires a validated binary (e.g., Red Hat's certified OpenSSL build)

**Base image:** UBI 9 (`registry.access.redhat.com/ubi9/ubi:9.7`) ships with Red Hat's FIPS-validated OpenSSL. So the setting is meaningful on this base — but only for operations that go through OpenSSL (TLS connections via reqwest/hyper, PostgreSQL connections via `sqlx` if using OpenSSL bindings).

**FIPS gaps in application crypto:**
- `bcrypt` (password hashing) uses the `blowfish` algorithm, which is **not** FIPS-approved. FIPS requires PBKDF2-SHA256, scrypt, or Argon2id for password hashing.
- `jsonwebtoken` HS256 (JWT signing) uses HMAC-SHA256, which is FIPS-compatible but runs through the crate's own implementation, not through OpenSSL's FIPS module.
- The Alpine Dockerfile variant (`Dockerfile.backend.alpine`) uses `vendored-openssl`, which is **not** the FIPS-validated Red Hat build.

**FedRAMP relevance:** SC-13 (cryptographic protection) requires FIPS 140-2/140-3 validated modules. The UBI 9 OpenSSL provider satisfies this for TLS; the application-level crypto (bcrypt, JWT) does not.

---

## A5. SAML Signature Verification — Secure Default, Optional Bypass

**Status:** Default is secure; deployment risk if misconfigured

**File:** [`backend/src/services/saml_service.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/services/saml_service.rs)

`require_signed_assertions` defaults to **`true`** (line 93–95). If no `SAML_IDP_CERTIFICATE` is configured and `require_signed_assertions` is true, the system correctly **rejects** the assertion (line ~656):

```rust
} else if self.config.require_signed_assertions {
    return Err(AppError::Authentication(
        "Signed assertions are required but no IdP certificate is configured".into(),
    ));
}
```

However, if an operator explicitly sets `SAML_REQUIRE_SIGNED_ASSERTIONS=false` and omits `SAML_IDP_CERTIFICATE`, the system will accept **unsigned SAML assertions** with only a warning log, which would allow forged authentication.

**Assessment:** The default is secure. The risk is an operator misconfiguring for "development" and leaving it in production. A startup deploy should enforce this in the Helm values or deployment documentation.

---

## A6. Audit Logging — Comprehensive Schema, Verify Invocation Coverage

**Status:** Positive with caveats

**File:** [`backend/src/services/audit_service.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/services/audit_service.rs)

The audit service defines 30 action types covering:
- **Authentication:** Login, Logout, LoginFailed, PasswordChanged, ApiTokenCreated/Revoked
- **User management:** Created, Updated, Deleted, Disabled, RoleAssigned/Revoked
- **Repository operations:** Created, Updated, Deleted, PermissionChanged
- **Artifact lifecycle:** Uploaded, Downloaded, Deleted, MetadataUpdated
- **System operations:** Backup/Restore start/complete/fail, PeerSync, SettingChanged, Plugin lifecycle

Each entry includes: `user_id`, `action`, `resource_type`, `resource_id`, `details` (JSON), `ip_address`, `correlation_id`, `created_at`.

**Caveat — not verified:** I have not confirmed that every handler that should call `AuditService::log()` actually does. For FedRAMP AU-2 (audit events) and AU-3 (audit content), each handler dealing with authentication, access control changes, and data modifications must emit audit entries. This should be verified by tracing callers of `AuditService::log()`.

**Gaps:**
- No audit log export/forwarding mechanism (SIEM integration) — required for AU-6
- No audit log retention policy configuration — required for AU-11
- Audit log is in PostgreSQL — large download volumes could create significant table bloat (`ArtifactDownloaded` events at scale)
- No tamper protection on audit records — an admin with DB access could delete entries

**Deployment recommendation — archival pattern:** For compliance retention (e.g., 1-year), export audit logs to S3 with lifecycle policies (S3 Standard → S3 Glacier after 90 days, delete after 365 days). This offloads storage from PostgreSQL, provides tamper resistance via S3 Object Lock, and satisfies AU-11 retention requirements. The application currently lacks a built-in export mechanism, so this would need to be implemented either as a scheduled job querying the `audit_entries` table or as an upstream contribution (see contribution opportunity #8).

---

## A7. Password Policy — Minimal Complexity Requirements

**Status:** Observation, low severity for internal-only deployment

**File:** [`backend/src/api/handlers/users.rs`, lines 65–102](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/api/handlers/users.rs)

Current policy:
- Minimum 8 characters, maximum 128
- Blacklist of 20 common passwords (password, qwerty123, 12345678, etc.)
- **No complexity requirements** — `abcdefgh` would pass

Initial admin bootstrap generates a random 20-character password from a 64-character alphabet (~120 bits entropy) and locks the API until it's changed (`must_change_password=true`). This is good.

**FedRAMP relevance:** IA-5 requires password complexity enforcement. For SSO-only deployments this is the IdP's responsibility, but if local accounts are used, the policy should require mixed character types or a longer minimum.

---

## A8. Rate Limiting — Per-Instance Only

**Status:** Observation, relevant for multi-replica deployments

**File:** [`backend/src/api/middleware/rate_limit.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/api/middleware/rate_limit.rs)

Rate limits are configured (default 120 auth attempts/min, 5000 API requests/min) but are **in-memory and per-instance**. With N replicas, an attacker gets N independent rate limit buckets.

Key extraction is reasonable: authenticated user ID, then `ConnectInfo` peer IP, then `X-Forwarded-For`, with `ip:unknown` as last resort.

**Recommendation:** For production, enforce rate limiting at the ingress controller level (NGINX rate_limit, AWS WAF, Envoy/Istio) rather than relying on per-pod in-process limits.

**Memory scaling analysis:** The in-process rate limiter uses `HashMap<String, (u32, Instant)>` with periodic cleanup every 60 seconds ([`routes.rs` lines 176–185](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/api/routes.rs#L176-L185) — `tokio::spawn` with `tokio::time::interval(Duration::from_secs(60))`). Each entry ≈ 150–200 bytes. In a 60-second window:
- 100 unique clients → ~20 KB (home lab / small startup)
- 10,000 unique clients → ~2 MB (unlikely for internal-only deployment)

Memory growth is **not** a practical concern for the intended deployment model. The cleanup is properly scheduled and prevents unbounded growth. The existing stress test (`scripts/stress/run-concurrent-uploads.sh 100`) would not exercise HashMap cardinality since it runs from a single host — a custom test with many source IPs would be needed to validate under adversarial conditions.

---

## A9. STIG Hardening — Good Container Baseline

**Status:** Positive observation

The Dockerfiles apply a meaningful subset of DISA STIG controls:

| Control ID | Description | Applied |
|---|---|---|
| `disable_users_coredumps` | `* hard core 0` | Yes |
| `accounts_max_concurrent_login_sessions` | `* hard maxlogins 10` | Yes |
| `no_empty_passwords` | Remove `nullok` from PAM | Yes |
| `accounts_umask_etc_login_defs` | UMASK 077 | Yes |
| `ensure_gpgcheck_local_packages` | `localpkg_gpgcheck=1` | Yes |
| CIS 6.1.13/6.1.14 (Alpine) | Remove SUID/SGID binaries | Yes |

Additionally:
- Non-root user (UID 1001) across all containers
- Machine-id cleaned for container isolation
- Read-only root filesystem in Kubernetes (via `securityContext`)

---

## A10. LDAP — Properly Implemented

**Status:** Positive observation

**File:** [`backend/src/services/ldap_service.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/services/ldap_service.rs)

- Uses search-then-bind pattern (correct for AD/LDAP)
- Supports STARTTLS and custom CA certs
- Input sanitization on LDAP filter construction
- `no_tls_verify` option exists but logs a warning

---

## A11. TOTP/2FA — Standard Implementation

**Status:** Positive observation

**File:** [`backend/src/api/handlers/totp.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/api/handlers/totp.rs)

- TOTP (RFC 6238): SHA1, 6 digits, 30-second window
- Backup codes: 10 codes, bcrypt-hashed (cost 10), single-use
- Secret generated via `totp_rs::Secret::generate_secret()`

**Note:** SHA1 is the standard for TOTP per RFC 6238 and is acceptable here — this is not the same as using SHA1 for document signing.

---

## A12. Supply Chain — Well-Maintained

**Status:** Positive observation

- **Lockfiles committed:** Both `Cargo.lock` and `package-lock.json` are in version control
- **Automated scanning:** cargo-audit (scheduled), Trivy container scanning (weekly), SonarCloud SAST, SBOM generation (CycloneDX) on Docker publish
- **Dependabot:** Configured weekly for Cargo, npm, Docker, and GitHub Actions across all repos
- **No `unsafe` in production code:** All `unsafe` blocks are test-only (env var manipulation in test teardown)
- **Base image pinning:** Tag-based only (e.g., `ubi9/ubi:9.7`), not digest-pinned. Acceptable for UBI but digest pinning would be more rigorous.
- **Niche dependency note:** `bergshamra` (XML digital signatures for SAML) is a small, single-maintainer crate. Monitor for security updates.

---

## A13. CORS — Safe Production Default

**Status:** Positive observation

**File:** [`backend/src/main.rs`, lines ~400–470](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/main.rs)

- Production mode: CORS only if `CORS_ORIGINS` env var is explicitly set; otherwise same-origin only
- Development mode: allows private network IPs (192.168.*, 10.*, etc.) + localhost
- Credentials only enabled in dev mode

---

## A14. Encryption at Rest and in Transit

### At rest (application level):
- **PostgreSQL data:** Protected by whatever the database host provides (see IaC section for Terraform defaults)
- **Artifact files on local storage:** No application-level encryption of files on disk
- **S3 storage:** Relies on bucket-level encryption configuration (not explicitly set by the application)

### In transit (application level):
- **Outbound HTTP client:** Custom CA supported (`CUSTOM_CA_CERT_PATH`). **`S3_INSECURE_TLS=true` exists** and disables certificate verification — must never be used in production.
- **No explicit TLS version pinning** in the HTTP client — relies on system OpenSSL defaults (TLS 1.2+ on UBI 9)
- **gRPC:** Plaintext TCP by default on port 9090, no TLS configured
- **Internal service communication:** No mTLS between backend and Meilisearch/Trivy/DependencyTrack

---

# Part B: IaC Observations (artifact-keeper-iac)

**Important:** The `artifact-keeper-iac` repo has no license file ([issue #59](https://github.com/artifact-keeper/artifact-keeper-iac/issues/59)). These observations are provided as **reference for building your own deployment templates**, not as an endorsement to use the IaC code directly.

---

## B1. Helm Chart — Strong Pod Security, Weak Defaults Elsewhere

### What the Helm chart does well:
All pod templates include hardened security contexts:
- `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`
- `capabilities.drop: [ALL]`
- `automountServiceAccountToken: false`
- Resource limits defined for all workloads
- Liveness/readiness/startup probes configured

**Files:** [`charts/artifact-keeper/templates/backend-deployment.yaml`](https://github.com/artifact-keeper/artifact-keeper-iac/blob/583adb7d3f885ccb0b5e77a894ef89af374f1f96/charts/artifact-keeper/templates/backend-deployment.yaml), [`web-deployment.yaml`](https://github.com/artifact-keeper/artifact-keeper-iac/blob/583adb7d3f885ccb0b5e77a894ef89af374f1f96/charts/artifact-keeper/templates/web-deployment.yaml)

### Defaults that need overriding for compliance:

| Setting | Default | Required | NIST Control |
|---|---|---|---|
| `networkPolicy.enabled` | `false` | `true` | AC-4 (traffic control) |
| `ingress.tls.enabled` | `false` | `true` + cert-manager | SC-8 (transmission confidentiality) |
| `secrets.jwtSecret` | `"dev-secret-change-in-production"` | Override via ExternalSecrets | IA-5 (authenticator management) |
| `backend.env.ADMIN_PASSWORD` | `"admin"` | Override via ExternalSecrets | IA-5 |
| `postgres.auth.password` | `"registry"` | Override via ExternalSecrets | IA-5 |
| `meilisearch.masterKey` | `"artifact-keeper-dev-key"` | Override via ExternalSecrets | IA-5 |
| `dependencyTrack.adminPassword` | `"ArtifactKeeper2026!"` | Override via ExternalSecrets | IA-5 |
| Pod Security Standards | Not set | `restricted` enforce label | CM-7 (least functionality) |
| Pod Disruption Budgets | `false` | `true` for HA | CP-10 (system recovery) |
| HPA autoscaling | `false` | Enable for production | SC-5 (DoS protection) |

**File:** [`charts/artifact-keeper/values.yaml`](https://github.com/artifact-keeper/artifact-keeper-iac/blob/583adb7d3f885ccb0b5e77a894ef89af374f1f96/charts/artifact-keeper/values.yaml)

**Mitigation available:** A production overlay (`values-production.yaml`) blanks all secrets and enables ExternalSecrets Operator integration. Any deployment **must** use the production overlay or equivalent.

### NetworkPolicy — Well-Designed But Off

When enabled, the chart defines 6 network policies with proper microsegmentation:
- Backend: ingress from web/edge only; egress to PostgreSQL, internal services, HTTPS
- Web: ingress from nginx-ingress; egress to backend + DNS
- PostgreSQL: ingress from backend + DependencyTrack only
- Meilisearch/Trivy/DependencyTrack: properly scoped

**File:** [`charts/artifact-keeper/templates/networkpolicy.yaml`](https://github.com/artifact-keeper/artifact-keeper-iac/blob/583adb7d3f885ccb0b5e77a894ef89af374f1f96/charts/artifact-keeper/templates/networkpolicy.yaml)

**Issue within NetworkPolicy:** `namespaceSelector: {}` for Prometheus scraping matches ANY namespace. Should be scoped to `namespace: monitoring` or equivalent.

### No Kubernetes RBAC Templates

The chart creates ServiceAccounts but **no Role, ClusterRole, RoleBinding, or ClusterRoleBinding**. The backend pod runs with default SA permissions, which is acceptable if `automountServiceAccountToken: false` (it is), but explicit minimal RBAC would be better practice.

### gRPC Port Exposed as ClusterIP Service

gRPC port 9090 is exposed as a Kubernetes Service (`ClusterIP` type), which means it's accessible from any pod in the cluster. With NetworkPolicy disabled (default), this means the unauthenticated reflection endpoint (finding A3) is reachable from any namespace.

---

## B2. Terraform — Solid Foundations, Production-Unsafe Defaults

### What Terraform does well:
- **EKS IAM:** Properly scoped assume-role policies for cluster and node roles
- **IRSA:** OIDC provider configured for service account IAM binding
- **RDS:** `storage_encrypted = true`, security group restricts to EKS nodes only
- **RDS password:** 32-character random, stored in AWS Secrets Manager
- **VPC:** Public/private subnet separation across 3 AZs, NAT gateway for private egress
- **S3:** Public access blocked (`block_public_acls`, `block_public_policy`, `restrict_public_buckets`, `ignore_public_acls`)

### Terraform defaults needing override:

| Setting | Default | Required | NIST Control |
|---|---|---|---|
| EKS secrets encryption | **Not configured** | Add `encryption_config` with KMS key | SC-28 (data at rest) |
| EKS cluster logging | Optional (empty list) | All 5 types: api, audit, authenticator, controllerManager, scheduler | AU-2 (audit events) |
| EKS public endpoint | Configurable | Set `false` for VPC-only | AC-17 (remote access) |
| RDS multi-AZ | `false` | `true` | CP-10 (system recovery) |
| RDS deletion protection | `false` | `true` | CP-9 (system backup) |
| VPC Flow Logs | Optional | Enable | AU-12 (audit generation) |

**Critical gap — EKS secrets encryption:**

**File:** [`terraform/modules/eks/main.tf`](https://github.com/artifact-keeper/artifact-keeper-iac/blob/583adb7d3f885ccb0b5e77a894ef89af374f1f96/terraform/modules/eks/main.tf)

The `aws_eks_cluster` resource at line ~95 has **no `encryption_config` block**. Kubernetes Secrets (including JWT secrets, DB passwords, API tokens) would be stored unencrypted in etcd. For FedRAMP SC-28, this must include:

```hcl
encryption_config {
  provider {
    key_arn = aws_kms_key.eks_secrets.arn
  }
  resources = ["secrets"]
}
```

---

## B3. Helm Hardcoded Credentials in Default Values

**Status:** Expected for dev convenience, but creates risk of accidental production use

**File:** [`charts/artifact-keeper/values.yaml`](https://github.com/artifact-keeper/artifact-keeper-iac/blob/583adb7d3f885ccb0b5e77a894ef89af374f1f96/charts/artifact-keeper/values.yaml)

| Line | Key | Value |
|---|---|---|
| ~101 | `backend.env.ADMIN_PASSWORD` | `"admin"` |
| ~214 | `postgres.auth.password` | `"registry"` |
| ~267 | `meilisearch.masterKey` | `"artifact-keeper-dev-key"` |
| ~327 | `dependencyTrack.adminPassword` | `"ArtifactKeeper2026!"` |
| ~366 | `secrets.jwtSecret` | `"dev-secret-change-in-production"` |
| ~367-368 | `secrets.s3AccessKey/s3SecretKey` | `"minioadmin"` / `"minioadmin-secret"` |

Also in mesh variants: `values-mesh-main.yaml` and `values-mesh-peer.yaml` both ship `ADMIN_PASSWORD: "admin"`.

The code comment on line ~364 warns never to commit real credentials. The production overlay correctly blanks these.

---

## B4. CORS Annotation in Ingress

**File:** [`charts/artifact-keeper/values.yaml`, line ~349](https://github.com/artifact-keeper/artifact-keeper-iac/blob/583adb7d3f885ccb0b5e77a894ef89af374f1f96/charts/artifact-keeper/values.yaml)

The ingress template includes `nginx.ingress.kubernetes.io/enable-cors: "true"` — this enables CORS at the ingress level with default (permissive) settings, separate from the application-level CORS handling. For production, either:
- Remove the ingress CORS annotation and rely on the application's CORS handling (which is safe-by-default), or
- Explicitly configure `cors-allow-origin` in the ingress annotations

---

# Part C: Summary Tables

## Application Blockers (must fix before FedRAMP-adjacent production)

| # | Finding | NIST Control | Severity | Effort |
|---|---|---|---|---|
| A1 | OIDC JWT signature not verified | IA-8, AC-17 | **Critical** | Medium PR |
| A2 | RBAC model not enforced at middleware | AC-3, AC-6 | **High** | Large PR |
| A3 | gRPC reflection unauthenticated | AC-3 | **High** | Small PR |

## Application Hardening Recommendations

| # | Finding | NIST Control | Severity |
|---|---|---|---|
| A4 | FIPS config aspirational, bcrypt not FIPS-approved | SC-13 | Medium |
| A6 | Audit log coverage/export not verified | AU-2, AU-6 | Medium |
| A7 | Password policy lacks complexity requirements | IA-5 | Low |
| A8 | Rate limiting per-instance only | SC-5 | Low |
| A14 | No TLS version pinning, gRPC plaintext, no mTLS | SC-8 | Medium |

## IaC Observations (inspiration, not directly usable — no license)

| # | Observation | NIST Control | Severity |
|---|---|---|---|
| B1 | NetworkPolicy disabled by default | AC-4 | Medium |
| B1 | No Pod Security Standards enforcement | CM-7 | Medium |
| B1 | No K8s RBAC templates | AC-2 | Medium |
| B2 | No EKS secrets encryption in etcd | SC-28 | **High** |
| B2 | EKS audit logging optional | AU-2 | **High** |
| B2 | RDS multi-AZ and deletion protection off | CP-9, CP-10 | Medium |
| B3 | Hardcoded dev credentials in values.yaml | IA-5 | Medium |

## Positive Signals (application)

- STIG-derived container hardening with real XCCDF rule IDs
- Audit logging infrastructure: 30 event types with IP, correlation ID, structured details
- Password hashing: bcrypt cost-12 with timing-safe verification
- API token system: scope enforcement, repo selectors, revocation tracking, cached lookups
- SAML: defaults to requiring signed assertions
- LDAP: search-then-bind, STARTTLS, CA cert support, filter sanitization
- TOTP: standard RFC 6238, bcrypt-hashed single-use backup codes
- CORS: safe-by-default in production mode
- Admin bootstrap: random 20-char password, API locked until changed, file permissions 0o600
- Supply chain: lockfiles committed, cargo-audit + Trivy + SonarCloud in CI, Dependabot across all repos, no unsafe in production code

## Positive Signals (IaC — for reference)

- Pod security contexts consistently applied (non-root, read-only rootfs, drop ALL)
- `automountServiceAccountToken: false` on all pods
- ExternalSecrets Operator integration in production profile
- NetworkPolicy template well-designed when enabled (6 policies, proper microsegmentation)
- RDS storage encryption enabled by default
- S3 public access blocked
- VPC with public/private subnet separation

## Upstream Contribution Opportunities

1. **OIDC JWKS verification** — Implement proper signature validation using the `jwks_uri` from discovery. Medium-sized PR.
2. **RBAC enforcement middleware** — Wire the existing model into request handling. Large PR, architectural.
3. **gRPC reflection guard** — Add env-var-controlled conditional for reflection. Small PR.
4. **Fail-closed FIPS check** — Startup check that OpenSSL FIPS mode is active, not just configured. Small PR.
5. **TLS version pinning** — Add `min_tls_version(reqwest::tls::Version::TLS_1_2)` to shared HTTP client. Small PR.
6. **bcrypt → Argon2id** — Replace non-FIPS-approved password hashing. Medium PR.
7. **Password complexity** — Add mixed-character or minimum-12-char requirement. Small PR.
8. **Audit log export** — Add syslog/webhook/S3 export for SIEM integration. Medium PR.

---

# Part D: Deployment Architecture Notes

These notes capture deployment-specific observations for operators building their own infrastructure around artifact-keeper.

## D1. Service Mesh — Istio Preferred Over nginx-ingress

The IaC Helm chart templates reference `nginx.ingress.kubernetes.io` annotations (B4) and the NetworkPolicy templates assume nginx-ingress as the ingress controller. For a new deployment:

- **Istio** provides auto-mTLS between all pods (addresses A14 mTLS gap and A3 plaintext gRPC), identity-based AuthorizationPolicy, and traffic management without separate ingress controller.
- **nginx-ingress** (now `ingress-nginx`) has a history of CVEs and is a less capable alternative for clusters already running a service mesh.
- Istio's `PeerAuthentication` in STRICT mode enforces mTLS cluster-wide, covering backend↔PostgreSQL, backend↔Meilisearch, and backend↔Trivy — none of which have application-level TLS.
- The gRPC port (9090) can be restricted via Istio `AuthorizationPolicy` to allow traffic only from specific source workloads, providing defense-in-depth even if reflection remains enabled.

**Note:** Istio mTLS validates pod identity but does not replace application-level auth. An attacker who compromises any pod in the mesh can still reach gRPC 9090 with a valid mTLS certificate. The A3 fix (disable reflection or add auth interceptor) remains necessary.

## D2. Secrets Injection — ExternalSecrets vs. secrets-store-csi-driver

The current IaC uses **ExternalSecrets Operator** with AWS Secrets Manager:
- ExternalSecrets CRD → syncs to K8s Secret → injected as **environment variables** via `secretKeyRef`
- Path: AWS Secrets Manager → ExternalSecrets controller → K8s Secret → env var

An alternative production pattern uses **secrets-store-csi-driver**:
- Secrets mounted as **files in a tmpfs volume**, never materialized as K8s Secret objects
- Avoids secrets existing as K8s Secret resources (which are base64 in etcd, visible via `kubectl get secret`)
- Path: AWS Secrets Manager → CSI driver → volume mount → file on tmpfs

**Tradeoffs:**
| | ExternalSecrets (env var) | secrets-store-csi (volume mount) |
|---|---|---|
| K8s Secret object created | Yes | Optional (sync feature) |
| Visible via `kubectl get secret` | Yes (base64) | No (unless sync enabled) |
| Application code change | None (`std::env::var`) | Must read from file path |
| Secret rotation | Controller polls (1h default) | CSI driver polls |
| Complexity | Lower | Higher (CSI driver + provider) |
| EKS secrets encryption dependency | High (secrets in etcd) | Low (secrets only on tmpfs) |

The artifact-keeper backend reads all secrets from environment variables (`std::env::var`). Using secrets-store-csi would require code changes to read from file paths, or use the CSI driver's sync-to-K8s-Secret feature (which negates some of the benefit).

For the intended deployment: if EKS secrets encryption (B2 fix) is applied and RBAC restricts `kubectl get secret`, ExternalSecrets via env vars is pragmatically acceptable. If the threat model includes etcd compromise or cluster-admin escalation, secrets-store-csi is the stronger choice.

## D3. TLS Certificate Management — cert-manager

The Helm chart's ingress TLS defaults to disabled (B1). For production:
- **cert-manager** with Let's Encrypt (external) or a private CA (internal) provides automated certificate lifecycle
- For internal-only deployment behind Teleport or VPN, a private CA via cert-manager's `CA` issuer is simpler than ACME
- Istio's built-in CA handles mTLS certificates automatically — cert-manager is only needed for the ingress edge (if exposed externally) or for the gRPC endpoint if it needs its own TLS

## D4. Audit Log Retention Architecture

For AU-11 (audit record retention) compliance:
1. **Short-term:** PostgreSQL `audit_entries` table serves active queries and dashboard views
2. **Archival:** Scheduled export (e.g., daily cron job) to S3 with lifecycle policies:
   - S3 Standard: 0–90 days (active retrieval)
   - S3 Glacier: 90–365 days (compliance archive)
   - Delete after 365 days (or per retention policy)
3. **Tamper protection:** S3 Object Lock (compliance mode) prevents deletion during retention period
4. **PostgreSQL cleanup:** After successful export, truncate old entries to prevent table bloat from high-volume `ArtifactDownloaded` events

This pattern requires an external job — the application has no built-in export mechanism (see upstream contribution opportunity #8).
