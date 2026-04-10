# Finding 004 — K8s Service-Name SSRF Allowance (By-Design Risk)

**Status:** Deployment risk — by design, but worth explicit operator awareness  
**Severity:** Low (requires privileged access to configure remote repos; no code bug)  
**Subtree commit:** `fb2fcd799c9a87b49f2170f1f46bc26bb902500f`

---

## Summary

`validate_outbound_url` explicitly allows single-label hostnames (e.g., `nexus`, `harbor`, `postgres`) as upstream URLs, because Kubernetes intra-namespace service names are single-label. This is a documented design trade-off, but it creates a meaningful SSRF surface in any Kubernetes deployment: **any service in the same namespace (or accessible namespace) can be configured as an upstream repository URL** without triggering the SSRF guard.

---

## Code path

**File:** [`backend/src/api/validation.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/api/validation.rs)

```rust
// Block known internal/metadata hostnames
let blocked_hosts = [
    "localhost",
    "metadata.google.internal",
    "metadata.azure.com",
    "169.254.169.254",
    "backend",
    "postgres",
    "redis",
    "meilisearch",
    "trivy",
];
```

The blocklist is a small hardcoded set. Any hostname not on this list — including any Kubernetes service name that the deployer didn't anticipate — passes validation.

The test suite documents this as intentional:

```rust
#[test]
fn test_allows_k8s_service_name() {
    // K8s deployments use single-label hostnames for intra-namespace services.
    // These must be allowed for remote repos pointing at other services.
    assert!(validate_outbound_url("http://nexus:8081/repository/pypi", "Test URL").is_ok());
}

#[test]
fn test_allows_k8s_fqdn_service() {
    assert!(
        validate_outbound_url("http://nexus.tools.svc.cluster.local:8081", "Test URL").is_ok()
    );
}
```

---

## Risk in context

### Home lab scenario

The user already runs Harbor and Gitea on the same network. If those services are accessible at e.g. `harbor` or `harbor.internal`, artifact-keeper can be pointed at them as an upstream URL without triggering the SSRF guard. An admin who misconfigures a remote repo could inadvertently pull from an internal service.

More critically: any other service on the network — Grafana, a database, an internal API — can be targeted.

### Kubernetes/startup scenario

In a k8s cluster, every service in the same namespace is reachable by its short name. A user with repo-admin privileges (but not cluster-admin) could create a remote repository pointing at:
- `http://vault:8200/` (HashiCorp Vault)
- `http://internal-api:3000/`
- `http://minio:9000/` (object storage)
- Any other in-namespace service not on the hardcoded blocklist

artifact-keeper would then proxy requests through to that service, potentially leaking responses into the artifact cache.

**Gatekeeping note:** Creating remote repositories typically requires admin or repo-admin permissions. In a startup, this is likely a small group. The risk is internal-actor abuse, not anonymous exploitation.

---

## What IS blocked

The hardcoded blocklist catches obvious Docker Compose / local dev hostnames:
- `localhost`, `backend`, `postgres`, `redis`, `meilisearch`, `trivy`
- GCP/Azure metadata endpoints
- `169.254.169.254` (AWS IMDS — also blocked by the IPv4 link-local check)

---

## Why this is hard to fully fix

Fixing SSRF in a system that is *designed* to proxy arbitrary URLs is inherently difficult. Any real fix requires either:

1. **DNS-resolved IP validation** — resolve the hostname and check the resulting IP against the private-range blocklist *after* DNS lookup, not just the string. This closes the DNS rebinding and single-label-hostname gaps simultaneously. The downside is that it requires an extra DNS lookup at validation time and is still vulnerable to rebinding if the TTL is short.
2. **Allowlist instead of blocklist** — only permit FQDNs matching an operator-configured pattern (e.g., `*.pypi.example.com`). Inflexible, but appropriate for a restrictive deployment.
3. **Network-level controls** — rely on firewall/network policy to prevent the artifact-keeper pod from reaching internal services, instead of trusting the application-layer guard.

---

## Recommended mitigations

### For the operator (immediate)

- Apply strict Kubernetes NetworkPolicy to the artifact-keeper pod:
  - Allow outbound to specific known upstream hostnames/IPs only
  - Deny all other outbound to cluster-internal CIDRs
- Restrict repo-admin access to a minimal set of trusted users
- Audit `upstream_url` values for all existing remote repositories at deployment time

### Upstream contribution idea

Add a system-level configuration option to restrict outbound connections to an operator-defined allowlist of upstream URL prefixes or hostname patterns:

```toml
[proxy]
# If set, only upstream URLs matching one of these prefixes are permitted.
# Overrides the built-in blocklist for that set of hosts.
allowed_upstream_prefixes = [
  "https://pypi.org/",
  "https://registry.npmjs.org/",
  "https://repo.maven.apache.org/",
]
```

This would be a significant hardening improvement for internal-only deployments and would be a reasonable upstream PR to propose.

---

## Classification

| | |
|---|---|
| **Type** | SSRF via insufficient blocklist (by-design trade-off) |
| **Requires privileges?** | Yes — repo-admin or admin |
| **Impact** | Internal service enumeration, proxying responses from non-registry services |
| **Deployment condition** | Any k8s or multi-service deployment |
| **Upstream PR candidate** | Yes — optional `allowed_upstream_prefixes` config |

