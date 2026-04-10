# Finding 002 — IPv6 Private Ranges Not Blocked in SSRF Guard

**Status:** Confirmed code gap  
**Severity:** Low–Medium (depends on whether the deployment has IPv6 connectivity to internal services)  
**Subtree commit:** `fb2fcd799c9a87b49f2170f1f46bc26bb902500f`

---

## Summary

`validate_outbound_url` blocks IPv4 private ranges (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`, `169.254.x.x`, loopback, etc.) comprehensively, but for IPv6 only blocks the loopback (`::1`) and unspecified (`::`) addresses.

The following IPv6 address classes are **not** blocked:

| Range | RFC | Description |
|-------|-----|-------------|
| `fc00::/7` | RFC 4193 | Unique local addresses (IPv6 equivalent of RFC 1918 private space) |
| `fe80::/10` | RFC 4291 | Link-local addresses |
| `::ffff:0:0/96` | RFC 4291 | IPv4-mapped IPv6 (`::ffff:127.0.0.1`, `::ffff:10.0.0.1`, etc.) |
| `::ffff:0:0:0/96` | RFC 2765 | IPv4-translated IPv6 |

---

## Code path

**File:** [`backend/src/api/validation.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/api/validation.rs)

```rust
if let Ok(ip) = bare_host.parse::<std::net::IpAddr>() {
    let is_blocked = match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        //                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        //                         Only ::1 and :: are blocked.
        //                         fc00::/7, fe80::/10, ::ffff:x.x.x.x NOT blocked.
    };
```

Contrast with the thorough IPv4 case which uses `is_private()`, `is_link_local()`, etc.

---

## Attack scenario

**IPv4-mapped IPv6 (`::ffff:127.0.0.1`)**

An operator adds a remote repository with upstream URL `http://[::ffff:127.0.0.1]/repo/`. The parser extracts `::ffff:127.0.0.1` as an `Ipv6Addr`, which is neither `::1` nor `::`, so it passes the block check. When reqwest connects, the OS network stack resolves this as a connection to `127.0.0.1` (loopback). This bypasses the loopback block entirely.

```
http://[::ffff:7f00:1]/   ← same as 127.0.0.1 in hex notation
http://[::ffff:127.0.0.1]/ ← also maps to loopback
```

Note: reqwest/hyper will only use IPv4-mapped IPv6 if the socket is in dual-stack mode. Whether this is exploitable depends on OS and runtime configuration, but it is a real gap that other SSRF-guard libraries (e.g., `ssrf-filter` in Node.js) treat as a known bypass class.

**Unique local (`fc00::/7`)**

In a dual-stack Kubernetes cluster or home lab where internal services have ULA addresses (e.g., Grafana at `fd12:3456:789a::1`), an operator could accidentally or maliciously point a remote repo at that address. The SSRF guard would not catch it.

---

## Verification

Quick check to confirm current behaviour:

```rust
// ::ffff:127.0.0.1 parsed as Ipv6Addr
let ip: std::net::Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
println!("{}", ip.is_loopback());     // false  ← not blocked
println!("{}", ip.is_unspecified());  // false  ← not blocked
// is_loopback() for Ipv6Addr only returns true for ::1
```

```bash
# Confirm via ripgrep that no other IPv6 checks exist
rg -n "is_unique_local\|fc00\|fe80\|ffff\|Ipv6" \
  artifact-keeper/backend/src/api/validation.rs
# Expected: no output (the missing checks)
```

---

## Recommended fix (upstream PR candidate)

Rust's standard library `Ipv6Addr` does not yet stabilise `is_unique_local()` or `is_unicast_link_local()`, but the checks can be implemented manually. The [`ipnet`](https://crates.io/crates/ipnet) crate (already used in many Rust projects) provides helpers.

Minimal manual approach:

```rust
std::net::IpAddr::V6(v6) => {
    v6.is_loopback()
        || v6.is_unspecified()
        // fc00::/7 — unique local (RFC 4193)
        || (v6.segments()[0] & 0xfe00) == 0xfc00
        // fe80::/10 — link-local (RFC 4291)
        || (v6.segments()[0] & 0xffc0) == 0xfe80
        // ::ffff:0:0/96 — IPv4-mapped (RFC 4291)
        || v6.to_ipv4_mapped().map(|v4| {
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
                || v4.is_unspecified() || v4.is_broadcast()
        }).unwrap_or(false)
}
```

Note: `to_ipv4_mapped()` is stable since Rust 1.63. This also handles the `::ffff:127.0.0.1` bypass.

---

## Classification

| | |
|---|---|
| **Type** | SSRF guard bypass (IPv6 private ranges) |
| **Exploitability** | Requires IPv6-reachable internal services or dual-stack networking |
| **Impact** | Internal service enumeration / access, cloud metadata via IPv6 IMDS |
| **Deployment condition** | IPv6-enabled infrastructure; home lab or k8s cluster with ULA addresses |
| **Upstream PR candidate** | Yes — small additive change to `validate_outbound_url` |

