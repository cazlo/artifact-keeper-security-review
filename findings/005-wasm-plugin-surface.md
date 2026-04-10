# Finding 005 — WASM Plugin System: High-Risk Optional Surface

**Status:** Deployment risk / high-risk optional feature  
**Severity:** High (if used) / None (if disabled at deployment time)  
**Subtree commit:** `fb2fcd799c9a87b49f2170f1f46bc26bb902500f`

---

## Summary

artifact-keeper ships a WASM plugin system that can clone arbitrary Git repositories, compile and load WASM binaries, and execute them inside the server process. This is the largest trust boundary in the codebase beyond the core proxy logic.

**For the intended use cases (private package proxy/cache for home lab or startup), this feature is not needed and should be explicitly disabled.** This finding documents the surface and the recommended approach for the specific deployment model.

---

## Feature scope

**Files:**
- [`backend/src/services/wasm_plugin_service.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/services/wasm_plugin_service.rs)
- [`backend/src/services/wasm_runtime.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/services/wasm_runtime.rs)
- [`backend/src/services/wasm_bindings.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/services/wasm_bindings.rs)
- [`backend/src/api/handlers/plugins.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/api/handlers/plugins.rs)
- [`backend/src/api/handlers/wasm_proxy.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/api/handlers/wasm_proxy.rs)

---

## What the plugin system does

1. **Git clone from an arbitrary URL**: `wasm_plugin_service.rs` accepts a Git URL, validates it with `validate_outbound_url`, and clones it to a temp directory using `git2::Repository::clone()`.
2. **Loads WASM from cloned content**: reads a `.wasm` file from the cloned repo.
3. **Executes WASM via a runtime** (likely Wasmtime or Wasmer, based on `wasm_runtime.rs`): calls plugin entry points with data from incoming requests/artifacts.
4. **Bindings surface**: `wasm_bindings.rs` defines what host functions the WASM module can call — this is the sandbox boundary.

---

## Risk areas (not yet fully reviewed)

### 1. Git clone surface

```rust
// wasm_plugin_service.rs ~line 692:
crate::api::validation::validate_outbound_url(url, "Plugin git URL")?;
// ...
let repo = self.clone_repository(url, temp_dir.path()).await?;
```

The Git URL is validated by `validate_outbound_url`, so direct SSRF via a `git://internal-host/` URL would be blocked for known-bad hosts. However:

- `git2::Repository::clone()` supports multiple protocols (`https`, `git`, `ssh`). Only `http`/`https` are allowed by `validate_outbound_url`; whether `git2` respects that at the transport layer is not verified.
- The cloned content is then treated as trusted input (WASM binary + manifest). A malicious Git repo could contain a crafted WASM binary designed to escape the sandbox or exploit the WASM runtime.

**This is unverified** — the sandbox boundary of `wasm_bindings.rs` has not been reviewed in this pass.

### 2. WASM sandbox boundary

The key question for WASM security is: what host functions does `wasm_bindings.rs` expose to the plugin? Common dangerous host functions include:
- Filesystem read/write
- Network access (outbound HTTP from within WASM)
- Environment variable access
- Subprocess execution

**Status:** Not yet reviewed. This requires reading `wasm_bindings.rs` and `wasm_runtime.rs` in detail.

### 3. Admin-only? Or user-installable?

From `wasm_plugin_service.rs`, plugins appear to require admin/privileged access to install. If any plugin management endpoint is accessible to non-admin users, that would be a significant escalation path. **Status:** Unverified in this pass.

### 4. Plugin code runs in the server process

Even a well-sandboxed WASM runtime executing in-process shares the same memory space, file descriptors, and network stack. A sandbox escape or runtime vulnerability in Wasmtime/Wasmer would give the plugin full process privileges.

---

## Deployment recommendation

**Disable the WASM plugin system entirely** for the private package proxy use case. Neither the home-lab nor the startup use case requires plugins.

Until artifact-keeper provides a clean compile-time or runtime disable flag, the operator-level mitigation is:

1. **Do not install any plugins.** The plugin system is inert if no plugins are installed.
2. **Restrict plugin API endpoints by network policy** if possible (the admin endpoints should already require authentication, but defense-in-depth is appropriate here).
3. **Use a non-admin service account** for CI/automation tokens. Tokens without admin scope cannot install plugins.

**Upstream contribution idea:** Add a `[plugins] enabled = false` configuration switch that causes plugin API endpoints to return 501 Not Implemented and prevents the plugin runtime from initialising. This follows the pattern of feature flags in projects like Gitea and Forgejo.

---

## What is NOT a current concern

- The Git clone URL is validated by `validate_outbound_url`, so SSRF via a direct Git URL is partially mitigated (same IPv6 gaps as finding 002 apply).
- Cloned WASM is stored locally, not executed from the network in real-time.

---

## Next review steps (if plugins cannot be avoided)

1. Read `wasm_bindings.rs` in full and document every host function exposed to plugins.
2. Check whether plugin installation is admin-only in the route definitions.
3. Verify the WASM runtime version (Wasmtime/Wasmer) and check for known CVEs.
4. Test whether a plugin can make outbound network connections via a host function.

---

## Classification

| | |
|---|---|
| **Type** | High-risk optional feature / attack surface |
| **Requires privileges?** | Likely admin (unverified) |
| **Impact (if exploitable)** | Remote code execution in server process |
| **Deployment recommendation** | Do not install plugins; await upstream disable-flag |
| **Upstream PR candidate** | Yes — `[plugins] enabled = false` config flag |

