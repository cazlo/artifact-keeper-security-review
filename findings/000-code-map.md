# 000 — Code Map: Important Paths for Security Review

**Subtree commit:** `f670ce9a010be8ca0a9eb7146f1026e9a77151e0`
**GitHub base:** `https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0`

---

## Top-level source layout

```
backend/src/
  api/
    middleware/        ← auth, rate-limiting, security headers
    handlers/          ← one file per package ecosystem + shared helpers
    validation.rs      ← centralised SSRF / URL guard
    routes.rs          ← Axum router wiring
  services/
    proxy_service.rs   ← cache + upstream fetch logic (core proxy)
    http_client.rs     ← shared reqwest ClientBuilder
    upload_service.rs  ← chunked upload flow
    upstream_auth.rs   ← Basic/token auth applied to upstream requests
    wasm_plugin_service.rs ← plugin install / exec (high-risk surface)
  storage/
    filesystem.rs      ← local disk backend (path sanitisation lives here)
    s3.rs / azure.rs / gcs.rs ← cloud backends
    mod.rs             ← StorageBackend trait
  formats/
    pypi.rs  npm.rs  maven.rs  cargo.rs  go.rs  nuget.rs … ← per-format parsers
```

---

## Key files for each review area

### SSRF & outbound HTTP

| File | Purpose |
|------|---------|
| [`backend/src/api/validation.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/validation.rs) | `validate_outbound_url()` / `is_blocked_url()` — centralised SSRF guard. Blocks scheme abuse, blocked hostnames, IPv4 private/link-local/metadata, IPv6 link-local/unique-local, and IPv4-mapped IPv6. Still string/host based; DNS rebinding remains a separate concern. |
| [`backend/src/services/http_client.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/http_client.rs) | `base_client_builder()` — builds the shared `reqwest::Client` and installs `ssrf_redirect_policy()` to re-check every redirect hop. |
| [`backend/src/services/proxy_service.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs) | Core cache/upstream fetch service. Re-check whether every outbound path uses the shared client builder before relying on redirect protection globally. |

### Auth middleware

| File | Purpose |
|------|---------|
| [`backend/src/api/middleware/auth.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/middleware/auth.rs) | `repo_visibility_middleware` — enforces public/private visibility, requires auth for writes, enforces API token repo scope, and now checks fine-grained repository permissions when permission rules exist. |
| [`backend/src/services/permission_service.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/permission_service.rs) | `PermissionService::check_permission()` — resolves direct and group-based permissions with a short in-process cache. |

### Upload / disk

| File | Purpose |
|------|---------|
| [`backend/src/api/handlers/upload.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/upload.rs) | Chunked upload API. `DefaultBodyLimit::max(256 MiB)` per chunk. Chunk size validated 1 MB–256 MB. **`total_size` still has no effective quota/max check in this path.** |
| [`backend/src/services/upload_service.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/upload_service.rs) | `validate_artifact_path()` rejects traversal. Pre-allocates temp file at declared `total_size` via `set_len()` (sparse file on Linux). **No repository quota check.** |

### Storage / path traversal

| File | Purpose |
|------|---------|
| [`backend/src/storage/filesystem.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/storage/filesystem.rs) | `key_to_path()` — strips `..` and absolute components by filtering only `Component::Normal` parts. Path traversal resistant at the storage layer. |

### PyPI/npm/Maven/Cargo handlers (in-scope ecosystems)

| File | Purpose |
|------|---------|
| [`backend/src/api/handlers/pypi.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/pypi.rs) | PEP 503 simple index + twine upload. Proxies index from upstream for remote repos. |
| [`backend/src/api/handlers/npm.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/npm.rs) | npm registry protocol. |
| [`backend/src/api/handlers/maven.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/maven.rs) | Maven repository protocol. |
| [`backend/src/api/handlers/cargo.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/cargo.rs) | Cargo sparse registry protocol. |
| [`backend/src/api/handlers/proxy_helpers.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/proxy_helpers.rs) | Shared helpers: `proxy_fetch`, `resolve_virtual_download`, `request_base_url`, `reject_write_if_not_hosted`. |

### High-risk optional surface

| File | Purpose |
|------|---------|
| [`backend/src/services/wasm_plugin_service.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/wasm_plugin_service.rs) | Clones arbitrary Git repos, loads WASM, executes under a runtime. Git URL is validated by `validate_outbound_url`. |
| [`backend/src/api/handlers/plugins.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/plugins.rs) | Plugin management routes. Current route wiring gates `/plugins` with ordinary auth, not admin; see finding 005. |
| [`backend/src/services/wasm_runtime.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/wasm_runtime.rs) | WASM execution host with fuel/memory/table limits and WASI imports. |

---

## Call chain: proxy fetch (happy path)

```
HTTP GET /pypi/{repo_key}/simple/{project}/
  → repo_visibility_middleware   (auth + visibility check)
  → pypi::simple_project()
      → resolve_pypi_repo()        (DB lookup via proxy_helpers)
      → if remote repo and no local artifacts:
          proxy_helpers::proxy_fetch()
            → ProxyService::fetch_artifact()
                → fetch_artifact_with_cache_path()
                    → get_cached_artifact()      (cache hit? return early)
                    → build_upstream_url()       (string concat)
                    → fetch_from_upstream(url)
                        → http_client.get(url).send()
                          shared client now re-validates redirect hops
                        → [if 401] validate_outbound_url(realm)
                               → obtain_bearer_token()
```

Key observation: `validate_outbound_url` is called at:
1. Repository creation time (upstream URL stored in DB)
2. OCI token realm discovery
3. Webhook / remote-instance / plugin-git-url registration

It is **not** called on each individual proxy request. Redirect destinations are now covered by the shared HTTP client's redirect policy when the request uses `base_client_builder()` / `default_client()`.

---

## Positive findings summary

| Area | Observation |
|------|-------------|
| Auth – write gate | `repo_visibility_middleware` requires auth for POST/PUT/PATCH/DELETE even on public repos |
| Auth – token scope | `AuthExtension::can_access_repo()` enforced in middleware; tokens can be scoped to specific repos |
| Storage traversal | `FilesystemStorage::key_to_path()` filters to `Component::Normal` only |
| Upload traversal | `validate_artifact_path()` rejects `..`, null bytes, encoded traversal, absolute paths |
| OCI realm SSRF | `validate_outbound_url` called before token endpoint fetch |
| Upload chunk guard | Body is read against declared `Content-Range`; excess bytes cause 400 |
