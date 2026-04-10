# Finding 001 — SSRF Gap: HTTP Redirects Not Re-Validated

**Status:** Confirmed code-path issue  
**Severity:** Medium (exploitable only if an upstream server can be made to redirect)  
**Subtree commit:** `fb2fcd799c9a87b49f2170f1f46bc26bb902500f`

---

## Summary

The centralised SSRF guard (`validate_outbound_url`) is applied to configured upstream URLs at registration time and to OCI bearer-realm URLs at token-fetch time, but **not** to the destinations of HTTP redirects that reqwest follows automatically.

reqwest's default redirect policy follows up to 10 redirects without calling back into application code. If an upstream package registry (or an attacker who can influence it) returns a `302 Location: http://169.254.169.254/...` response, reqwest will follow the redirect and the response will be returned to the proxy cache — bypassing the SSRF guard entirely.

---

## Code path

### 1. HTTP client — no redirect policy configured

**File:** [`backend/src/services/http_client.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/services/http_client.rs)

```rust
pub fn base_client_builder() -> ClientBuilder {
    log_proxy_env();
    let mut builder = reqwest::Client::builder();
    // ... custom CA cert loading ...
    builder   // ← no .redirect(...) call; reqwest default applies
}
```

reqwest's built-in default is `redirect::Policy::limited(10)` — follow up to 10 redirects, unconditionally.

### 2. Proxy service — `send()` follows redirects before the app sees the response

**File:** [`backend/src/services/proxy_service.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/services/proxy_service.rs)

```rust
async fn fetch_from_upstream(
    &self,
    url: &str,
    repo_id: Uuid,
) -> Result<(Bytes, Option<String>, Option<String>, String)> {
    // ...
    let response = request
        .send()    // ← redirects are followed transparently here
        .await
        .map_err(|e| AppError::Storage(...))?;
    // ...
    Self::read_upstream_response(response, url).await
}
```

The `effective_url` (final URL after redirects) is returned by `read_upstream_response` and is visible in logs, but it is never passed through `validate_outbound_url`.

### 3. SSRF guard — only sees the initial URL

**File:** [`backend/src/api/validation.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/api/validation.rs)

`validate_outbound_url` is a static string/IP check. It is called at:
- `repositories` handler — when storing `upstream_url`
- `proxy_service.rs` — for OCI bearer **realm** only, not the artifact URL
- Webhook, remote-instance, plugin-git-url registration

It is **never** called in the redirect chain.

### 4. OCI bearer realm — correctly validated

```rust
// In fetch_from_upstream(), after a 401:
crate::api::validation::validate_outbound_url(realm, "OCI token realm")?;
let token = self.obtain_bearer_token(realm, ...).await?;
```

The OCI path is protected. The artifact-download redirect path is not.

---

## Attack scenario (threat-model aligned)

This matters for the **internal deployment** use case in the following way:

1. Operator configures a remote repository pointing at a legitimate upstream (e.g., `https://pypi.org`). The upstream URL passes `validate_outbound_url` at creation time.
2. An attacker with influence over the upstream (supply-chain compromise, BGP hijack, or simply a test against a misconfigured mirror) makes `pypi.org` return `302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
3. artifact-keeper's proxy follows the redirect, reads the cloud metadata response, and caches it under the PyPI artifact path.
4. Any subsequent request to that artifact path returns the metadata credentials to the requesting client.

More realistic internal variant (no upstream compromise required):
- Operator mistakenly points a remote repo at a URL that internally 302s through an internal host.
- The SSRF guard never fires because it only checked the initial URL.

---

## What is NOT a risk here

- The initial `upstream_url` is validated at repository creation. An operator cannot simply type in `http://169.254.169.254/` as an upstream URL; that would be rejected immediately.
- This is therefore a **secondary-request SSRF** (redirect-following), not a direct misconfiguration bypass.

---

## Reproduction sketch (not yet tested live)

```bash
# Stand up a redirect server:
python3 -c "
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
        self.end_headers()
socketserver.TCPServer(('', 9999), H).serve_forever()
"

# In artifact-keeper, create a remote PyPI repo pointing at:
#   http://<your-host>:9999
# Then do: pip install --index-url http://<ak-host>/pypi/<repo>/simple/ requests
# Observe what gets cached under the artifact path.
```

A live reproduction against a running instance would confirm exploitability.

---

## Recommended fix (upstream PR candidate)

In `base_client_builder()`, set a custom redirect policy that re-validates each destination:

```rust
use reqwest::redirect;

pub fn base_client_builder() -> ClientBuilder {
    log_proxy_env();
    let mut builder = reqwest::Client::builder()
        .redirect(redirect::Policy::custom(|attempt| {
            let url = attempt.url();
            let url_str = url.to_string();
            match crate::api::validation::validate_outbound_url(&url_str, "redirect target") {
                Ok(()) => attempt.follow(),
                Err(_) => attempt.error(format!(
                    "Redirect to blocked URL rejected: {}",
                    url_str
                )),
            }
        }));
    // ... CA cert loading ...
    builder
}
```

Alternative (simpler, more conservative): disable redirects entirely for proxy requests and handle `3xx` responses explicitly in `fetch_from_upstream`. Package registries rarely need redirect-following for artifact downloads; PyPI's canonical download URLs are parsed from the simple index, not followed directly.

---

## Classification

| | |
|---|---|
| **Type** | SSRF (secondary-request, redirect-following) |
| **Requires upstream compromise?** | Yes (or DNS manipulation, or a misconfigured internal redirect) |
| **Impact** | Cloud metadata access, internal service enumeration |
| **Deployment condition** | Any deployment where the backend has access to IMDSv1 (EC2, GCP, Azure VMs without IMDSv2 enforcement) |
| **Upstream PR candidate** | Yes — small, targeted fix in `http_client.rs` |

