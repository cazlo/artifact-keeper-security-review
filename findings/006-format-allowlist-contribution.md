# Contribution Idea 006 — Per-Format Enable/Disable (Format Allowlist)

**Type:** Feature / hardening contribution idea  
**Status:** Not yet implemented — no existing mechanism found  
**Lift estimate:** Medium (mostly mechanical; the router structure is already clean)  
**Subtree commit:** `fb2fcd799c9a87b49f2170f1f46bc26bb902500f`

---

## Motivation

artifact-keeper currently ships and activates all 30+ package format handlers
unconditionally. For the target use cases this is both a UX problem and a
security concern:

**Home lab / private cluster**  
The operator only wants PyPI, npm, Maven, and maybe Cargo. Having Puppet,
Ansible, CocoaPods, CRAN, Incus, and HuggingFace routes live means:
- Larger attack surface for bugs in handlers the operator will never use
- Confusing UI (every format appears in the repository creation dropdown)
- Unnecessary route surface for a future path-confusion or normalization bug

**Startup / platform team use case**  
A platform or security team may want to explicitly control *which* ecosystems
developers are allowed to pull from. If only `pypi` and `npm` routes exist,
a developer cannot accidentally (or deliberately) configure a Conda or RubyGems
remote repo that bypasses supply-chain controls.

This is analogous to how Gitea/Forgejo allow disabling entire feature modules
(Issues, Wiki, Releases) via config — reducing attack surface for features
you don't use.

---

## Where the change goes

**File:** [`backend/src/api/routes.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/api/routes.rs)

The entire format route block is already a clean isolated builder (lines 44–76):

```rust
let format_routes = Router::new()
    .nest("/npm",        handlers::npm::router())
    .nest("/maven",      handlers::maven::router())
    .nest("/pypi",       handlers::pypi::router())
    .nest("/debian",     handlers::debian::router())
    .nest("/nuget",      handlers::nuget::router())
    .nest("/rpm",        handlers::rpm::router())
    .nest("/cargo",      handlers::cargo::router())
    .nest("/gems",       handlers::rubygems::router())
    .nest("/lfs",        handlers::gitlfs::router())
    .nest("/pub",        handlers::pub_registry::router())
    .nest("/go",         handlers::goproxy::router())
    .nest("/helm",       handlers::helm::router())
    .nest("/composer",   handlers::composer::router())
    .nest("/conan",      handlers::conan::router())
    .nest("/alpine",     handlers::alpine::router())
    .nest("/conda",      handlers::conda::router())
    // ... 15+ more ...
    .nest("/ext",        handlers::wasm_proxy::router());
```

No per-format gating exists today. This block is the right place to apply it.

**File:** [`backend/src/config.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/config.rs)

No format-enable flags exist. A new config section would be added here.

---

## Proposed design

### Config (TOML / env-var)

```toml
# artifact-keeper.toml
[formats]
# If set, only the listed formats are enabled. All others return 404.
# Omit this key entirely to enable all formats (current behaviour, default).
enabled = ["pypi", "npm", "maven", "cargo"]

# Alternatively, a blocklist variant (either/or, not both):
# disabled = ["wasm_proxy", "huggingface", "incus", "puppet", "ansible"]
```

Environment variable form (for Docker/k8s):
```
ARTIFACT_KEEPER_FORMATS_ENABLED=pypi,npm,maven,cargo
```

**Recommendation: use an allowlist (`enabled`), not a blocklist.**  
A blocklist requires operators to know every format name and actively maintain
it as new formats are added. An allowlist is opt-in: new formats don't appear
until the operator adds them, which is the right default for security-conscious
deployments.

### Router change (sketch)

```rust
// In create_router(), after loading config:
let enabled = &state.config.formats.enabled; // Option<HashSet<String>>

let mut format_routes = Router::new();

macro_rules! maybe_nest {
    ($path:literal, $router:expr, $name:literal) => {
        if enabled.as_ref().map_or(true, |e| e.contains($name)) {
            format_routes = format_routes.nest($path, $router);
        }
    };
}

maybe_nest!("/npm",      handlers::npm::router(),      "npm");
maybe_nest!("/maven",    handlers::maven::router(),    "maven");
maybe_nest!("/pypi",     handlers::pypi::router(),     "pypi");
maybe_nest!("/cargo",    handlers::cargo::router(),    "cargo");
// ... etc
```

Or equivalently without a macro, with a helper function that returns
`Router::new()` (empty, no routes) for disabled formats.

### Repository creation enforcement

Disabling a format's HTTP routes prevents *new* traffic to that format, but an
operator could still create a repository with a disabled format via the REST
API (`POST /api/v1/repositories`). The `repositories` handler should also
check the format against the enabled set and return `400 Bad Request` if the
format is disabled:

```rust
// In handlers/repositories.rs, create_repository():
if !state.config.formats.is_enabled(&req.format) {
    return Err(AppError::Validation(
        format!("Format '{}' is disabled on this instance", req.format)
    ));
}
```

### What happens to existing repositories of a disabled format

The operator may have existing repos of a disabled format (e.g., they try out
Conda and later disable it). Two reasonable behaviours:

1. **Silent 404** — disabled format routes simply don't exist, so requests 404. Existing data stays in the database and storage, untouched. Re-enabling the format restores access.
2. **Explicit 503** — a catch-all route on the format prefix returns 503 with a message like "This format is disabled on this instance." More discoverable.

Option 2 is friendlier to operators debugging why a `pip install` suddenly
fails. It requires adding a minimal catch-all handler for each disabled prefix.

---

## Lift breakdown

| Area | Work | Estimate |
|------|------|----------|
| Config struct | Add `FormatConfig { enabled: Option<HashSet<String>> }` | ~20 lines |
| Router gating | Conditional `.nest()` calls in `create_router()` | ~40 lines |
| Repo creation validation | One check in `create_repository` handler | ~10 lines |
| 503 catch-all (optional) | One generic not-enabled handler | ~20 lines |
| Startup log | Log which formats are enabled/disabled at startup | ~10 lines |
| Tests | Unit tests for config parsing + integration test | ~50 lines |
| Docs | Update deployment guide with examples | ~30 lines |

Total: **~150–200 lines**, mostly mechanical. No fundamental architecture
change. The router pattern already supports this cleanly.

---

## Security value for the intended use cases

| Use case | Benefit |
|----------|---------|
| Home lab | Removes ~25 format handlers from the attack surface in a 5-format deployment |
| Startup platform | Prevents developers from creating unsanctioned ecosystem repos |
| Both | Reduces path for future format-handler bugs to affect unrelated ecosystems |
| Both | Smaller footprint → easier audit of what's actually running |

---

## Upstream PR pitch

This would be a clean, well-scoped PR:
- No breaking changes (default behaviour: all formats enabled, same as today)
- Opt-in hardening for operators who want it
- Aligns with how other self-hosted tools (Gitea, Forgejo, Verdaccio) handle feature gating
- Directly useful for the "internal artifact proxy" positioning the project targets

Suggested title: **"feat: optional per-format enable/disable via config allowlist"**

---

## Related findings

- [005-wasm-plugin-surface.md](./005-wasm-plugin-surface.md) — the WASM plugin
  handler (`/ext` prefix) would be a natural candidate for the disabled-by-default
  list; format gating provides the mechanism to enforce that

