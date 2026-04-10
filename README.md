# artifact-keeper-security-review

In-line agentic security review of the [artifact-keeper](https://github.com/artifact-keeper) organization's repositories.

All code under review is included as git subtrees with full history (no `--squash`).

---

## Subtrees under review

| Subtree prefix | Upstream repo | Pinned commit | Description |
|---|---|---|---|
| `artifact-keeper/` | [artifact-keeper/artifact-keeper](https://github.com/artifact-keeper/artifact-keeper) | `fb2fcd799c9a87b49f2170f1f46bc26bb902500f` | **Rust backend** — core registry server, proxy, API, DB migrations, plugin host |
| `artifact-keeper-web/` | [artifact-keeper/artifact-keeper-web](https://github.com/artifact-keeper/artifact-keeper-web) | `10fd8569b6e91ad174867b45a971a55880029964` | **Next.js 15 frontend** — web UI dashboard (TypeScript, React 19, Tailwind) |
| `artifact-keeper-iac/` | [artifact-keeper/artifact-keeper-iac](https://github.com/artifact-keeper/artifact-keeper-iac) | `583adb7d3f885ccb0b5e77a894ef89af374f1f96` | **Infrastructure as Code** — Helm charts, Terraform (AWS), ArgoCD, monitoring |
| `artifact-keeper-api/` | [artifact-keeper/artifact-keeper-api](https://github.com/artifact-keeper/artifact-keeper-api) | `4d7d207f839b81ca4e11b6fb70fc7efd35d85a7d` | **OpenAPI 3.1 spec** — auto-generated API spec + SDK generators (TS, Kotlin, Swift, Rust) |
| `artifact-keeper-example-plugin/` | [artifact-keeper/artifact-keeper-example-plugin](https://github.com/artifact-keeper/artifact-keeper-example-plugin) | `23d495209d8761dd14b71c2468c570a8b5156d28` | **Example WASM plugins** — reference format handler plugins (Unity, RPM, PyPI) |

---

## Repository layout

```
artifact-keeper/                ← backend (Rust) — primary review target
artifact-keeper-web/            ← frontend (Next.js/TypeScript)
artifact-keeper-iac/            ← infrastructure (Helm/Terraform/ArgoCD)
artifact-keeper-api/            ← API spec (OpenAPI 3.1) + generated SDKs
artifact-keeper-example-plugin/ ← WASM plugin examples (Rust)
findings/                       ← security review findings (one file per topic)
AGENTS.md                       ← agent instructions and review scope
```

---

## Updating subtrees

Pull the latest upstream commits into any subtree (full history, no squash):

```bash
git subtree pull --prefix=artifact-keeper \
  https://github.com/artifact-keeper/artifact-keeper.git main

git subtree pull --prefix=artifact-keeper-web \
  https://github.com/artifact-keeper/artifact-keeper-web.git main

git subtree pull --prefix=artifact-keeper-iac \
  https://github.com/artifact-keeper/artifact-keeper-iac.git main

git subtree pull --prefix=artifact-keeper-api \
  https://github.com/artifact-keeper/artifact-keeper-api.git main

git subtree pull --prefix=artifact-keeper-example-plugin \
  https://github.com/artifact-keeper/artifact-keeper-example-plugin.git main
```

---

## Setting up Rust tooling (Linux)

The project under review is written in **Rust** (not Go). The agent notes below
reflect that. To read, search, and build the code you'll need:

### 1. Install Rust via rustup

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Follow prompts; the default toolchain is fine.
source "$HOME/.cargo/env"
```

Verify:

```bash
rustc --version   # e.g. rustc 1.77.2
cargo --version   # e.g. cargo 1.77.2
```

### 2. Install ripgrep (rg) – fast code search

```bash
# Fedora / RHEL
sudo dnf install ripgrep

# Debian / Ubuntu
sudo apt-get install ripgrep

# Or via cargo
cargo install ripgrep
```

### 3. Install cargo-audit – dependency vulnerability scanner

```bash
cargo install cargo-audit
```

Run from the project root:

```bash
cd artifact-keeper
cargo audit
```

### 4. Install cargo-geiger – unsafe code detector

```bash
cargo install cargo-geiger
cd artifact-keeper
cargo geiger 2>&1 | head -80
```

### 5. Optional: sqlx-cli (for inspecting migrations)

```bash
cargo install sqlx-cli --no-default-features --features postgres
```

### 6. Build the project (optional – needs PostgreSQL env vars)

The backend requires a running Postgres instance for `sqlx` compile-time
query checking. For static analysis you do **not** need to build; grep and
`cargo check` work without a live database when `SQLX_OFFLINE=true`:

```bash
cd artifact-keeper/backend
SQLX_OFFLINE=true cargo check 2>&1 | head -40
```

### 7. Quick code search examples

```bash
# From the review root
cd artifact-keeper

# Find all outbound HTTP client usages
rg -n "reqwest|Client::builder|redirect|base_client_builder"

# Find all places validate_outbound_url is (or isn't) called
rg -n "validate_outbound_url"

# Find auth middleware wiring
rg -n "repo_visibility_middleware|optional_auth_middleware|auth_middleware"

# Dump all .rs files for the key areas
find backend/src/api/middleware backend/src/services \
  -name "*.rs" | sort
```

---

## Findings index

See the [`findings/`](./findings/) directory. Files are numbered; lower numbers
are generally higher severity or were reviewed earlier.

| File | Topic |
|------|-------|
| [000-code-map.md](findings/000-code-map.md) | File/function map of important code paths |
| [001-ssrf-via-redirects.md](findings/001-ssrf-via-redirects.md) | SSRF gap: redirects not re-validated |
| [002-ipv6-private-ranges.md](findings/002-ipv6-private-ranges.md) | IPv6 private ranges not blocked in SSRF guard |
| [003-upload-no-quota-enforcement.md](findings/003-upload-no-quota-enforcement.md) | Disk exhaustion: quota_bytes not checked in upload path |
| [004-k8s-service-name-allowance.md](findings/004-k8s-service-name-allowance.md) | By-design K8s service name SSRF risk |
| [005-wasm-plugin-surface.md](findings/005-wasm-plugin-surface.md) | WASM plugin system – high-risk optional surface |
| [006-format-allowlist-contribution.md](findings/006-format-allowlist-contribution.md) | Contribution idea: per-format enable/disable config allowlist |

