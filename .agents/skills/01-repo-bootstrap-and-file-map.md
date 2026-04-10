# Skill: repo bootstrap and file mapping

## Goal
Create a local map of the code paths most relevant to the intended security review so later agents can search efficiently and stop rediscovering the same files.

## Success criteria
Produce a markdown note containing:
- key directories
- relevant files for auth, proxying, HTTP client setup, validation, and package handlers
- a short sentence for what each file appears to do
- any notable feature flags, config switches, or env vars

## What to look for

### Common/core areas
- main backend entrypoints
- route registration
- middleware registration
- config loading
- database/storage abstractions
- shared HTTP client creation
- URL validation or allow/deny logic

### Package-specific areas
Only prioritize these ecosystems unless something shared forces expansion:
- PyPI
- npm
- Maven / Java
- Cargo / Rust

### Risky optional areas
Map these, but do not spend most time here yet:
- plugins / WASM
- replication / sync
- scanner integrations
- SSO providers

## Suggested process

1. Find top-level modules and route wiring.
2. Identify shared middleware.
3. Identify outbound HTTP client construction.
4. Identify URL validation functions.
5. Identify handlers/services for PyPI, npm, Maven, and Cargo.
6. Identify config keys controlling package formats, auth, uploads, plugins, and upstream access.

## Suggested commands

```bash
rg -n "Router|route\(|middleware|from_fn|tower|axum" backend/
rg -n "reqwest|Client::builder|redirect|timeout|proxy\(" backend/
rg -n "validate.*url|forbidden.*host|private.*ip|metadata" backend/
rg -n "pypi|npm|maven|cargo" backend/
rg -n "plugin|wasm|replication|saml|oidc|oauth|ldap" backend/
```

## Output format
Use a simple table or bullet list, for example:
- `backend/src/api/routes.rs`: central route registration, includes package-format mounts
- `backend/src/api/middleware/auth.rs`: shared auth/authz enforcement
- `backend/src/services/http_client.rs`: shared outbound HTTP client builder

## Pitfalls
- do not assume file names match actual authority; trace call sites
- do not over-index on README docs if code disagrees
- do not try to map the entire repo before starting useful review work
