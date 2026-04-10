# Skill: static security review for a Rust service

## Goal
Perform a targeted static security review of Artifact Keeper even if the reviewer is not fluent in Rust.

## Mindset
You do not need to be a Rust expert to find useful issues. Focus on trust boundaries, data flow, defaults, and dangerous capabilities.

## What matters more than idiomatic Rust knowledge
- where untrusted input enters
- where outbound requests happen
- where auth decisions happen
- where filesystem or storage writes happen
- where limits are absent or intentionally disabled
- where optional dangerous features are enabled

## High-value bug classes for this project

### 1. SSRF / outbound fetch abuse
Look for:
- URL validation that only checks the initial URL string
- redirect-following without final target validation
- DNS rebinding possibilities
- secondary fetches driven by upstream metadata or auth challenges
- internal service names explicitly allowed for convenience

### 2. Authn / authz mistakes
Look for:
- read vs write mismatches on public repositories
- token scoping mistakes between repositories
- handler-specific bypasses around shared middleware
- admin-only operations that rely on UI assumptions rather than server-side checks

### 3. Path and package-name normalization bugs
Look for:
- path joining from user-controlled identifiers
- URL-decoding mismatches
- case-sensitivity mismatches
- alternate separators or traversal semantics
- different normalization rules between ecosystems

### 4. Storage and upload safety
Look for:
- disabled default body limits
- per-handler limits missing or inconsistently applied
- temp-file cleanup issues
- size/accounting logic that trusts headers or metadata too much

### 5. Optional code execution / extension surface
Look for:
- plugins
- external tool invocation
- unpacking of untrusted archives
- Git clone / ZIP import features

## Practical Rust reading heuristics

### Follow the input
Start from routes/handlers and trace into services.

### Search for common sink functions
Examples:
- HTTP client send paths
- file write/create/open
- process spawning
- archive unpacking
- DB queries using user-controlled values

### Look for configuration gates
Rust projects often wire dangerous behavior through config structs and feature flags. Read the config layer early.

### Ignore most type noise
When reading Rust for security review, skip deep type details unless they affect:
- ownership/lifetime in a security-sensitive cache
- async/concurrency race behavior
- error handling that changes enforcement

## Suggested searches

```bash
rg -n "send\(|execute\(|request\(|redirect|location|realm" backend/
rg -n "File::|OpenOptions|create_dir|rename\(|remove_file|remove_dir" backend/
rg -n "spawn\(|Command::new|tokio::process" backend/
rg -n "tar|zip|archive|unpack|extract" backend/
rg -n "public|private|visibility|scope|token|admin|permission" backend/
rg -n "DefaultBodyLimit|content_length_limit|max_upload|quota|size limit" backend/
```

## How to write findings
Use one of these labels:
- **Confirmed issue**: code path clearly unsafe or repro exists
- **Plausible issue**: code path suggests risk but not yet proven
- **Hardening recommendation**: not a bug, but improves safety for intended deployment

Each finding should include:
- title
- affected component/file
- threat scenario
- why it matters for the user's actual deployment
- evidence from code
- confidence level
- next test or patch idea

## Pitfalls
- do not confuse broad feature surface with a specific vulnerability
- do not claim a bypass until you have traced the handler/middleware path
- do not assume safe defaults if code comments say handlers must enforce their own limits
