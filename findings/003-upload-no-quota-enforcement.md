# Finding 003 — Disk Exhaustion: `quota_bytes` Not Enforced in Upload Path

**Status:** Confirmed deployment risk (code gap — feature exists but is not wired up)  
**Severity:** Medium (authenticated user required; can fill disk on unprotected deployments)  
**Subtree commit:** `fb2fcd799c9a87b49f2170f1f46bc26bb902500f`

---

## Summary

The `repositories` table has a `quota_bytes` column and the `Repository` model exposes it, but no code in the upload path reads or enforces it. An authenticated user can upload arbitrarily large files until the underlying storage is full.

---

## Code path

### 1. `quota_bytes` exists in the data model

**File:** `backend/src/models/repository.rs` — the `Repository` struct includes `pub quota_bytes: Option<i64>`.  
**Migration:** `backend/migrations/003_repositories.sql` (inferred from schema).

### 2. Upload service — no quota check

**File:** [`backend/src/services/upload_service.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/services/upload_service.rs)

```bash
# Confirm: quota never appears in upload_service.rs
grep -n "quota" backend/src/services/upload_service.rs
# → (no output)
```

The word `quota` does not appear anywhere in the upload service.

### 3. Upload handler — `total_size` is only validated to be `> 0`

**File:** [`backend/src/api/handlers/upload.rs`](https://github.com/artifact-keeper/artifact-keeper/blob/fb2fcd799c9a87b49f2170f1f46bc26bb902500f/backend/src/api/handlers/upload.rs)

```rust
pub struct CreateSessionRequest {
    pub total_size: i64,    // ← client-declared, only checked > 0
    pub chunk_size: Option<i32>,
    // ...
}
```

```rust
// In upload_service.rs CreateSessionParams handling:
if p.total_size <= 0 {
    return Err(UploadError::InvalidChunk("total_size must be a positive integer".into()));
}
// No upper bound check. No quota check. total_size can be i64::MAX - 1.
```

### 4. Pre-allocation of declared size

```rust
// Pre-allocate temp file at the expected size (sparse file on most FS)
file.set_len(p.total_size as u64).await?;
```

On Linux filesystems that support sparse files (ext4, xfs, btrfs), `set_len()` with an enormous value succeeds immediately and does not consume physical blocks. However, as the attacker writes chunks, real disk blocks are allocated. With no quota check, the attacker can consume the full available disk capacity.

### 5. Chunk body limit

The PATCH handler correctly rejects bodies that exceed the declared `Content-Range`:

```rust
if data.len() > expected_len {
    return Err(map_err(StatusCode::BAD_REQUEST, "Body exceeds declared Content-Range length"));
}
```

This limits each *chunk* to the declared chunk size (max 256 MB), but does not limit the *total* upload size.

---

## Attack scenario

1. Authenticated user creates an upload session:
   ```json
   POST /api/v1/uploads
   { "repository_key": "my-repo", "artifact_path": "attack.bin",
     "total_size": 9223372036854775806, "checksum_sha256": "<any>",
     "chunk_size": 268435456 }
   ```
   This returns a valid session with `chunk_count ≈ 34 billion`.

2. User sends 256 MB chunks. Each PATCH succeeds and writes to disk.

3. Disk fills up. Service stops being able to write artifacts (and potentially write logs, temp files, DB WAL, etc.).

Note: `total_size = i64::MAX - 1` maps to ≈8.5 exabytes, far beyond any real disk. In practice the attacker writes until storage is full. No admin action is needed per chunk beyond the initial session creation.

---

## Context and mitigations

- **Auth is required**: the chunked upload API requires an authenticated user (`Extension(auth): Extension<AuthExtension>`). Unauthenticated users cannot reach this path.
- **Public repos**: even on public repos, write operations are gated by `repo_visibility_middleware`'s write-auth check. So this is an authenticated-write-path issue only.
- **For a startup or home lab**: internal users and CI tokens are the primary authenticators. A rogue employee, compromised CI token, or confused-deputy scenario could fill the disk.

---

## Recommended mitigations

### Deployment hardening (immediate, no code change)

1. Set `quota_bytes` on every repository. Currently this field is optional and defaults to `NULL` (no limit). Even a generous limit (e.g., 100 GB) prevents runaway consumption.
2. Run artifact-keeper on a dedicated storage volume separate from OS/DB volumes. If the artifact volume fills, the database and OS remain healthy.

### Code fix (upstream PR candidate)

In `upload_service.rs`, add a quota check during session creation:

```rust
// After resolving the repository:
if let Some(quota) = repo.quota_bytes {
    let used: i64 = sqlx::query_scalar!(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM artifacts WHERE repository_id = $1 AND is_deleted = false",
        repo_id
    ).fetch_one(db).await?;
    if used + p.total_size > quota {
        return Err(UploadError::QuotaExceeded { quota, used });
    }
}
```

And add a sensible default maximum `total_size` even when no quota is set (e.g., 1 TB or configurable via system settings).

---

## Classification

| | |
|---|---|
| **Type** | Resource exhaustion / missing quota enforcement |
| **Requires auth?** | Yes — authenticated write access |
| **Impact** | Disk exhaustion → service unavailability |
| **Deployment condition** | Any deployment where `quota_bytes` is NULL (the default) |
| **Upstream PR candidate** | Yes — wire `quota_bytes` check into `CreateSession` flow |

