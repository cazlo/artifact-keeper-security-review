# Finding 008 - Remote Proxy Pulls Do Not Support Publish-Age Cooldown / Quarantine

**Type:** Security hardening gap / upstream contribution idea  
**Status:** Confirmed in current subtree  
**Severity:** Medium for public-registry proxy use; high-value mitigation for software development environments  
**Current subtree commit:** `f670ce9a010be8ca0a9eb7146f1026e9a77151e0`

---

## Summary

Artifact Keeper has a quarantine/cooldown feature for newly uploaded artifacts, but the current remote proxy cache path does not appear to apply that control to packages pulled from upstream registries.

A remote PyPI/npm/Maven/Cargo proxy in front of public registries should be able to delay newly published upstream package versions, for example "do not serve versions published less than 7 days ago unless an admin explicitly releases them." This directly mitigates the now-common fast-publish / fast-remove malware pattern where compromised versions are detected and removed from public registries within hours.

Important nuance: this is not evidence of malice or a direct auth bypass. It is a missing security control in the remote proxy path.

This does not appear to duplicate issue #472 / PR #714. That work added a quarantine period for uploaded artifacts: local `artifacts` rows can be held, released by scanner/admin action, or rejected. The remaining gap here is narrower: remote pull-through cache entries are served through `ProxyService`, are intentionally not inserted into `artifacts` because of the #1278 storage-routing fix, and do not appear to have a publish-age or remote-cache safety decision before they are served.

---

## Current Code Receipts

### Quarantine is upload-oriented

`quarantine_service.rs` describes the feature as applying when "newly uploaded artifacts" are held in `quarantined` state, with per-repo/global config keys:

- [`backend/src/services/quarantine_service.rs#L1-L11`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/quarantine_service.rs#L1-L11)

The PR that introduced this behavior is explicitly titled "quarantine period for uploaded artifacts" and describes upload-time quarantine, scanner release/reject transitions, and admin release/reject endpoints:

- GitHub PR #714: https://github.com/artifact-keeper/artifact-keeper/pull/714
- GitHub issue #472: https://github.com/artifact-keeper/artifact-keeper/issues/472

The service computes quarantine expiry from local ingest time (`now + duration`), not from remote publish metadata:

- [`backend/src/services/quarantine_service.rs#L60-L68`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/quarantine_service.rs#L60-L68)

`ArtifactService::create` applies quarantine after inserting a normal uploaded artifact row:

- [`backend/src/services/artifact_service.rs#L343-L370`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/artifact_service.rs#L343-L370)

### Local download paths enforce quarantine

The local fetch helpers include `quarantine_status` / `quarantine_until` and call the quarantine gate before reading from storage:

- [`backend/src/api/handlers/proxy_helpers.rs#L1259-L1303`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/proxy_helpers.rs#L1259-L1303)

The shared local artifact serving helper also checks quarantine before serving bytes:

- [`backend/src/api/handlers/proxy_helpers.rs#L2273-L2294`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/proxy_helpers.rs#L2273-L2294)

Example format handlers check quarantine only after they have found a local `artifacts` row:

- PyPI local file path: [`backend/src/api/handlers/pypi.rs#L1113-L1116`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/pypi.rs#L1113-L1116)
- npm local tarball path: [`backend/src/api/handlers/npm.rs#L1107-L1110`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/npm.rs#L1107-L1110)
- Maven local path: [`backend/src/api/handlers/maven.rs#L1369-L1372`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/maven.rs#L1369-L1372)
- Cargo local path: [`backend/src/api/handlers/cargo.rs#L920-L923`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/cargo.rs#L920-L923)

### Remote proxy paths bypass this model

Generic remote fetches go through `ProxyService::fetch_artifact`, not through a first-class artifact row with quarantine fields:

- [`backend/src/api/handlers/proxy_helpers.rs#L378-L391`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/proxy_helpers.rs#L378-L391)

`ProxyService::fetch_artifact_with_cache_path_and_accept` serves a cache hit immediately, or fetches from upstream, writes the proxy cache, and returns the upstream bytes:

- [`backend/src/services/proxy_service.rs#L719-L809`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L719-L809)

`cache_artifact` explicitly does **not** insert proxy-cached content into the `artifacts` table:

- [`backend/src/services/proxy_service.rs#L1843-L1936`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L1843-L1936)
- The source-level regression test pins that behavior: [`backend/src/services/proxy_service.rs#L5953-L5999`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L5953-L5999)

Concrete format examples:

- npm remote tarballs call `proxy_fetch(...)` and return the content, with no quarantine/publish-age gate in that branch: [`backend/src/api/handlers/npm.rs#L994-L1012`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/npm.rs#L994-L1012)
- PyPI virtual remote members check proxy cache or call `fetch_from_pypi_remote(...)` and return the content before reaching the local-artifact quarantine gate: [`backend/src/api/handlers/pypi.rs#L1046-L1091`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/pypi.rs#L1046-L1091)
- Virtual remote members are intentionally routed through `ProxyService` rather than local artifact lookup: [`backend/src/api/handlers/proxy_helpers.rs#L920-L941`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/proxy_helpers.rs#L920-L941)

Assessment: the current code has quarantine enforcement for normal/local artifact rows, but remote pull-through cache entries generally live in proxy cache metadata/object storage and are served through proxy helpers. I did not find a publish-age policy check or a quarantine status object for these remote cache entries.

---

## Why Publish Age Matters

The useful control is not "hold for 7 days after Artifact Keeper first saw it." The useful control is "hold until upstream publish time + configured cooldown."

If Artifact Keeper first sees a malicious package six days after publication, a 7-day ingest-time quarantine delays it for another week even though the high-risk window has mostly passed. Conversely, if Artifact Keeper first sees it 10 minutes after publication, an ingest-time hold works by accident, but the policy cannot reason about upstream age consistently across caches and mirrors.

Available upstream metadata:

- PyPI's Simple JSON API includes per-file `upload-time` and `yanked` fields in distribution metadata. See PyPI docs: https://docs.pypi.org/api/index-api/
- npm packuments include version publication times; npm itself now has `min-release-age`, which installs only versions older than a configured number of days. See npm config docs: https://docs.npmjs.com/using-npm/config/#min-release-age
- Maven Central exposes timestamps in repository listings and search/index metadata, though implementation details will vary by upstream.
- Cargo/crates.io exposes crate version publication timestamps via registry/API metadata, but a robust implementation should be tested against the sparse index and API behavior rather than assumed.

Chainguard's package registry is a useful reference model: their JavaScript repository documents malware scanning plus a configurable cooldown for newly published upstream versions, and returns an error while a version is within the cooldown window. See: https://edu.chainguard.dev/chainguard/libraries/javascript/overview/

---

## Threat Context

Recent supply-chain incidents support a cooldown window as practical defense in depth:

- Snyk's LiteLLM writeup reports malicious `litellm` versions `1.82.7` and `1.82.8` were published to PyPI on March 24, 2026 after credentials were stolen through a compromised Trivy path, and PyPI quarantined the package about three hours later: https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
- The Axios npm compromise is an independent example: Datadog reports malicious `axios` versions `1.14.1` and `0.30.4` were published on March 31, 2026 after an npm maintainer account compromise, and the attack chain was effective for roughly three hours before npm removed the packages: https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/
- Chainguard explicitly frames cooldown as a window for the security community to identify malicious packages before builds can pull them: https://edu.chainguard.dev/chainguard/libraries/javascript/overview/

Inference: a 7-day cooldown would have blocked both the LiteLLM and Axios malicious versions for the entire time they were live on their public registries, while still allowing an admin to override for urgent fixes if Artifact Keeper supports release/unquarantine workflow for remote cache entries.

---

## Admin Workflow Gap

Artifact Keeper has admin endpoints to release or reject a quarantined artifact:

- Release: [`backend/src/api/handlers/quarantine.rs#L126-L162`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/quarantine.rs#L126-L162)
- Reject: [`backend/src/api/handlers/quarantine.rs#L183-L221`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/quarantine.rs#L183-L221)

However, because generic proxy-cached remote entries are not first-class `artifacts` rows, an admin cannot reliably inspect, release, or reject the new remote version through the existing quarantine endpoints.

I also did not find an event emission when an artifact first enters quarantine. The current quarantine handler emits release/reject events, but `ArtifactService::create` only logs when it sets the initial quarantine state. For a real cooldown workflow, admins need notification/listing for newly quarantined remote packages and a way to approve urgent pulls.

---

## Cached-Bad Cleanup Gap

Cooldown is only the pre-ingest side of the control. A complete remote policy also needs a way to remove or disable a package version after it was already cached and later determined to be unsafe.

Current code has internal proxy-cache invalidation helpers:

- `ProxyService::invalidate_cache(...)` deletes a cached content object and its metadata sidecar for a repository/path: [`backend/src/services/proxy_service.rs#L1026-L1036`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L1026-L1036)
- `ProxyService::invalidate_cache_by_key(...)` does the same by repo key/path: [`backend/src/services/proxy_service.rs#L1038-L1050`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L1038-L1050)
- APT has a specific cache-coherence path that invalidates `Packages*` cache entries when an upstream `Release` file changes: [`backend/src/services/proxy_service.rs#L1052-L1103`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L1052-L1103), [`backend/src/services/proxy_service.rs#L1169-L1195`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L1169-L1195)

However, I did not find a general admin/API workflow to purge a proxy-cached remote package version by ecosystem identity. The generic artifact delete endpoint looks up an `artifacts` row and therefore does not naturally cover proxy-cache-only remote entries:

- [`backend/src/api/handlers/repositories.rs#L3074-L3101`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/repositories.rs#L3074-L3101)

The public remote/virtual repository docs state that cached artifacts can be manually invalidated via the API, but in the pinned backend routes I found cache TTL endpoints and the internal invalidation helpers above, not a general exposed cache-invalidation route:

- Docs: https://artifactkeeper.com/docs/advanced/remote-virtual/#cache-behavior
- [`backend/src/api/handlers/repositories.rs#L208-L226`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/repositories.rs#L208-L226)

If a cache-invalidation API exists elsewhere or is being added in a newer branch, it would help the manual purge side of this feature. It would still need to be connected to package identity/version, policy state, yanked/removed metadata, and stale-cache suppression for known-bad entries.

There is also an important continuity/security tension. In the buffered proxy path, if the cache entry is expired and the upstream fetch fails, Artifact Keeper serves stale cached content when available:

- [`backend/src/services/proxy_service.rs#L754-L825`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L754-L825)
- The stale-cache helper intentionally loads expired cached content and verifies only the local checksum against cache metadata: [`backend/src/services/proxy_service.rs#L1948-L1985`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L1948-L1985)

That behavior is good for upstream outage continuity, but it must not override a security removal signal. If upstream metadata says a version was yanked/removed, or an Artifact Keeper policy/scan marks a cached version as malware, normal requests should not receive the stale cache object.

---

## Recommended Design for 1.3 Policy Engine

Add a remote-ingest and remote-cache policy that runs before serving a newly fetched, freshly cached, or stale cached upstream artifact:

1. Resolve package identity: ecosystem, repository, package name, version, filename/path, checksum.
2. Resolve upstream publish timestamp from ecosystem metadata.
3. Evaluate repository policy:
   - `remote_publish_age_cooldown = 7d` for public PyPI/npm/Maven/Cargo upstreams.
   - `remote_publish_age_cooldown = 0` or disabled for trusted upstreams that already enforce cooldown, such as Chainguard.
   - Optional package/repo allowlist for emergency overrides.
4. If the artifact is still within the cooldown:
   - Do not serve it to normal clients.
   - Record a first-class pending/quarantined remote artifact or separate `proxy_quarantine` row.
   - Notify admins via event bus/webhook/email.
   - Return a clear package-manager-compatible error.
5. Allow admins to release or reject by package identity, not only by local artifact UUID.
6. Support cache purge/disable after a version was already cached:
   - manual admin purge by package identity and version/path/checksum;
   - automated purge or reject when upstream metadata says the version was yanked/removed or when malware intelligence/policy marks it unsafe;
   - no stale-cache fallback for entries with a security removal/rejection decision.
7. Cache the policy decision and upstream publish timestamp so every request does not refetch metadata.

Virtual repositories should apply the policy at the member repository that actually supplies the candidate artifact, not as a single flat rule over the whole virtual repository. A common virtual setup might be:

- hosted/internal repository: no remote publish-age cooldown; internally published artifacts use normal local/upload policy;
- Chainguard-backed remote: cooldown disabled or `0`, because the upstream already applies malware scanning and cooldown;
- public-registry remote fallback: 7-day publish-age cooldown.

During virtual resolution, a candidate blocked by its member's cooldown policy must not be served. The resolver should then either continue to another member that can legally satisfy the request or return a clear cooldown/quarantine error if the blocked candidate is the only match. This avoids both double quarantine for trusted remotes and accidental bypass through a public fallback.

The same member-level behavior should apply to cache cleanup. If the public fallback cached a bad npm package version, purging/rejecting that member's cached candidate should not affect an internal hosted artifact with the same name/version or a Chainguard-backed remote entry that has its own policy decision.

Important implementation constraint: do not undo the #1278 fix by blindly re-inserting proxy cache entries into `artifacts` with the old storage routing bug. If remote quarantines need first-class rows, they should use an explicit storage-routing design or a separate proxy-cache/quarantine table.

---

## Draft GitHub Issue

Title:

```text
Add remote proxy publish-age cooldown/quarantine policy for pull-through caches
```

Body, following `.github/ISSUE_TEMPLATE/feature_request.yml`:

````markdown
## Problem Statement

I would like to propose adding a remote proxy cooldown/quarantine policy for pull-through cache repositories, ideally as part of the 1.3 policy engine work / #840 policy-engine discussion.

Recent package-registry incidents have shown a fast-burn pattern: attackers publish malicious versions using compromised credentials, the versions receive installs quickly, and the registry or maintainer removes/quarantines them within hours.

Examples:

- The March 24, 2026 LiteLLM PyPI compromise involved malicious versions `1.82.7` and `1.82.8`; public reporting says PyPI quarantined the package roughly three hours after publication.
- The March 31, 2026 Axios npm compromise involved malicious versions `1.14.1` and `0.30.4`; Datadog reports the attack chain was effective for roughly three hours before npm removed the compromised packages.

A 7-day publish-age cooldown would have blocked both sets of malicious versions for ordinary clients while still allowing an admin override for urgent fixes.

The current Artifact Keeper quarantine feature appears to be upload/local-artifact oriented:

- `quarantine_service` describes holding newly uploaded artifacts and computes `quarantine_until` from local `now + duration`.
- `ArtifactService::create` applies quarantine after inserting a normal artifact row.
- Local download helpers check `quarantine_status` / `quarantine_until` before serving.

I do not think this duplicates #472 / #714. That work appears to implement upload quarantine for local artifact rows. This request is specifically for remote pull-through cache entries, where the proxy may fetch, cache, and serve an upstream package that was published only minutes ago.

Remote proxy pull-through paths appear to go through `ProxyService` and proxy cache metadata/object storage. `cache_artifact` currently intentionally does not insert proxy-cached content into the `artifacts` table because of the #1278 storage-routing fix. That means remote proxy cache entries generally do not have a first-class quarantine state for existing release/reject APIs to manage.

So the current feature does not seem to protect the high-risk case I care about most: a remote npm/PyPI/etc. proxy immediately serving a just-published malicious upstream version.

## Proposed Solution

For remote repositories, add a policy that evaluates upstream package publish time and cached-version safety before serving a package/version:

- Resolve package identity: ecosystem, package name, version, filename/path, checksum.
- Resolve upstream publish timestamp from ecosystem metadata.
- Compare `now - upstream_published_at` against the repo policy.
- If still inside cooldown:
  - do not serve to normal clients;
  - record the pending/quarantined remote artifact or proxy-cache entry;
  - notify admins;
  - expose release/reject endpoints or policy overrides;
  - return a clear package-manager-compatible error.
- If outside cooldown, serve and cache normally.

I think the key is that the cooldown should be based on upstream publish metadata, not Artifact Keeper's first ingest time.

The policy should also cover already-cached content:

- If an admin rejects a cached remote package/version, purge or disable that cache entry and prevent stale-cache fallback from serving it.
- If upstream metadata says a version was yanked/removed, or malware intelligence marks it unsafe, automatically purge or reject the cached entry.
- Provide an admin API/UI path to purge a proxy cache entry by package identity, version/path, and repository.
- Preserve outage continuity for ordinary upstream outages, but distinguish that from security removal signals. A removed/yanked/blocked package should not be served merely because it exists in stale cache.

Virtual repositories should evaluate this per member repository. For example, a single virtual npm repository may contain:

- an internal hosted npm repository with no remote cooldown;
- a Chainguard-backed remote with cooldown set to `0`, because Chainguard already enforces malware scanning and cooldown;
- a public npm remote fallback with a 7-day cooldown.

If the public fallback has a matching version that is still inside cooldown, that candidate should not be served. The virtual resolver should continue to a later member only if that later member can satisfy the request under its own policy; otherwise it should return a clear cooldown/quarantine error. This keeps trusted remotes usable without allowing public fallback to bypass the policy.

Cache purge/reject should also be member-scoped in virtual repositories. Purging a bad cached package from a public fallback member should not delete or disable an internal hosted artifact, nor should it affect a Chainguard-backed member with a separate policy decision.

## Configuration / Policy Shape

Suggested shape:

```yaml
remote_policy:
  publish_age_cooldown: 7d
  action: quarantine
```

or per repository:

```json
{
  "remote_publish_age_cooldown_minutes": 10080,
  "remote_publish_age_cooldown_enabled": true
}
```

For Chainguard-backed remotes or other trusted registries that already enforce cooldown:

```json
{
  "remote_publish_age_cooldown_minutes": 0
}
```

## Admin workflow

Admins need a way to:

- list packages/versions currently blocked by cooldown;
- get notified when a new remote package/version is quarantined;
- release a specific package/version immediately for urgent fixes;
- reject or keep blocked a package/version if it is suspicious.
- purge or disable an already-cached remote package/version that was later found to be malicious.

The existing quarantine release/reject endpoints are a good starting point, but remote proxy cache entries may need either a separate table or a first-class proxy-cache artifact model so this does not regress the #1278 storage-routing fix.

## Alternatives Considered

- Client-side package-manager settings such as npm `min-release-age` help, but they are easy to miss across developer machines, CI images, and non-npm ecosystems. A repository-manager policy gives one central enforcement point.
- Using only vulnerability/malware scanners is useful, but these incidents often happen before scanner signatures, advisories, or registry blocks exist. Publish-age cooldown covers the detection gap.
- Reusing the current upload quarantine by inserting remote proxy cache entries into `artifacts` would be risky unless the #1278 storage-routing issue is explicitly solved. A separate proxy-cache/quarantine table may be cleaner.
- Relying on cache TTL alone is not enough: a malicious package can remain available until TTL expiry, and stale-cache fallback is desirable for outages but unsafe for known-bad removals unless policy distinguishes those cases.

## Use Case

As a developer platform or security team, I want Artifact Keeper remote and virtual repositories to delay newly published upstream package versions by policy so that public-registry malware has time to be detected before developer machines or CI systems can install it.

## Component

Backend / API

## Additional Context

- PyPI Simple JSON metadata includes per-file `upload-time`: https://docs.pypi.org/api/index-api/
- npm supports a client-side `min-release-age` setting: https://docs.npmjs.com/using-npm/config/#min-release-age
- Chainguard documents malware scanning plus a configurable cooldown for newly published upstream versions: https://edu.chainguard.dev/chainguard/libraries/javascript/overview/
- LiteLLM incident reference: https://snyk.io/blog/poisoned-security-scanner-backdooring-litellm/
- Axios incident reference: https://securitylabs.datadoghq.com/articles/axios-npm-supply-chain-compromise/
- Current code has internal proxy-cache invalidation helpers, but I do not see a general admin/API workflow for package-version purge or upstream-yank-driven purge of proxy-cache-only entries.
- The remote/virtual repository docs mention manual cache invalidation, but I could not find a general exposed invalidation route in the pinned backend routes. If one exists elsewhere, this feature could build on it, but it would still need package-version identity, policy state, and stale-cache suppression for known-bad entries.

## Willingness to help

I am happy to help contribute to the design and implementation, especially around PyPI/npm metadata handling and tests for the remote proxy paths.

## Pre-submission Checklist

- [x] I have searched existing issues and feature requests to ensure this isn't a duplicate.
- [x] I have reviewed the documentation to confirm this feature doesn't already exist.
````

---

## Classification

| | |
|---|---|
| **Issue type** | Missing remote-proxy policy/quarantine control |
| **Requires auth?** | Depends on repo visibility; public/anonymous read remote repos are most exposed |
| **Impact** | Newly published malicious upstream versions can be served immediately by pull-through cache |
| **Best mitigation** | Publish-age-based remote cooldown with admin release workflow |
| **Upstream PR candidate** | Yes, likely best aligned with planned policy-engine work |
