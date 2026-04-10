# Skill: deployment hardening review for Artifact Keeper

## Goal
Translate code-review findings into a practical hardening baseline for internal-only deployment.

## Intended deployment assumptions
This service is not intended to be internet-exposed for the user's main use case.

Primary assumptions:
- private/VPC-only or Teleport-gated access
- SSO for write/admin paths
- internal read access may be broader
- proxying only to approved upstreams
- continuity/caching is a primary business reason for deployment

## Hardening categories

### 1. Network exposure
Recommend:
- private-only ingress
- no direct public exposure
- restricted admin path access
- egress rules limiting outbound traffic to approved upstreams and dependencies

Questions to answer:
- does the app require broad egress by default?
- can unused ecosystems or external integrations be disabled cleanly?

### 2. Auth and identity
Recommend:
- strict auth for admin and write paths
- clear repo-level authorization
- strong secret/JWT/session handling
- avoid optional/weak identity modes unless truly necessary

Questions to answer:
- what is safe minimum auth config?
- are there insecure-but-convenient modes that should be forbidden in prod?

### 3. Dangerous optional features
Default recommendation unless required:
- disable plugins
- disable replication
- disable unused package ecosystems
- disable unneeded scanners/integrations

Questions to answer:
- can these be disabled via config/env?
- are they still partially reachable when disabled?

### 4. Upload and storage controls
Recommend:
- explicit upload size limits
- storage quota monitoring
- temp-file cleanup verification
- alerting on failed/partial uploads
- object store or disk permissions scoped narrowly

### 5. Operational continuity
Recommend:
- backup/restore story for metadata and storage
- health checks and alerts for upstream failures
- cache hit/miss observability
- clear behavior when upstreams are unavailable

### 6. Logging and evidence
Recommend:
- auth failure logging
- upstream fetch logging for denied/redirected targets
- audit logging for admin/config changes
- enough telemetry to investigate poisoning or continuity issues

## Output format
Create a deployment baseline document with:
- required settings
- recommended settings
- forbidden settings/modes
- optional future enhancements

## Pitfalls
- do not assume internal-only means safe; internal pivots still matter
- do not recommend optional high-risk features just because they exist
- do not confuse resilience with security; both matter here
