# Contribution Idea 009 - Dynamic AWS Auth for ECR and CodeArtifact Remotes

**Type:** Feature / migration support contribution idea  
**Status:** Not implemented in pinned subtree; static-token workaround appears viable  
**Current subtree commit:** `f670ce9a010be8ca0a9eb7146f1026e9a77151e0`

---

## Summary

Artifact Keeper does not appear to have native dynamic AWS auth support for remote repositories in the pinned backend. The current remote repository auth model supports static Basic and Bearer credentials, plus OCI-style bearer challenge handling. I found no local references to `aws_sdk_ecr`, `aws_sdk_codeartifact`, `GetAuthorizationToken`, or equivalent AWS token minting logic.

This is not a vulnerability. It is a useful upstream feature request for organizations that want Artifact Keeper to proxy internally published packages from AWS CodeArtifact or private container images from Amazon ECR without storing long-lived AWS secrets or running a separate token-refresh controller.

The core ask is broader than CodeArtifact: add AWS-backed dynamic upstream auth for remotes using the runtime AWS credential chain, especially IRSA / EKS Pod Identity in Kubernetes.

---

## AWS Token Model

AWS CodeArtifact and Amazon ECR both use IAM-authenticated AWS APIs to vend short-lived credentials for package-manager or registry access.

CodeArtifact:

- AWS documents `GetAuthorizationToken` as requiring `codeartifact:GetAuthorizationToken` and `sts:GetServiceBearerToken`.
- Tokens default to 12 hours and can be configured between 15 minutes and 12 hours.
- CodeArtifact supports Cargo, generic, Maven, npm, NuGet, PyPI, Ruby, and Swift package formats.

References:

- https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_GetAuthorizationToken.html
- https://docs.aws.amazon.com/codeartifact/latest/ug/tokens-authentication.html
- https://docs.aws.amazon.com/codeartifact/latest/ug/packages-overview.html

ECR:

- AWS documents ECR `GetAuthorizationToken` as returning an authorization token valid for 12 hours.
- The token is base64 encoded and can be used for Docker/OCI registry login.
- For direct HTTP API access, AWS documents passing the authorization token as `Authorization: Basic <token>`.

References:

- https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetAuthorizationToken.html
- https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry_auth.html

---

## Local Evidence

### Remote auth is currently static Basic/Bearer

The upstream auth service explicitly documents and models only Basic and Bearer:

- [`backend/src/services/upstream_auth.rs#L1-L19`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/upstream_auth.rs#L1-L19)

The parser rejects any auth type other than `basic` or `bearer`:

- [`backend/src/services/upstream_auth.rs#L61-L78`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/upstream_auth.rs#L61-L78)

The request builder applies those two variants directly as HTTP Basic or Bearer auth:

- [`backend/src/services/upstream_auth.rs#L81-L88`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/upstream_auth.rs#L81-L88)

The repository create request describes `upstream_auth_type` as `"basic"` or `"bearer"` only:

- [`backend/src/api/handlers/repositories.rs#L302-L307`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/repositories.rs#L302-L307)

The `PUT /api/v1/repositories/{key}/upstream-auth` request supports `"basic"`, `"bearer"`, or `"none"`:

- [`backend/src/api/handlers/repositories.rs#L3508-L3514`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/repositories.rs#L3508-L3514)
- [`backend/src/api/handlers/repositories.rs#L3553-L3584`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/repositories.rs#L3553-L3584)

The frontend create dialog exposes only `None`, `Basic`, and `Bearer token`:

- [`artifact-keeper-web/src/app/(app)/repositories/_components/repo-dialogs.tsx#L390-L443`](https://github.com/artifact-keeper/artifact-keeper-web/blob/ea664a1533364194e9c20407b8a6b1ef9eac9376/src/app/(app)/repositories/_components/repo-dialogs.tsx#L390-L443)

### OCI remote support exists, but not ECR-native token minting

Artifact Keeper has OCI/Docker remote behavior and explicitly treats ECR as a non-Docker-Hub upstream in image-name normalization:

- [`backend/src/api/handlers/oci_v2.rs#L945-L974`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/api/handlers/oci_v2.rs#L945-L974)

The generic proxy service supports OCI registry bearer-token challenge handling:

- [`backend/src/services/proxy_service.rs#L1445-L1452`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L1445-L1452)
- [`backend/src/services/proxy_service.rs#L1497-L1527`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L1497-L1527)

That is useful for registries such as Docker Hub, but it is not the same as calling AWS ECR `GetAuthorizationToken` through IAM and applying the resulting Basic token to ECR requests.

### Existing workaround should work

The proxy fetch path reloads upstream auth from the database before making upstream requests:

- [`backend/src/services/proxy_service.rs#L1479-L1485`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L1479-L1485)

It also reloads configured auth for upstream ETag checks:

- [`backend/src/services/proxy_service.rs#L1996-L2004`](https://github.com/artifact-keeper/artifact-keeper/blob/f670ce9a010be8ca0a9eb7146f1026e9a77151e0/backend/src/services/proxy_service.rs#L1996-L2004)

So a cronjob/controller that periodically calls AWS and updates the remote repository's static upstream credential should be viable:

- CodeArtifact: call `aws codeartifact get-authorization-token`, then update the remote's Bearer or Basic-style token depending on the package-manager endpoint.
- ECR: call `aws ecr get-authorization-token` or `aws ecr get-login-password`, then update the OCI remote's Basic credentials for `AWS:<password>` or `Authorization: Basic <base64-token>` as appropriate.

This workaround is operationally awkward but useful enough for early trials. It requires separate automation, a privileged Artifact Keeper API token, token-expiry monitoring, and retry/failure handling.

---

## Why Native Support Matters

For the startup migration use case, AWS-hosted artifact services may contain internally published packages and container images that are not available from public registries. A pull-through cache in front of them helps with:

- phased migration away from CodeArtifact or ECR without forcing all developers and CI jobs to change at once;
- continuity if AWS auth, CodeArtifact, ECR, or account configuration has an outage;
- caching and retaining packages/images already in use;
- reducing direct package-manager and container-registry authentication complexity for developers and CI;
- centralizing remote package/image policy alongside public-registry remotes.

The static-token workaround leaves token lifecycle outside Artifact Keeper. If the refresh job fails, cache misses start failing once the old AWS-vended token expires.

Native support would also avoid the thing we actually do not want: storing long-lived AWS access keys in Artifact Keeper. In Kubernetes, the preferred deployment shape should be IRSA or EKS Pod Identity attached to the Artifact Keeper service account.

---

## Proposed Feature

Add native AWS-backed upstream auth providers for remote repositories.

Suggested auth types:

- `aws_codeartifact`
- `aws_ecr`

Shared configuration:

- `region`
- optional `role_arn` / external ID for cross-account access
- optional `endpoint_url` for testing
- optional `duration_seconds` where the AWS API supports it
- rely on AWS default credential chain by default, including IRSA / EKS Pod Identity

CodeArtifact-specific configuration:

- `domain`
- `domain_owner`
- `repository`
- package format / endpoint mode if needed to decide Basic vs Bearer/header shape

ECR-specific configuration:

- `registry_id` / account ID
- `registry_uri` or derive from account ID and region
- private ECR vs ECR Public as a future extension

Runtime behavior:

1. Use AWS SDK credentials from the environment/default provider chain, including IRSA / EKS Pod Identity in Kubernetes.
2. Call the relevant AWS token API:
   - CodeArtifact `GetAuthorizationToken`
   - ECR `GetAuthorizationToken`
3. Cache the returned token in memory with its expiration timestamp.
4. Refresh proactively before expiration and singleflight concurrent refreshes.
5. Apply the token to outbound upstream requests in the provider-specific shape:
   - CodeArtifact package-manager auth format;
   - ECR `Authorization: Basic <token>` / username `AWS` plus decoded password, depending on request path.
6. Avoid persisting generated AWS-vended tokens in `repository_config`; persist only stable provider config.
7. Emit health/telemetry for token refresh failures and token time-to-expiry.

Security considerations:

- Keep AWS credentials out of repository records; prefer runtime IAM/IRSA.
- Scope IAM policy to the intended CodeArtifact domain/repository or ECR registry/repositories where possible.
- Do not log AWS-vended tokens, AWS session tokens, or generated Authorization headers.
- Do not send AWS-vended credentials to unrelated redirected hosts or OCI bearer-token challenge realms.
- Preserve the existing outbound URL validation and redirect/SSRF hardening.
- Make token cache keys include provider, region, account/domain/repository/registry, and the effective AWS identity/role so credentials cannot bleed between remotes.

---

## Draft GitHub Issue

Title:

```text
Add dynamic AWS auth providers for ECR and CodeArtifact remotes
```

Body:

````markdown
## Problem Statement

I would like Artifact Keeper remote repositories to support dynamic AWS-backed upstream auth for Amazon ECR and AWS CodeArtifact without requiring external token-refresh automation or stored long-lived AWS secrets.

Today Artifact Keeper appears to support static upstream Basic and Bearer credentials for remote repositories, plus OCI-style bearer challenge handling. That means AWS-backed remotes can likely be made to work by periodically generating AWS-vended tokens and updating Artifact Keeper's upstream auth config, but the lifecycle is outside Artifact Keeper.

Examples:

- CodeArtifact requires IAM-authenticated `GetAuthorizationToken` calls to mint temporary package-manager tokens.
- ECR requires IAM-authenticated `GetAuthorizationToken` / `get-login-password` style credentials for Docker/OCI registry access.

That workaround is fragile for an internal artifact proxy/cache:

- operators need separate automation to call AWS and update Artifact Keeper;
- the automation needs a privileged Artifact Keeper API token;
- refresh failure means cache misses start failing when the old token expires;
- short-lived AWS-vended tokens may be stored in Artifact Keeper config even though they could be minted on demand;
- the safer Kubernetes deployment model is workload identity, such as IRSA or EKS Pod Identity, not static AWS access keys.

The use case is proxying internally published packages or container images during a phased migration, or using Artifact Keeper as a cache/policy layer in front of existing AWS artifact services.

## Proposed Solution

Add dynamic AWS upstream auth providers for remote repositories:

- `aws_codeartifact`
- `aws_ecr`

At runtime Artifact Keeper would:

1. use the AWS default credential chain, including IRSA / EKS Pod Identity;
2. call the relevant AWS token API;
3. cache the returned token in memory until near expiration;
4. refresh proactively and singleflight concurrent refreshes;
5. apply the token to upstream package-manager or OCI registry requests in the provider-specific auth shape;
6. avoid persisting generated AWS-vended tokens in repository config.

Suggested CodeArtifact config:

- region
- domain
- domain owner
- repository
- optional duration seconds
- optional role ARN / external ID

Suggested ECR config:

- region
- registry ID / account ID
- registry URI, or derive it from account ID and region
- optional role ARN / external ID

## Alternatives Considered

Use external automation to periodically mint AWS tokens and update Artifact Keeper's existing upstream auth configuration:

- `aws codeartifact get-authorization-token` for CodeArtifact remotes;
- `aws ecr get-login-password` or `aws ecr get-authorization-token` for ECR remotes;
- `PUT /api/v1/repositories/{key}/upstream-auth` to update Artifact Keeper.

This likely works because Artifact Keeper reloads upstream auth before proxy fetches, but it requires separate refresh automation, a privileged Artifact Keeper API token, expiry monitoring, and failure handling. It also means short-lived AWS-vended tokens may be persisted as repository credentials.

Another alternative is storing long-lived AWS access keys and implementing token refresh outside the Artifact Keeper process. I would prefer not to do that; the safer Kubernetes deployment model is workload identity.

## Use Case

As a platform/security engineer, I want Artifact Keeper to proxy AWS CodeArtifact packages and ECR container images using the server's IAM role, so that developers and CI can use Artifact Keeper as the internal artifact cache/policy layer without each client needing direct AWS package-registry credentials.

This matters for:

- phased migration away from CodeArtifact or ECR;
- caching internally published packages/images already in use;
- preserving continuity during AWS auth/service/configuration issues;
- avoiding direct public or AWS registry pulls from developer machines and CI;
- keeping package/image policy centralized in Artifact Keeper.

## Component

Backend / API

Also related to Authentication / Authorization and Docker / Deployment.

## Additional Context

Current local evidence from the pinned backend:

- Upstream auth currently models static Basic and Bearer only.
- Repository create/update API docs describe `upstream_auth_type` as `basic`, `bearer`, or `none`.
- The proxy fetch path reloads upstream auth before upstream requests, so a static-token refresh workaround should be possible.
- OCI remote support exists, but I did not find ECR-native AWS token minting.
- I did not find local references to `aws_sdk_ecr`, `aws_sdk_codeartifact`, `GetAuthorizationToken`, or equivalent AWS token-provider code.

AWS references:

- CodeArtifact tokens: https://docs.aws.amazon.com/codeartifact/latest/ug/tokens-authentication.html
- CodeArtifact `GetAuthorizationToken`: https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_GetAuthorizationToken.html
- CodeArtifact package formats: https://docs.aws.amazon.com/codeartifact/latest/ug/packages-overview.html
- ECR auth: https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry_auth.html
- ECR `GetAuthorizationToken`: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetAuthorizationToken.html

Security notes:

- Prefer runtime IAM through IRSA / EKS Pod Identity.
- Do not store AWS access keys or short-lived AWS-vended tokens as long-lived repository secrets.
- Required CodeArtifact permissions include `codeartifact:GetAuthorizationToken` and `sts:GetServiceBearerToken`.
- Required ECR permissions include `ecr:GetAuthorizationToken`, plus normal image pull permissions such as layer and image metadata reads.
- Tokens and generated Authorization headers must not be logged.
- Token cache keys should include provider, region, account/domain/repository/registry, and effective AWS identity/role.
- AWS-vended credentials should not be forwarded to unrelated redirected hosts or OCI challenge realms.
- Existing outbound URL validation and redirect/SSRF protections should continue to apply.

## Pre-submission Checklist

- [ ] I have searched existing issues and feature requests to ensure this isn't a duplicate
- [ ] I have reviewed the documentation to confirm this feature doesn't already exist
````
