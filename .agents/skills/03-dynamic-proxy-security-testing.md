# Skill: dynamic security testing for an internal artifact proxy/cache

## Goal
Build a practical hostile test plan for Artifact Keeper as a private artifact proxy/cache for PyPI, npm, Maven, and Cargo.

## Target deployment model
Assume the likely secure deployment model is:
- internal-only service
- private ingress only
- limited egress to approved upstreams
- plugins disabled
- only required package formats enabled

## Priority bug classes to test

### 1. SSRF and outbound fetch pivots
Test whether the service can be induced to fetch internal or unexpected targets through:
- direct upstream URLs
- redirects from approved upstreams
- DNS rebinding
- auth challenge realm URLs
- metadata-provided URLs

#### Test ideas
- approved external URL returns 302 to `http://127.0.0.1:...`
- approved external URL returns 302 to RFC1918 target
- hostname initially resolves public, then rebinds to internal
- upstream returns realm pointing to internal target

### 2. Authz boundary tests
Test whether:
- public repo write paths still require auth
- token scoped to repo A can read/write repo B
- format-specific handlers accidentally bypass common rules
- admin or config routes can be reached through alternate APIs

### 3. Cache poisoning / path confusion
Test whether package metadata or naming can cause:
- package mix-up between repos
- weird normalization collisions
- wrong artifact served after upstream fetch
- path traversal or alternate encoded separators

### 4. Resource exhaustion
Test whether:
- large uploads fill local storage
- partial/aborted uploads leak temp files
- repeated cache misses or streaming requests exhaust memory or file descriptors
- malformed metadata causes excessive CPU or parser work

## Practical harness ideas

### Safe local lab approach
Run Artifact Keeper locally with:
- a private test repo for each ecosystem
- a fake upstream server you control
- detailed logs enabled
- restricted egress if possible

### Useful helper services
Build a tiny helper server that can:
- return arbitrary redirects
- change DNS answers if your lab supports it
- return crafted auth challenges
- serve malformed package metadata
- log every inbound request for proof

## Suggested test matrix

### PyPI
- simple index metadata with malicious links
- weird package names and normalization variants
- redirecting package files

### npm
- scoped package names
- tarball URLs pointing somewhere unexpected
- metadata variations that reference alternate hosts

### Maven
- group/artifact/version path weirdness
- snapshot/metadata edge cases
- redirecting artifact downloads

### Cargo
- index and crate download indirection
- auth-challenge / token realm interactions if relevant
- crate path normalization

## Output expectations
For each test case, record:
- setup
- request made
- expected safe behavior
- observed behavior
- logs/evidence
- severity if unsafe

## Pitfalls
- do not test against real upstreams first; use controlled helpers
- do not call something SSRF if the target was still an approved upstream
- do not conflate a network policy block with application-layer safety; document both separately
