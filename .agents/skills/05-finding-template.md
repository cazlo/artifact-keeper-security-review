# Skill: finding write-up template

Use this template for every meaningful issue or hardening recommendation.

## Title
A concise statement of the issue.

## Type
Choose one:
- Confirmed issue
- Plausible issue
- Hardening recommendation

## Component
List the relevant file(s), handler(s), and feature area.

## Threat scenario
Describe how an attacker or misconfiguration would trigger the behavior.

## Why it matters here
Tie it back to the user's intended deployment:
- internal artifact proxy/cache
- PyPI/npm/Maven/Cargo focus
- continuity and controlled egress matter

## Evidence
Include:
- code references
- grep snippets
- logs
- repro steps if available

## Confidence
Choose one:
- High
- Medium
- Low

## Severity / impact
Describe the realistic impact, not generic worst-case marketing language.

## Recommended next step
One of:
- write a repro
- trace deeper in code
- propose a patch
- document as deployment guidance
