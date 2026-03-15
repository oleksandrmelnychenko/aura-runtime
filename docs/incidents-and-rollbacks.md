# Incidents and Rollbacks

## Purpose

This document defines the minimum operational posture AURA Core uses while it
is being prepared for production use.

Because AURA is a library/runtime rather than a hosted service, rollback means
reverting runtime, model, pattern, or corpus artifacts in a controlled and
traceable way.

## Incident Classes

The following incident classes matter most:

- critical false negative on child-safety risk
- harmful false positive on support or trusted-adult boundary cases
- protobuf or ABI incompatibility
- context export/import corruption
- privacy leak through logging or telemetry
- major latency or memory regression that degrades safety behavior

## Required Rollback Units

Production preparation should keep these artifacts independently identifiable:

- runtime/library build version
- protobuf wire version
- context schema version
- pattern bundle version
- model bundle version
- evaluation corpus snapshot

If these cannot be identified separately, rollback will be harder than it
should be.

## Minimum Safe Rollback Behavior

The system should be able to roll back to the previous known-good combination
of:

- runtime build
- pattern data
- model assets
- evaluation baseline

Until remote configuration exists, rollback may simply mean shipping the prior
embedded artifact set, but that artifact set still needs to be documented.

## Kill-Switch Expectations

The long-term production posture should support disabling or dampening:

- optional ML features
- specific pattern bundles
- specific high-risk UI actions
- new inference-aware policy branches

The ability to reduce surface area safely is part of operational readiness.

## Incident Triage Expectations

Every incident review should answer:

- what user-visible behavior failed
- whether the failure was metric-visible before release
- which slice or corpus should have caught it
- whether the issue came from runtime logic, data, contract drift, or policy
- whether rollback, forward-fix, or threshold tightening is the right response

## Release Artifact Requirements For Incident Response

Incident handling is much easier if each release candidate carries:

- commit SHA
- release-report artifact
- corpus snapshot identifiers
- model and pattern identifiers
- compatibility test result summary

Without this evidence, rollback becomes guesswork.

## Privacy Rules During Incidents

Incidents do not override privacy discipline automatically.

Even under incident pressure:

- avoid default raw transcript capture
- use narrowed access windows
- log access approvals
- delete temporary sensitive captures on the approved schedule

## Current Operational Baseline

The current rollback anchor is the unified evidence bundle:

- release report
- contract evidence
- dataset evidence
- audit evidence
- FFI smoke evidence
- FFI soak evidence

This gives incident response one stable machine-readable entrypoint for the
runtime, contract, privacy, and dataset posture of a candidate build.

## Minimum Runbook Steps

1. Freeze the failing release candidate and preserve its release artifact.
2. Identify whether the failure is data, model, runtime, or contract related.
3. Compare against the previous known-good release artifact.
4. Decide whether to roll back the whole runtime or only a dependent artifact.
5. Record the root cause and the missing gate that should be added.
6. Add regression coverage before re-promoting the fix.
