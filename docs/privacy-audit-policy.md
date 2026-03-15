# Privacy and Audit Policy

## Purpose

AURA Core is built for child and teen safety use cases. Privacy, explainability,
and auditability must therefore coexist without depending on unsafe logging of
raw conversations.

This document defines the default policy for telemetry, logging, and audit
records.

## Core Principles

- default to no raw conversation logging
- keep analysis in-process by default
- log decisions and evidence classes, not private transcript content
- make audit trails reviewable without reconstructing full child conversations
- require explicit approval for any elevated debugging path

## Data Classes

### Sensitive Content

This includes:

- raw message text
- raw media payloads
- full conversation transcripts
- exported context state containing raw identifiers if not protected

This class must not be logged by default.

### Operational Metadata

This includes:

- release version
- schema versions
- suite identifiers
- slice identifiers
- detector and policy reason codes
- aggregate risk metrics
- timing and performance stats

This class is generally safe to log when it does not reconstruct private
content.

### Restricted Identifiers

This includes:

- sender IDs
- conversation IDs
- contact IDs

These should be treated as restricted data and should be hashed, tokenized, or
otherwise protected unless an approved incident workflow requires otherwise.

The current routine audit path tokenizes them under
`sha256_truncated_24hex_process_salted`. Deployments that need stable token
linkage across process restarts should provide an explicit
`AURA_AUDIT_TOKEN_SALT` override rather than falling back to plaintext logging.

## Default Logging Rules

Allowed by default:

- runtime version
- protobuf and state schema versions
- action outputs
- reason codes
- threat families
- aggregate scores
- latency and throughput metrics
- release-report summaries

Forbidden by default:

- raw message text
- raw image, voice, or video payloads
- full exported context blobs in logs
- plaintext child identifiers
- screenshots or pasted chats in automated telemetry

## Audit Event Shape

The audit record should be structured and minimal. It should include:

- event timestamp
- runtime version
- wire version
- state schema version
- analyzer mode or protection level
- threat type and top threat scores
- `reason_codes`
- `ui_actions`
- parent-alert level
- follow-up actions
- contact trend and circle tier when available
- a stable internal request ID

It should not include full transcript text.

Current machine-readable audit evidence uses:

- audit schema: `aura.audit_record.v1`
- identifier scheme: `sha256_truncated_24hex_process_salted`
- forbidden-field proof for `sender_id`, `conversation_id`, `text`, and
  `message_text`

## Debugging Exceptions

Any workflow that needs higher-fidelity content access must satisfy all of the
following:

- explicit approval for the incident or investigation
- smallest possible time window
- smallest possible user set
- documented reason for access
- retention and deletion plan

Debug access is an exception path, not a normal observability strategy.

## Dataset and Evaluation Privacy

Evaluation corpora must follow the same privacy posture:

- external curated cases need provenance and review metadata
- corpus files must not include unnecessary identifying detail
- test fixtures should prefer synthetic or de-identified messenger-like data
- realistic cases should preserve behavior patterns without carrying real user
  identifiers

## Retention Expectations

Until stronger operational infrastructure exists, the default expectation is:

- keep release artifacts and aggregate reports
- avoid retaining sensitive raw debugging data
- delete exceptional debug captures on the shortest approved schedule

## Current Enforcement Expectations

- structured audit schema without raw transcript dependence
- hashed or tokenized identifiers for routine diagnostics
- release artifacts that can explain decisions through reasons and actions
- explicit review before adding any new telemetry field tied to user content
- machine-readable audit evidence proving forbidden plaintext fields are absent

## Release Blockers

A release is blocked if it introduces:

- new raw-content logging by default
- new plaintext identifiers in routine logs
- undocumented export of sensitive context state
- telemetry fields that cannot be justified under this policy

## Enforced Evidence

Promotion evidence should include an audit artifact that verifies:

- the audit schema version is explicit
- identifiers are tokenized under a declared scheme
- raw `sender_id`, `conversation_id`, `text`, and `message_text` fields are absent
- the sample record still carries reasons, actions, and top threat scores
