# ADR 0001: Canonical Local Decision API

- Status: accepted; source implementation complete, artifact/client acceptance pending
- Date: 2026-08-01
- Release blocker: `REL-002`

## Context

The Apple boundary exposes canonical Safety Case ingestion but does not return
the immediate product decision needed by child, guardian, and review surfaces.
Reintroducing the former general analysis API would expose a broad payload,
create a second state-mutation path, and let clients rebuild policy from raw
scores.

The native runtime already has one exactly-once source ledger and one guarded
stateful path that updates conversation context, KIDS memory, and Safety Case
state. The product decision must use that path rather than analyze the same
message independently.

## Decision

Add one ABI operation, `aura_analyze_local_decision`, with protobuf
`LocalDecisionAnalyzeRequest` and `LocalDecisionAnalyzeResponse` messages.

The compact decision contains only:

- `ProductDecisionSurface`;
- `ActionRecommendation`;
- bounded machine-readable reason codes;
- `InferenceSummary`;
- the active runtime backend and an explicit degradation flag.

It excludes message text, explanations, individual detection signals, contact
identifiers, arbitrary JSON, and host display copy. The response also carries
the canonical Safety Case disposition, case identity/revision/generation, and
runtime-state schema version.

## Transaction and retry contract

| Concern | Owner and rule |
| --- | --- |
| Source identity | Host supplies stable account, subject, conversation, event, and revision keys. Native validates them before analysis. |
| First attempt | Native preflights the source ledger, runs the stateful Agent pipeline once, reduces Safety Case state, checks the persistence envelope, and returns one typed decision only after success. |
| Duplicate | Native does not invoke the analyzer and returns a content-free duplicate disposition. The host resolves the previously persisted response by canonical identity. |
| Stale revision | Native does not invoke the analyzer, returns `latest_revision`, and exposes no product decision. |
| Projection or persistence-envelope failure | Native exposes no product decision. Context and case changes are rolled back and a bounded rejected receipt prevents accidental replay in the current runtime. |
| Host persistence commit | Before applying UI or guardian effects, the host atomically stores the response, exported context, and encrypted account-scoped Safety Case state. |
| Host persistence failure | The host must not apply the decision. It destroys the uncommitted handle, restores the last durable context and Safety Case state into a fresh handle, reapplies the signed execution policy, and retries the same identity. |
| Restart after commit but before display | The host reads and applies the stored typed response. Calling native again yields a duplicate receipt and cannot double-apply context or Safety Case state. |
| Terminal source checkpoint | Only after the host inbox row is durably terminal, the host calls `aura_acknowledge_source_checkpoint` and persists the resulting compacted native state. Native forgets ignored/rejected receipts but retains every receipt that covers a Safety Case observation. |
| Background/foreground repetition | The same identity/revision follows the duplicate rule. An edit must increment revision. |
| Display copy | The application owns localization keys and text. Native returns policy enums and reason codes only. |

## Compatibility

The change is additive: existing protobuf field numbers and C functions remain
unchanged. `CanonicalSafetyAnalyzeResponse` stays content-free. The local
decision and terminal-source checkpoint symbols are added to the exact Apple
export allowlist. The checkpoint consumes an existing
`CanonicalSafetyEventIdentity` protobuf and returns no buffer.

## Consequences

There is one state-mutating product analysis path and no double-apply between
local decisions and Safety Case lifecycle. Durable retry remains a host/native
protocol: the native library cannot claim a host database transaction has
committed. UI application before the host commit, or source acknowledgement
before the inbox event is durably terminal, is a contract violation.
