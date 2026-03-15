# Proto and ABI Stability

## Purpose

This document defines change rules for the messenger protobuf contract, the C
ABI, and the persisted context state used by AURA Core.

The contract surface is safety-critical. A release is not stable if evaluation
is green but the boundary can drift silently.

## Contract Surfaces

### Protobuf Wire Contract

Primary schema:

- [`proto/aura/messenger/v1/messenger.proto`](../proto/aura/messenger/v1/messenger.proto)

Generated contract crate:

- [`crates/aura-proto`](../crates/aura-proto)

### C ABI Boundary

Public C header:

- [`include/aura_ffi.h`](../include/aura_ffi.h)

Implementation crate:

- [`crates/aura-ffi`](../crates/aura-ffi)

### Persisted Context State

Current persisted protobuf state lives under `TrackerState` and carries its own
`schema_version` field in the messenger protobuf contract.

## Version Tracks

Three version tracks must stay distinct:

1. `Wire version`
   The protobuf API contract version. Current package path is `aura.messenger.v1`.
2. `State schema version`
   The version used for persisted tracker/contact state import and export.
3. `Runtime release version`
   The shipping version of the library or embedded runtime.

Do not overload one of these tracks to represent all three concerns.

## Current Enforcement Snapshot

As of the current release-hardening track:

- wire package: `aura.messenger.v1`
- wire major version: `1`
- persisted state schema version: `2`
- compatibility fixtures pinned for `AnalysisResult`, `TrackerState`, and
  `BatchAnalyzeResponse`
- contract evidence emitted by `contract_evidence`
- C header smoke compile enforced in CI and promotion workflows
- FFI request-size caps emitted as machine-readable evidence

## Wire Compatibility Rules

Allowed in the current major wire version:

- adding new optional or repeated fields
- adding new enum values only when older clients can safely ignore them
- adding new protobuf messages without mutating existing message semantics

Not allowed in the current major wire version:

- renumbering fields
- reusing removed field numbers
- changing field types
- changing scalar/repeated/map shape of existing fields
- changing semantic meaning of an existing field without versioning

If a field is removed:

- reserve the field number
- reserve the field name where appropriate
- document the migration reason

If an enum value is removed:

- reserve the value number
- never repurpose it for a different semantic

Breaking protobuf changes require a new wire-major path such as `v2`, not an
in-place mutation of `v1`.

## ABI Stability Rules

The C ABI contract should treat these items as frozen:

- `AuraBuffer` memory layout
- existing exported function names
- parameter ordering and pointer semantics
- ownership rules for returned buffers and error strings

Safe additive changes:

- adding new exported functions
- adding new helper APIs that do not mutate the meaning of existing ones

Breaking changes that require a new ABI major:

- changing the layout of `AuraBuffer`
- changing return conventions for existing functions
- changing ownership rules for `aura_last_error`, `aura_free_buffer`, or
  `aura_free_string`
- changing handle lifetime semantics

## Persisted State Rules

`TrackerState.schema_version` must be used as the persisted state compatibility
anchor.

Rules:

- additive state fields are preferred
- removed or repurposed state fields require explicit migration handling
- import behavior for older schema versions must be documented and tested
- import of unsupported future schema versions must fail safely and clearly

Context corruption is a production incident, not a normal edge case.

## Error and Failure Semantics

The ABI must remain panic-free from the caller's perspective.

Required behavior:

- invalid input buffers return failure and set a stable error message
- null handles return failure and set a stable error message
- oversized request buffers fail before protobuf decode and do not mutate state
- malformed context imports fail safely without partial silent corruption
- missing models or patterns must degrade according to documented rules
- callers never need undefined behavior knowledge to use the ABI safely

## Required Compatibility Tests

### Protobuf

- encode/decode round-trip tests for key messages
- golden vector tests for stable message shapes
- tests that ensure removed field numbers are not reused

### ABI

- C header compile smoke tests
- null and invalid input tests
- request-size limit tests for config, analyze, batch, and import paths
- truncated buffer tests
- ownership and free-path tests
- batch processing edge-case tests

### Persisted State

- export/import round-trip tests
- backward import tests for prior schema versions
- failure tests for unsupported future schema versions
- repeated export/import soak tests that prove idempotent sync across handles

Current implementation already covers round-trip fixtures, malformed-input
rejection, oversized-request rejection, unsupported future schema rejection,
and repeated state-sync soak runs.

## Release Requirements

A production release is blocked unless it includes:

- protobuf compatibility evidence
- ABI compatibility evidence
- context-state compatibility evidence
- documented FFI request-size limits
- FFI state-sync soak evidence
- curated soak failure diagnosis for flaky or failing state-sync runs
- documented version stamps for runtime, wire, and state schema

These release-boundary artifacts should be addressable through one stable
evidence manifest so automation does not need to discover each JSON file ad hoc.

## Current Boundary Evidence

Current contract evidence also records the active request-size limits:

- config request: `65536` bytes
- message and analyze-context request: `1048576` bytes
- batch analyze request: `4194304` bytes
- import-context request: `4194304` bytes
- small control request: `16384` bytes

These limits are part of the boundary contract and must be reviewed before
being raised.
