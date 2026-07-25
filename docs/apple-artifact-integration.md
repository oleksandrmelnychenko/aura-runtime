# Apple Artifact Integration Contract

Status: Stage 7 migration contract, July 25, 2026.

## Current Boundary

The Rust repository emits:

- Apple release manifest schema `5`;
- runtime artifact descriptor schema `3`;
- verification report
  `aura.apple_artifact_verification.v1`;
- one XCFramework with device, simulator, and Mac Catalyst slices.

The current committed iOS validator still accepts the previous exact manifest
schema `4` and descriptor schema `2`. That rejection is intentional: exact
shape validation prevents a new binary provenance contract from entering the
app without a reviewed client migration.

The iOS repository also has an unrelated unfinished BLE/offline worktree.
Stage 7 must not update its local package pin or artifact parser inside that
mixed change set.

## Schema 5 Additions

The release manifest adds:

- `source_tree_sha256`;
- `shippable`;
- `runtime_release_version`;
- `wire_package`;
- `wire_major_version`;
- `state_schema_version`;
- `ffi_contract_version`.

The descriptor carries the same provenance and contract-version fields. The
client must require equality between manifest and descriptor values.

## Required iOS Validation

The migrated Swift contract must reject the artifact unless:

- manifest schema is exactly `5`;
- descriptor schema is exactly `3`;
- `source_tree_dirty == false`;
- `shippable == true`;
- `source_tree_sha256` is a nonzero lowercase SHA-256 digest;
- runtime release version is nonempty and matches the native runtime;
- wire package is exactly `aura.messenger.v1` with major `1`;
- persisted state schema is `3`;
- FFI contract version is `1`;
- manifest and descriptor provenance fields are identical;
- descriptor, identity environment, trust keyring, headers, Info.plist, and all
  three binaries match their declared hashes;
- the production trust manifest accepts the runtime, model, and descriptor
  identities.

Unknown or missing keys remain a hard failure. A dirty artifact is suitable
only for local compilation and must never be accepted by the production trust
build phase.

## Pin Sequence

1. Land the reviewed Rust refactor and Stage 7 provenance changes.
2. Build `dist/apple` from that clean revision with
   `just apple-artifact-build-release`.
3. Preserve the passing
   `artifacts/apple-release-verification.json`.
4. Isolate or finish the unrelated iOS BLE/offline worktree.
5. Update `AuraNativeReleaseArtifactContract.swift` for schemas `5` and `3`.
6. Update the local-package/artifact pin to the exact Rust source revision and
   binary hashes.
7. Run the production trust-manifest build phase and focused Aura runtime
   contract tests against device and simulator slices.
8. Record the Rust revision, iOS revision, source-tree digest, binary digests,
   and test result in the release evidence bundle.

No pin should reference an uncommitted source tree or a verification report
whose `shippable` field is false.
