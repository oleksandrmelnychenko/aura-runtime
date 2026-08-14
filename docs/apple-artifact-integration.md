# Apple Artifact Integration Contract

Status: REL-009 hardened artifact provenance contract, August 13, 2026.

The source ABI includes the additive typed `aura_analyze_local_decision` and
terminal `aura_acknowledge_source_checkpoint` symbols plus generated Swift
protobuf models. The release XCFramework is bound to a clean source revision,
verified before any rebuild, and then rebuilt twice from that exact revision.
The gate checks the export allowlist, source digest, complete file inventory,
headers, slices, and binary hashes. External iOS acceptance and its exact
artifact pin remain a separate gate: a client must not assume the new symbols
exist until it accepts the manifest and binary produced by the sequence below.

## Current Boundary

The Rust repository emits:

- Apple release manifest schema `5`;
- runtime artifact descriptor schema `3`;
- verification report
  `aura.apple_artifact_verification.v1`;
- one XCFramework with device, simulator, and Mac Catalyst slices.

The iOS validator accepts only manifest schema `5` and descriptor schema `3`
and binds the local package to an exact commit and source-tree digest. Exact
shape validation prevents a binary provenance contract from entering the app
without a reviewed client migration.

The release builder uses a fresh Cargo target directory for every invocation,
rejects ambient Rust compiler flags, remaps repository/toolchain/build paths,
and rejects archives that still contain any of those local paths. The hardened
gate first verifies the exact checked-in 11-file `dist/apple` inventory. It
then performs two sequential clean builds from the source commit in different
absolute directories outside the checkout and requires:

```text
checked-in inventory == build 1 inventory == build 2 inventory
```

This is evidence of deterministic repeatability and absolute-path independence
on the pinned runner. It is not independent reproduction and does not establish
trust in the compiler, toolchain distribution, runner image, or build service.

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

`source_tree_sha256` uses the domain-separated
`aura.build-source-tree.v2` algorithm over every tracked or untracked
build-relevant file. It excludes generated `dist/apple` outputs and exactly
two non-build governance artifacts:
`crates/aura-core/data/refactor_baseline_v1.json` and
`docs/refactor-diff-approvals.json`. Those files contain the artifact hashes
they review, so including them would create a cryptographic self-reference.
All neighboring governed datasets, CI code, headers, Rust/Swift sources, lock
files, and release scripts remain inside the digest.

Version `v2` hashes materialized build-relevant file bytes, including every
Git LFS-backed source object currently in scope (about 5.5 GiB / 5.9 GB). For
each LFS path, verification derives the expected object identifier and size
from the exact stage-zero index pointer and requires the working file to match
both. An LFS pointer file, missing object, wrong-size object, or same-size
object with a different digest fails closed. The caller must therefore provide
a checkout with all required LFS objects already materialized.

Changing the contract to hash only a selected subset of build-relevant LFS
objects would change the meaning of the digest and requires a new
`aura.build-source-tree.v3` algorithm. It must not be introduced as an
implementation optimization under the `v2` identifier.

## Hardened Provenance Sequence

Let `H` be the reviewed source commit, `A` its generated artifact commit, and
`R` the exact manually dispatched release revision on protected `main`. `R` may equal `A`, or it
may be a later governance-only descendant that records approval of `A`. A
shippable candidate is valid only when all of the following hold:

1. The caller provides full Git history and materialized Git LFS objects. The
   verifier does not silently fetch history or artifact bytes.
2. `A` has exactly one parent, that parent is `H`, and `H != A`.
3. The manifest records the full 40-character `H` revision and the `v2` source
   digest computed from materialized files at `H`.
4. The `H..A` diff changes only the generated Apple artifact paths allowed by
   the release contract. Source, build scripts, governance data, and unrelated
   files must not change in `A`.
5. Every commit in the optional `A..R` suffix has exactly one parent and changes
   only `docs/refactor-diff-approvals.json` and/or
   `crates/aura-core/data/refactor_baseline_v1.json`. The checked-in Apple
   inventory at `R` must therefore remain byte-identical to `A`. Version 1
   bounds the lineage at 16 commits from the first child of `H` through `R`
   (`A` plus at most 15 governance commits).
6. Before any build can overwrite output, the verifier checks the complete
   checked-in 11-file `dist/apple` tree, rejects missing or extra entries and
   non-regular files, and validates every declared identity and hash.
7. Two fresh builds are run sequentially from `H`, in distinct absolute source
   and output directories. Their build commands do not receive `A` as a declared
   input, and each exact output inventory must equal the checked-in inventory
   and the other build. Because linked worktrees share one trusted runner and
   Git repository, this does not prove candidate-blind or hermetic execution;
   the source and build scripts are trusted inputs to this gate.
8. The release environment uses Xcode `26.2` and Rust `1.96.1`; a different
   resolved tool version is a hard failure rather than an equivalent build.

Pull-request validation may exercise the builder and verifier, but a synthetic
pull-request merge revision cannot issue release provenance evidence. The
strict sequence must run against exact revision `R`; its machine report binds
`source_revision=H`, `artifact_revision=A`, and `release_revision=R`.

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
2. Treat that clean, reviewed commit as `H`; ensure the checkout has full
   history and all required Git LFS objects materialized.
3. Build `dist/apple` from `H` with `just apple-artifact-build-release` using
   Xcode `26.2` and Rust `1.96.1`.
4. Create `A` as the direct child of `H` and commit only the permitted generated
   `dist/apple` outputs. Do not amend source or governance files into `A`.
5. Record the exact refactor-diff approval and/or accepted baseline in one or
   more linear governance-only commits after `A`; call the resulting release
   revision `R`. Do not modify `dist/apple` in this suffix.
6. On exact revision `R`, verify the checked-in 11-file inventory before any
   rebuild, then run the two-build reproducibility gate from `H`.
7. Preserve both `artifacts/apple-release-verification.json` and
   `artifacts/apple-reproducibility.json` from the passing strict run.
8. Update `AuraNativeReleaseArtifactContract.swift` for schemas `5` and `3`.
9. Update the local-package/artifact pin to the exact Rust source revision,
   artifact commit, and binary hashes.
10. Run the production trust-manifest build phase and focused Aura runtime
   contract tests against device and simulator slices.
11. Record `H`, `A`, `R`, the iOS revision, source-tree digest, binary digests,
    pinned tool versions, runner identity, and test results in the release
    evidence bundle.

No pin should reference an uncommitted source tree or a verification report
whose `shippable` field is false.
