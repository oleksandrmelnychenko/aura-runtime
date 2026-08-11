# Release decision contract

`ci/release_decision.py` implements the top-level
`aura.release_decision.v1` GO/NO-GO contract. It is deliberately separate from
Apple `shippable` and the technical evidence manifest: a correctly built
binary is not, by itself, authorization to release it.

The first supported profile is `agent-kids-rules-context`. For this profile,
ONNX models, Relay decisions, and Military policy must be demonstrably disabled.
They cannot be treated as `not_in_scope` merely because their evidence was
omitted.

## Required evidence

A `go` decision requires all of the following for one exact candidate:

- a passing `aura.evidence_manifest.v1` and its successful Ed25519 attestation
  verification;
- a passing, clean, shippable Apple artifact verification plus the exact Apple
  release manifest;
- a passing pilot gate containing all four real review signoffs, mandatory
  KIDS checks, rollback triggers, stop conditions, and review cadence;
- an external `aura.product_integration_acceptance.v1` produced after client
  contract tests accept the exact Apple artifact;
- matching source revision, source-tree digest, runtime identity, artifact
  hashes, and profile scope across every child.

The product-acceptance template is
`docs/product-integration-acceptance.template.json`. It binds the evidence
manifest, its signature verification, Apple verification, Apple manifest, and
pilot gate by SHA-256. It also records successful local-decision,
terminal-checkpoint, and restart-replay client contracts.

Missing input produces a machine-readable `no-go` with a `blocked` category.
Malformed, mismatched, stale, or contradictory input produces `no-go` with a
`fail` category. The tool never converts missing evidence to pass and does not
export local file paths.

## Create a decision

```bash
python3 ci/release_decision.py create \
  --candidate-revision '<40 lowercase Git revision>' \
  --runtime-version 0.2.0 \
  --profile agent-kids-rules-context \
  --evidence-manifest artifacts/evidence-manifest.json \
  --evidence-attestation-verification artifacts/evidence-manifest.attestation-verification.json \
  --apple-artifact-verification artifacts/apple-release-verification.json \
  --apple-release-manifest dist/apple/release-manifest.json \
  --pilot-gate-report artifacts/pilot-gate-report.json \
  --product-integration-acceptance artifacts/product-integration-acceptance.json \
  --output artifacts/release-decision.json \
  --require-go
```

Without `--require-go`, the command still writes a valid `no-go` artifact and
returns success. This is useful for rehearsals. A promotion job must use
`--require-go`.

## Operator signature

Only a structurally and semantically consistent `go` decision can be signed:

```bash
python3 ci/release_decision.py sign \
  --decision artifacts/release-decision.json \
  --private-key /protected/release-operator-private.pem \
  --key-id release-operator-2026-01 \
  --evidence-manifest artifacts/evidence-manifest.json \
  --evidence-attestation-verification artifacts/evidence-manifest.attestation-verification.json \
  --apple-artifact-verification artifacts/apple-release-verification.json \
  --apple-release-manifest dist/apple/release-manifest.json \
  --pilot-gate-report artifacts/pilot-gate-report.json \
  --product-integration-acceptance artifacts/product-integration-acceptance.json \
  --output artifacts/release-decision.attestation.json

python3 ci/release_decision.py verify \
  --decision artifacts/release-decision.json \
  --attestation artifacts/release-decision.attestation.json \
  --public-key /trusted/release-operator-public.pem \
  --expected-key-id release-operator-2026-01 \
  --output artifacts/release-decision.attestation-verification.json \
  --require-pass
```

Before signing, the command reopens all six source-evidence files, verifies
their recorded SHA-256 identities, and independently recomputes every decision
field except the generation timestamp. The detached Ed25519 signature then
binds the exact decision bytes, candidate, profile, source revision, key
identifier, and trusted public-key SPKI digest. A `no-go` decision cannot be
signed by this command. Private keys must remain outside the repository and use
owner-only permissions.

## Security boundary

The decision proves that the listed evidence files were mutually consistent
and that a trusted release operator signed the resulting `go`. It does not
prove that a human reviewer was independent or honest, that an external client
test was competently designed, or that no signing key was compromised. Those
claims remain organizational controls and must not be inferred from the JSON
alone.
