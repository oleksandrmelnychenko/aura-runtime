# Release decision contract

`ci/release_decision.py` implements the top-level
`aura.release_decision.v2` GO/NO-GO contract. It is deliberately separate from
Apple `shippable` and the technical evidence manifest: a correctly built
binary is not, by itself, authorization to release it.

The first supported profile is `agent-kids-rules-context`. For this profile,
ONNX models, Relay decisions, and Military policy must be demonstrably disabled.
They cannot be treated as `not_in_scope` merely because their evidence was
omitted.

## Required evidence

A `go` decision requires all of the following for one exact candidate:

- a passing `aura.evidence_manifest.v1`, its raw Ed25519 attestation, a pinned
  public key plus expected key identifier, and an exactly matching derived
  verification report;
- a passing, clean, shippable Apple artifact verification, the exact Apple
  release manifest, and a strict two-build reproducibility report binding
  source `H`, artifact `A`, and release revision `R`;
- a passing `aura.pilot_gate_report.v2` whose report and each of exactly four
  real review signoffs bind the exact release revision `R`, plus mandatory KIDS
  checks, rollback triggers, stop conditions, and review cadence; reviewer
  labels are governance assertions, not cryptographic identities;
- an external `aura.product_integration_acceptance.v2` produced after client
  contract tests accept the exact Apple artifact;
- matching source revision, source-tree digest, runtime identity, artifact
  hashes, and profile scope across every child.

The product-acceptance template is
`docs/product-integration-acceptance.template.json`. It binds the evidence
manifest, its raw signature and signer SPKI, its signature verification,
Apple verification, Apple manifest,
Apple reproducibility proof, and pilot gate by SHA-256. It also records exact
`A`/`R` plus successful local-decision,
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
  --evidence-attestation artifacts/evidence-manifest.attestation.json \
  --evidence-public-key /trusted/evidence-signer-public.pem \
  --expected-evidence-key-id evidence-signer-2026-01 \
  --evidence-attestation-verification artifacts/evidence-manifest.attestation-verification.json \
  --apple-artifact-verification artifacts/apple-release-verification.json \
  --apple-artifact-reproducibility artifacts/apple-reproducibility.json \
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
  --evidence-attestation artifacts/evidence-manifest.attestation.json \
  --evidence-public-key /trusted/evidence-signer-public.pem \
  --expected-evidence-key-id evidence-signer-2026-01 \
  --evidence-attestation-verification artifacts/evidence-manifest.attestation-verification.json \
  --apple-artifact-verification artifacts/apple-release-verification.json \
  --apple-artifact-reproducibility artifacts/apple-reproducibility.json \
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

Before signing, the command reopens every source-evidence file, reads bounded
stable snapshots, independently verifies the raw evidence-manifest signature
against the pinned key and expected key identifier, requires the supplied
derived report to match exactly, and recomputes every decision field except the
generation timestamp. The detached Ed25519 signature binds the exact decision
bytes, `H`/`A`/`R`, the raw evidence-attestation digest, and the evidence signer
identity. The release-operator SPKI must differ from the evidence-signer SPKI;
the verifier enforces the same separation. A `no-go` decision cannot be signed.
Private keys must remain outside the repository and use owner-only permissions.

## Security boundary

The decision proves that the listed evidence files were mutually consistent
and that a trusted release operator signed the resulting `go`. It does not
prove that a human reviewer was independent or honest, that an external client
test was competently designed, or that no signing key was compromised. Those
claims remain organizational controls and must not be inferred from the JSON
alone.

After signing, package and re-verify the exact evidence graph with the
fixed-layout terminal dossier described in
`docs/release-candidate-dossier.md`. Its unsigned index is inventory and
transport metadata only; it never replaces this signed decision as the release
authority.
