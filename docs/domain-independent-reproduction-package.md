# Private independent-reproduction package

`aura.domain.independent_reproduction_package.v1` is the private,
content-addressed inventory that follows a valid
`aura.domain.independent_evaluation_evidence.v2` chain. It closes the gap
between a signed aggregate claim and the files an independent team needs to
inspect and rerun the frozen analysis.

The package is not a scientific result. A successful core report has status
`manifest_consistent`: all required file identities are present, bounded,
ordered, and cross-linked to the validated preregistration, result bundle,
final manifest, trust policy, and RFC 3161 receipts. It does not mean that a
second team executed the analysis or reproduced its outcome.

## Required private files

The primary inventory retains the exact canonical preregistration, policy,
build provenance, trust policy, source tree, Cargo.lock, toolchain descriptor,
evaluated binary, known-seed registry, fixed corpus, inclusion and exclusion
criteria, label ontology, safe-boundary definition, split and attack manifests,
agreement bootstrap seed, blinded review packet, each reviewer assignment and
decision bundle, review-coverage matrix, agreement-analysis output,
adjudication manifest and decisions, predictions, analysis-environment lock,
exclusions, protocol deviations, optional exploratory output, and complete
private result-evidence bundle.

For every timestamp receipt, the inventory separately retains:

- the original nonce-bearing DER request and DER response;
- the selected certificate chain as individual DER files in signer-to-anchor
  order;
- the complete CRL DER set, unique and sorted by SHA-256.

The core recomputes the same domain-separated certificate-chain and revocation
aggregates used by the timestamp adapter. Schema v1 accepts the adapter's exact
bounds: 2–7 certificates and 1–6 CRLs. The CRL count must equal the number of
non-anchor certificates.

## Materialize without exporting paths

Create a private descriptor with schema
`aura.domain.reproduction_materialization_descriptor.v1`. It has the same top
identity fields as the output manifest, `primary_artifacts` entries with
`role`, `ordinal`, and `path`, and `timestamp_materials` entries with:

```json
{
  "subject_kind": "reviewer_receipt",
  "reviewer_index": 0,
  "request_path": "timestamps/reviewer-0.tsq",
  "response_path": "timestamps/reviewer-0.tsr",
  "certificate_chain_der_paths": [
    "timestamps/tsa-signer.der",
    "timestamps/tsa-root.der"
  ],
  "revocation_crl_der_paths": [
    "timestamps/tsa-issuer.crl.der"
  ]
}
```

Paths may be absolute or relative to the descriptor. The descriptor and output
must remain inside the controlled private research environment and outside the
`source_tree` repository, so producing the manifest cannot change the digest it
is calculating.

```sh
python3 ci/domain_reproduction_manifest.py \
  --descriptor private/reproduction-descriptor.json \
  --output private/reproduction-manifest.json
```

The materializer opens each regular file without following symbolic links,
streams at most 1 TiB per file through SHA-256, rejects mutation during the
read, records exact byte length, and writes through a directory-bound atomic
output. The output contains no local path. Every primary entry records
`digest_kind` and `covered_file_count`: exact single files use
`raw_file_sha256`, typed compact documents use `canonical_json_sha256`, and
`source_tree` uses the same domain-separated `build_source_tree_v2` Git-tree
algorithm as the Apple release gate. Limits are 40 primary artifacts, 10
timestamp groups, 100,000 represented source/file entries, and 4 TiB total for
schema v1. Confirmatory `source_tree` materialization additionally rejects a
dirty repository.

The descriptor's four top digests must come from the trusted Rust validation
context:

- `preregistration_canonical_sha256`;
- `result_bundle_sha256`;
- `final_manifest_sha256`;
- `evidence_bundle_canonical_sha256`, calculated with
  `domain_study_result_canonical_sha256` over the typed private bundle.

Then call `validate_domain_study_reproduction_manifest` with the same
preregistration, evidence JSON, policy, build provenance, known-seed registry,
and trust policy used for the result-chain validation. This reruns the entire
signed result validator before checking the reproduction inventory.

## Claim and privacy boundary

Both `public_distribution_permitted` and
`independent_recomputation_completed` must be false. The materializer and core
reject a descriptor or manifest that changes either value. Raw corpus,
reviewer, child-safety, military, consent, or governance material must not be
copied into public release evidence.

Moving beyond `manifest_consistent` requires a separate, signed record from an
authorized independent environment. That later record must bind the package
digest, exact command, implementation and environment lock, hardware class,
seed set, normalized recomputed output, deviations, and comparison with the
frozen result. Even then, the claim remains limited by sampling,
representativeness, labeling, blinding, governance, and key-control assumptions.
