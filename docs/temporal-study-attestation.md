# Temporal study commitment attestation

`ci/temporal_study_attestation.py` creates and verifies a detached Ed25519
attestation for `aura.military.temporal_study_commitment.v1`. The signature is
domain-separated from release-manifest signatures and binds both the exact file
bytes and AURA's canonical commitment representation.

The signed claims include the study identity, declared registration time,
corpus class, preregistration digest, corpus digest, packet digest, trusted-key
identity, and public-key SPKI digest. Any semantic change or byte-only rewrite
of the committed file invalidates the attestation.

## Institutional key

Use a dedicated study-governance key from an approved HSM, key-management
service, or controlled signing host. For a local rehearsal only:

```sh
openssl genpkey -algorithm Ed25519 \
  -out /protected/aura-temporal-study-private.pem
chmod 600 /protected/aura-temporal-study-private.pem
openssl pkey \
  -in /protected/aura-temporal-study-private.pem \
  -pubout \
  -out /trusted/aura-temporal-study-public.pem
```

Do not reuse the release-manifest key. Do not commit, log, distribute, or place
the private key beside public study artifacts. The signer rejects a symlink or
group/world-readable private key.

## Sign before review

After generating the blind packet and public study commitment, but before
reviewers receive the packet:

```sh
python3 ci/temporal_study_attestation.py sign \
  --commitment review/temporal-study-commitment.json \
  --private-key /protected/aura-temporal-study-private.pem \
  --key-id temporal-study-board-2026-01 \
  --output review/temporal-study-commitment.attestation.json
```

The signer accepts only the strict v1 commitment schema, high-assurance
agreement thresholds, valid fixed counts, and supported corpus classes. It
rejects duplicate JSON fields and malformed canonical digests.

## Verify with a trusted public key

Verification requires a public key obtained through an independent trust
channel and an expected key identifier:

```sh
python3 ci/temporal_study_attestation.py verify \
  --commitment review/temporal-study-commitment.json \
  --attestation review/temporal-study-commitment.attestation.json \
  --public-key /trusted/aura-temporal-study-public.pem \
  --expected-key-id temporal-study-board-2026-01 \
  --output artifacts/temporal-study-attestation-verification.json \
  --require-pass
```

The verification report is safe to include in release evidence. It contains
digests and pseudonymous key/study identifiers, never private-key material,
reviewer identities, corpus labels, or message content.

Provide it to the unified evidence manifest together with the review report:

```sh
python3 ci/generate_evidence_manifest.py \
  ... \
  --temporal-independent-review-report \
    artifacts/temporal-independent-review-report.json \
  --temporal-study-attestation-verification \
    artifacts/temporal-study-attestation-verification.json
```

Temporal policy activation remains `pending` when the external review passes
but this trusted-key verification is absent. A mismatched or invalid
verification fails the activation gate.

## Time-evidence boundary

This attestation proves that the holder of the institutional private key signed
the exact commitment. It does not prove when signing occurred. The verification
report therefore fixes `trusted_timestamp_assurance` to `absent`; a caller
cannot promote it to a stronger value.

For confirmatory doctoral evidence, additionally submit the commitment digest
to an independent RFC 3161 timestamp authority or an approved append-only or
write-once institutional log before labels are collected. Preserve the receipt,
authority trust chain, verification output, and governance record. Trusted
timestamp verification is a separate future evidence contract and must not be
inferred from `registered_at_ms` or the Ed25519 signature.
