# Evidence manifest Ed25519 attestation

`ci/evidence_attestation.py` creates and verifies a detached Ed25519
attestation for the exact bytes of `aura.evidence_manifest.v1`. The signed
claims bind the manifest SHA-256 digest, key identifier, signature algorithm,
and trusted public-key SPKI digest. Verification requires an externally trusted
public key; the attestation cannot substitute its own key.

## Key generation

Generate keys in an approved secret-management environment, not in the source
tree:

```sh
openssl genpkey -algorithm Ed25519 -out aura-evidence-private.pem
chmod 600 aura-evidence-private.pem
openssl pkey -in aura-evidence-private.pem -pubout -out aura-evidence-public.pem
```

The private key must never be committed, added to an artifact, written to logs,
or distributed to verifier hosts. Rotate it by introducing a new `key_id` and
trusted public key before removing the old trust entry.

## Local signing and verification

```sh
python3 ci/evidence_attestation.py sign \
  --manifest artifacts/evidence-manifest.json \
  --private-key /protected/aura-evidence-private.pem \
  --key-id release-2026-01 \
  --output artifacts/evidence-manifest.attestation.json

python3 ci/evidence_attestation.py verify \
  --manifest artifacts/evidence-manifest.json \
  --attestation artifacts/evidence-manifest.attestation.json \
  --public-key /trusted/aura-evidence-public.pem \
  --expected-key-id release-2026-01 \
  --output artifacts/evidence-manifest.attestation-verification.json \
  --require-pass
```

Local release rehearsals accept the same paths through command-line options or
the environment variables `AURA_EVIDENCE_SIGNING_PRIVATE_KEY_PATH`,
`AURA_EVIDENCE_SIGNING_PUBLIC_KEY_PATH`, and
`AURA_EVIDENCE_SIGNING_KEY_ID`. Release rehearsals are blocked when credentials
are absent; staging rehearsals may remain unsigned.

## Hosted release boundary

`Promotion Gate` and `Release Evidence Freeze` are deliberately secretless.
They generate and freeze unsigned evidence, but never receive an evidence
private key and never run evidence-signing code from the candidate revision.
For release, Promotion first consumes a caller-pinned successful
`Pilot Signoff Ingest` run and re-verifies its exact signed four-role bundle
against the externally configured public trust policy. Freeze repeats that
verification and binds `pilot-signoff-verification.json` into the regenerated
manifest. The pilot policy is not copied into the artifact and is distinct from
the evidence-signing key.

After the unsigned evidence is frozen, an approved external signing boundary
must attest its exact manifest bytes. Use a reviewed immutable signer or a
non-exportable KMS/HSM key, then verify the detached attestation against an
externally pinned public key and expected key identifier. Product acceptance
and the final release decision fail closed until those externally produced
artifacts are present and valid. Do not configure the evidence private key as a
repository-scoped Actions secret or expose it to a candidate-controlled job.
