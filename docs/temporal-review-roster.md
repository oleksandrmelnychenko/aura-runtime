# Precommitted temporal-review roster

`ci/temporal_review_roster.py` freezes the pseudonymous reviewer roster before
review decisions are completed. The coordinator signs the exact roster with a
separately trusted Ed25519 key and obtains an RFC 3161 timestamp for the signed
attestation. Receipt-chain verification then requires every reviewer and the
adjudicator to use the role, affiliation token, key identifier, and pinned SPKI
digest recorded in that roster.

This closes an important post-selection path: a passing study cannot replace a
reviewer, affiliation claim, or signing key after seeing the review results and
still reuse the original trusted roster timestamp.

## Privacy-minimized schema

The `aura.military.temporal_review_roster.v1` document contains no names,
emails, personnel numbers, free text, or copies of governance records. Each
participant entry contains:

- a study-scoped participant token and affiliation token;
- role `reviewer` or `adjudicator`;
- the independently provisioned Ed25519 key identifier and SPKI SHA-256;
- SHA-256 digests of controlled eligibility, affiliation-evidence,
  conflict-of-interest, and blinding-acknowledgement records.

All participant tokens, affiliations, key identities, and governance-record
digests must be distinct. At least two reviewers and exactly one adjudicator are
required. Participants are sorted by token so the canonical digest is stable.

Example:

```json
{
  "schema_version": "aura.military.temporal_review_roster.v1",
  "roster_id": "temporal_roster_2026_01",
  "study_id": "external_temporal_study_2026",
  "preregistration_canonical_sha256": "<64 lowercase hex>",
  "study_commitment_canonical_sha256": "<64 lowercase hex>",
  "packet_id": "temporal_round_2026_01",
  "packet_canonical_sha256": "<64 lowercase hex>",
  "protocol": {
    "distinct_reviewer_affiliations": true,
    "independent_adjudicator": true,
    "conflict_screening_records": true,
    "blinding_acknowledgements": true,
    "post_timestamp_changes_forbidden": true
  },
  "participants": [
    {
      "participant_token": "reviewer_a_8f2c10",
      "affiliation_token": "affiliation_a_8f2c10",
      "role": "reviewer",
      "signing_key_id": "institution-a-review-2026",
      "signing_key_spki_sha256": "<64 lowercase hex>",
      "eligibility_record_sha256": "<64 lowercase hex>",
      "affiliation_evidence_sha256": "<64 lowercase hex>",
      "conflict_declaration_sha256": "<64 lowercase hex>",
      "blinding_acknowledgement_sha256": "<64 lowercase hex>"
    }
  ]
}
```

## Coordinator trust

The coordinator roster key must be different from all participant keys and
from the release-evidence key. Provision its expected SPKI SHA-256 through an
independent institutional channel. Production signing should use an HSM or
managed signing service. A development key can be generated with:

```bash
openssl genpkey -algorithm Ed25519 -out /protected/roster-coordinator.private.pem
chmod 600 /protected/roster-coordinator.private.pem
openssl pkey -in /protected/roster-coordinator.private.pem \
  -pubout -out review/roster-coordinator.public.pem
```

The local signer rejects symbolic links, non-regular keys, oversized keys, and
group/world-readable permissions.

## Freeze, sign, and timestamp

Sign the exact roster:

```bash
python3 ci/temporal_review_roster.py sign \
  --roster review/temporal-review-roster.json \
  --private-key /protected/roster-coordinator.private.pem \
  --key-id study-coordinator-roster-2026 \
  --output review/temporal-review-roster.attestation.json
```

Create a nonce-bearing RFC 3161 request over the signed attestation:

```bash
python3 ci/temporal_review_roster.py request \
  --attestation review/temporal-review-roster.attestation.json \
  --policy-oid 1.2.3.4.1 \
  --output review/temporal-review-roster.tsq
```

Submit the unchanged DER request to the approved TSA and preserve the response
as `review/temporal-review-roster.tsr`. Verify it with independently
provisioned coordinator and TSA pins:

```bash
python3 ci/temporal_review_roster.py verify \
  --roster review/temporal-review-roster.json \
  --attestation review/temporal-review-roster.attestation.json \
  --public-key review/roster-coordinator.public.pem \
  --expected-key-id study-coordinator-roster-2026 \
  --expected-signer-spki-sha256 '<coordinator SPKI SHA-256>' \
  --timestamp-request review/temporal-review-roster.tsq \
  --timestamp-response review/temporal-review-roster.tsr \
  --ca-file trust/tsa-roots.pem \
  --untrusted-chain trust/tsa-intermediates.pem \
  --revocation-crl trust/tsa-issuer.crl.pem \
  --revocation-crl trust/intermediate-issuer.crl.pem \
  --expected-policy-oid 1.2.3.4.1 \
  --expected-tsa-spki-sha256 '<TSA SPKI SHA-256>' \
  --output /protected/temporal-review-roster-verification.json \
  --require-pass
```

The roster receipt is included directly in
`aura.military.temporal_review_receipt_index.v3`. Full chain verification
repeats the signature and timestamp checks from the raw inputs; it does not
trust a copied `status=pass` report.

## Supported claim and boundary

A passing v3 receipt-chain report proves that the roster existed after the
trusted study commitment and before every declared review completion and
signed reviewer receipt. It also proves exact identity/key consistency between
the roster and signed submissions.

It does not prove that a human started work only after the roster timestamp,
that an affiliation or conflict declaration is truthful, that reviewers did
not coordinate outside the system, or that the coordinator is organizationally
independent. The controlled source records, recruitment procedure, access
audit, conflict review, and oversight decision remain necessary study evidence.
The aggregate release report exports only counts and set digests; raw roster
entries remain controlled material.
