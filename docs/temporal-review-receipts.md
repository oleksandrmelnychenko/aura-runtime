# Signed and trusted-time temporal review receipts

`ci/temporal_review_receipt.py` turns a packet-bound temporal review into an
independently witnessed chronology. Every reviewer freezes one complete
submission, signs it with a distinct Ed25519 key, and obtains an RFC 3161
timestamp for the exact signed attestation. The adjudicator then binds the exact
reviewer attestation and timestamp-response digests, signs the complete
adjudication submission, and obtains a later timestamp.

The unit of evidence is a participant's complete submission for one frozen
study packet. Per-case timestamps are deliberately not used: they would add
cost, disclosure surface, and ambiguous partial ordering without strengthening
the claim that the complete label set was frozen before adjudication.

## What the chain proves

A passing `aura.military.temporal_review_receipt_chain_verification.v3` report
proves all of the following:

- the study commitment's accuracy-adjusted trusted upper time is earlier than
  the precommitted roster and every reviewer's trusted lower time;
- the roster's participant roles, affiliations, key identifiers, and pinned
  SPKI digests exactly match all signed submissions;
- the roster timestamp is earlier than every declared review completion and
  reviewer receipt;
- each review decision declares a completion time after the trusted commitment
  and before the lower time bound of its own signed receipt;
- every reviewer attestation has a valid Ed25519 signature from its pinned key;
- every reviewer attestation is bound to a nonce-bearing RFC 3161 response, a
  pinned policy OID, a trusted certificate chain at `genTime`, and a pinned TSA
  SPKI digest;
- every timestamp has issuer-signed complete CRLs covering every non-anchor
  certificate in the selected TSA chain at `genTime`;
- the adjudicator submission names the exact reviewer participant token,
  attestation digest, and timestamp-response digest for every reviewer;
- all reviewer receipt upper bounds are earlier than every adjudication
  decision and the adjudicator receipt lower bound;
- the deterministic review bundle reconstructed from the signed submissions is
  byte-for-meaning equivalent to the evaluated bundle;
- the v5 independent-review report and the receipt chain carry the same
  canonical review-bundle SHA-256 digest.

Strict interval comparisons are intentional. For a timestamp with `genTime = t`
and accuracy `a`, the verifier treats trusted time as `[t-a, t+a]`. Equality or
overlap does not establish precedence and therefore fails closed.

## What the chain does not prove

Cryptography cannot prove reviewer expertise, institutional independence,
correct affiliation, effective blinding, absence of coordination, or honest
human judgment. Those properties require documented recruitment, conflict-of-
interest declarations, access controls, blinding records, and independent
study oversight. The bundle's participant and affiliation tokens are
pseudonymous claims whose real-world mapping remains controlled study material.

The chain reports `full_chain_crl_at_gen_time` after offline CRL validation.
This proves PKIX revocation status under the archived CRLs at `genTime`; it does
not rule out later backdated revocation, undiscovered compromise, or CA/TSA
policy failure. See `docs/rfc3161-historical-revocation.md`.

## Participant keys

Use one signing key and one key identifier per participant. Do not share a key
between reviewers, the adjudicator, or the study coordinator. Production keys
should be created and used in an institutional HSM or equivalent managed key
service. A local development key can be generated with:

```bash
openssl genpkey -algorithm Ed25519 -out reviewer-a.private.pem
chmod 600 reviewer-a.private.pem
openssl pkey -in reviewer-a.private.pem -pubout -out reviewer-a.public.pem
```

The command-line signer rejects symbolic links and private keys readable by the
group or other users. Public key fingerprints are present only in controlled
per-receipt verification material; the aggregate release report exports no
individual participant key digest.

## Reviewer submission

Create one `aura.military.temporal_review_submission.v1` document for every
reviewer. Decisions must be uniquely keyed and sorted by `blind_case_token`;
reason codes must also be sorted and unique. A reviewer submission has an empty
`reviewer_receipt_links` array.

```json
{
  "schema_version": "aura.military.temporal_review_submission.v1",
  "study_id": "external_temporal_study_2026",
  "preregistration_canonical_sha256": "<64 lowercase hex>",
  "study_commitment_canonical_sha256": "<64 lowercase hex>",
  "packet_id": "temporal_round_2026_01",
  "packet_canonical_sha256": "<64 lowercase hex>",
  "participant_token": "reviewer_a_8f2c10",
  "affiliation_token": "affiliation_a_8f2c10",
  "role": "reviewer",
  "decisions": [
    {
      "blind_case_token": "blind_0123456789abcdef0123456789abcdef",
      "expected_reason_codes": ["military.temporal.influence_pressure"],
      "completed_at_ms": 1780000120000
    }
  ],
  "reviewer_receipt_links": []
}
```

Freeze and sign it:

```bash
python3 ci/temporal_review_receipt.py sign \
  --submission review/reviewer-a.submission.json \
  --private-key /protected/reviewer-a.private.pem \
  --key-id institution-a-review-2026 \
  --output review/reviewer-a.attestation.json
```

Create a DER timestamp request over the exact attestation bytes:

```bash
python3 ci/temporal_review_receipt.py request \
  --attestation review/reviewer-a.attestation.json \
  --policy-oid 1.2.3.4.1 \
  --output review/reviewer-a.tsq
```

Send the request unchanged to the approved timestamp authority and preserve the
DER response as `review/reviewer-a.tsr`. Then verify the individual receipt:

```bash
python3 ci/temporal_review_receipt.py verify \
  --submission review/reviewer-a.submission.json \
  --attestation review/reviewer-a.attestation.json \
  --public-key review/reviewer-a.public.pem \
  --expected-key-id institution-a-review-2026 \
  --expected-signer-spki-sha256 '<independently provisioned 64 lowercase hex>' \
  --timestamp-request review/reviewer-a.tsq \
  --timestamp-response review/reviewer-a.tsr \
  --ca-file trust/tsa-roots.pem \
  --untrusted-chain trust/tsa-intermediates.pem \
  --revocation-crl trust/tsa-issuer.crl.pem \
  --revocation-crl trust/intermediate-issuer.crl.pem \
  --expected-policy-oid 1.2.3.4.1 \
  --expected-tsa-spki-sha256 '<64 lowercase hex>' \
  --output /protected/reviewer-a.receipt-verification.json \
  --require-pass
```

## Adjudication receipt

Do not expose adjudication labels before all reviewer receipts have passed and
been frozen. Build the adjudicator's `reviewer_receipt_links` from every
reviewer's controlled verification report:

```json
[
  {
    "participant_token": "reviewer_a_8f2c10",
    "submission_attestation_sha256": "<reviewer attestation digest>",
    "timestamp_response_sha256": "<reviewer RFC 3161 response digest>"
  },
  {
    "participant_token": "reviewer_b_41ad22",
    "submission_attestation_sha256": "<reviewer attestation digest>",
    "timestamp_response_sha256": "<reviewer RFC 3161 response digest>"
  }
]
```

The links must be sorted by `participant_token`. The adjudicator submission uses
role `adjudicator`, contains one decision for every blind case, and is signed,
timestamped, and individually verified with the same commands and a distinct
key. Its trusted lower time must be strictly later than the greatest reviewer
receipt upper time. A real study should obtain naturally separated timestamps;
never modify claimed times or timestamp accuracy to force non-overlap.

## Deterministic assembly

Assemble the exact v3 bundle consumed by `temporal_independent_review`:

```bash
python3 ci/temporal_review_receipt.py assemble \
  --template review/temporal-review-template.json \
  --study-commitment review/temporal-study-commitment.json \
  --reviewer-submission review/reviewer-a.submission.json \
  --reviewer-submission review/reviewer-b.submission.json \
  --adjudicator-submission review/adjudicator.submission.json \
  --output review/temporal-review-bundle.json
```

Run the Rust evaluator on this bundle. A packet-bound report now uses
`aura.military.temporal_review_report.v5` and records
`review_bundle_canonical_sha256` so downstream evidence cannot substitute a
different label bundle.

## Chain index and aggregate verification

The controlled v3 receipt index names the review bundle and raw trusted study
timestamp receipt, precommitted roster receipt, every reviewer package, and the
single adjudicator package. A copied study timestamp report is not trusted.
Relative paths are resolved from the index directory.

```json
{
  "schema_version": "aura.military.temporal_review_receipt_index.v3",
  "review_bundle": "temporal-review-bundle.json",
  "study_timestamp_receipt": {
    "commitment": "temporal-study-commitment.json",
    "timestamp_request": "temporal-study-commitment.tsq",
    "timestamp_response": "temporal-study-commitment.tsr",
    "ca_file": "tsa-roots.pem",
    "untrusted_chain": "tsa-intermediates.pem",
    "revocation_crls": ["tsa-issuer.crl.pem", "intermediate-issuer.crl.pem"],
    "expected_policy_oid": "1.2.3.4.1",
    "expected_tsa_spki_sha256": "<64 lowercase hex>"
  },
  "review_roster_receipt": {
    "roster": "temporal-review-roster.json",
    "attestation": "temporal-review-roster.attestation.json",
    "public_key": "roster-coordinator.public.pem",
    "expected_key_id": "study-coordinator-roster-2026",
    "expected_signer_spki_sha256": "<independently provisioned 64 lowercase hex>",
    "timestamp_request": "temporal-review-roster.tsq",
    "timestamp_response": "temporal-review-roster.tsr",
    "ca_file": "tsa-roots.pem",
    "untrusted_chain": "tsa-intermediates.pem",
    "revocation_crls": ["tsa-issuer.crl.pem", "intermediate-issuer.crl.pem"],
    "expected_policy_oid": "1.2.3.4.1",
    "expected_tsa_spki_sha256": "<64 lowercase hex>"
  },
  "reviewer_receipts": [
    {
      "submission": "reviewer-a.submission.json",
      "attestation": "reviewer-a.attestation.json",
      "public_key": "reviewer-a.public.pem",
      "expected_key_id": "institution-a-review-2026",
      "expected_signer_spki_sha256": "<independently provisioned 64 lowercase hex>",
      "timestamp_request": "reviewer-a.tsq",
      "timestamp_response": "reviewer-a.tsr",
      "ca_file": "tsa-roots.pem",
      "untrusted_chain": "tsa-intermediates.pem",
      "revocation_crls": ["tsa-issuer.crl.pem", "intermediate-issuer.crl.pem"],
      "expected_policy_oid": "1.2.3.4.1",
      "expected_tsa_spki_sha256": "<64 lowercase hex>"
    }
  ],
  "adjudicator_receipt": {
    "submission": "adjudicator.submission.json",
    "attestation": "adjudicator.attestation.json",
    "public_key": "adjudicator.public.pem",
    "expected_key_id": "institution-c-adjudication-2026",
    "expected_signer_spki_sha256": "<independently provisioned 64 lowercase hex>",
    "timestamp_request": "adjudicator.tsq",
    "timestamp_response": "adjudicator.tsr",
    "ca_file": "tsa-roots.pem",
    "untrusted_chain": "tsa-intermediates.pem",
    "revocation_crls": ["tsa-issuer.crl.pem", "intermediate-issuer.crl.pem"],
    "expected_policy_oid": "1.2.3.4.1",
    "expected_tsa_spki_sha256": "<64 lowercase hex>"
  }
}
```

Verify the entire chain directly from its signatures, timestamp requests,
responses, and trust material:

```bash
python3 ci/temporal_review_receipt.py verify-chain \
  --index review/temporal-review-receipt-index.json \
  --output artifacts/temporal-review-receipt-chain-verification.json \
  --require-pass
```

The output is aggregate and release-safe: it contains counts, study and packet
bindings, bundle digests, trusted interval boundaries, and proof flags. It does
not contain participant tokens, affiliation tokens, individual public-key
digests, case tokens, decision labels, or raw text. Keep submissions,
attestations, public keys, timestamp requests and responses, CRLs, and the index
in controlled evidence storage.

## Release evidence gate

Pass the aggregate report beside the v5 independent-review report and trusted
study timestamp:

```bash
python3 ci/generate_evidence_manifest.py \
  ... \
  --temporal-independent-review-report \
    artifacts/temporal-independent-review-report.json \
  --temporal-study-attestation-verification \
    artifacts/temporal-study-attestation-verification.json \
  --temporal-study-timestamp-verification \
    artifacts/temporal-study-timestamp-verification.json \
  --temporal-review-receipt-chain-verification \
    artifacts/temporal-review-receipt-chain-verification.json
```

Temporal policy activation remains `pending` when this chain is absent. A
supplied invalid, privacy-unsafe, chronologically overlapping, or mismatched
chain fails the evidence gate. A pass still authorizes only the separately
defined activation decision; it does not itself enable runtime policy or action
execution.
