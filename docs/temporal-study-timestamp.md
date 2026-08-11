# Trusted timestamp for a temporal study commitment

`ci/temporal_study_timestamp.py` creates and verifies an RFC 3161 timestamp for
the exact bytes of `aura.military.temporal_study_commitment.v1`. It is the time
counterpart to the institutional Ed25519 signature: the signature authenticates
the study-governance signer, while the timestamp proves that the commitment's
SHA-256 message imprint was accepted by the selected timestamp authority no
later than the upper end of its declared `genTime` accuracy interval.

The verifier accepts only a SHA-256, nonce-bearing request that asks for the TSA
certificate. It binds the response both to that request and to the original
commitment file, requires the expected numeric policy OID, validates the
certificate chain at `genTime`, and pins the timestamp signer by its expected
SPKI SHA-256 digest.

## Establish trust before the study

The study-governance record must name:

- the timestamp authority and numeric RFC 3161 policy OID;
- the approved root trust bundle and any required intermediate certificates;
- the exact TSA signer SPKI SHA-256 obtained through an independent channel;
- the authority's retention, clock, audit, revocation, and incident policies;
- the people permitted to submit and verify study commitments.

Do not derive the expected signer identity only from the response being
verified. For an approved TSA certificate, calculate its SPKI digest with:

```sh
openssl x509 -in /trusted/tsa-signer.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256
```

Record only the 64 lowercase hexadecimal digits after `SHA2-256(...) =`.

## Create the request before review

After the blind packet and commitment are generated, create a DER request:

```sh
python3 ci/temporal_study_timestamp.py request \
  --commitment review/temporal-study-commitment.json \
  --policy-oid 1.2.3.4.5 \
  --output review/temporal-study-commitment.tsq
```

Submit the `.tsq` bytes using the organization's approved TSA transport. The
tool deliberately performs no network request: TSA endpoint credentials,
proxy policy, availability, retry semantics, and evidence leakage remain under
deployment control. Store the returned DER response as, for example,
`review/temporal-study-commitment.tsr` before any reviewer receives a packet.

## Verify the response

Verify with independently provisioned trust material and the pinned signer:

```sh
python3 ci/temporal_study_timestamp.py verify \
  --commitment review/temporal-study-commitment.json \
  --request review/temporal-study-commitment.tsq \
  --response review/temporal-study-commitment.tsr \
  --ca-file /trusted/tsa-roots.pem \
  --untrusted-chain /trusted/tsa-intermediates.pem \
  --expected-policy-oid 1.2.3.4.5 \
  --expected-tsa-spki-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --output artifacts/temporal-study-timestamp-verification.json \
  --require-pass
```

Omit `--untrusted-chain` only when no intermediate chain is needed. Retain the
commitment, request, response, signer and chain certificates, trust-policy
record, verification report, and the OpenSSL version used for verification.

Provide the trusted study artifacts, v5 review report, and aggregate receipt
chain to the evidence manifest:

```sh
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

Policy activation passes this part of the gate only when the trusted timestamp
matches the study commitment, attestation, review report, and signed receipt
chain. The commitment upper bound `genTime + accuracy` must be strictly earlier
than every reviewer receipt lower bound. The verifier requires an explicit
accuracy no greater than five minutes; an unspecified, wider, equal, or
overlapping interval cannot establish ordering.

## Exact claim and remaining boundary

The timestamp verifies that the exact commitment bytes existed no later than
the upper end of the TSA interval at `genTime + accuracy`, subject to the
authority, certificate, clock, and selected policy. The v5 aggregate review
report exposes the earliest and
latest annotation and adjudication completion times with
`decision_time_assurance = bundle_declared`.

The separate receipt protocol now timestamps the exact signed reviewer and
adjudicator attestations and verifies strict trusted-time interval precedence.
See `docs/temporal-review-receipts.md`. This independently witnesses when each
complete signed submission existed, but does not prove when work began, that a
reviewer never saw labels earlier, that participant affiliations are genuine,
or that the human-entered completion time is honest.

Certificate revocation is intentionally reported as `not_checked`. Validation
at `genTime` supports historical certificate validity but is not long-term
validation. Preserve contemporaneous CRL or OCSP evidence under the study
governance protocol before making a stronger revocation or archival claim.

The wire and verification rules follow [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html),
the modern signer-certificate identifier is covered by
[RFC 5816](https://www.rfc-editor.org/rfc/rfc5816.html), and the executable
certificate checks use the documented
[`openssl ts`](https://docs.openssl.org/3.6/man1/openssl-ts/) verification
interface.
