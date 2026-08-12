# Trusted timestamp adapter for domain-study results

`ci/domain_result_timestamp_adapter.py` is the operational bridge between the
shared OpenSSL RFC 3161 verifier and
`aura.domain.trusted_timestamp_verification.v2` receipts accepted by
`aura-domain`.

The adapter does not implement a second certificate validator. It snapshots
bounded original inputs, delegates nonce, message-imprint, policy, PKIX path,
TSA SPKI, and complete historical CRL verification to
`ci/temporal_study_timestamp.py`, then signs the resulting claims with the
separately provisioned Ed25519 timestamp-verifier key.

## Exact timestamp subject

The timestamp subject must be the exact compact bytes returned by
`aura_domain::domain_study_result_canonical_json` for the relevant typed
artifact. Do not pretty-print, reorder fields, append a newline, or construct
the subject from an unordered map. The result validator independently
serializes the typed artifact and rejects a receipt whose subject digest does
not match.

The six accepted subject kinds are:

- `preregistration_attestation`;
- `reviewer_receipt`;
- `reviewer_agreement_analysis`;
- `adjudication_start_authorization`;
- `adjudication_receipt`;
- `final_evidence_manifest`.

Create a nonce-bearing DER request over one exact subject:

```sh
python3 ci/domain_result_timestamp_adapter.py request \
  --subject private/preregistration-attestation.canonical.json \
  --policy-oid 1.2.3.4.5 \
  --output private/preregistration-attestation.tsq
```

The tool performs no network request. Submit the `.tsq` using the approved TSA
transport and retain the returned DER response unchanged.

## Verify original evidence and issue the receipt

Provision the adapter key independently from the institution, reviewer,
adjudicator, and final-manifest keys. On POSIX systems its file must not be a
symbolic link and must not allow group or world access.

```sh
python3 ci/domain_result_timestamp_adapter.py verify-sign \
  --subject private/preregistration-attestation.canonical.json \
  --subject-kind preregistration_attestation \
  --request private/preregistration-attestation.tsq \
  --response private/preregistration-attestation.tsr \
  --ca-file /trusted/tsa-roots.pem \
  --untrusted-chain /trusted/tsa-intermediates.pem \
  --revocation-crl /trusted/tsa-issuer.crl.pem \
  --revocation-crl /trusted/intermediate-issuer.crl.pem \
  --expected-policy-oid 1.2.3.4.5 \
  --expected-tsa-spki-sha256 '<64 lowercase hexadecimal characters>' \
  --private-key /controlled/timestamp-verifier-ed25519.pem \
  --key-id timestamp_verifier_2026 \
  --output private/preregistration-timestamp-receipt.json \
  --require-pass
```

Omit `--untrusted-chain` only when the selected chain has no intermediate.
Supply exactly one complete CRL for every non-anchor certificate issuer. The
receipt can then populate the matching timestamp field of
`DomainStudyResultEvidenceBundle`.

Repeat the process independently for each reviewer receipt and for agreement
analysis, adjudication-start authorization, adjudication receipt, and final
manifest. Reusing a copied verification report is not accepted: every receipt
is created from the original subject, DER request, DER response, selected
certificate material, and CRLs.

## Byte-level evidence identities

The signed receipt binds:

- SHA-256 of the exact subject, DER request, and DER response;
- the selected certificate chain from TSA signer to trust anchor;
- the complete CRL set covering every non-anchor chain certificate at
  `genTime`;
- the pinned TSA SPKI, numeric policy OID, exact generation time represented by
  its floor millisecond plus the 0..999 microsecond remainder, and declared
  accuracy. Trusted interval endpoints are rounded outward, and fractional
  `genTime` is checked against PKIX and CRL evidence at both adjacent seconds.

The selected-chain digest is SHA-256 over the domain
`aura.domain.rfc3161-certificate-chain.v1\0`, a four-byte big-endian item
count, and the raw 32-byte certificate DER digests in signer-to-anchor order.
The revocation digest uses the same framing under
`aura.domain.rfc3161-revocation-evidence.v1\0`, with unique CRL DER digests
sorted in ascending hexadecimal order.

The original inputs, trust-policy record, adapter software revision, OpenSSL
version, and generated receipt remain controlled research evidence and must be
retained. The content-free public result does not contain these private files.

## Claim boundary

Under the governance assumption that only the approved adapter procedure
controls the trusted verifier key, a valid receipt is cryptographic evidence
that this key attested to one exact RFC 3161 response, selected chain, and
historical CRL set. A verifier cannot prove from the signature alone that a
particular software build or operational procedure actually ran. The receipt
supports document-integrity and trusted-time ordering. It does not prove
real-world detector effectiveness, representative sampling, truthful human
labels, organizational independence, absence of undiscovered key compromise,
or perpetual certificate validity. It never enables runtime policy or product
actions.
