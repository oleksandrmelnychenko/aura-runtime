# Historical revocation evidence for RFC 3161

Every trusted timestamp verification requires offline X.509 revocation evidence.
The verifier reports `revocation_assurance = full_chain_crl_at_gen_time` only
when complete CRLs cover the TSA certificate and every non-anchor intermediate
certificate at the token's `genTime`.

## Evidence contract

Provide one PEM CRL for each issuer above a non-anchor certificate in the chain.
Repeat `--revocation-crl` when the TSA uses intermediates:

```bash
python3 ci/temporal_study_timestamp.py verify \
  --commitment review/temporal-study-commitment.json \
  --request review/temporal-study-commitment.tsq \
  --response review/temporal-study-commitment.tsr \
  --ca-file trust/tsa-roots.pem \
  --untrusted-chain trust/tsa-intermediates.pem \
  --revocation-crl trust/tsa-issuer.crl.pem \
  --revocation-crl trust/intermediate-issuer.crl.pem \
  --expected-policy-oid 1.2.3.4.1 \
  --expected-tsa-spki-sha256 '<64 lowercase hex>' \
  --output artifacts/temporal-study-timestamp-verification.json \
  --require-pass
```

Verification is offline and fail-closed. It requires:

- exactly one full CRL for every issuer selected in the actual TSA chain;
- no unrelated or duplicate issuer CRL;
- `thisUpdate <= genTime <= nextUpdate`;
- a CRL number no wider than 160 bits;
- valid CRL and certificate signatures under the pinned trust anchors;
- `timestampsign` purpose, RFC 5280 strict mode, authentication level 2, and
  full non-anchor chain checking at `genTime`;
- no network retrieval, delta CRL, indirect CRL, or distribution-point-scoped
  CRL.

The verification report records DER SHA-256 digests, hashed issuer names, CRL
numbers, coverage intervals, the aggregate CRL-set digest, and the number of
certificates checked. Raw issuer names are not exported.

The receipt-chain v3 index carries the raw study commitment timestamp package,
roster package, reviewer packages, and adjudicator package. Every package names
its CRLs. The aggregate verifier repeats all signature, timestamp, certificate,
and revocation checks from raw inputs; it does not trust a copied verification
report.

## Exact claim

This evidence establishes that issuer-signed complete CRLs considered the TSA
chain non-revoked under PKIX processing at the asserted `genTime`. It also binds
the exact CRLs to the verification and aggregate evidence reports.

It does not prove that a private key was never compromised, that a later CRL
will not report a revocation or invalidity date affecting the earlier period,
or that the CA/TSA followed its operational policy honestly. It is historical
revocation checking, not perpetual validity.

Long-term preservation still requires controlled retention of the request,
response, certificates, trust anchors, CRLs, policy documents, verification
software identity, and signed evidence manifest. Before accepted algorithms or
keys weaken, renew the evidence with an archival timestamp or evidence-record
mechanism. The current contract deliberately does not accept OCSP: a safe OCSP
profile needs separate rules for responder authorization, response freshness,
`producedAt`/`thisUpdate`/`nextUpdate`, nonce policy, and responder-chain
revocation.

The timestamp and revocation rules follow
[RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html),
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html), and the official
[OpenSSL verification options](https://docs.openssl.org/3.6/man1/openssl-verification-options/).
