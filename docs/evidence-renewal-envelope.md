# Evidence renewal envelope

The AURA evidence-renewal profile preserves a fixed set of research and
release evidence by periodically placing a new RFC 3161 timestamp over a
deterministic commitment. It is an operational preservation envelope, not an
implementation of RFC 4998 Evidence Record Syntax or RFC 6283 XMLERS.

The profile identifier is:

```text
aura_rfc3161_renewal_envelope_not_rfc4998_ers
```

Every verification report exports `rfc4998_ers_conformance = false`. This
marker is part of the machine-readable contract and prevents an AURA envelope
from being represented as a standards-conformant Evidence Record.

## Preserved set

Create a first commitment from all materials needed to reproduce and validate
the evidence claim. The labels are exported, but local paths are not:

```bash
python3 ci/temporal_evidence_renewal.py create \
  --renewal-id aura_temporal_study_2026 \
  --sequence-number 1 \
  --created-at-ms 1786464000000 \
  --evidence-item evidence_manifest=artifacts/evidence-manifest.json \
  --evidence-item manifest_attestation=artifacts/evidence-manifest-attestation.json \
  --evidence-item manifest_public_key=trust/evidence-manifest-public.pem \
  --evidence-item study_commitment=review/temporal-study-commitment.json \
  --evidence-item study_timestamp_request=review/temporal-study-commitment.tsq \
  --evidence-item study_timestamp_response=review/temporal-study-commitment.tsr \
  --evidence-item tsa_roots=trust/tsa-roots.pem \
  --evidence-item tsa_intermediates=trust/tsa-intermediates.pem \
  --evidence-item tsa_crl=trust/tsa-issuer.crl.pem \
  --output archive/renewal-01.json
```

Each item must be a nonempty regular file, not a symbolic link. The tool reads
it through a bounded file descriptor and rejects a file that changes during
hashing. The commitment contains a sorted label, byte length, and SHA-256
digest for each item plus a domain-separated digest of the complete set.

Paths, raw evidence, certificate subject names, and the contents of evidence
files are not copied into the verification report.

## Timestamp and verify one link

Create a nonce-bearing request and obtain a response from the configured TSA:

```bash
python3 ci/temporal_evidence_renewal.py request \
  --commitment archive/renewal-01.json \
  --policy-oid 1.2.3.4.1 \
  --output archive/renewal-01.tsq
```

Verification uses the same pinned-policy, pinned-TSA, full-chain CRL contract
as every other trusted AURA timestamp:

```bash
python3 ci/temporal_evidence_renewal.py verify \
  --commitment archive/renewal-01.json \
  --evidence-item evidence_manifest=artifacts/evidence-manifest.json \
  --evidence-item manifest_attestation=artifacts/evidence-manifest-attestation.json \
  --evidence-item manifest_public_key=trust/evidence-manifest-public.pem \
  --evidence-item study_commitment=review/temporal-study-commitment.json \
  --evidence-item study_timestamp_request=review/temporal-study-commitment.tsq \
  --evidence-item study_timestamp_response=review/temporal-study-commitment.tsr \
  --evidence-item tsa_roots=trust/tsa-roots.pem \
  --evidence-item tsa_intermediates=trust/tsa-intermediates.pem \
  --evidence-item tsa_crl=trust/tsa-issuer.crl.pem \
  --timestamp-request archive/renewal-01.tsq \
  --timestamp-response archive/renewal-01.tsr \
  --ca-file trust/current-renewal-tsa-roots.pem \
  --untrusted-chain trust/current-renewal-tsa-intermediates.pem \
  --revocation-crl trust/current-renewal-tsa-issuer.crl.pem \
  --expected-policy-oid 1.2.3.4.1 \
  --expected-tsa-spki-sha256 '<64 lowercase hex>' \
  --output artifacts/evidence-renewal-01-verification.json \
  --require-pass
```

## Renew the timestamp

Before the current timestamp key, certificate, or accepted public-key
algorithm becomes unsuitable, create the next commitment. The evidence set
must remain byte-for-byte identical in the AURA timestamp-renewal profile.
First record the complete raw verification package for the preceding link:

```json
{
  "commitment": "renewal-01.json",
  "timestamp_request": "renewal-01.tsq",
  "timestamp_response": "renewal-01.tsr",
  "ca_file": "../trust/renewal-01-roots.pem",
  "untrusted_chain": "../trust/renewal-01-intermediates.pem",
  "revocation_crls": ["../trust/renewal-01-issuer.crl.pem"],
  "expected_policy_oid": "1.2.3.4.1",
  "expected_tsa_spki_sha256": "<64 lowercase hex>"
}
```

Then create the next commitment:

```bash
python3 ci/temporal_evidence_renewal.py create \
  --renewal-id aura_temporal_study_2026 \
  --sequence-number 2 \
  --created-at-ms 1818000000000 \
  --previous-link-package archive/renewal-01-package.json \
  --evidence-item evidence_manifest=artifacts/evidence-manifest.json \
  ... \
  --output archive/renewal-02.json
```

The new commitment binds the raw and canonical predecessor commitment,
request, timestamp response, trust anchors, untrusted chain, complete CRL
files, expected policy OID, pinned TSA SPKI, and the unchanged evidence set.
Sequence numbers must be contiguous. Trusted-time intervals must not overlap.
Verification of every non-initial link receives the same
`--previous-link-package`; the package is local input, while its complete
cryptographic descriptor is fixed by the new commitment.

If any evidence file must be added or replaced, or SHA-256 itself is no longer
accepted, this profile deliberately fails. That event requires a new archive
set or a standards-conformant ERS/XMLERS hash-tree renewal process; silently
changing the set would invalidate the preservation claim.

## Re-verify the complete chain

Long-term verification must use the raw input of every link. A path index is
local operator input and is not itself treated as proof:

```json
{
  "schema_version": "aura.research.evidence_renewal_index.v1",
  "evidence_items": [
    {"label": "evidence_manifest", "path": "../artifacts/evidence-manifest.json"},
    {"label": "manifest_attestation", "path": "../artifacts/evidence-manifest-attestation.json"}
  ],
  "renewals": [
    {
      "commitment": "renewal-01.json",
      "timestamp_request": "renewal-01.tsq",
      "timestamp_response": "renewal-01.tsr",
      "ca_file": "../trust/renewal-01-roots.pem",
      "untrusted_chain": "../trust/renewal-01-intermediates.pem",
      "revocation_crls": ["../trust/renewal-01-issuer.crl.pem"],
      "expected_policy_oid": "1.2.3.4.1",
      "expected_tsa_spki_sha256": "<64 lowercase hex>"
    }
  ]
}
```

```bash
python3 ci/temporal_evidence_renewal.py verify-chain \
  --index archive/renewal-index.json \
  --output artifacts/evidence-renewal-chain-verification.json \
  --require-pass
```

The aggregate report is `pass` only after rehashing every preserved file and
re-verifying every request, response, TSA signer, trust chain, policy, nonce,
exact fractional `genTime`, outward-rounded accuracy interval, and historical
CRL set from raw inputs. Per-link and chain verification reports use schema v2;
legacy v1 reports must be regenerated from their raw evidence before release.

## Exact claim and limitation

A passing chain establishes that the fixed byte set matches its original
commitment and that every listed RFC 3161 authority timestamped the linked
commitment within a strictly ordered series, under the archived PKIX and CRL
evidence. It extends evidence of existence and integrity while the employed
algorithms and authorities remain acceptable under an external cryptographic
policy.

It does not establish the truth of the archived scientific results, human
independence, absence of key compromise, honesty of a TSA, or indefinite
validity. The tool does not decide when an algorithm becomes weak and does not
implement hash-tree renewal, Merkle proofs, ASN.1 ERS, or XMLERS. Operators
must retain every raw evidence file, commitment, request, response,
certificate, trust anchor, CRL, policy document, path index, and verifier
identity.

The design is informed by the renewal model in
[RFC 4998](https://www.rfc-editor.org/rfc/rfc4998.html) and
[RFC 6283](https://www.rfc-editor.org/rfc/rfc6283.html), while its
non-conformance with those formats is explicit.
