# Independent domain result evidence

Status: machine-verifiable result-chain contract implemented; no independent
corpus has yet completed this protocol.

## Claim boundary

This contract answers a narrow question: does one exact frozen AURA domain
build meet the descriptive thresholds fixed by its v1 preregistration on one
exact frozen corpus, with a complete and chronologically admissible review
chain?

It does not establish causality, universal real-world effectiveness,
representativeness of the sampling frame, reviewer expertise, or the truth of
institutional independence declarations. Those remain governance and
replication questions. The strongest machine state is therefore
`independent_evidence_candidate`, not scientific truth or production
activation authority.

## Private verification bundle

The controlled research environment supplies a strict bundle. The required
top-level schema is
`aura.domain.independent_evaluation_evidence.v2`. Legacy v1 bundles do not
contain the exact fractional trusted-time contract and must be regenerated
from retained RFC 3161, certificate-chain, CRL, and signed-artifact inputs;
they are never promoted in place to a passing v2 result.

The bundle contains:

1. an Ed25519 institutional attestation of the canonical preregistration;
2. an independently verified RFC 3161 trusted-chain receipt for that
   attestation;
3. two to five individually signed reviewer receipts, each bound to the study,
   blind packet, assignment manifest, decision bundle, affiliation commitment,
   and completed-case count;
4. an RFC 3161 verification receipt for every reviewer receipt;
5. private assignment manifests whose exact canonical digests match the signed
   reviewer receipts, and a case matrix that must be their exact transpose;
6. governed reviewer-agreement claims bound to the frozen statistic, BCa
   method, repetition count, seed, reviewer receipts, and coverage matrix, plus
   a trusted timestamp proving completion before adjudication;
7. a domain-separated adjudicator-signed start authorization and trusted
   timestamp issued only after the agreement-analysis interval ends;
8. a private adjudication manifest whose exact digest is signed by the separate
   adjudicator and whose case set must exactly match the coverage matrix;
9. a separately signed adjudication receipt bound to the complete reviewer
   receipt set and frozen adjudication manifest;
10. an RFC 3161 verification receipt for adjudication;
11. a content-free aggregate result bundle with integer confusion counts,
   exclusions, incomplete cases, safe-boundary counts, per-family
   attack-variant counts, review coverage, protocol deviations, and exact input
   digests;
12. an institutionally signed final evidence manifest and its own RFC 3161
   verification receipt.

The signed final manifest also binds the canonical digest of the complete trust
policy used for validation: every role key, the TSA SPKI and policy OID, and all
reviewer affiliation commitments. A later report can therefore identify the
exact trust-root snapshot instead of relying on an unnamed verifier setup.

The RFC 3161 receipt is a domain-separated Ed25519 attestation produced by a
trusted timestamp-verification adapter after it verifies the original request,
response, ordered TSA certificate chain, policy, nonce, and complete revocation
evidence. The receipt binds the SHA-256 digests of those original artifacts.
Trust comes from the configured verifier key and TSA SPKI/policy allow-list; a
self-declared timestamp JSON is not accepted.

The executable bridge and its byte-level certificate/CRL digest framing are
specified in `docs/domain-result-trusted-timestamp-adapter.md`. Typed subjects
must be exported with `domain_study_result_canonical_json`; this avoids asking
an external process to reproduce Rust struct-field ordering by convention.

The validator uses timestamp uncertainty intervals. The latest possible
preregistration time must be earlier than the earliest possible reviewer time;
all reviewer intervals must end before the agreement analysis; that analysis
must end before the separately signed and timestamped authorization to begin
adjudication; adjudication completion must follow that authorization and
precede the signed final manifest. Declared application clocks never replace
these trusted intervals.

The entry point rejects empty inputs, preregistrations larger than 2 MiB, and
result evidence larger than 8 MiB. All count arithmetic is checked; overflow is
invalid evidence rather than a saturating or wrapping result.

## Recomputed outcomes

The result bundle cannot supply its own pass booleans. The validator recomputes:

- per-threat precision, recall, F1, and macro F1 from integer confusion counts;
- a conservative per-threat F1 from the precision and recall Wilson lower
  bounds, plus its macro mean;
- safe-boundary false-positive rate;
- total and per-preregistered-family attack-variant consistency coverage;
- two-sided 95% Wilson bounds for binomial proportions.

An independent candidate requires both the fixed point thresholds and the
conservative Wilson bounds: every recall lower bound and the attack-consistency
lower bound, both globally and for every attack family, must meet their floors,
while the safe-boundary false-positive upper bound must remain below its
ceiling. Krippendorff's nominal alpha is
checked against the preregistered agreement floor and bound to the frozen
review-analysis digest. Its lower two-sided 95% bound must also meet that floor.
The exact statistic, case-resampling BCa bootstrap method, resample count, and
seed digest are part of the canonical preregistration, so a different agreement
coefficient or uncertainty procedure cannot be substituted after review.

Any excluded or incomplete fixed case, missing attack variant, insufficient
review coverage, or incomplete adjudication yields `incomplete`. A complete
negative study remains valid evidence with `thresholds_not_met`; it is never
discarded. Repository and internally curated corpora can only produce
`engineering_only`, regardless of perfect metrics.

The report and final manifest carry outcome status separately from the evidence
maturity ceiling. Thus an internal corpus remains `engineering_only`, while its
outcome is still explicitly `incomplete`, `thresholds_not_met`, or
`thresholds_met`. The public report retains content-free case counts, review
coverage, strata, attack-family coverage, and deviation counts for negative and
incomplete studies.

The aggregate coverage counts are bound to a private case-to-reviewer coverage
matrix digest. Each row uses small indices into the sorted signed-receipt array,
not repeated reviewer key identifiers, and the validator enforces the frozen
per-case maximum. Every row must also be the exact transpose of the
reviewer-signed assignment manifests. This makes later audit substitution
detectable, but the public validator cannot prove that a private assignment or
affiliation describes a real person or institution; independent governance
must inspect those records.
Likewise, recomputation from signed aggregate counts proves internal arithmetic
consistency, not that those counts faithfully summarize the private prediction
and label bundles. The final signed manifest and their digests make that claim
auditable; an independent reproducer must still recompute the aggregates from
the governed private artifacts.

## Privacy and activation boundary

Reviewer key identifiers and affiliation commitments exist only in the private
verification bundle. The returned report and final manifest expose counts and
cryptographic digests, not reviewer identifiers, raw messages, stable actor
identifiers, or blind mappings.

For Military temporal evaluation, the exact preregistered policy must still be
`shadow_only`, with both runtime policy execution and product actions disabled.
No result status produced by this contract can enable either path.

## Operational prerequisites

Before a real confirmatory run, governance must provision distinct trusted
keys for the institution, timestamp verifier, reviewers, and adjudicator;
archive the original RFC 3161 artifacts and revocation material; freeze the
corpus and review packet; and retain private case-level material under the
approved ethics, consent, access, and retention controls. Public study and
result tokens must be non-personal. Affiliation commitments must hash governed
randomly salted commitment artifacts, never raw institution names that permit
dictionary recovery.

This adapter completes receipt issuance, not independent reproducibility of the
study. The implemented private reproduction-package gate is documented in
`docs/domain-independent-reproduction-package.md`. It checks that every
content-addressed primary decision, prediction, exclusion, deviation, build,
trust, and timestamp artifact is represented and cross-linked before a later
independent aggregate recomputation can be attempted. Its strongest status is
`manifest_consistent`; it cannot claim that the attempt occurred or succeeded.
