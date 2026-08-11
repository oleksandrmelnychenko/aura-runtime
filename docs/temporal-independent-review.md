# Temporal independent-review protocol

This protocol produces confirmatory evidence for the content-free temporal
decision layer. It separates the frozen corpus, the machine-generated target
labels, two or more independent human reviews, and a separate adjudication.
The release gate accepts only a preregistered, packet-bound v3 result from an
embargoed external corpus. The public repository seed remains regression
evidence and cannot authorize policy activation.

## Scientific status and roles

The workflow distinguishes four claims:

- packet binding supports internal integrity and makes later substitution of
  the corpus, preregistration, or review packet detectable;
- reviewer agreement measures reproducibility of the labeling decision;
- exact adjudicated agreement measures reproduction of the frozen target;
- an external corpus supports broader validity only to the extent that its
  sampling frame and collection setting are genuinely independent.

Use separate people or teams for these roles:

- the corpus custodian freezes the external corpus and its sampling frame;
- the coordinator generates blind material and retains the secret map;
- at least two reviewers from distinct affiliations label every case without
  the map, corpus target labels, or another reviewer's decisions;
- an adjudicator from another affiliation sees reviewer decisions only after
  they are frozen and does not serve as a reviewer.

Names, email addresses, message text, source identifiers, absolute event
times, and content hashes must not be placed in the review bundle. Recruitment,
training, exclusions, conflicts, and deviations are retained in a separate
controlled study record.

## Freeze the corpus and preregistration

The external corpus uses the same strict schema as the repository temporal
corpus, but it must have a different `dataset_id` and different canonical
digest. Before collecting reviewer labels:

1. Freeze the inclusion and exclusion rules, fixed case count, negative-control
   minimum, per-reason positive minimum, required coverage tags, and planned
   subgroup tags. The high-assurance floor is 30 total cases, 18 negative
   controls, and four positive cases for every supported reason code.
2. Copy `docs/temporal-review-preregistration.template.json` and replace its
   study identity, registration time, hypotheses, counts, and tags.
3. Keep the exact three primary outcomes. The validator rejects optional
   stopping, imputation of missing reviews, undeclared handling of undefined
   agreement, or agreement thresholds below `0.8`.
4. Ensure the corpus is inaccessible to reviewers before packet distribution.

The preregistration is serialized by AURA into a deterministic field order and
its SHA-256 digest is bound into every generated artifact. Changing any parsed
field after generation invalidates the packet.

## Generate packet-bound material

Create a fresh 32-byte secret outside the repository for every review round:

```sh
openssl rand -out /protected/temporal-review-round.key 32
chmod 600 /protected/temporal-review-round.key
```

Generate four outputs from the frozen corpus and preregistration:

```sh
cargo run --locked -p aura-military --features evaluation \
  --example temporal_blind_review_packet -- \
  --packet-id temporal_round_2026_01 \
  --corpus /protected/external-temporal-corpus.json \
  --preregistration review/temporal-review-preregistration.json \
  --blinding-key /protected/temporal-review-round.key \
  --packet-output review/temporal-review-packet.json \
  --coordinator-map-output /protected/temporal-review-coordinator-map.json \
  --review-template-output review/temporal-review-bundle.json \
  --study-commitment-output review/temporal-study-commitment.json
```

The command refuses symbolic-link keys, group/world-readable keys, output paths
that overwrite inputs, duplicate output paths, and pre-existing outputs.

The reviewer packet contains per-round HMAC-derived case tokens, case-local
actor and content-reference tokens, event times relative to the current event,
the interpreted event context needed by the temporal layer, binary evidence
eligibility decisions, and the allowed reason-code catalog. It omits internal
case identifiers, corpus tags, target labels, absolute timestamps, source
identifiers, event identifiers, content hashes, and numeric upstream confidence.

The owner-only coordinator map binds blind tokens to internal case identifiers.
It and the blinding key must never be distributed to reviewers or uploaded as
release evidence.

The public study commitment binds:

- study and packet identities;
- registration time and corpus class;
- preregistration, corpus, and packet digests;
- fixed case count and minimum reviewer count;
- both prespecified minimum agreement thresholds.

Before labels are collected, have the exact commitment bytes signed with a
dedicated institutional key and record the commitment digest in an external
append-only or write-once log with a trusted timestamp. A cryptographic
signature authenticates a signer but does not, by itself, prove when the file
existed. Preserve the signature, certificate or public-key identity, timestamp
receipt, and verification record with the study materials. The executable
signing and trusted-key verification procedure is defined in
`docs/temporal-study-attestation.md`; RFC 3161 request and trusted-time
verification are defined in `docs/temporal-study-timestamp.md`.
Individual reviewer and adjudicator signing, timestamping, deterministic
assembly, and chain verification are defined in
`docs/temporal-review-receipts.md`.

## Populate the v3 review bundle

The generated bundle is already bound to `study_id`, the preregistration
digest, `packet_id`, and the packet digest. Each case uses only its blind token:

```json
{
  "blind_case_token": "blind_0123456789abcdef0123456789abcdef",
  "annotations": [
    {
      "reviewer_token": "reviewer_a_8f2c10",
      "expected_reason_codes": ["military.temporal.influence_pressure"],
      "completed_at_ms": 1780000000000
    },
    {
      "reviewer_token": "reviewer_b_41ad22",
      "expected_reason_codes": ["military.temporal.influence_pressure"],
      "completed_at_ms": 1780000001000
    }
  ],
  "adjudication": {
    "adjudicator_token": "adjudicator_c_77b901",
    "expected_reason_codes": ["military.temporal.influence_pressure"],
    "completed_at_ms": 1780000002000
  }
}
```

Negative decisions use an empty `expected_reason_codes` array. Reviewer and
affiliation tokens contain only ASCII letters, digits, `_`, `-`, or `.`. They
are validated but omitted from the aggregate report. Reviewer labels must not
be replaced with the adjudicated result.

## Evaluate after label freeze

```sh
cargo run --locked -p aura-military --features evaluation \
  --example temporal_independent_review -- \
  --corpus /protected/external-temporal-corpus.json \
  --preregistration review/temporal-review-preregistration.json \
  --study-commitment review/temporal-study-commitment.json \
  --blind-packet review/temporal-review-packet.json \
  --coordinator-map /protected/temporal-review-coordinator-map.json \
  --review-bundle review/temporal-review-bundle.json \
  --output artifacts/temporal-independent-review-report.json \
  --require-pass
```

The evaluator rejects altered commitments, preregistrations, packets or maps;
unknown or duplicate tokens; affiliation overlap; unsupported labels; and
review decisions timestamped at or before preregistration; and adjudication
that precedes label freeze. The report contains aggregate metrics and canonical
digests but no blind mapping or internal case identifiers. Report schema v5
adds the canonical SHA-256 digest of the exact input review bundle and
also publishes the declared preregistration time and the earliest/latest
annotation and adjudication completion times. These values are marked
`decision_time_assurance = bundle_declared`; they are chronology inputs, not
independent trusted timestamps.

Primary metrics are:

- adjudicated exact-set match against the fixed target for every case;
- exact-set agreement for every reviewer pair, reported as agreements divided
  by all pair comparisons;
- nominal Krippendorff alpha over binary present/absent decisions for every
  case and reason code, plus per-reason summaries.

Undefined alpha is serialized as `null` with its unit and decision counts; it
is never converted to zero. A complete exact adjudication can still fail when
reviewer agreement is below either preregistered threshold. Exploratory
subgroups must be reported separately from the fixed primary outcomes.

## Release and research limits

The evidence manifest accepts a passing review for policy activation only when
all of these hold: packet-bound blinding, packet-bound preregistration, a valid
study-commitment digest, trusted-key Ed25519 verification, a matching RFC 3161
commitment verification, and a matching chain of individually signed and
RFC 3161 timestamped reviewer and adjudicator receipts with strictly
non-overlapping accuracy-adjusted intervals,
`embargoed_external` corpus class, finite agreement metrics, and both agreement
values at least `0.8`. A passing review without study attestation, trusted
commitment timestamp, or review-receipt chain remains `pending`. Invalid,
privacy-unsafe, chronologically overlapping, or mismatched supplied trust
evidence fails the activation gate. The final evidence manifest still requires
its separate release attestation.

Packet binding does not prove reviewer expertise, representative sampling,
construct validity, ecological validity, or independence of the corpus source.
This study evaluates the temporal decision layer over already interpreted,
content-free features; it is not end-to-end validation of text interpretation.
Report missing data, exclusions, protocol deviations, disagreement, and failed
replications without rewriting the preregistration. Strong doctoral evidence
requires multiple difficult corpora, independent annotation, documented
sampling frames, uncertainty analysis, attack variations, and replication in
another setting.

The commitment timestamp and receipt chain prove a bounded order between the
frozen commitment, signed reviewer submissions, and signed adjudication
submission. They do not prove when work began, reviewer expertise, genuine
institutional independence, absence of coordination, or truthful local
completion-time declarations. Those remain governance and experimental-design
claims that require separate records and oversight.

Omitting `--corpus` uses the embedded public seed for regression only. The
legacy declaration-only path remains available for old material, but neither
legacy review nor the public seed can satisfy activation readiness.
