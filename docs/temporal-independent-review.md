# Temporal independent-review protocol

This protocol separates machine-generated seed labels from independently
produced human labels. The committed temporal seed corpus is synthetic and its
case identifiers reveal expected classes. A declaration such as
`label_blinding: true` is therefore insufficient by itself.

Temporal policy activation remains `pending` until a packet-bound v2 review
reports `pass`. The disabled Shadow implementation may still be released
because it has no action-execution path.

## Roles and frozen decisions

- At least two human reviewers label every case without the coordinator map,
  source corpus, seed expectations, or another reviewer's labels.
- Reviewers use distinct pseudonymous reviewer and affiliation tokens.
- A third human from another affiliation acts only as adjudicator.
- Reviewer labels are frozen before the adjudicator receives them.
- Adjudication occurs strictly after all reviewer labels for that case.
- Names, email addresses, message text, source identifiers, and content hashes
  must not be placed in the review bundle.

The study protocol, inclusion criteria, primary metrics, and stopping rules
should be preregistered before labels are collected. Reviewer disagreements
must be retained in the aggregate metrics rather than silently overwritten.

## Generate packet-bound material

Create a fresh 32-byte secret for each review round outside the repository:

```sh
openssl rand -out /protected/temporal-review-round.key 32
chmod 600 /protected/temporal-review-round.key
```

The generator rejects symbolic-link keys, keys accessible by group or world,
and pre-existing output files; use new paths for every round.

Generate three separate outputs:

```sh
cargo run --locked -p aura-military --features evaluation \
  --example temporal_blind_review_packet -- \
  --packet-id temporal_round_2026_01 \
  --blinding-key /protected/temporal-review-round.key \
  --packet-output review/temporal-review-packet.json \
  --coordinator-map-output /protected/temporal-review-coordinator-map.json \
  --review-template-output review/temporal-review-bundle.json
```

The reviewer packet contains:

- a 128-bit HMAC-derived token for each case;
- per-case actor and content-reference tokens with no cross-case stability;
- event times relative to the current event, not absolute timestamps;
- interpreted event kind and context required to assess the temporal chain;
- binary evidence-eligibility flags required by the frozen temporal policy;
- the allowed non-content reason-code catalog.

It does not contain internal case identifiers, corpus tags, seed expectations,
absolute timestamps, source actor numbers, source content hashes, event IDs, or
numeric upstream machine-confidence values. The packet exposes only the frozen
threshold decisions needed to reproduce the temporal layer. Case order and
tokens change between review rounds.

The coordinator map binds the exact corpus digest to the canonical packet
digest and maps blind tokens back to internal case identifiers. It is written
with owner-only permissions and must not be distributed to reviewers, uploaded
as release evidence, or committed. Keep the blinding key and coordinator map
separate from the packet until reviewer labels are frozen.

## Populate the v2 review bundle

The generated template is bound to `packet_id` and
`packet_canonical_sha256`. Each case uses only `blind_case_token`:

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

Negative cases use an empty `expected_reason_codes` array. Reviewer and
affiliation tokens contain only ASCII letters, digits, `_`, `-`, or `.`. They
are validated but never exported in the aggregate report.

## Validate after label freeze

```sh
cargo run --locked -p aura-military --features evaluation \
  --example temporal_independent_review -- \
  --blind-packet review/temporal-review-packet.json \
  --coordinator-map /protected/temporal-review-coordinator-map.json \
  --review-bundle review/temporal-review-bundle.json \
  --output artifacts/temporal-independent-review-report.json \
  --require-pass
```

The validator rejects packet or mapping tampering, unknown or duplicate blind
tokens, stale corpus bindings, unknown reviewers, affiliation overlap,
adjudication performed before label freeze, and unsupported reason codes. The
generated report contains aggregate metrics and packet commitments but no
blind-token mapping or internal case identifiers.

The legacy v1 bundle validator remains available for old material, but its
report has `blinding_assurance: declared_only` and cannot satisfy temporal
policy activation readiness. Packet-aware reports use the v2 report schema.

## Evidence limits

Packet binding prevents accidental label leakage through case names and makes
post-review substitution detectable. It does not by itself prove external
validity, ecological validity, reviewer expertise, or representative sampling.
It evaluates the temporal decision layer over already interpreted, content-free
event features; it is not an independent end-to-end validation of upstream text
interpretation.

The committed seed corpus is public, so a determined reviewer could still
attempt structural matching against the repository. Results from that corpus
remain release-regression evidence only. Strong research evidence requires a
new difficult corpus that is inaccessible to reviewers before packet creation,
independent recruitment and training records, prespecified analysis, reported
agreement and disagreement, and replication on data from another setting.
