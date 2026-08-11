# Temporal independent-review protocol

This protocol separates machine-generated temporal test labels from claims of
independent human validation. The committed seed corpus is synthetic. It must
not be described as independently validated until this gate reports `pass`.

## Roles and blinding

- Two human reviewers label every case without access to the seed expectation.
- The two reviewers use distinct pseudonymous reviewer and affiliation tokens.
- A third human from an affiliation not used by either reviewer acts only as
  adjudicator and must not review the same case.
- The adjudicator resolves both agreements and disagreements after both labels
  are frozen.
- Names, email addresses, message text, actor identifiers, and content hashes
  must not be placed in the review bundle.

Reviewer and affiliation tokens are local pseudonyms containing only ASCII
letters, digits, `_`, `-`, or `.`. They are read for validation but are never
exported in the generated report.

## Case record

Each entry in `cases` has this shape:

```json
{
  "case_id": "influence_pressure_positive",
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

The reviewer registry declares each token, its pseudonymous affiliation, and
one role: `reviewer` or `adjudicator`. Negative cases use an empty
`expected_reason_codes` array.

## Corpus binding and gate

Start from `docs/temporal-independent-review.template.json`. Before review,
confirm that `corpus_sha256` matches the exact corpus under evaluation. The
validator rejects a stale digest instead of silently reviewing another corpus.

```sh
cargo run --locked -p aura-military --features evaluation \
  --example temporal_independent_review -- \
  --review-bundle path/to/completed-review.json \
  --output artifacts/temporal-independent-review-report.json \
  --require-pass
```

The gate passes only when every corpus case has two independent annotations,
a separate completed adjudication, and an adjudicated label equal to the label
used by the evaluation corpus. Until then the honest status is `pending`.

The disabled Shadow implementation may be released while this review remains
pending because it has no action-execution path. The unified evidence manifest
nevertheless reports `temporal_policy_activation_readiness: pending`; enabling
the temporal policy must require that value to be `pass`.
