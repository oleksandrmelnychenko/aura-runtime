# AURA client detector internal blind holdout v1

Status: protocol and tooling ready; authoring and independent internal
annotation are pending.

This is the no-purchase path for obtaining substantially stronger detector
evidence. It produces an internally blinded, conversation-level EN/UK/RU
holdout. It does **not** become external independent certification merely
because the files are hidden from the detector developer.

## Fixed design

- 3 governed languages: English, Ukrainian, Russian;
- 8 threat families: grooming, manipulation, bullying, self-harm, threat,
  explicit, NSFW, and phishing;
- 10 risky/safe counterfactual pairs per language and family;
- 240 pairs, 480 conversations, at least 960 messages;
- two independent native-speaker annotations per case;
- third-reviewer adjudication for every disagreement;
- no detector execution before case and gold-label SHA-256 commitments are
  frozen;
- no real child conversations, names, handles, links, phone numbers, precise
  locations, or other direct identifiers.

The pair structure is for coverage, not for telling annotators the expected
answer. Annotation packets omit assignment, target family, polarity, author,
and pair identifiers.

## Separation of roles

1. **Protocol owner** freezes this protocol and the release thresholds.
2. **Authors** receive authoring assignments and write original synthetic
   conversations. They must not inspect detector rules, outputs, failed IDs,
   or the earlier diagnostic fixtures.
3. **Reviewers A and B** receive differently ordered blind packets for their
   native language. They work independently and must not communicate labels.
4. **Adjudicator C** sees only disagreements after A and B have submitted.
5. **Evaluation operator** freezes the exact files, runs the probe once, and
   publishes the full aggregate report even when it fails.
6. **Detector developers** receive only the frozen manifest and aggregate
   result until the release decision is recorded. Failed case text is not
   disclosed during the confirmatory run.

One person may cover multiple roles only when staffing requires it, but that
weakens the evidence and must be recorded. The author of a case may never be
either of its first two reviewers.

## Authoring rules

- Write natural conversations of 2–6 messages; do not write isolated keyword
  lists.
- Keep risky and safe members of a pair lexically comparable while changing
  the actual speech act or stance.
- Safe cases should include support, refusal, reporting, education, quotation,
  third-party discussion, protective negation, or crisis support.
- Risky cases must contain an unambiguous active risk after the annotated onset;
  introductory benign turns are allowed and encouraged.
- Self-harm cases must distinguish the protected person's own distress from a
  supportive response or report about another person.
- Code-switching and obfuscation must remain readable to a native speaker.
- Use `[LINK]`, `[PHONE]`, `[HANDLE]`, and `[LOCATION]`; never copy real chats.
- Do not translate an English seed mechanically. Ukrainian and Russian cases
  must be authored or substantively rewritten by native speakers.

## Label definitions

Reviewers label the primary mechanism, its first unambiguous onset turn, and
the minimum safe product action:

- `grooming`: trust-building, secrecy, isolation, boundary testing, migration
  to a private channel, or image/contact solicitation involving a minor;
- `manipulation`: coercion, blackmail, gaslighting, exploitative pressure, or
  deceptive control;
- `bullying`: targeted humiliation, harassment, exclusion, or repeated peer
  abuse;
- `self_harm`: the protected person's own ideation, intent, plan, coercion into
  self-harm, or acute self-harm crisis;
- `threat`: credible threatened violence or harm;
- `explicit`: explicit sexual content where the content itself is the primary
  mechanism;
- `nsfw`: non-explicit adult or sexualized content unsuitable for the protected
  account;
- `phishing`: deceptive credential, payment, secret, or account-access request;
- `none`: no active threat; discussion, quotation, support, refusal, and
  reporting remain `none` unless the speaker also performs an active harmful
  act outside that context.

## Workflow

Generate the fixed authoring matrix:

```bash
python3 training/internal_holdout.py assignments \
  --protocol experiments/client-detector-internal-holdout-v1/protocol.json \
  --output artifacts/internal-holdout-v1/authoring-assignments.jsonl
python3 training/internal_holdout.py authoring-packets \
  --protocol experiments/client-detector-internal-holdout-v1/protocol.json \
  --assignments artifacts/internal-holdout-v1/authoring-assignments.jsonl \
  --output-dir artifacts/internal-holdout-v1/authoring-packets
```

Authors return one case per assignment using
`schemas/case.schema.json`. Validate privacy, completeness, exact duplication,
and near-duplication against the developer-visible corpora, then create the six
blind reviewer packets:

```bash
python3 training/internal_holdout.py packets \
  --protocol experiments/client-detector-internal-holdout-v1/protocol.json \
  --assignments artifacts/internal-holdout-v1/authoring-assignments.jsonl \
  --cases PRIVATE/cases.jsonl \
  --reference-json crates/aura-core/data/realistic_chat_cases.json \
  --reference-json crates/aura-core/data/external_curated_chat_cases.json \
  --reference-json experiments/client-detector-logic/data/client_detector_logic_cases_v1.json \
  --output-dir PRIVATE/packets
```

After A and B submit filled packets, merge them. An absent third review causes
a fail-closed `blocked` result when any disagreement exists:

```bash
python3 training/internal_holdout.py adjudicate \
  --cases PRIVATE/cases.jsonl \
  --review-a PRIVATE/review-a/*.filled.jsonl \
  --review-b PRIVATE/review-b/*.filled.jsonl \
  --review-c PRIVATE/review-c/*.filled.jsonl \
  --gold-output PRIVATE/gold.jsonl \
  --report-output PRIVATE/adjudication-report.json
```

Freeze exact inputs before any detector run:

```bash
python3 training/internal_holdout.py freeze \
  --protocol experiments/client-detector-internal-holdout-v1/protocol.json \
  --assignments artifacts/internal-holdout-v1/authoring-assignments.jsonl \
  --cases PRIVATE/cases.jsonl \
  --gold PRIVATE/gold.jsonl \
  --adjudication-report PRIVATE/adjudication-report.json \
  --output PRIVATE/frozen-manifest.json
```

Build the sequential conversation probe and evaluate exactly once:

```bash
cargo build --locked --release -p aura-core \
  --example client_detector_conversation_probe
python3 training/internal_holdout.py evaluate \
  --manifest PRIVATE/frozen-manifest.json \
  --protocol experiments/client-detector-internal-holdout-v1/protocol.json \
  --assignments artifacts/internal-holdout-v1/authoring-assignments.jsonl \
  --cases PRIVATE/cases.jsonl \
  --gold PRIVATE/gold.jsonl \
  --probe target/release/examples/client_detector_conversation_probe \
  --output artifacts/internal-holdout-v1/result.json
```

Shell globs in the example must resolve to the exact expected files before the
command is recorded. Private plaintext and gold labels stay outside Git. Only
the protocol, schemas, frozen digest manifest, and content-free aggregate
result may enter release evidence.

## Interpretation boundary

A passing result can close the internal confirmatory portion of `REL-011` and
justify moving to a tightly controlled on-device shadow pilot. It cannot claim
field effectiveness, external validation, clinical self-harm validity, or
generalization beyond EN/UK/RU. Physical-device behavior, human safety signoff,
clean artifact identity, and production pinning remain separate gates.
