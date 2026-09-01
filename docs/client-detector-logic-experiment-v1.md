# Client detector logic experiment v1

Status: prespecified before running the new logic experiments.

This protocol evaluates whether the current on-device AURA detector makes the
right distinction, not merely whether existing regression fixtures still pass.
It is scoped to the local client fallback runtime. The current checkout does
not contain governed ONNX artifacts, so no result from this protocol may be
presented as model-backed production evidence.

## Frozen implementation under test

- Git commit: `4580e602639970fb936b46d43a6c366985ea3b39`
- Pre-experiment worktree diff SHA-256:
  `49464eb6a5b3df5852d4fe100589951212d897dab367e29101b3b0081e1fad74`
- Pattern database: `PatternDatabase::default_mvp()`
- Account policy: child, Kids domain, High protection, shadow rollout
- Languages: English, Ukrainian, and Russian
- Runtime backend must be recorded by the runner. A fallback backend is not an
  ONNX result.

The implementation, fixtures, thresholds, and scoring code must not be changed
between the first custom run and the recorded result. Any later detector change
requires a new result clearly marked as post-change and the original result must
remain available for comparison.

## Hypotheses

H1. Direct, semantically unambiguous child-safety threats cross the frozen
family threshold in at least 90% of cases overall and at least 80% within every
reported language/threat slice that has at least 10 cases.

H2. Safe counterfactuals containing the same high-risk words but changing the
speech act or stance (support, refusal, reporting, education, quotation, or
third-party discussion) remain below every threat-family threshold in at least
95% of cases overall and 90% within every slice with at least 10 cases.

H3. Meaning-preserving manipulations (case, compatibility Unicode, combining
marks, mixed-script confusables, punctuation insertion, and spacing) preserve
the expected detection decision in at least 90% of variants. Each transform is
reported separately.

H4. The predicted threat family is correct in at least 85% of detected positive
cases. A detection under the wrong family is a classification error, not a true
positive.

H5. Client action is directionally safe: positive cases must not be `Allow`,
while safe counterfactuals must not be `Block`. Warning-only differences are
reported separately from classification.

## Frozen operating thresholds

These thresholds are fixed before the custom experiment and are applied to all
cases in a family. Per-case thresholds are prohibited.

| Threat family | Threshold |
|---|---:|
| grooming | 0.55 |
| manipulation | 0.55 |
| bullying | 0.55 |
| self_harm | 0.70 |
| threat | 0.60 |
| explicit | 0.55 |
| nsfw | 0.55 |
| phishing | 0.55 |

Any other non-`none` family uses 0.55 for false-positive accounting. It is
reported as `other` in the compact matrix unless it is an expected label.

For a safe case, a false positive occurs when *any* scored threat family crosses
its threshold. For a positive case, a true positive requires the expected
family to cross its threshold. A different family crossing threshold is also
recorded in the full confusion matrix.

## Experiments

### E0: existing-suite baseline

Run the canonical external-curated and realistic suites unchanged. Treat their
metrics as descriptive regression evidence only: both corpora are maintained by
the AURA team, use authored labels, and allow case-specific thresholds.

### E1: counterfactual semantic pairs

Use paired examples in which the risky and safe messages share high-information
tokens while the intent or stance changes. Required safe categories are:

- supportive response to distress;
- refusal or safety boundary;
- reporting another person's abuse;
- educational/news discussion;
- explicit negation of a dangerous request;
- quoted or third-party speech.

Report pair accuracy, safe false-positive rate, positive recall, wrong-family
rate, action errors, reason codes, and layer attribution.

### E2: metamorphic robustness

Apply deterministic transforms to positive seed messages. Each transform must
preserve human-readable meaning. Report decision preservation by transform and
by threat/language. Do not count an unreadable mutation as evidence.

### E3: broad-label validation split

Use the repository-local KoalaAI validation split without tuning on it. This is
an auxiliary external-source check only: its moderation labels do not map
perfectly to AURA's child-safety taxonomy, it may overlap historical training
sources, and the dataset card warns of label inconsistency. Report only mappings
that are direct enough to defend:

- `SH` -> self_harm;
- `HR` -> bullying/harassment broad alert;
- `V` or `V2` -> threat/violence broad alert;
- all-zero rows -> no broad safety alert.

Sexual labels are not treated as grooming labels. Results must include the
mapping limitation and source support counts.

## Metrics and uncertainty

Primary metrics are recall, false-positive rate, specificity, expected-family
accuracy, macro recall, pair accuracy, and action-error counts. Every proportion
is reported with a two-sided 95% Wilson interval and raw numerator/denominator.
Results with fewer than 10 examples in a slice are descriptive and cannot pass a
release gate. Calibration (Brier/ECE) is secondary because the labels are
categorical and small slices make ECE unstable.

The report must include:

- a full expected-vs-predicted confusion matrix including `none` and `other`;
- per-language and per-threat support;
- all failed case identifiers and outputs, without private user content;
- detector layer and reason-code distributions;
- runtime backend and dataset/file digests;
- latency median, p95, and maximum as diagnostic data only.

## Interpretation boundary

E1 and E2 are mechanistic, developer-authored experiments and may reveal bugs,
but they are not an independent estimate of field accuracy. E3 is more external
but still broad-label and potentially training-contaminated. A release claim
requires a separately held, independently reviewed, conversation-level set and
shadow-mode pilot evidence. No detector threshold or lexicon expansion should
be promoted solely because it improves this developer-visible protocol.
