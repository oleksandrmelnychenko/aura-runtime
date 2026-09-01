# Client detector logic experiment v1 — results

Date: 2026-08-31

Conclusion: the current client fallback has high recall on internally authored
phrases, but it is not yet a semantically reliable child-safety detector. Its
largest correctness defect is context polarity: quoted, reported, negated, and
supportive messages frequently inherit the risk of the words they discuss. Its
second defect is poor generalization outside the maintained lexicons, with a
material Russian-language coverage gap.

No detector rule, threshold, or policy was changed after observing these
results. This is a diagnosis and experiment-infrastructure change only.

The subsequent implementation and same-fixture regression are recorded
separately in `docs/client-detector-semantic-hardening-v1-results.md`. They do
not alter this frozen diagnosis and are not independent release evidence.

## Runtime and identity

- Protocol: `docs/client-detector-logic-experiment-v1.md`
- Pair fixture: `aura_client_detector_logic_pairs_v1`
- Fixture SHA-256:
  `8111b48d3bde9156e860fab869da4bffbe531a14b8e8cb14dff6fca8773bbbef`
- Frozen Git commit: `4580e602639970fb936b46d43a6c366985ea3b39`
- Frozen pre-experiment diff SHA-256:
  `49464eb6a5b3df5852d4fe100589951212d897dab367e29101b3b0081e1fad74`
- Actual runtime backend: `rules_fallback`
- Loaded models: none
- Product mode: shadow

The result therefore evaluates the native rule/lexicon fallback, not the
governed ONNX runtime and not the final Apple artifact.

## E0 — existing suites

| Suite | Positives detected | Negatives flagged | Reported result |
|---|---:|---:|---:|
| external curated mixed | 33/33 | 0/30 | PASS |
| external curated gold-reviewed | 29/29 | 0/24 | PASS |
| realistic chat | 44/44 | 0/40 | PASS |

These are regression results, not independent validity evidence. Both JSON
corpora are maintained by `aura_core_team`; messages closely reflect known
rules; and scenario classification uses a case-specific threshold while only
checking the primary/tracked threat families. An off-target family can therefore
escape false-positive accounting.

## E1 — frozen semantic counterfactual pairs

The fixture contains 24 risky and 24 safe messages arranged as 24 pairs in
English, Ukrainian, and Russian. Safe cases preserve high-information words but
change the speech act or stance to support, refusal, reporting, education,
negation, or third-party quotation.

| Metric | Result | Wilson 95% interval | Prespecified target |
|---|---:|---:|---:|
| expected-family recall | 20/24 = 83.3% | 64.1–93.3% | >=90% overall |
| expected-family top accuracy | 20/24 = 83.3% | 64.1–93.3% | >=85% |
| safe false-positive rate | 14/24 = 58.3% | 38.8–75.5% | <=5% |
| safe specificity | 10/24 = 41.7% | 24.5–61.2% | >=95% |
| full pair accuracy | 8/24 = 33.3% | 18.0–53.3% | no separate gate |

Action errors: three risky messages were allowed and one safe English grooming
counterfactual was blocked.

### Language slices

| Language | Positive recall | Safe false positives | Safe specificity |
|---|---:|---:|---:|
| English | 8/8 | 6/8 | 2/8 |
| Ukrainian | 8/8 | 4/8 | 4/8 |
| Russian | 4/8 | 4/8 | 4/8 |

Each positive or negative language support is only eight, so the slice values
are descriptive. They are still sufficient to reveal a systematic Russian
coverage failure: parent-deception grooming, blackmail, and threatened school
violence were allowed, while suicide coercion was mislabeled as self-harm.

### Confusion matrix

Rows are expected, columns are the highest family crossing its frozen threshold.

| Expected | bullying | grooming | manipulation | self_harm | none |
|---|---:|---:|---:|---:|---:|
| bullying | 5 | 0 | 0 | 0 | 1 |
| grooming | 0 | 5 | 0 | 0 | 1 |
| manipulation | 0 | 0 | 4 | 1 | 1 |
| self_harm | 0 | 0 | 0 | 6 | 0 |
| none | 1 | 6 | 2 | 5 | 10 |

False positives were not low-confidence noise: representative safe messages
reached grooming 0.90, manipulation 0.88, self-harm 0.90, and bullying 0.84.

## E2 — metamorphic robustness

Twelve positive seeds were transformed with case changes, zero-width
characters, punctuation insertion, mixed-script confusables, combining marks,
and (for English) fullwidth compatibility characters.

| Metric | Result | Wilson 95% interval |
|---|---:|---:|
| base seed detection | 11/12 = 91.7% | 64.6–98.5% |
| all variant detection | 55/64 = 85.9% | 75.4–92.4% |
| preservation from detected bases | 55/59 = 93.2% | 83.8–97.3% |

By transform:

- case: 11/12
- zero-width: 11/12
- punctuation: 11/12
- mixed-script confusable: 11/12
- fullwidth English: 4/4
- combining marks: 7/12

The new Unicode lexical normalization is effective for most transforms. The
remaining combining-mark failures cluster in Russian and in one Ukrainian
self-harm case whose 0.63 score fell below the frozen 0.70 operating threshold.
The Russian manipulation base seed itself was never assigned to manipulation,
so its five variants are taxonomy/coverage failures rather than new evasion
failures.

## E3 — repository-local KoalaAI validation split

The deterministic sample rule selects the smallest
`sha256(cohort + NUL + prompt)` after exact-text deduplication. The Parquet file
SHA-256 is
`2a23ed76c709709422539aba7efeba2c8d0c4baba809f69e8020336639326b0a`.

### All-language stress result

| Broad label | Result |
|---|---:|
| self-harm recall | 1/200 = 0.5% |
| harassment recall | 18/200 = 9.0% |
| violence recall | 6/200 = 3.0% |
| all-zero safe specificity | 196/200 = 98.0% |

Manual audit showed a major scope confound: the deterministic sample contains
Czech, Belarusian, Swedish, Kazakh, Spanish, German, and other languages that
the current client does not claim to support. This result is retained as a
multilingual stress result, not treated as supported-language recall.

### Post-hoc English-ASCII exploratory slice

After observing that confound, a deterministic ASCII plus English-function-word
heuristic was added. Because it was added after the first result, this slice is
explicitly exploratory.

| Broad label | Scoped support | Result | Wilson 95% interval |
|---|---:|---:|---:|
| self-harm | 67 | 1/67 = 1.5% | 0.3–8.0% |
| harassment | 200 of 3,506 | 49/200 = 24.5% | 19.1–30.9% |
| violence | 200 of 372 | 17/200 = 8.5% | 5.4–13.2% |
| all-zero safe | 200 of 8,831 | 177/200 = 88.5% specificity | 83.3–92.2% |

These are broad moderation labels, not AURA labels. In particular, KoalaAI
`SH` includes third-person death descriptions and directed “kill yourself”
harassment; `V/V2` includes descriptive violence rather than direct threats.
The numbers cannot be promoted as exact AURA recall. They do show that the
fallback is phrase-bound rather than a general semantic classifier and that
`explicit` is a frequent off-target top prediction on harassment/violence rows.

## Root-cause analysis

### 1. Current evaluation can hide wrong-family and off-target alerts

`summarize_scenario_classification` scores only the positive case's
`primary_threat`, or a negative case's manually supplied `tracked_threats`.
It does not construct a full multiclass confusion matrix and does not scan every
family for a negative. Per-case `detection_threshold` further prevents a single
operating-point claim.

### 2. Context recognition exists but is incomplete and phrase-bound

The interpreter can label quote/report/support/stance, but quote/report
suppression covers threat, bullying, hate, propaganda, military categories, and
self-harm. It intentionally does not suppress grooming or manipulation. That
leaves quoted blackmail and quoted grooming requests active. Support recognition
is itself a small phrase list, so semantically supportive wording outside that
list keeps self-harm signals.

Adding a global “quoted means safe” rule would be unsafe: an attacker could wrap
a real request in quotation marks. The fix needs span/role semantics: identify
the risky quoted span, the message author's stance outside it, reporting or
protective intent, negation scope, and whether the current sender is soliciting
the dangerous action.

### 3. Russian child-safety coverage is materially incomplete

The Kids lexicon is rich in English and Ukrainian but sparse in Russian for
grooming, manipulation, bullying, and self-harm. Generic patterns catch some
Russian phrases, but the child-domain rule set does not provide parity. Adding
translations alone is insufficient; they need risky/safe counterfactual pairs
and action-level tests to avoid doubling false positives.

### 4. Fallback “ML” signals are rule signals with semantic-looking names

The active backend is `rules_fallback`, yet outputs include reason codes such as
`ml.safety.grooming`, `ml.toxicity`, and `ml.uncertainty.guardian_review`.
Diagnostics must not treat these as model evidence. The current production
readiness document already blocks rollout until governed ONNX assets are
restored and activated.

### 5. Cold-start latency needs a separate controlled experiment

The first broad-probe process exposed a large cold/warm split on the same
193-byte input:

- first analysis: 1,977,031 microseconds;
- second: 5,767 microseconds;
- third: 5,194 microseconds.

That result did not reproduce after the filesystem and executable were warm.
Three later fresh-process runs over 124 analyses reported median latency of
1,951-1,982 microseconds, p95 of 4,524-4,920 microseconds, and maximum latency of
7,972-17,647 microseconds. The compiled Kids lexicon is stored behind a global
`OnceLock` and is first materialized during analysis, but the current evidence
does not isolate it as the cause of the two-second outlier. Treat this as a
cold-start hypothesis, not a confirmed performance defect. A controlled test
must separate executable/file-cache loading, analyzer initialization, lexicon
compilation, and first inference, then repeat after device cold boot.

## Evidence-backed next implementation order

1. Replace the existing release classification summary with fixed-threshold,
   all-family confusion/FPR accounting while keeping legacy output for
   compatibility.
2. Add a structured message-role stage for quote span, author stance, negation,
   report/support intent, speaker, and target. Use it to filter or downweight
   signals only when protective semantics are corroborated.
3. Add Russian parity as paired risky/safe semantics, not a phrase dump.
4. Instrument analyzer initialization and first inference separately, measure
   both after device cold boot, then precompile/warm the Kids lexicon before the
   runtime reports ready if it is confirmed as material.
5. Restore governed ONNX artifacts and repeat the same frozen experiments with
   backend/model hashes recorded.
6. Obtain an independently reviewed, held-out, conversation-level dataset and
   shadow-mode human review before changing release thresholds.

## Reproduction

```bash
cargo run --quiet --example external_curated_eval -p aura-core
cargo run --quiet --example realistic_eval -p aura-core
cargo run --quiet --example client_detector_logic_experiment -p aura-core
cargo build --quiet --example client_detector_jsonl_probe -p aura-core
PYTHONPATH=/path/to/pyarrow \
  python3 training/evaluate_client_fallback_holdout.py \
  --parquet data/raw/hf/KoalaAI_Text-Moderation-Multilingual/validation.parquet \
  --probe target/debug/examples/client_detector_jsonl_probe
```

The English heuristic rerun adds
`--language-scope english_ascii_heuristic`.
