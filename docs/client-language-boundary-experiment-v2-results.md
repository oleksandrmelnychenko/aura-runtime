# Client language-boundary experiment v2 results

Status: developer shadow experiment completed on 2026-08-31. Production span
emission remains disabled.

## Corrected question

Can directional windows and deterministic Unicode-script alignment improve
governed-to-governed switch boundaries while keeping every unsupported-language
control fail-closed?

The v1 `exact boundary recall` denominator included transitions with an
unsupported expected side. That metric could require the classifier to emit a
label it is explicitly forbidden to emit. V2 preserves the old fixture but
reports those concerns separately:

- exact boundary recall only for `en`, `uk`, or `ru` on both sides;
- any governed-label emission over unsupported tokens;
- emission on the unsupported-side token at a mixed boundary;
- activation of unsupported monolingual samples.

## Expanded frozen setup

- the original 24 samples plus 27 additive controls;
- 51 samples and 757 word tokens in total;
- 468 governed and 289 unsupported tokens;
- 24 governed-to-governed boundaries and 9 mixed unsupported boundaries;
- additional Bulgarian, Belarusian, Serbian, Kazakh, Tatar, Macedonian, Polish,
  German, Spanish, and Czech controls;
- shared-alphabet Cyrillic controls intentionally avoid characters outside the
  Ukrainian/Russian scalar union, so the alphabet veto alone cannot pass the
  experiment;
- iPhone 17 Pro simulator, iOS 26.2, Xcode 26.2, CPU-only Core ML.

The additive texts are developer-authored diagnostic fixtures. They have not
been independently collected, license-reviewed, or native-speaker adjudicated.

## Algorithm experiment

The safe candidate requires:

1. agreement from centered, leading, and trailing five-word shadow windows for
   ordinary token coverage;
2. two consecutive confirmations on each side of a directional change point;
3. one selected split per contiguous change-point cluster;
4. deterministic Unicode-script alignment for Latin-to-Cyrillic boundaries;
5. the original Core ML, hashed n-gram, Apple recognizer, and alphabet-veto
   agreement for every underlying label.

It is implemented only inside
`AuraShadowLanguageBoundaryExperimentTests`. No runtime producer consumes it.

## Results

| Variant | Governed coverage | Emitted precision | Switch sample recall | Exact governed boundary recall | Unsupported emissions |
|---|---:|---:|---:|---:|---:|
| Centered five-word baseline | 64.53% | 96.49% | 66.67% | 25.00% (6/24) | 11/289 |
| Higher-coverage center consensus + pairs | 58.12% | 97.84% | 61.11% | 45.83% (11/24) | 6/289 |
| Strict three-way consensus | 10.68% | 100.00% | 22.22% | 0.00% (0/24) | 0/289 |
| Strict consensus + confirmed/script-aligned pairs | 15.38% | 100.00% | 55.56% | 45.83% (11/24) | 0/289 |

The higher-coverage variants are rejected because even one unsupported
activation violates the safety boundary. The selected shadow variant recovered
11 governed boundaries with no wrong or unsupported emission, but emitted only
72 of 468 governed tokens.

Machine-readable decision evidence is stored in
`experiments/client-language-boundary-v2/results-ios-26.2.json`.

## Decision

Keep `LanguageEvidenceV1.spans` empty. Do not wire this experiment into
`AuraLanguageEvidenceProducer`.

The experiment validates the metric correction and a safer change-point
primitive, not production readiness. Promotion still requires an independently
collected and native-speaker-adjudicated corpus, explicit ambiguous-token
policy, iOS 18 and iOS 26 physical-device profiling, replay-stable UTF-8 span
construction, and a separately governed artifact/policy review.
