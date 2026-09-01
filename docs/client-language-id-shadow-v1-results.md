# Client language-ID shadow v1 results

Status: shadow implementation completed on 2026-08-31. It is not connected to
production candidate routing or span emission.

## Implemented boundary

The Swift test target contains an independently governed language-ID bundle;
the production `AuraAgent` target contains neither the model resources nor the
shadow loader:

- a Create ML `MLTextClassifier` candidate model;
- a deterministic 2-to-5-character hashed n-gram open-set veto;
- Apple `NLLanguageRecognizer` agreement;
- a Cyrillic alphabet allowlist that abstains on scalars outside the governed
  Ukrainian/Russian union;
- a source-pinned manifest digest and exact SHA-256 for every compiled artifact;
- strict manifest shape, inventory, file-size, path, model-layout, and output
  validation;
- actor-serialized `NLModel` access with no plaintext retention.

The bundle is exactly 1,382,911 bytes including its manifest. Its manifest
SHA-256 is
`7bfb27d993fda7591a2414722cefcc8d3c5372638164122bede0bb5450236d5f`.
Changing the model or policy therefore requires an explicit source-pin review.

## Development data

The deterministic pipeline produced:

- 13,616 training rows;
- 2,814 calibration rows;
- 2,990 test rows;
- labels `en`, `uk`, `ru`, and unsupported-control `tt`.

The split is disjoint by SHA-256 of the normalized labeled text. It is not an
independent release holdout. Native-speaker adjudication, source-label review,
and redistribution-license approval are still missing.

## Component metrics

The Core ML closed-set classifier had 1.56% calibration error and 1.61% test
error. Its high output probabilities were not treated as calibrated safety
confidence.

At n-gram margin `0.20`:

| Slice | Supported coverage | Precision when emitted | Unsupported -> supported count |
|---|---:|---:|---:|
| Calibration | 90.88% | 99.95% | 0 |
| Test | 91.39% | 99.90% | 1 |

The single test emission comes from a row labeled Tatar whose content all three
classifiers identify as Russian. That is a suspected annotation defect, not an
authorized relabeling. It remains a release blocker until independent language
review resolves it.

## iOS 26.2 frozen span experiment

The shadow ensemble was evaluated on the previous 24-sample, 308-token corpus
with Belarusian, Bulgarian, Kazakh, and Serbian controls:

| Variant | Coverage | Precision when emitted | Switch sample recall | Exact boundary recall | Unsupported emission |
|---|---:|---:|---:|---:|---:|
| Five-word shadow windows | 33.77% | 100.00% | 54.55% | 0.00% | 0.00% |
| Conservative runs >= 3 | 27.92% | 100.00% | 45.45% | 0.00% | 0.00% |

This eliminates the observed unsupported-language activation, but abstains too
often and does not recover exact switch boundaries. It is therefore diagnostic
shadow evidence, not a production improvement claim.

The later expanded v2 boundary experiment found that this v1 exact-boundary
metric mixed governed-to-governed transitions with transitions whose other side
was intentionally unsupported. V2 separates safety and boundary denominators,
adds harder same-alphabet controls, and remains a production no-go. See
`docs/client-language-boundary-experiment-v2-results.md`.

## Decision

Keep production text-derived candidates disabled and
`LanguageEvidenceV1.spans` empty. The release producer emits only a validated
client declaration. The shadow component has no runtime wiring and is isolated
to the test target.

Promotion requires:

1. an independently collected and native-speaker-adjudicated conversational
   corpus with broader same-alphabet controls;
2. explicit resolution of mislabeled-source rows and license provenance;
3. materially better boundary recall without unsupported-language activation;
4. iOS 18, iOS 26, and physical-device load, latency, memory, and energy results;
5. a separate artifact and policy approval after the evidence is frozen.
