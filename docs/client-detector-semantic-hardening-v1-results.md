# Client detector semantic hardening v1 — post-diagnostic results

Date: 2026-08-31

Status: engineering regression passed; independent release validity remains
open.

This document records the implementation performed after the frozen
`client-detector-logic-experiment-v1` diagnosis. It does not replace or mutate
the original result. The same fixture was used to design and exercise the fix,
so the measurements below are post-diagnostic regression evidence, not an
independent estimate of production accuracy.

## Implemented boundary

- Message interpretation now separates text inside closed quote spans from the
  current author's text outside them.
- A signal is suppressed as a report, lesson, refusal, protective negation, or
  crisis-support response only when the outside text corroborates that stance.
- A bare quoted threat remains active. An unclosed quote fails closed. A direct
  request, threat, blackmail, or self-referential crisis statement outside the
  quoted span also keeps the signal active.
- The boundary is applied before signals become confirmed events and is also
  applied to downstream context signals, preventing suppressed observations
  from entering memory or policy as confirmed risk.
- English, Ukrainian, and Russian protective cues are explicit. Russian Kids
  rules now cover the four gaps exposed by v1: parent-deception grooming,
  image blackmail, suicide coercion, and threatened violence.
- Unicode normalization composes legitimate Cyrillic letters first and removes
  only remaining combining-mark noise. This preserves `й`, `ї`, and `ё` while
  closing the combining-mark evasion observed in Ukrainian and Russian.

No `unsafe` code was introduced.

## Same-fixture before/after regression

The frozen fixture contains 24 risky and 24 safe messages in 24
counterfactual pairs, with eight pairs per supported language.

| Metric | Frozen diagnosis | Post-diagnostic regression |
| --- | ---: | ---: |
| expected-family recall | 20/24 = 83.3% | 24/24 = 100% |
| safe false-positive rate | 14/24 = 58.3% | 0/24 = 0% |
| safe specificity | 10/24 = 41.7% | 24/24 = 100% |
| full pair accuracy | 8/24 = 33.3% | 24/24 = 100% |

Post-diagnostic language slices are 8/8 expected-family positives and 0/8 safe
false positives for each of English, Ukrainian, and Russian. The Wilson 95%
lower bound for each eight-case recall/specificity slice is only 67.6%, which
is further evidence that these small slices cannot authorize release.

## Metamorphic regression

The 12 positive seeds and their case, zero-width, punctuation, mixed-script,
combining-mark, and English fullwidth variants now produce:

| Metric | Frozen diagnosis | Post-diagnostic regression |
| --- | ---: | ---: |
| base seed detection | 11/12 = 91.7% | 12/12 = 100% |
| all variant detection | 55/64 = 85.9% | 64/64 = 100% |
| preservation from detected seeds | 55/59 = 93.2% | 64/64 = 100% |

All six transform groups have zero failed case IDs. The 64/64 Wilson 95%
interval is approximately 94.3–100%.

## Post-hardening auxiliary broad-label check

The unchanged deterministic KoalaAI validation sampler was rerun against the
post-hardening `rules_fallback`. This remains auxiliary broad-label evidence;
KoalaAI labels are neither conversation-level nor equivalent to AURA's child
safety taxonomy.

| Slice | Self-harm | Harassment | Violence | Safe specificity |
| --- | ---: | ---: | ---: | ---: |
| all-language stress | 2/200 (1.0%) | 20/200 (10.0%) | 7/200 (3.5%) | 196/200 (98.0%) |
| post-hoc English-ASCII | 2/67 (3.0%) | 56/200 (28.0%) | 25/200 (12.5%) | 177/200 (88.5%) |

Relative to the frozen diagnostic run, every broad positive cohort increased
slightly while both safe-specificity numerators remained unchanged. The result
does not establish exact AURA recall: the broad labels include third-person,
descriptive, and off-taxonomy content, and the English slice remains post-hoc.
It does confirm that the current fallback is still phrase-bound rather than a
general semantic classifier. The exact content-free reports are
`artifacts/internal-holdout-v1/koala-post-semantic-all.json` and
`artifacts/internal-holdout-v1/koala-post-semantic-english-ascii.json`.

## Release interpretation

This closes the known mechanistic failures in the frozen v1 fixture. It does
not close `REL-011`. Promotion from shadow to product enforcement still
requires all of the following on a fixed clean release candidate:

1. an independently authored and held-out conversation-level corpus;
2. native-speaker review for English, Ukrainian, and Russian, including
   pragmatics, mixed-language messages, and adversarial quote/stance cases;
3. prespecified all-family thresholds and confidence intervals with adequate
   support per language and harm family;
4. product-action and physical-device validation against the exact pinned
   Apple artifact;
5. the required child-safety, self-harm, security/privacy, and release-owner
   approvals.

Until those gates pass, the honest status is `engineering regression passed /
release blocked`, and the rules fallback remains shadow evidence only.

The self-funded/internal path is now prespecified in
`experiments/client-detector-internal-holdout-v1/README.md`. Its 480 original
conversations, double native-speaker review, disagreement adjudication, frozen
file identities, and one-shot conversation probe can provide stronger internal
confirmatory evidence. Because AURA still controls the protocol and staffing,
that result must remain labeled `internal_blinded_holdout`; it does not replace
the external evidence boundary above.

## Reproduction

```bash
cargo test -p aura-patterns --locked
cargo test -p aura-kids --locked
cargo test -p aura-core context::interpretation::tests --locked
cargo test -p aura-core russian_ --locked
cargo run --quiet --example client_detector_logic_experiment -p aura-core
```
