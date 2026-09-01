# Client detector developer challenge v1 — first frozen run

Date: 2026-09-01

Status: `diagnostic_fail`; release eligibility: `false`.

This document records the first detector execution over the frozen
developer-authored challenge. The challenge is diagnostic evidence only. It
is not blinded, independently authored, or independently reviewed, and it
cannot close `REL-011`.

## Design and freeze

The corpus contains 240 counterfactual pairs / 480 synthetic two-turn
conversations. Every English, Ukrainian, and Russian threat-family slice has
10 risky and 10 safe cases for each of grooming, manipulation, bullying,
self-harm, threat, explicit content, NSFW content, and phishing.

Within each pair, the target phrase and account/conversation metadata are
fixed. The risky member uses the phrase as an active intent or request. The
safe member places the exact phrase inside a closed quotation and follows it
with an explicit report, refusal, educational, or supportive stance. This
tests whether the rules fallback distinguishes semantic context from keyword
presence.

The corpus was generated and hashed before the probe was executed:

- manifest SHA-256:
  `04079ced58585cb0154306dcd4dd0975f9caa43a39c1c15cf4b1dea91e6b5210`;
- cases SHA-256:
  `d4af8f1bfb20763c3dcfc938b4496d73ce08c324c43cba02d1ce22ce3cc14d8c`;
- gold SHA-256:
  `0d6abd2329be1136a60c0126523916138a5187456a30cbd2f4ced728f2021b5b`;
- release probe SHA-256:
  `669d9653bbc6564181ebf4dc652d91cb0cf59fa081adb56bd036da9912fd6260`;
- result SHA-256:
  `8dbeedaed3c098c9df21c933d47537c8343116eaf0788080d7708a2f6036c2fc`.

The result contains aggregate metrics and failed case IDs only; it contains no
message plaintext. V1 must not be edited after observing these results. Any
fixture change requires a new dataset version.

## Overall result

The release build executed with the `rules_fallback` backend.

| Metric | Result | Prespecified target | Outcome |
| --- | ---: | ---: | --- |
| expected-family recall | 38/240 = 15.8% | at least 90% | fail |
| safe specificity | 206/240 = 85.8% | at least 95% | fail |
| family accuracy among detected positives | 37/38 = 97.4% | at least 85% | pass |
| complete pair accuracy | 5/240 = 2.1% | at least 90% | fail |
| risky cases left at `Allow` | 194 | 0 | fail |
| safe cases escalated to `Block` | 6 | 0 | fail |

The high 37/38 family accuracy is conditional on only 38 detected risky
cases. It must not be presented as broad classifier accuracy. The dominant
failure is missing semantically valid formulations, not confusion between
families after detection.

## Language slices

| Language | Expected-family recall | Safe specificity |
| --- | ---: | ---: |
| English | 16/80 = 20.0% | 69/80 = 86.3% |
| Ukrainian | 10/80 = 12.5% | 70/80 = 87.5% |
| Russian | 12/80 = 15.0% | 67/80 = 83.8% |

All three languages fail recall by a wide margin. This is not only a
Ukrainian/Russian parity problem: the English rules are also strongly
phrase-bound.

## Threat-family slices

| Family | Expected-family recall | Safe specificity |
| --- | ---: | ---: |
| grooming | 7/30 = 23.3% | 24/30 = 80.0% |
| manipulation | 5/30 = 16.7% | 24/30 = 80.0% |
| bullying | 5/30 = 16.7% | 26/30 = 86.7% |
| self-harm | 3/30 = 10.0% | 28/30 = 93.3% |
| threat | 11/30 = 36.7% | 20/30 = 66.7% |
| explicit | 5/30 = 16.7% | 25/30 = 83.3% |
| NSFW | 1/30 = 3.3% | 29/30 = 96.7% |
| phishing | 1/30 = 3.3% | 30/30 = 100.0% |

Threat has the best recall but the worst quote/counter-speech specificity.
NSFW and phishing have almost no recall on the authored formulations. Six of
the 34 safe alerts reached `Block`, so the context error is product-relevant,
not merely a harmless score fluctuation.

## Failure interpretation

The result supports four bounded engineering conclusions:

1. Expanding a small phrase list will not be sufficient. The fallback needs a
   compositional signal layer that recognizes intent, target, secrecy,
   coercion, urgency, credential requests, and first-person crisis semantics.
2. Quote handling must remain fail-closed for incomplete quotations, but a
   closed quotation plus explicit outside-text counter-stance is not being
   suppressed consistently across families.
3. Family routing is mostly coherent after a signal fires; lowering global
   thresholds would primarily increase false positives and is not the correct
   first intervention.
4. English, Ukrainian, and Russian need a shared semantic contract with
   language-specific realization and morphology, rather than three unrelated
   bags of phrases.

For self-harm and other safety-critical families, the product-policy owner
must explicitly decide whether a quoted report should remain visible as a
support signal even when it is not an active-risk assertion. That policy
question should be represented separately from classifier correctness rather
than hidden by threshold tuning.

## Performance observation

Across 960 analyzed turns on this Mac release run, detector-reported latency
was 786,097 microseconds median, 993,892 microseconds p95, and 2,186,213
microseconds maximum. The bulk harness also creates a fresh `Analyzer` for
each independent conversation, so total wall-clock additionally includes 480
initializations. These figures are diagnostic host measurements, not iPhone
performance evidence, but they are high enough to require a dedicated
profile before product enforcement.

## Next engineering gate

The frozen v1 corpus becomes a regression input, not a tuning target. The next
implementation should first add reusable structured semantic primitives and
profile their cost, then rerun this exact corpus without changing its hashes.
A separate v2 challenge may add code-switching, morphology, slang, and
obfuscation only after v1 behavior is understood. The internal blinded
480-conversation workflow remains a separate confirmatory gate and must still
be authored and reviewed without detector access.

## Reproduction

```bash
python3 -m unittest training.test_developer_challenge training.test_internal_holdout
python3 training/developer_challenge.py build \
  --protocol experiments/client-detector-developer-challenge-v1/protocol.json \
  --scenario-bank experiments/client-detector-developer-challenge-v1/scenario-bank.json \
  --output-dir artifacts/developer-challenge-v1
cargo build --release -p aura-core --example client_detector_conversation_probe
python3 training/developer_challenge.py evaluate \
  --manifest artifacts/developer-challenge-v1/manifest.json \
  --protocol experiments/client-detector-developer-challenge-v1/protocol.json \
  --scenario-bank experiments/client-detector-developer-challenge-v1/scenario-bank.json \
  --cases artifacts/developer-challenge-v1/cases.jsonl \
  --gold artifacts/developer-challenge-v1/gold.jsonl \
  --probe target/release/examples/client_detector_conversation_probe \
  --output artifacts/developer-challenge-v1/result.json
```
