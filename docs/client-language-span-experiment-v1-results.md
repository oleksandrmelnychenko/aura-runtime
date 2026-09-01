# Client language-span experiment v1 results

Status: developer experiment completed on 2026-08-31. Production span emission
remains disabled.

## Question

Can Apple NaturalLanguage safely produce same-script language spans for the
bounded `LanguageEvidenceV1` contract without allowing unsupported Cyrillic
languages to activate governed Ukrainian or Russian detector packs?

## Frozen setup

- iPhone 17 Pro simulator, iOS 26.2, Xcode 26.2;
- 24 neutral samples and 308 evaluated word tokens;
- governed languages: English, Ukrainian, and Russian;
- unsupported controls: Belarusian, Bulgarian, Kazakh, and Serbian;
- monolingual, sentence-switch, inline-switch, short-switch, quoted, and
  loanword cases;
- fixture:
  `swift/Tests/AuraAgentTests/Fixtures/language_span_experiment_v1.json`;
- evaluator: `AuraLanguageSpanExperimentTests`.

This is a small developer corpus. It is diagnostic evidence, not an independent
held-out evaluation or native-speaker release approval.

## Results

| Variant | Coverage | Emitted precision | Supported switch sample recall | Exact boundary recall | Unsupported -> supported emission |
|---|---:|---:|---:|---:|---:|
| Token `NLTagger(.language)` | 100.00% | 69.48% | 36.36% | 28.57% | 77.78% |
| Sentence recognizer | 100.00% | 72.73% | 36.36% | 28.57% | 29.17% |
| Five-word windows | 100.00% | 79.22% | 100.00% | 50.00% | 30.56% |
| Per-sentence five-word windows | 100.00% | 80.52% | 100.00% | 64.29% | 29.17% |
| Conservative run >= 3 | 75.00% | 93.51% | 81.82% | 57.14% | 13.89% |
| Whole-message gated conservative | 70.45% | 95.39% | 81.82% | 57.14% | 6.94% |
| Strict unsupported-window rejection | 62.01% | 97.38% | 72.73% | 50.00% | 0.00% |
| Strict core, one-token boundary margin | 56.17% | 99.42% | 72.73% | 21.43% | 0.00% |
| Strict core, two-token boundary margin | 50.65% | 100.00% | 63.64% | 21.43% | 0.00% |

The exact machine-readable output is stored in
`experiments/client-language-span-v1/results-ios-26.2.json`.

## What the experiment established

`NLTagger(.language)` is not a span detector in these samples. It commonly
assigned the message-dominant language to every token. Sentence classification
separated long Ukrainian/Russian sentences but could not resolve inline
switches.

Five-word windows recovered every supported switch sample, but their confidence
was not calibrated: wrong Belarusian, Serbian, Bulgarian, or Kazakh assignments
often carried scores near `1.0`. A confidence threshold alone therefore cannot
make the path safe.

Rejecting an entire message when any strong window leaves the governed language
set removed unsupported-to-supported emissions in this corpus. Removing two
tokens from each internal run boundary then reached 100% emitted precision, but
coverage fell to 50.65% and supported switch sample recall to 63.64%. Exact
boundary recall is intentionally low because core spans abstain near uncertain
boundaries.

## Decision

Do not populate `LanguageEvidenceV1.spans` from Apple NaturalLanguage yet.
Message-level candidates and locally recomputed Unicode script evidence remain
the active path.

Before production spans, require:

1. a substantially larger held-out conversational corpus with native-speaker
   adjudication and unsupported-language confusion controls;
2. iOS 18 and iOS 26 device results, including OS-version drift;
3. exact UTF-8 span-construction and replay determinism tests;
4. warm/init latency, memory, and energy measurements on physical devices;
5. a governed custom on-device language-ID model or another independently
   calibrated abstaining classifier if Apple-only coverage remains inadequate.
