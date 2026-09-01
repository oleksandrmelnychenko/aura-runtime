# Multilingual detector architecture v1

Status: phase 1, the bounded phase 2 wire contract, and its release-safe Swift
producer are implemented locally on 2026-08-31. This document does not claim
that any language beyond the governed release set is production-supported.

## Goal

Extend client-side safety detection across languages and mixed-language
messages without multiplying unreviewed phrase lists, trusting a single
caller-supplied language label, or weakening the existing fail-closed release
contracts.

Threat taxonomy, context semantics, product policy, and language realization
are separate concerns:

1. the shared taxonomy defines what is being detected;
2. language/script evidence selects eligible detector packs;
3. lexical and model layers produce bounded signals;
4. structured context determines speaker, target, quote, stance, negation,
   report, and support intent;
5. product policy maps confirmed signals to actions.

No language pack may own product thresholds or bypass structured context.

## Phase 1 implementation

### Typed content-minimizing evidence

`aura-domain::LanguageEvidence` contains only:

- validated lowercase BCP-47-style candidates;
- evidence source (`message_hint`, `on_device_classifier`, or
  `runtime_default`);
- bounded confidence;
- Unicode script counts;
- validated, non-overlapping UTF-8 language-span offsets;
- a count of malformed hints discarded at the boundary.

It never retains message plaintext. Invalid legacy hints do not disable
analysis. Serialization remains output-only; the protobuf FFI boundary is the
only typed deserializer and enforces the version and collection invariants.

### Bounded protobuf and FFI contract

`MessageInput.language_evidence` carries `LanguageEvidenceV1` while the legacy
`MessageInput.language` field remains supported. The boundary enforces:

- `schema_version == 1`;
- at most 4 message-level candidates and 32 spans;
- canonical lowercase language tags;
- finite confidence in `0..=1`;
- one client-declared candidate with confidence exactly 1;
- recognized source/script enums;
- sorted, non-overlapping UTF-8 scalar boundaries inside analyzed text;
- declared script presence in each span;
- a matching on-device-classifier candidate for every span;
- consistency between the legacy language and a typed client declaration.

Script evidence is recomputed from local plaintext during analysis, so supplied
metadata cannot hide an observed script. The validated evidence is propagated
through core pattern routing and the Kids domain input. Language candidates are
strictly additive: neither a client declaration nor a classifier candidate may
disable the governed `en`, `uk`, or `ru` release packs. Rule IDs remain
deduplicated after bounded multi-route scanning.

### Mixed-script pattern routing

The pattern layer now derives routes from the per-message hint, runtime default,
and observed scripts. A hint can prioritize its own route but cannot suppress
the governed release routes. A second script can add conservative supported
routes:

- Latin -> `en`;
- Cyrillic -> `uk`, `ru`;
- Greek -> `el`;
- Arabic -> `ar`;
- Hebrew -> `he`;
- Devanagari -> `hi`;
- Han -> `zh`;
- hiragana/katakana -> `ja`;
- hangul -> `ko`.

These are routing candidates, not claims that script uniquely identifies a
language. For example, a pure Cyrillic message hinted as Ukrainian still keeps
the governed Russian pack active because attacker-controlled content or a stale
client hint must not narrow safety coverage. A Latin plus Cyrillic message
hinted as English also activates supported Ukrainian and Russian routes. Rule
IDs are deduplicated after multi-route scanning.

When the message hint is absent, the previous `en`/`uk`/`ru` fallback coverage
is preserved. An unsupported but valid hint still receives universal rules
without silently being treated as English.

### Lexicon schema v2 contract

`LexicalRuleRecord` now supports optional canonical `languages` and `scripts`.
The closed v1 validator rejects either field. The v2 validator requires:

- valid BCP-47-style language tags;
- sorted, unique language tags;
- sorted, unique script identifiers;
- all existing metadata, matcher, score, action, and identity invariants.

Empty scope remains universal. If both language and script scopes exist, both
must match. Scoped rules without evidence do not run. Existing embedded Kids
and Military v1 packs remain byte-identical and retain their pinned digests.

## Evidence after phase 1

The frozen semantic experiment produced exactly the same results before and
after the architecture change:

- expected-family recall: 20/24 (83.3%);
- safe false-positive rate: 14/24 (58.3%);
- pair accuracy: 8/24 (33.3%);
- metamorphic variant detection: 55/64 (85.9%).

This is expected: no rule, model, threshold, or product policy changed. The
result is compatibility evidence only; the previously diagnosed semantic
context failures remain open.

## Conservative Swift producer

`AuraLanguageEvidenceProducer` now enriches typed local-decision requests before
protobuf serialization when the host has not already supplied evidence. The
release path deliberately accepts only explicit client declarations. It:

- keeps the legacy client declaration first with confidence exactly `1`;
- never infers a production routing candidate from message text;
- returns no evidence for a missing or malformed declaration rather than
  falling back to an uncalibrated classifier;
- preserves caller-supplied typed evidence exactly rather than merging or
  recomputing it inside the runtime;
- emits no spans. Same-script span segmentation remains an independent
  experiment and release gate.

The producer cannot change detector thresholds, actions, or product policy.
Older native protobuf consumers ignore the additive field, while release use of
the new evidence still requires rebuilding and governing the native artifact.

### Span experiment decision

A frozen 24-sample, 308-token Apple NaturalLanguage experiment compared token,
sentence, sliding-window, and conservative core-span strategies across governed
English/Ukrainian/Russian data and Belarusian/Bulgarian/Kazakh/Serbian confusion
controls. Full-coverage variants produced unacceptable false supported-language
emissions. The strict two-token-margin prototype reached 100% emitted precision
and zero unsupported-to-supported emissions on this small corpus, but retained
only 50.65% of tokens and detected 63.64% of supported switch samples.

This is a no-go for production spans. `LanguageEvidenceV1.spans` remains empty;
the detailed diagnostic evidence is in
`docs/client-language-span-experiment-v1-results.md`.

### Governed shadow language-ID ensemble

A separately pinned, test-target-only shadow bundle combines a Create ML text classifier, a
deterministic hashed character n-gram veto, Apple language agreement, and a
governed Cyrillic alphabet boundary. The loader validates the exact manifest,
artifact inventory, SHA-256 values, binary layout, and model outputs before any
shadow inference. `NLModel` access is actor-serialized and no plaintext is
retained. Neither the loader nor its 1.3 MB resource bundle is compiled or
copied into the production `AuraAgent` target.

The ensemble rejected every Belarusian, Bulgarian, Kazakh, and Serbian control
in the frozen iOS 26.2 span experiment, but emitted only 33.77% of tokens and
had 0% exact boundary recall. The development corpus is also not independently
adjudicated. The component therefore remains internal and shadow-only; it is not
wired into `AuraLanguageEvidenceProducer`. Full results are in
`docs/client-language-id-shadow-v1-results.md`.

An expanded 51-sample v2 experiment corrected the boundary denominator and
added harder Cyrillic and Latin open-set controls. Confirmed directional
change-points plus deterministic Latin/Cyrillic alignment recovered 11 of 24
governed boundaries at 100% emitted precision and zero unsupported emissions,
but governed coverage was only 15.38%. Higher-coverage variants activated
unsupported controls and were rejected. Production spans therefore remain
disabled; see `docs/client-language-boundary-experiment-v2-results.md`.

## Required language onboarding matrix

Every new language must have independently reviewable support for each cell:

`language x threat family x risky/safe polarity x context role x obfuscation x code-switch pair`

Minimum reported metrics are:

- expected-family recall and wrong-family rate;
- all-family false-positive rate and specificity;
- risky/safe counterfactual pair accuracy;
- safe block errors and risky allow errors;
- robustness by transform;
- warm latency, initialization latency, memory, and artifact size;
- worst-language and worst-context slices, not only micro averages.

Developer-visible examples can diagnose defects but cannot approve a release.
Production support requires an independently reviewed held-out conversational
set, native-speaker adversarial review, governed artifact identity, and an
on-device shadow pilot.

## Next phases

1. Replace the shadow model's development data with an independently evaluated,
   native-speaker-adjudicated language-ID corpus and improve boundary recall
   without allowing unsupported-language activation.
2. Add structured multilingual context semantics before expanding phrase
   coverage, so quotes, reports, refusals, and support do not inherit the risk
   of the words they discuss.
3. Migrate one existing pack to schema v2 through the canonical digest and
   manifest compiler, then repeat all frozen experiments.
4. Add governed multilingual ONNX identity and per-language calibration. Model
   outputs and lexical rules remain independent evidence layers.
5. Add new languages only through the onboarding matrix and release gates.

Translation-before-detection is not an authoritative path. It can alter stance
or negation, creates privacy and latency costs, and gives attackers a second
evasion surface. It may be evaluated in shadow mode as auxiliary evidence.
