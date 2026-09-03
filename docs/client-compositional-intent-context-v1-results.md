# Client compositional intent/context results

Status: client-runtime engineering gates passed; independent release validation remains blocked.

Date: 2026-09-03.

## Final client-runtime hardening evidence

This phase is limited to the offline client runtime. It does not add a network
transport, HTTP client, server integration, Apple artifact, or application UI.

- detector outputs now carry typed lexical, compositional, or derived origin;
- attribution and protective-context suppression use the source threat family,
  including shared event kinds such as explicit and NSFW sexual content;
- compositional predicates are represented by a typed, allocation-free rule
  matrix with explicit route priority and score overrides;
- the rule matrix is differential-tested against the prior formulas for the
  empty set, all singletons, all pairs, all triples, and 200,000 deterministic
  sparse masks;
- the governed code-switch suite contains eight safe/risky counterfactual
  pairs covering all eight client families, four EN/UK/RU language directions,
  lexical and compositional origins, and report, refusal, and crisis-support
  contexts; each pair is also exercised with straight and curly quotes;
- dataset evidence passes for realistic, external-curated, 240-case benign,
  and code-switch corpora, with changelog, provenance, privacy, and exact hash
  validation;
- the all-features Cargo graph has no HTTP/TLS client dependency and the source
  has no socket transport; ONNX Runtime uses the local dynamic-loader feature
  without its build-time downloader;
- no new `unsafe` block, protobuf wire change, C ABI change, or persisted-state
  format change was introduced.

The full offline workspace test command passed across all targets and features.
Strict Clippy passed with warnings denied, and all 445 CI Python tests passed.
Both FFI world fixtures and both periodic export/import client-boundary fixtures
passed for the six-month and dense two-year scenarios.

The refactor differential gate passed with 326 reviewed changes: 314 approved
safety improvements, 12 structural-only changes, zero regressions, and zero
invalid approvals. Its lifecycle suite processed 20,347 events with 100% recall,
100% precision, zero clean false positives, and no findings.

Release performance was measured from the exact configured Cargo target:

| Tier | Events | Elapsed | Peak RSS | Recall | Clean FP rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| 10k | 13,647 | 31.98 s | 386.8 MiB | 100% | 0% |
| 50k | 54,495 | 133.39 s | 899.4 MiB | 100% | 0% |
| 100k | 102,151 | 246.83 s | 1519.5 MiB | 100% | 0% |

These are local engineering measurements, not physical-device certification.

## Evidence boundary

This result is a post-diagnostic rerun on the unchanged, developer-authored
challenge. The detector team had already seen the corpus and used its first run
to design the compositional architecture. The result is therefore engineering
regression evidence only. It does not close `REL-011`, the internal blinded
holdout, independent native-speaker review, physical-device performance, or
human safety approval.

The original first-run result remains unchanged. No protocol, scenario, case,
gold, or manifest file was regenerated or edited for this rerun.

## Frozen identity

- dataset: `aura_client_detector_developer_challenge_v1`;
- conversations: 480, arranged as 240 risky/safe pairs;
- languages: English, Ukrainian, Russian;
- families: grooming, manipulation, bullying, self-harm, threat, explicit,
  NSFW, phishing;
- frozen manifest SHA-256:
  `04079ced58585cb0154306dcd4dd0975f9caa43a39c1c15cf4b1dea91e6b5210`;
- release probe SHA-256:
  `4607150049946a976d989ff017d1fe99e5583b468d6856b63596ecec1cef07cd`;
- content-free result SHA-256:
  `9aa230f49d6d6e75d31fe6a92b58ec4f4b8198e486eb982b202bb265ff16e7fb`.

## Result

The unchanged diagnostic contract returned `diagnostic_pass`:

| Metric | Result | Prespecified gate |
| --- | ---: | ---: |
| Expected-family recall | 240/240 = 100% | at least 90% |
| Safe specificity | 240/240 = 100% | at least 95% |
| Pair accuracy | 240/240 = 100% | at least 90% |
| Detected primary-family accuracy | 228/240 = 95.00% | at least 85% |
| Risky `Allow` errors | 0 | 0 |
| Safe `Block` errors | 0 | 0 |
| Language/family slice failures | 0 | 0 |

Twelve risky messages remained multi-label primary-family confusions while
still carrying the expected family above its preregistered threshold. They are
not missed-risk or unsafe-action errors, but they remain useful taxonomy
hardening work for later independent corpora.

## Content-free performance attribution

- Analyzer initialization: 6 cache misses, median 927,339 us, maximum
  965,437 us;
- runtime reset: 480 resets, median 23 us, p95 41 us, maximum 1,588 us;
- detector-reported turn latency: 960 turns, median 1,832 us, p95 7,241 us;
- probe-reported conversation wall time: 480 conversations, median 5,218 us,
  p95 10,973 us;
- evaluator-observed full probe wall time: 17,940,519 us;
- runtime backend: `rules_fallback`.

The new attribution removes Analyzer initialization from steady-state turn
latency and proves conversation-state reset between independent cases. The
refactor gate now provides a frozen 10k comparative envelope for the current
runtime, while exact release builds on supported iPhones remain mandatory.

## Implemented mechanism

- bounded UTF-8 semantic spans, tokens, clauses, quote structures and raw
  EN/UK/RU actor/modal/negation cues;
- ambiguous or unclosed quote state that cannot enable safe suppression;
- multi-family domain compositions with typed event routes;
- structured closed-quote plus independent report/refusal/education/support
  confirmation in `ContextInterpreter`;
- bounded chat-shorthand support recognition that preserves active-author
  self-harm fail-closed behavior;
- phishing request routing that cannot contaminate grooming or propaganda
  memory, and direct coercive-manipulation precedence over non-self-harm
  memory relabeling;
- canonical persisted severity metrics for deterministic multi-runtime
  export/import handoff;
- fail-closed semantic-capacity handling;
- Analyzer reuse by immutable profile with explicit runtime reset;
- no `unsafe`, protobuf, C ABI, or persisted-state format change.

## Remaining release gates

1. Run the separately authored internal blinded holdout without further tuning.
2. Complete double native-speaker review and adjudication.
3. Profile the exact release artifact on every supported iPhone class; local
   10k/50k/100k measurements do not replace device evidence.
4. Rust full-workspace tests, warning-free Clippy, offline dependency checks,
   replay gates, and the refactor baseline are green. Run the Swift/XCFramework,
   device, artifact-pin, and human safety signoff gates separately.
5. Treat external independent validation as separate evidence; never relabel
   this developer-authored pass as certification.
