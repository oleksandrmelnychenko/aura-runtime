# Client compositional intent/context v1 results

Status: developer regression passed; release validation remains blocked.

Date: 2026-09-01.

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
latency and proves conversation-state reset between independent cases. It does
not establish the required no-more-than-5% semantic regression because a full
cached pre-composition baseline was not captured before integration. Exact
release builds on supported iPhones remain mandatory.

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
3. Capture a comparable pre/post semantic performance baseline and profile the
   exact release artifact on every supported iPhone class.
4. Rust full-workspace tests and warning-free Clippy are green. Run the
   Swift/XCFramework, device, artifact-pin, and human safety signoff gates.
5. Treat external independent validation as separate evidence; never relabel
   this developer-authored pass as certification.
