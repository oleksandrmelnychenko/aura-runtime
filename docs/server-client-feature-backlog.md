# Server, Client, and Feature Backlog

Status: active planning document, initialized May 15, 2026.

This file is the working backlog for turning `ecliptix-aura` from a strong
component into an integrated messenger safety system. It is intentionally
pragmatic: every item should either improve real child safety, make integration
safer, or reduce production risk.

## Current Baseline

Recent component state:

- Relationship metadata is present in protobuf/contract, native input, FFI,
  relay risk, local analyzer, and world simulation.
- Local analyzer uses relationship metadata conservatively: it can boost
  relevant existing signals but does not create a threat from relationship
  metadata alone.
- `world_sim` has quality metrics and CI-style gates for labeled recall and
  clean false-positive rate.
- Dense two-year lifecycle fixture exists:
  `crates/aura-core/data/world_lifecycle_suite/sofia_13_to_15_dense_2y.json`.

Latest known dense lifecycle gate:

- actors: 56
- conversations: 25
- total events: 6,839
- labeled events: 6,833
- positives: 25
- clean labeled background: 6,808
- false negatives: 0
- clean false positives: 0
- recall: 100%
- precision: 100%
- clean false-positive rate: 0%

## Operating Principles

- The server must not require plaintext message content for normal protected
  messenger operation.
- The client remains the authoritative place for message-content analysis and
  immediate UI policy.
- Server-side intelligence should use privacy-preserving metadata, reputation,
  attestation, aggregate risk, and optional explicit shadow/eval payloads.
- Relationship metadata is context, not guilt. It may raise concern only when
  combined with content, behavior, or reputation evidence.
- Every major feature needs a realistic scenario, a negative-control scenario,
  and an integration gate before it is treated as production-ready.

## P0 Integration Gates

- [ ] Add a CI command for the dense two-year world gate:
  `cargo run -p aura-core --example world_sim -- --input crates/aura-core/data/world_lifecycle_suite/sofia_13_to_15_dense_2y.json --summary-only --require-clean --min-labeled-recall 0.95 --max-clean-fp-rate 0.01`.
- [ ] Add FFI replay coverage for the six-month and two-year world fixtures,
  not only direct `aura-core` execution.
- [ ] Add client-boundary replay that imports/exports conversation state during
  long world simulations to verify persistence across app restarts.
- [ ] Add performance gates for 10k, 50k, and 100k message runs:
  runtime, memory growth, and context-store bounds.
- [ ] Add a release report section that records world-simulation metrics by
  relationship, surface, language, and expected threat.

## Server Backlog

### Privacy-Preserving Relay

- [ ] Define the production relay contract for encrypted messenger integration:
  what the client sends, what the server may infer, and what never leaves the
  device.
- [ ] Implement server-side sender reputation using protected tokens, not raw
  sender identifiers.
- [ ] Track cross-conversation repeated-risk metadata without plaintext message
  content.
- [ ] Add server-side relationship evidence sources:
  guardian-verified, school directory, platform verified, address book,
  local heuristic, self-declared, server reputation.
- [ ] Add trust-source freshness and revocation semantics.
- [ ] Add server risk hints that map cleanly into local
  `server_sender_risk_hint` and relationship metadata.

### Server AI Models

- [ ] Define what server AI is allowed to see in protected messenger mode:
  metadata-only by default; plaintext only in explicit opt-in eval/shadow
  environments.
- [ ] Build a server-side risk model for sender/account reputation using:
  repeated reports, cross-conversation spread, age/relationship claims,
  account churn, link reputation, and abuse velocity.
- [ ] Add model output contracts that are explainable and bounded:
  risk score, confidence, reason codes, uncertainty, freshness.
- [ ] Add calibration gates for server AI hints so they cannot silently turn
  into hard enforcement.
- [ ] Add model rollback and kill-switch behavior for server risk hints.

### Server Operations

- [ ] Add observability dashboards for aggregate risk and gate health without
  storing plaintext messages.
- [ ] Add abuse-resistant rate limits for reputation poisoning attempts.
- [ ] Add incident runbooks for false positives, missed grooming, bad server
  hints, relay outages, and model rollback.
- [ ] Add privacy audit evidence for every new server telemetry field.
- [ ] Add staged rollout controls by account age band, locale, and platform.

## Client Backlog

### FFI and Runtime Integration

- [ ] Build mobile/desktop sample integrations for the protobuf-only FFI.
- [ ] Add long-run FFI soak tests using realistic world fixtures.
- [ ] Verify state export/import across app restart, device migration, and
  multi-device sync boundaries.
- [ ] Add strict request-size, malformed protobuf, and out-of-order event tests
  for client integration.
- [ ] Add a stable client capability payload so relay and runtime can reason
  about supported features without guessing.

### On-Device State

- [ ] Define encrypted local storage requirements for conversation state,
  contact memory, and kids memory.
- [ ] Add retention and TTL tests for two-year lifecycles.
- [ ] Add state compaction tests for high-volume group chats and public
  comment surfaces.
- [ ] Add local-only relationship derivation from address book, guardian
  settings, school directory imports, and local heuristics.
- [ ] Add guardian override and revocation flows for trusted adults.

### Product UI

- [ ] Implement product surfaces for:
  warn before display, blur until tap, confirm before link open, suggest block,
  suggest report, restrict unknown contact, guardian escalation.
- [ ] Add child-facing copy variants that are calm, non-accusatory, and
  age-appropriate.
- [ ] Add guardian-facing explanations that summarize risk without exposing
  unnecessary private content.
- [ ] Add safe adult false-positive review flows.
- [ ] Add flows for repeated unknown adult contact across multiple accounts.
- [ ] Add crisis/self-harm UI flow with local resources and guardian escalation.

## Feature Backlog

### Safety Features

- [ ] Unknown adult and fake-teen contact hardening:
  relationship metadata, account age, conversation velocity, secrecy, gifts,
  platform move requests.
- [ ] Cross-account repeat offender detection:
  same sender risk across new conversation IDs and backup accounts.
- [ ] Public comment surface detection:
  contact move requests, age-gap comments, grooming in public-to-DM funnels.
- [ ] Link safety:
  phishing, scam, fake giveaways, credential requests, payment/card requests.
- [ ] PII and doxxing:
  phone, address, school, location, family details, coordinated reposting.
- [ ] Propaganda and coordinated influence:
  repeated narratives, bot-like timing, multi-sender reinforcement.
- [ ] Bullying and pile-on behavior:
  group dynamics, role reversal, defenders, recovery after intervention.
- [ ] Self-harm spillover:
  bullying-to-crisis trajectories and protective support context.

### Scenario and Evaluation Features

- [ ] Add more two-year lifecycle fixtures:
  clean-only negative control, rural/urban school, multilingual family,
  gaming-heavy child, public creator teen, high-risk unknown adult network.
- [ ] Add adversarial perturbations inside long worlds:
  emoji padding, leetspeak, zero-width spaces, typo drop/swap, punctuation
  stripping, mixed alphabets.
- [ ] Add attachment-like metadata scenarios:
  images, voice-message references, file names, link previews, media captions.
- [ ] Add multi-child worlds to test group-level dynamics without confusing
  one protected account's state with another.
- [ ] Add scenario dashboards that show metrics by age band, surface,
  relationship, threat, language, and time horizon.

### AI and Model Features

- [ ] Define local model bundle targets:
  size, latency, memory, quantization, supported platforms, fallback behavior.
- [ ] Add optional ONNX model gates for environments that provide model assets.
- [ ] Add model confidence calibration against realistic and adversarial
  scenario suites.
- [ ] Add uncertainty behavior tests:
  downgrade, guardian warn, no hard block on unsupported evidence.
- [ ] Add server model evals using metadata-only features and explicit
  privacy-preserving labels.

## Performance Backlog

- [ ] Optimize volume runners so analyzer construction is not repeated per
  case where reusable state is safe.
- [ ] Add reusable pattern database and analyzer pools for eval-only runners.
- [ ] Add Rayon or worker-pool parallelism for independent scenario packs.
- [ ] Add memory guards for kids memory and conversation tracker growth.
- [ ] Add benchmark reports for:
  single message latency, batch throughput, 10k world, 100k world, FFI replay.

## Documentation Backlog

- [ ] Update product integration contract with relationship metadata examples.
- [ ] Document the server/client privacy boundary for protected messenger mode.
- [ ] Add client implementation guide for iOS, Android, desktop, and server
  relay integration.
- [ ] Add threat-model document for relay reputation poisoning and metadata
  abuse.
- [ ] Add release checklist for long-world simulation promotion.

## Done Criteria For New Items

An item should not be marked done unless it has:

- implementation or explicit design artifact,
- targeted tests,
- at least one realistic positive scenario,
- at least one negative-control scenario,
- CI or manual verification command,
- privacy review if it touches telemetry, server relay, identifiers, or logs,
- product contract update if it changes client-visible behavior.
