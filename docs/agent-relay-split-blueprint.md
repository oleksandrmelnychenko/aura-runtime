# AURA Agent / Relay Split Blueprint

## Purpose

This document freezes the target architecture for splitting AURA into:

- `AURA Agent`: the on-device runtime shipped inside the mobile client
- `AURA Relay`: the remote intelligence service used for heavy inference and cross-chat intelligence

The goal is not to create a thin client.

The goal is:

- keep instant, offline-safe protection on device
- move heavy ML and global intelligence off device
- preserve one canonical semantics pipeline across client and server

## Why This Split Is Needed

Measured locally on `2026-04-06`:

- `aura_ffi.dll` release, fallback-only: `3.65 MiB`
- `aura_ffi.dll` release, `onnx` feature enabled: `3.94 MiB`

The Rust runtime itself is small enough for mobile.

The problem is model payload:

- current production `safety + intent` model set: `1097.93 MiB`
- current production bundle with FFI + ONNX model set: `1101.87 MiB`
- current `unified.onnx` set: `125.19 MiB`
- `unified.onnx` bundle with FFI: `129.13 MiB`

This means the current on-device ML packaging is the blocker, not the core Rust library.

## Design Goal

The canonical runtime shape should become:

`Agent local observations -> Agent local context -> local decision or Relay escalation -> Relay remote findings -> Agent final policy surface`

The final user-facing decision should still be assembled inside `Agent`.

`Relay` improves precision, disambiguation, and global intelligence.

`Agent` remains responsible for minimum safe behavior when:

- the network is unavailable
- the relay is slow
- the relay is degraded
- privacy rules prohibit sending the message upstream

## Hard Boundary

### Agent must own

- text normalization
- pattern/rule detectors
- URL/phishing heuristics
- local conversation context
- local behavior tracker
- immediate safety actions
- offline fallback behavior
- privacy gating before remote calls

### Relay must own

- heavy ML inference
- ambiguity resolution
- cross-conversation correlation
- sender/network intelligence
- remote calibration and model rollout
- multi-tenant review/risk enrichment

### Relay must not own

- the only copy of minimum safety logic
- direct user-facing UI policy
- mandatory dependency for obvious high-risk local actions

## Canonical Semantics Contract

The semantic pipeline from [`context-architecture-blueprint.md`](./context-architecture-blueprint.md) still applies.

`RawObservation -> ThreatContextFrame -> ConfirmedEvent -> Memory -> Inference -> Policy -> Product Surface`

The split changes where parts execute, not what they mean.

Rules:

1. `Agent` may produce local `RawObservation`, local `ThreatContextFrame`, and local `ConfirmedEvent`.
2. `Relay` may add remote observations and remote context signals, but it must use the same typed contracts.
3. `Policy` remains client-authoritative.
4. `Relay` returns typed findings, not UI commands.

## Target Crate Map

This is the target end-state, not the first migration step.

### Shared crates

- `aura-contracts`
  - canonical typed entities shared by Agent and Relay
  - `RawObservation`
  - `ThreatContextFrame`
  - `ConfirmedEvent`
  - `InferenceSummary`
  - `ActionRecommendation` inputs
  - remote request/response DTOs

- `aura-domain`
  - domain plugin contracts
  - domain-neutral interfaces only
  - no server-only or client-only side effects

- `aura-patterns`
  - normalization
  - pattern DB
  - URL/domain heuristics
  - safe to compile for Agent and Relay

- `aura-policy-data`
  - policy tables
  - calibration manifests
  - allowlists/threshold bundles
  - declarative config shared by both sides when needed

- `aura-wire-device`
  - protobuf/device wire contracts for app <-> FFI
  - current `aura-proto` can evolve into this

- `aura-wire-relay`
  - request/response schema for Agent <-> Relay
  - versioning, capability negotiation, TTLs

### Agent-side crates

- `aura-agent-core`
  - on-device orchestration
  - pattern + local context + local memory + local inference
  - remote escalation decision
  - remote finding fusion
  - final policy assembly inputs

- `aura-agent-policy`
  - final action logic
  - guardian/review/product surfacing
  - local-first fail-safe rules

- `aura-agent-ffi`
  - mobile FFI surface
  - wraps `aura-agent-core`
  - current `aura-ffi` should converge here

- `aura-agent-net`
  - Relay client
  - retries, timeouts, auth headers
  - request shaping
  - response caching

- `aura-ml-lite`
  - optional lightweight local heuristics only
  - lexicon gate
  - cheap fallback scoring
  - no heavy ONNX payload in production mobile profile

### Relay-side crates

- `aura-relay-api`
  - HTTP/gRPC ingress
  - auth
  - rate limiting
  - idempotency
  - request validation

- `aura-relay-core`
  - remote orchestration
  - intake shaping
  - routing
  - shared execution graph

- `aura-relay-ml`
  - ONNX / inference engine
  - model loading
  - batching
  - tokenizer/model bundles
  - calibration-aware inference

- `aura-relay-context`
  - cross-conversation memory
  - sender intelligence
  - network/cohort intelligence
  - coordinated-behavior enrichments

- `aura-relay-risk`
  - remote score fusion
  - stance disambiguation
  - final remote findings

- `aura-relay-store`
  - persistence for remote memory
  - feature store / reputation / cached outputs

## Current Repo -> Target Mapping

### Current `aura-core`

Current `aura-core` mixes:

- local runtime
- context interpretation
- tracker
- inference
- policy
- product
- eval/release logic

Target split:

- local runtime parts -> `aura-agent-core`
- policy/product parts -> `aura-agent-policy`
- shared typed contracts -> `aura-contracts`
- any remote-only intelligence -> `aura-relay-core`, `aura-relay-context`, `aura-relay-risk`

`aura-core` should become a temporary compatibility shell, then disappear.

### Current `aura-ffi`

Target:

- rename or converge into `aura-agent-ffi`

### Current `aura-ml`

Current `aura-ml` contains both:

- cheap fallback/rule-based logic
- heavy ONNX runtime path

Target split:

- cheap fallback path -> `aura-ml-lite`
- heavy ONNX/runtime path -> `aura-relay-ml`

### Current `aura-proto`

Target:

- device-facing wire contracts stay in `aura-wire-device`
- new Agent <-> Relay transport types move to `aura-wire-relay`

### Current `aura-kids` and `aura-military`

Keep as domain packs, but enforce:

- no direct network dependencies
- no global memory assumptions
- no server-only hidden behavior

Any remote-only enrichment should live outside these crates.

## Agent Responsibilities In Detail

`Agent` should be able to act alone for:

- explicit direct threats
- self-harm crisis indicators
- sexual/minor-risk anchors
- phishing/suspicious links
- obvious coercion/blackmail anchors
- obvious slur/abuse anchors

`Agent` should ask `Relay` for help when:

- the case is ambiguous
- the risk is medium/high but not decisive
- global reputation matters
- cross-chat correlation matters
- a heavy model would materially change precision

## Relay Request Contract

The first Relay contract should stay small and typed.

Recommended request shape:

- `schema_version`
- `request_id`
- `message_id`
- `account_type`
- `protection_level`
- `conversation_type`
- `language`
- `text`
- `local_observations`
- `local_context_summary`
- `recent_message_window`
- `server_sender_risk_hint` if already known
- `privacy_mode`
- `client_capabilities`
- `deadline_ms`

Recommended request constraints:

- default serialized payload under `8 KB`
- recent window capped to last `3-5` messages
- hard text window cap for relay-bound context
- no raw local tracker dump

## Relay Response Contract

Recommended response shape:

- `schema_version`
- `request_id`
- `remote_observations`
- `remote_context_summary`
- `remote_inference_summary`
- `reason_codes`
- `context_markers`
- `confidence`
- `expires_at_ms`
- optional `sender_reputation_hint`
- optional `correlation_findings`

Important:

- response returns typed findings
- response must not directly return `Block/Warn/Blur` UI commands as the source of truth
- final product action remains an Agent decision

## Privacy Rules

The split must be privacy-shaped, not only size-shaped.

Rules:

1. Agent decides whether a message may be sent to Relay.
2. Clear local positives may be handled without remote submission.
3. Relay receives only the minimum context window needed for disambiguation.
4. Remote storage of raw content must be explicitly bounded by TTL and policy.
5. Review/debug surfaces must never require full raw chat history by default.

## Latency and Availability Budgets

Recommended initial budgets:

- Agent local explicit-anchor path: `p50 < 15 ms`, `p95 < 40 ms`
- Relay round-trip target: `p50 < 150 ms`, `p95 < 400 ms`
- Agent fail-open is forbidden for clear-risk classes
- Relay timeout must degrade to local-safe behavior, not to silent allow

## Production Build Profiles

The mobile production profile should become:

- `default`: no heavy ONNX models on device
- local patterns/context/tracker/policy enabled
- remote escalation enabled

Optional non-production profiles:

- `agent-onnx-lab`
- `agent-unified-benchmark`
- `offline-high-privacy`

This keeps one codebase but separates product deployment modes cleanly.

## Migration Order

The migration should not begin with a full repo rewrite.

### Phase 0. Freeze contracts and budgets

- freeze `Agent` vs `Relay` responsibility boundaries
- freeze latency, privacy, and payload budgets
- freeze which threat families are local-first vs remote-assisted

Output:

- this blueprint
- a typed relay request/response draft

### Phase 1. Extract shared contracts

- create `aura-contracts`
- move canonical typed entities out of `aura-core`
- create `aura-wire-relay`
- keep `aura-proto` device-facing only

Success criteria:

- `aura-core` stops being the owner of shared public contracts

### Phase 2. Create `aura-agent-core`

- extract local runtime orchestration from `aura-core`
- keep pattern layer, interpreter, tracker, local inference, and local policy inputs on device
- make remote call optional and injectable

Success criteria:

- `aura-agent-core` can run fully without any Relay

### Phase 3. Convert `aura-ffi` into `aura-agent-ffi`

- rebind FFI to `aura-agent-core`
- keep existing mobile API stable where possible
- add optional remote-analysis entrypoints later, not first

Success criteria:

- current app can use Agent without depending on Relay availability

### Phase 4. Split `aura-ml`

- move ONNX/heavy model path into `aura-relay-ml`
- keep cheap fallback logic in `aura-ml-lite`
- remove heavy model expectation from default mobile prod build

Success criteria:

- mobile production build does not require shipping `safety.onnx.data` or `intent.onnx.data`

### Phase 5. Create minimal Relay

- add `aura-relay-api`
- add `aura-relay-core`
- implement a no-op or simple inference-backed response
- wire auth, deadlines, and version negotiation

Success criteria:

- Agent can perform a typed remote assist call in integration tests

### Phase 6. Move remote-only intelligence

- move cross-chat correlation to Relay
- move sender/network intelligence to Relay
- move ambiguity-heavy stance disambiguation to Relay

Success criteria:

- Agent no longer pretends to own global intelligence it cannot observe locally

### Phase 7. Move product rollout to hybrid mode

- define local-first decision classes
- define relay-assisted classes
- define timeout/degradation behavior
- instrument precision delta between local-only and relay-assisted outcomes

Success criteria:

- product behavior is stable under offline, timeout, and degraded relay scenarios

### Phase 8. Collapse transitional shell

- shrink or delete `aura-core` as the mixed-responsibility crate
- keep only the new explicit Agent/Relay/shared crates

Success criteria:

- no ambiguity remains about where semantics, policy, and heavy inference live

## Do Not Do

- do not move final UI policy to Relay
- do not make obvious local threat handling depend on network
- do not keep duplicate semantics in Agent and Relay with different meaning
- do not ship current `safety + intent` `.onnx.data` payload to mobile production
- do not start with ten new crates before contracts are frozen

## Immediate Next Step

The next practical step should be:

1. create `aura-contracts`
2. create `aura-wire-relay`
3. define the first `AgentAnalyzeRequest` / `RelayAnalyzeResponse`
4. extract `aura-agent-core` from current `aura-core`

That is the smallest migration slice that changes architecture without stalling delivery.
