# Phase 3 Pilot Readiness Roadmap

This document is the handoff from the Phase 2 release-hardening track into the
next major operating phase for AURA Core.

Phase 3 is not another generic cleanup pass. The goal is to turn a hardened
core runtime into something that can survive a controlled pilot, shadow-mode
deployment, and real product integration without losing policy clarity or
operational discipline.

## Why Phase 3 Starts Now

Phase 2 established the foundation:

- release gates and evidence bundles are operational
- protobuf, FFI, and persisted state contracts are guarded
- privacy and dataset evidence are part of promotion
- simulation tooling exists and now exercises realistic multi-chat timelines

The next bottleneck is no longer basic runtime hardening. The next bottleneck
is proving that AURA behaves correctly under real product flows, real human
review loops, and messier child/teen social dynamics.

## Phase 3 Mission

Build pilot-ready confidence in AURA by combining:

- stronger policy semantics for ambiguous and high-stakes cases
- shadow-mode and replay workflows for real integration validation
- machine-readable regression corpora derived from realistic simulations
- explicit product-facing contracts for guardian alerts and child-visible
  interventions

## Target End State

At the end of Phase 3, AURA should have:

- a shadow-mode operating path that can run without user-facing enforcement
- a promotion-ready regression corpus derived from realistic and synthetic world
  simulations
- stronger policy behavior for trusted-adult boundaries, supportive self-harm
  cases, coercive control, and reputation/image abuse
- a reviewable mapping from core outputs to product actions, guardian alerts,
  and follow-up workflows
- an explicit pilot gate that is stricter than local simulation success but
  lighter than a full production rollout

## Workstreams

### 1. Shadow-Mode Runtime and Replay

Objective: run AURA in realistic product conditions before broad enforcement.

Tasks:

- define a shadow-mode integration contract where analysis runs fully but
  user-facing actions can be suppressed or mirrored
- add replay-friendly event capture for integration environments without logging
  forbidden plaintext fields
- persist structured pilot artifacts that let the team compare:
  - raw model/runtime output
  - policy output
  - UI action selection
  - guardian alert selection
- make it easy to replay captured pilot slices through the same release-eval
  tooling used in CI

Expected outputs:

- shadow-mode request/response contract
- replay bundle format
- pilot artifact manifest
- dry-run or mirror-mode examples for product integration teams

### 2. Simulation to Regression Corpus Promotion

Objective: stop treating large simulations as demo-only assets.

Tasks:

- identify stable high-value scenarios from:
  - `mega_simulation`
  - `world_sim`
  - `olena_world`
- convert stable scenarios into machine-readable regression bundles with:
  - expected primary threat
  - minimum action
  - minimum guardian alert
  - allowed label ambiguity when action-level behavior is the real invariant
- separate:
  - hard safety regressions
  - taxonomy cleanup cases
  - known ambiguous-but-acceptable cases
- add a pilot-focused slice set for:
  - teen group chats
  - social-media humiliation
  - coercive friendship dynamics
  - trusted-adult ambiguity
  - supportive versus risky self-harm contexts

Expected outputs:

- formalized simulation regression corpus
- scenario expectation schema
- pilot-specific slice manifest
- CI entrypoint for replaying promoted simulation cases

### 3. Core Policy and Psychological Modeling

Objective: improve the places where action selection matters more than raw
toxicity detection.

Priority themes:

- trusted-adult boundary cases
- supportive versus dangerous self-harm responses
- coercive control over time
- reputation abuse, screenshot abuse, and image-based humiliation
- manipulation chains that should not collapse into grooming by default

Tasks:

- split supportive self-harm language from attempt-proximity and coercive
  self-harm threats more explicitly
- expand reputation/image-abuse semantics beyond generic bullying
- deepen coercive-control latent state tracking across repeated conversations
- preserve protective-factor reasoning instead of only accumulating threat
  evidence
- tighten action-policy mapping where the primary risk is social fallout rather
  than immediate content severity

Expected outputs:

- stronger policy slices in evaluation and simulation corpora
- clearer latent-state evidence for guardian/product surfaces
- fewer action-level mismatches in ambiguous cases

### 4. Product Integration Contract

Objective: make core results usable by a real messenger product without ad hoc
glue logic.

Tasks:

- define a stable mapping from:
  - `threat_type`
  - `reason_codes`
  - `inference.latent_states`
  - `recommended_action`
  to product-visible surfaces
- classify which decisions are:
  - child-facing only
  - guardian-facing only
  - moderation/review-facing only
- document which actions are acceptable in:
  - shadow mode
  - staging pilot
  - guardian-enabled rollout
- define product-safe defaults for uncertain or mixed-signal cases

Expected outputs:

- integration contract for messenger clients
- guardian alert handling guide
- child-visible intervention policy
- ambiguity handling rules for pilot rollout

### 5. Pilot Gate and Operational Review

Objective: create a gate that reflects controlled real-world use, not just lab
evaluation.

Tasks:

- define pilot entry criteria on top of Phase 2 release gates
- require stable shadow-mode bundles over repeated runs, not a single green
  snapshot
- add human-review signoff requirements for:
  - false-positive hotspots
  - self-harm boundary cases
  - trusted-adult scenarios
  - reputation/image abuse pathways
- define rollback triggers specific to pilot environments

Expected outputs:

- `pilot-ready` decision contract
- shadow-mode review checklist
- pilot rollback triggers
- operator review cadence and ownership

## Milestone Sequence

### Milestone 1: Shadow Mode Foundation

Ship first:

- shadow-mode contract
- replay artifact format
- promoted simulation regression schema
- pilot artifact manifest

Exit criteria:

- captured pilot-style artifacts can be replayed deterministically
- simulations are no longer demo-only
- no forbidden plaintext fields enter pilot evidence

### Milestone 2: Policy Depth on Ambiguous Cases

Ship next:

- trusted-adult boundary improvements
- self-harm supportive-versus-risky separation
- reputation/image-abuse slices
- coercive-control strengthening

Exit criteria:

- ambiguous high-stakes slices have explicit expected policy behavior
- shadow-mode review shows fewer action-level disagreements on target slices

### Milestone 3: Pilot Gate

Ship last:

- pilot checklist
- operator review process
- staged rollout contract
- promotion evidence extension for pilot-ready status

Exit criteria:

- pilot gate can be run repeatably
- shadow-mode bundles are interpretable and reviewable
- rollback conditions are explicit before first controlled rollout

## What Is Explicitly Out Of Scope Here

- broadening AURA into a general moderation SDK
- adding unrelated engagement or companion features
- jumping straight to heavy mathematical upgrades before pilot semantics are
  stable
- treating synthetic simulation wins as equivalent to pilot evidence

## Definition Of Done

Phase 3 is done only when all of the following are true:

- shadow-mode execution is possible without product-side guesswork
- promoted simulation corpora are machine-readable and regression-ready
- ambiguous high-stakes policy areas have explicit expected behavior
- product-facing action contracts are stable enough for pilot integration
- pilot gating is reviewable, repeatable, and rollback-aware

Current status: in progress. The first shadow-mode foundation slice is now
implemented through:

- `aura_core::pilot` shadow bundle schema
- `world_sim --shadow-output` plaintext-free replay artifacts
- pilot shadow bundle wiring in unified evidence manifests and promotion paths
