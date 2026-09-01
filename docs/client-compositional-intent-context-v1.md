# Client compositional intent/context v1

Status: developer regression passed; release validation blocked.

Date: 2026-09-01.

## Problem statement

The frozen developer challenge showed that the current `rules_fallback`
usually assigns the correct family after a detector signal exists (37/38), but
finds the expected family in only 38/240 risky conversations. It also raises
34/240 safe counterfactuals and blocks six of them. The dominant defect is
therefore not a global threshold problem. Phrase and model layers fail to
produce observations for valid novel formulations, while contextual semantics
mostly operate after an observation already exists.

The first run and its corpus identities remain immutable. Improvements driven
by this result are post-diagnostic engineering regression, not independent
accuracy evidence.

The implemented post-diagnostic rerun now passes every prespecified developer
gate on the unchanged v1 corpus: 240/240 expected-family recall, 240/240 safe
specificity, 240/240 pair accuracy, zero risky `Allow`, zero safe `Block`, and
221/240 primary-family accuracy. Exact hashes, performance attribution, and
remaining evidence gates are recorded in
`docs/client-compositional-intent-context-v1-results.md`.

## Canonical ownership

The implementation must preserve the existing authority chain:

```text
bounded message
  -> raw structural evidence
  -> domain-owned compositional candidates
  -> ContextInterpreter confirmation
  -> confirmed events
  -> memory / inference
  -> policy
  -> product surface
```

- `aura-domain` owns bounded, language-aware structural evidence types.
- `aura-kids` owns KIDS threat compositions and typed event routing.
- `aura-core::ContextInterpreter` remains the sole owner of final speech act,
  stance, directionality, reciprocity, suppression, and memory eligibility.
- `Analyzer` orchestrates stages; it must not reconstruct semantic decisions
  from reason-code strings or diagnostic markers.
- Policy maps confirmed risk to an action. A detector or language pack cannot
  assign product behavior by bypassing interpretation.

## Raw semantic representation

The initial representation is deliberately evidence-only. It may contain:

- UTF-8-safe byte spans;
- normalized tokens and language/script routes;
- clause and sentence boundaries;
- closed quote spans and explicit ambiguous/unclosed quote state;
- raw lexical roles such as actor reference, target reference, request cue,
  future/conditional cue, negation cue, urgency cue, and report/support cue;
- domain-neutral concepts such as secrecy, isolation, credential, code, link,
  media, sexual content, meeting, location, gift, violence, self-harm,
  humiliation, exclusion, debt, and coercion.

It must not assign final `SpeechAct`, `Stance`, `Directionality`, or
`Reciprocity`. Those meanings depend on sender identity, protected-account
identity, relationship metadata, timeline, and the rest of the message, and
therefore belong to the interpreter.

Every collection and input is bounded. Limit exhaustion must produce typed,
content-free diagnostics and retain the already-governed fallback path. It
must never silently turn an oversized or structurally ambiguous message into a
clean `Allow`.

## Compositional candidates

A composition requires evidence from independent semantic dimensions, not
multiple synonyms for the same word. Initial KIDS compositions are:

| Family | Required composition examples |
| --- | --- |
| self-harm | first-person reference + intent/plan/hopelessness + self-harm/death concept; urgency raises confidence |
| threat | future, conditional, or imperative cue + violence/property-harm concept + directed target |
| grooming | secrecy/isolation/platform-switch plus meeting/media/location/gift progression, calibrated by minor/contact context |
| manipulation | guilt/debt/isolation/false-consensus/blackmail plus compelled action or dependency |
| phishing | credential/code/payment concept plus request/urgency/deceptive-service/link cue |
| explicit | sexual/intimate concept plus direct request, creation, or targeted media exchange |
| NSFW | sexual/adult-content concept plus distribution, consumption, attachment, channel, or broadcast cue |
| bullying | directed target plus devaluation, humiliation, mockery, exclusion, or repeated social attack |

One message may yield multiple candidates. The interpreter and inference layers
must receive the evidence instead of forcing an early mutually exclusive
family. For example, suicide coercion can legitimately carry manipulation and
self-harm relevance, while a sexual-media request with secrecy can carry
explicit and grooming relevance.

## Span-aware context rules

The interpreter must evaluate each candidate against its evidence spans:

1. A candidate wholly inside a syntactically closed quotation may be
   suppressed only when text outside the quote provides an explicit reporting,
   refusal, education, counter-speech, or support stance.
2. A bare quotation is neutral evidence, not sufficient suppression.
3. Unclosed, mismatched, nested beyond the supported bound, or otherwise
   ambiguous quoting fails closed.
4. Active-risk evidence outside the quote cannot be suppressed by a safe cue
   elsewhere in the message.
5. Negation attaches to a bounded clause/evidence span; one negation cannot
   cancel an unrelated later request or threat.
6. Self-referential crisis evidence outside a quote remains active even when
   the same message asks for help.
7. A genuine support/report context may change product presentation without
   rewriting the underlying quoted family as an active author intent.

## Product-policy separation

Evaluation and implementation must distinguish three questions:

1. Which harm family is present in the discussed content?
2. Is the current author expressing active intent, quoting/reporting it,
   refusing it, or supporting someone?
3. Which product action is safe for that combination?

This prevents a quoted self-harm report from becoming a punitive block while
also preventing an active first-person crisis from becoming `Allow`. The
historical v1 result remains unchanged; a versioned evaluation contract will
measure family, context role, and action separately.

## Performance contract

Performance work begins with attribution, not assumptions. The harness must
report content-free:

- analyzer initialization time;
- runtime reset time between independent conversations;
- detector-reported per-turn analysis latency;
- full probe wall time;
- backend and exact binary digest.

The semantic hot path should normalize and segment once, reuse compiled
immutable language tables, borrow message data where ownership is unnecessary,
and avoid reason-code `String` allocation until the explainability boundary.
Static dispatch is preferred for fixed on-device stages. `unsafe` is not
permitted in v1. A future exception would require a measured bottleneck,
reviewed safety proof, fuzz/Miri coverage, and a material benchmark win.

No semantic wave may add an unexplained performance regression above 5% on
the unchanged baseline. Final budgets require release-build profiling on both
the host and the exact supported iPhone artifact.

## Delivery waves

### Wave 0 — attribution without behavior change

- Add initialization/reset/wall-clock attribution to the developer probe.
- Preserve existing output fields and frozen corpus identities.
- Record a content-free baseline against the exact release binary.

### Wave 1 — bounded semantic substrate

- Add validated spans, tokens, clauses, and quote structure to `aura-domain`.
- Add Unicode, oversized-input, malformed-quote, and determinism tests.
- Do not connect the new representation to detector decisions yet.

### Wave 2 — self-harm and threat shadow candidates

- Add domain-owned compositional rules and stable typed event routes.
- Run candidates beside existing behavior without product enforcement.
- Compare family/context/action outputs and latency on the exact frozen v1.

### Wave 3 — grooming and manipulation

- Add secrecy, isolation, dependency, debt, blackmail, meeting, media, gift,
  and platform-switch compositions.
- Add multi-turn progression and memory-contamination tests.

### Wave 4 — phishing, explicit, NSFW, and bullying

- Separate targeted sexual requests from adult-content distribution.
- Add credential/code/payment request composition without requiring a real URL.
- Add directed devaluation/exclusion composition and repeated-attack inference.

### Wave 5 — interpreted integration

- Carry candidate evidence spans through `RawObservation`.
- Confirm or suppress candidates only in `ContextInterpreter`.
- Persist only confirmed typed events.
- Remove any new dependency on `reason_code` parsing from business decisions.

### Wave 6 — evidence and promotion

- Pass unit, differential, metamorphic, replay, memory-contamination, fuzz,
  full workspace, and performance gates.
- Rerun the exact frozen developer v1 without editing its corpus.
- Execute the separately authored internal blinded holdout.
- Keep external/native-speaker, physical-device, artifact-pin, and human
  safety approvals as separate release gates.

## Engineering acceptance

The unchanged developer challenge targets remain:

- expected-family recall at least 90%;
- safe specificity at least 95%;
- pair accuracy at least 90%;
- zero risky `Allow` errors;
- zero safe `Block` errors;
- all language/family slice gates pass.

Passing them is necessary engineering regression evidence, but not sufficient
release evidence because the detector team has seen and authored the corpus.

## Non-goals for v1

- no global threshold reduction;
- no new product UI or guardian-report semantics;
- no protobuf v1, C ABI, or persisted-state schema break;
- no remote translation or network fetch in the analysis path;
- no model retraining disguised as a rules refactor;
- no `unsafe` optimization;
- no claim that developer-authored results close `REL-011`.
