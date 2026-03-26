# KIDS Memory Escalation Matrix

This document is the operator-facing explainability trail for `kids.memory.*`
signals and guardian escalation behavior.

Status: synchronized with runtime behavior on March 26, 2026.

## Contract

- Any signal with a reason code listed in the mandatory set below must trigger
  guardian escalation in `aura-kids` policy logic.
- This rule is applied even if signal priority is below
  `guardian_escalation_priority` and even if severity is not `critical`.
- Source of truth in code:
  - `crates/aura-kids/src/policy/guardian.rs`
  - `mandatory_guardian_reason_codes()`

## Mandatory Memory Reasons

- `kids.memory.grooming_progression`
- `kids.memory.sustained_sextortion`
- `kids.memory.bullying_cascade_selfharm`
- `kids.memory.sender_risk_accumulation`
- `kids.memory.new_sender_fast_escalation`
- `kids.memory.cross_conversation_repeat_offender`
- `kids.memory.victim_vulnerability_targeting`

## Operational Meaning

- `grooming_progression`: repeated grooming behavior by sender plus active
  manipulation pressure in current context.
- `sustained_sextortion`: repeated blackmail/sextortion pattern in ongoing
  interaction window.
- `bullying_cascade_selfharm`: bullying accumulation in conversation with
  self-harm vulnerability present.
- `sender_risk_accumulation`: sender risk score accumulation crosses policy
  threshold in active window.
- `new_sender_fast_escalation`: unknown/new sender combines grooming with
  blackmail/sextortion cues.
- `cross_conversation_repeat_offender`: sender repeatedly appears as high-risk
  across multiple conversations.
- `victim_vulnerability_targeting`: manipulative or grooming pressure aimed into
  a conversation already carrying self-harm vulnerability.

## Operator Guidance

- Treat these reason codes as immediate guardian-review class findings.
- Do not downgrade these findings in pilot triage solely because a single
  message score appears borderline.
- If these reason codes spike after rule updates, run regression suite and
  inspect slice-level drift before changing thresholds.
