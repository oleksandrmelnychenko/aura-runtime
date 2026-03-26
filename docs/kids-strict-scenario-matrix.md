# KIDS Strict Scenario Matrix

This matrix defines the minimum strict-profile scenario coverage required before
pilot expansion or release promotion for KIDS domain behavior.

Status: synchronized with runtime and corpora on March 26, 2026.

## Required Harmful Slices

- `classic_grooming` and `trusted_adult_grooming`
- `screenshot_blackmail` and `sustained_sextortion_progression`
- `group_bullying` and `bullying_selfharm_cascade`
- `acute_selfharm` and `suicide_coercion`
- `phishing_link`
- `mixed_language_grooming`
- `mixed_language_group_bullying`
- `mixed_language_selfharm_crisis`
- `mixed_language_image_blackmail`
- `noisy_shorthand_grooming`

## Required Benign / False-Positive Slices

- `negative_control_trusted_adult`
- `negative_control_teen_flirting`
- `false_positive_friends`
- `negative_control_multilingual_support`
- `negative_control_multilingual_peer_chat`
- `bystander_rescue`

## Runtime-Memory Critical Reasons

The following reason codes must stay visible in strict test artifacts:

- `kids.memory.grooming_progression`
- `kids.memory.sustained_sextortion`
- `kids.memory.bullying_cascade_selfharm`
- `kids.memory.sender_risk_accumulation`
- `kids.memory.new_sender_fast_escalation`
- `kids.memory.cross_conversation_repeat_offender`
- `kids.memory.victim_vulnerability_targeting`

## Dataset Anchors

- Canonical scenarios: `crates/aura-core/src/eval_scenarios.rs`
- Realistic corpus: `crates/aura-core/data/realistic_chat_cases.json`
- Policy expectations: `crates/aura-core/data/action_policy_expectations.json`

## Promotion Readiness Rule

Promotion is blocked when any required harmful or benign slice is missing from
policy expectations, or when strict artifacts do not include the mandatory
`kids.memory.*` reasons listed above.
