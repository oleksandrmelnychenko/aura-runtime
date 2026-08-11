use std::collections::HashSet;
use std::sync::OnceLock;

use aura_domain::{
    validate_schema_version, DomainAction, DomainEventKind, DomainSignal, DomainTemporalActorRole,
    DomainTemporalDirectionality, DomainTemporalEvent, DomainTemporalInput, DomainTemporalOutput,
    DomainTemporalSpeechAct,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MilitaryTemporalPolicy {
    schema_version: u32,
    enabled: bool,
    analysis_window_ms: u64,
    disclosure_window_ms: u64,
    max_events: usize,
    min_event_confidence: f32,
    min_influence_messages: usize,
    min_influence_kinds: usize,
    influence_pressure: TemporalSignalTemplate,
    operational_collection: TemporalSignalTemplate,
    linked_disclosure: TemporalSignalTemplate,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemporalSignalTemplate {
    threat_key: String,
    reason_code: String,
    threat_type: String,
    severity: String,
    score: f32,
    priority: u8,
    action: Option<DomainAction>,
}

impl TemporalSignalTemplate {
    fn to_signal(&self) -> DomainSignal {
        DomainSignal {
            threat_key: self.threat_key.clone(),
            score: self.score,
            reason_code: self.reason_code.clone(),
            threat_type: Some(self.threat_type.clone()),
            severity: Some(self.severity.clone()),
            priority: Some(self.priority),
            action: self.action,
        }
    }
}

#[derive(Default)]
struct InfluenceSupport {
    messages: HashSet<(u64, u64)>,
    kinds: HashSet<DomainEventKind>,
}

impl InfluenceSupport {
    fn satisfies(&self, policy: &MilitaryTemporalPolicy) -> bool {
        self.messages.len() >= policy.min_influence_messages
            && self.kinds.len() >= policy.min_influence_kinds
    }
}

static MILITARY_TEMPORAL_POLICY: OnceLock<Result<MilitaryTemporalPolicy, String>> = OnceLock::new();

fn military_temporal_policy() -> Result<&'static MilitaryTemporalPolicy, &'static str> {
    MILITARY_TEMPORAL_POLICY
        .get_or_init(|| {
            let raw = include_str!("../data/temporal_fusion_rules.json");
            let policy: MilitaryTemporalPolicy = serde_json::from_str(raw)
                .map_err(|err| format!("invalid military temporal rule pack: {err}"))?;
            validate_policy(&policy)?;
            Ok(policy)
        })
        .as_ref()
        .map_err(String::as_str)
}

fn validate_policy(policy: &MilitaryTemporalPolicy) -> Result<(), String> {
    validate_schema_version(policy.schema_version, "military temporal policy")?;
    if policy.analysis_window_ms == 0 {
        return Err("analysis_window_ms must be greater than zero".to_string());
    }
    if policy.disclosure_window_ms == 0 || policy.disclosure_window_ms > policy.analysis_window_ms {
        return Err("disclosure_window_ms must be within the analysis window".to_string());
    }
    if !(1..=500).contains(&policy.max_events) {
        return Err("max_events must be within 1..=500".to_string());
    }
    if !(0.0..=1.0).contains(&policy.min_event_confidence) {
        return Err("min_event_confidence must be within 0..=1".to_string());
    }
    if policy.min_influence_messages < 2 {
        return Err("min_influence_messages must be at least two".to_string());
    }
    if !(2..=3).contains(&policy.min_influence_kinds) {
        return Err("min_influence_kinds must be within 2..=3".to_string());
    }
    validate_template(&policy.influence_pressure)?;
    validate_template(&policy.operational_collection)?;
    validate_template(&policy.linked_disclosure)
}

fn validate_template(template: &TemporalSignalTemplate) -> Result<(), String> {
    if template.threat_key.trim().is_empty()
        || template.reason_code.trim().is_empty()
        || template.threat_type.trim().is_empty()
        || template.severity.trim().is_empty()
    {
        return Err("temporal signal metadata must not be empty".to_string());
    }
    if !(0.0..=1.0).contains(&template.score) {
        return Err("temporal signal score must be within 0..=1".to_string());
    }
    if template.priority == 0 {
        return Err("temporal signal priority must be greater than zero".to_string());
    }
    Ok(())
}

pub(crate) fn temporal_enabled() -> bool {
    military_temporal_policy().is_ok_and(|policy| policy.enabled)
}

pub(crate) fn run_military_temporal_pipeline(input: &DomainTemporalInput) -> DomainTemporalOutput {
    let Ok(policy) = military_temporal_policy() else {
        return DomainTemporalOutput::default();
    };
    evaluate_with_policy(input, policy)
}

#[cfg(feature = "evaluation")]
pub(crate) fn run_military_temporal_shadow_pipeline(
    input: &DomainTemporalInput,
) -> Result<DomainTemporalOutput, String> {
    let mut policy = military_temporal_policy()
        .map_err(ToString::to_string)?
        .clone();
    policy.enabled = true;
    Ok(evaluate_with_policy(input, &policy))
}

fn evaluate_with_policy(
    input: &DomainTemporalInput,
    policy: &MilitaryTemporalPolicy,
) -> DomainTemporalOutput {
    if !policy.enabled || input.current_content_hash.is_none() {
        return DomainTemporalOutput::default();
    }

    let window_start = input.as_of_ms.saturating_sub(policy.analysis_window_ms);
    let events = bounded_events(input, policy, window_start);
    let mut signals = Vec::with_capacity(3);

    if current_event_matches(input, &events, is_influence_event) {
        let support = influence_support(
            &events,
            input.current_actor_id,
            input.as_of_ms.saturating_add(1),
            window_start,
        );
        if support.satisfies(policy) {
            signals.push(policy.influence_pressure.to_signal());
        }
    }

    if current_event_matches(input, &events, is_collection_event)
        && operational_collection_supported(
            &events,
            input.current_actor_id,
            input.as_of_ms,
            window_start,
            policy,
        )
    {
        signals.push(policy.operational_collection.to_signal());
    }

    if current_event_matches(input, &events, is_protected_disclosure_event)
        && linked_disclosure_supported(input, &events, policy)
    {
        signals.push(policy.linked_disclosure.to_signal());
    }

    signals.sort_by(|left, right| {
        right
            .priority
            .unwrap_or_default()
            .cmp(&left.priority.unwrap_or_default())
    });
    let action = strongest_action(&signals);
    DomainTemporalOutput { signals, action }
}

fn bounded_events<'a>(
    input: &'a DomainTemporalInput,
    policy: &MilitaryTemporalPolicy,
    window_start: u64,
) -> Vec<&'a DomainTemporalEvent> {
    let mut events: Vec<&DomainTemporalEvent> = input
        .events
        .iter()
        .filter(|event| {
            event.timestamp_ms >= window_start
                && event.timestamp_ms <= input.as_of_ms
                && event.confidence >= policy.min_event_confidence
                && event.content_hash.is_some()
                && event.context.supports_temporal_inference()
        })
        .collect();
    events.sort_by_key(|event| (event.timestamp_ms, event.event_id));
    if events.len() > policy.max_events {
        let keep_from = events.len() - policy.max_events;
        events.drain(0..keep_from);
    }
    events
}

fn current_event_matches(
    input: &DomainTemporalInput,
    events: &[&DomainTemporalEvent],
    predicate: fn(&DomainTemporalEvent) -> bool,
) -> bool {
    events.iter().any(|event| {
        event.actor_id == input.current_actor_id
            && event.timestamp_ms == input.as_of_ms
            && event.content_hash == input.current_content_hash
            && predicate(event)
    })
}

fn influence_support(
    events: &[&DomainTemporalEvent],
    actor_id: u32,
    before_ms: u64,
    window_start: u64,
) -> InfluenceSupport {
    let mut support = InfluenceSupport::default();
    for event in events {
        if event.actor_id != actor_id
            || event.actor_role != DomainTemporalActorRole::External
            || event.timestamp_ms < window_start
            || event.timestamp_ms >= before_ms
            || !is_influence_event(event)
        {
            continue;
        }
        let Some(content_hash) = event.content_hash else {
            continue;
        };
        support.messages.insert((event.timestamp_ms, content_hash));
        support.kinds.insert(event.kind);
    }
    support
}

fn operational_collection_supported(
    events: &[&DomainTemporalEvent],
    actor_id: u32,
    collection_at_ms: u64,
    window_start: u64,
    policy: &MilitaryTemporalPolicy,
) -> bool {
    influence_support(events, actor_id, collection_at_ms, window_start).satisfies(policy)
}

fn linked_disclosure_supported(
    input: &DomainTemporalInput,
    events: &[&DomainTemporalEvent],
    policy: &MilitaryTemporalPolicy,
) -> bool {
    let disclosure_start = input.as_of_ms.saturating_sub(policy.disclosure_window_ms);
    events.iter().any(|collection| {
        collection.actor_role == DomainTemporalActorRole::External
            && collection.timestamp_ms >= disclosure_start
            && collection.timestamp_ms < input.as_of_ms
            && is_collection_event(collection)
            && operational_collection_supported(
                events,
                collection.actor_id,
                collection.timestamp_ms,
                input.as_of_ms.saturating_sub(policy.analysis_window_ms),
                policy,
            )
    })
}

fn is_influence_event(event: &DomainTemporalEvent) -> bool {
    event.actor_role == DomainTemporalActorRole::External
        && matches!(
            event.kind,
            DomainEventKind::PropagandaNarrative
                | DomainEventKind::MilitaryDisinfo
                | DomainEventKind::PsyopsPattern
        )
}

fn is_collection_event(event: &DomainTemporalEvent) -> bool {
    if event.actor_role != DomainTemporalActorRole::External {
        return false;
    }
    match event.kind {
        DomainEventKind::IntelGathering => matches!(
            event.context.speech_act,
            DomainTemporalSpeechAct::Ask | DomainTemporalSpeechAct::Solicit
        ),
        DomainEventKind::MilitaryPhishing => matches!(
            event.context.speech_act,
            DomainTemporalSpeechAct::Assert
                | DomainTemporalSpeechAct::Ask
                | DomainTemporalSpeechAct::Solicit
        ),
        DomainEventKind::CoordinateMention => {
            matches!(
                event.context.speech_act,
                DomainTemporalSpeechAct::Ask | DomainTemporalSpeechAct::Solicit
            ) && matches!(
                event.context.directionality,
                DomainTemporalDirectionality::DirectedAtUser
            )
        }
        _ => false,
    }
}

fn is_protected_disclosure_event(event: &DomainTemporalEvent) -> bool {
    event.actor_role == DomainTemporalActorRole::ProtectedAccount
        && event.context.speech_act == DomainTemporalSpeechAct::Assert
        && !matches!(
            event.context.directionality,
            DomainTemporalDirectionality::SelfReferential
                | DomainTemporalDirectionality::ThirdParty
        )
        && matches!(
            event.kind,
            DomainEventKind::PositionLeak
                | DomainEventKind::UnitInfoLeak
                | DomainEventKind::EquipmentLeak
                | DomainEventKind::CoordinateMention
        )
}

fn strongest_action(signals: &[DomainSignal]) -> Option<DomainAction> {
    signals
        .iter()
        .filter_map(|signal| signal.action)
        .max_by_key(|action| match action {
            DomainAction::Allow => 0,
            DomainAction::Mark => 1,
            DomainAction::Warn => 2,
            DomainAction::Block => 3,
        })
}

#[cfg(test)]
mod tests {
    use aura_domain::{DomainConversationType, DomainTemporalContext, DomainTemporalStance};

    use super::*;

    const EXTERNAL_ACTOR: u32 = 1;
    const PROTECTED_ACTOR: u32 = 2;

    fn policy_enabled() -> MilitaryTemporalPolicy {
        let mut policy = military_temporal_policy()
            .expect("embedded temporal policy")
            .clone();
        policy.enabled = true;
        policy
    }

    fn event(
        event_id: u64,
        timestamp_ms: u64,
        actor_id: u32,
        actor_role: DomainTemporalActorRole,
        kind: DomainEventKind,
        speech_act: DomainTemporalSpeechAct,
        content_hash: u64,
    ) -> DomainTemporalEvent {
        DomainTemporalEvent {
            event_id,
            timestamp_ms,
            actor_id,
            actor_role,
            kind,
            confidence: 0.9,
            content_hash: Some(content_hash),
            context: DomainTemporalContext {
                speech_act,
                stance: DomainTemporalStance::Endorse,
                directionality: DomainTemporalDirectionality::DirectedAtUser,
                trusted_contact: false,
                confidence: 0.9,
            },
        }
    }

    fn input(
        as_of_ms: u64,
        current_actor_id: u32,
        current_content_hash: u64,
        events: Vec<DomainTemporalEvent>,
    ) -> DomainTemporalInput {
        DomainTemporalInput {
            as_of_ms,
            current_actor_id,
            current_content_hash: Some(current_content_hash),
            conversation_type: DomainConversationType::Direct,
            events,
        }
    }

    fn influence_events() -> Vec<DomainTemporalEvent> {
        vec![
            event(
                1,
                1_000,
                EXTERNAL_ACTOR,
                DomainTemporalActorRole::External,
                DomainEventKind::PropagandaNarrative,
                DomainTemporalSpeechAct::Assert,
                11,
            ),
            event(
                2,
                2_000,
                EXTERNAL_ACTOR,
                DomainTemporalActorRole::External,
                DomainEventKind::PsyopsPattern,
                DomainTemporalSpeechAct::Assert,
                22,
            ),
        ]
    }

    #[test]
    fn embedded_temporal_policy_is_disabled() {
        assert!(!temporal_enabled());
    }

    #[test]
    fn distinct_influence_families_complete_pressure_state() {
        let events = influence_events();
        let input = input(2_000, EXTERNAL_ACTOR, 22, events);

        let output = evaluate_with_policy(&input, &policy_enabled());

        assert!(output
            .signals
            .iter()
            .any(|signal| signal.reason_code == "military.temporal.influence_pressure"));
    }

    #[test]
    fn repeated_single_influence_family_does_not_complete_pressure_state() {
        let events = vec![
            event(
                1,
                1_000,
                EXTERNAL_ACTOR,
                DomainTemporalActorRole::External,
                DomainEventKind::PropagandaNarrative,
                DomainTemporalSpeechAct::Assert,
                11,
            ),
            event(
                2,
                2_000,
                EXTERNAL_ACTOR,
                DomainTemporalActorRole::External,
                DomainEventKind::PropagandaNarrative,
                DomainTemporalSpeechAct::Assert,
                22,
            ),
        ];
        let input = input(2_000, EXTERNAL_ACTOR, 22, events);

        let output = evaluate_with_policy(&input, &policy_enabled());

        assert!(output.signals.is_empty());
    }

    #[test]
    fn collection_after_influence_emits_operational_collection_signal() {
        let mut events = influence_events();
        events.push(event(
            3,
            3_000,
            EXTERNAL_ACTOR,
            DomainTemporalActorRole::External,
            DomainEventKind::IntelGathering,
            DomainTemporalSpeechAct::Solicit,
            33,
        ));
        let input = input(3_000, EXTERNAL_ACTOR, 33, events);

        let output = evaluate_with_policy(&input, &policy_enabled());

        assert!(output.signals.iter().any(|signal| {
            signal.reason_code == "military.temporal.operational_collection_attempt"
        }));
    }

    #[test]
    fn same_timestamp_evidence_does_not_create_ordered_collection_chain() {
        let mut events = influence_events();
        events[1].timestamp_ms = 3_000;
        events.push(event(
            3,
            3_000,
            EXTERNAL_ACTOR,
            DomainTemporalActorRole::External,
            DomainEventKind::IntelGathering,
            DomainTemporalSpeechAct::Solicit,
            33,
        ));
        let input = input(3_000, EXTERNAL_ACTOR, 33, events);

        let output = evaluate_with_policy(&input, &policy_enabled());

        assert!(output.signals.is_empty());
    }

    #[test]
    fn counter_speech_does_not_enter_influence_support() {
        let mut events = influence_events();
        events[1].context.speech_act = DomainTemporalSpeechAct::Counter;
        events[1].context.stance = DomainTemporalStance::Oppose;
        let input = input(2_000, EXTERNAL_ACTOR, 22, events);

        let output = evaluate_with_policy(&input, &policy_enabled());

        assert!(output.signals.is_empty());
    }

    #[test]
    fn protected_disclosure_after_collection_emits_linked_disclosure_signal() {
        let mut events = influence_events();
        events.push(event(
            3,
            3_000,
            EXTERNAL_ACTOR,
            DomainTemporalActorRole::External,
            DomainEventKind::IntelGathering,
            DomainTemporalSpeechAct::Solicit,
            33,
        ));
        events.push(event(
            4,
            4_000,
            PROTECTED_ACTOR,
            DomainTemporalActorRole::ProtectedAccount,
            DomainEventKind::CoordinateMention,
            DomainTemporalSpeechAct::Assert,
            44,
        ));
        let input = input(4_000, PROTECTED_ACTOR, 44, events);

        let output = evaluate_with_policy(&input, &policy_enabled());

        assert!(output.signals.iter().any(|signal| {
            signal.reason_code == "military.temporal.influence_linked_disclosure"
        }));
    }

    #[test]
    fn event_storage_order_does_not_change_temporal_result() {
        let mut events = influence_events();
        events.push(event(
            3,
            3_000,
            EXTERNAL_ACTOR,
            DomainTemporalActorRole::External,
            DomainEventKind::IntelGathering,
            DomainTemporalSpeechAct::Solicit,
            33,
        ));
        let forward = input(3_000, EXTERNAL_ACTOR, 33, events.clone());
        events.reverse();
        let reversed = input(3_000, EXTERNAL_ACTOR, 33, events);

        let forward_output = evaluate_with_policy(&forward, &policy_enabled());
        let reversed_output = evaluate_with_policy(&reversed, &policy_enabled());

        assert_eq!(forward_output, reversed_output);
    }

    #[test]
    fn evidence_from_different_external_actors_does_not_combine() {
        let events = vec![
            event(
                1,
                1_000,
                EXTERNAL_ACTOR,
                DomainTemporalActorRole::External,
                DomainEventKind::PropagandaNarrative,
                DomainTemporalSpeechAct::Assert,
                11,
            ),
            event(
                2,
                2_000,
                9,
                DomainTemporalActorRole::External,
                DomainEventKind::PsyopsPattern,
                DomainTemporalSpeechAct::Assert,
                22,
            ),
            event(
                3,
                3_000,
                EXTERNAL_ACTOR,
                DomainTemporalActorRole::External,
                DomainEventKind::IntelGathering,
                DomainTemporalSpeechAct::Solicit,
                33,
            ),
        ];
        let input = input(3_000, EXTERNAL_ACTOR, 33, events);

        let output = evaluate_with_policy(&input, &policy_enabled());

        assert!(output.signals.is_empty());
    }

    #[test]
    fn future_evidence_does_not_influence_backfilled_message() {
        let mut events = influence_events();
        events.push(event(
            3,
            3_000,
            EXTERNAL_ACTOR,
            DomainTemporalActorRole::External,
            DomainEventKind::IntelGathering,
            DomainTemporalSpeechAct::Solicit,
            33,
        ));
        let input = input(2_000, EXTERNAL_ACTOR, 22, events);

        let output = evaluate_with_policy(&input, &policy_enabled());

        assert_eq!(output.signals.len(), 1);
    }

    #[test]
    fn legacy_event_without_interpreted_context_does_not_contribute() {
        let mut events = influence_events();
        events[0].context = DomainTemporalContext::default();
        let input = input(2_000, EXTERNAL_ACTOR, 22, events);

        let output = evaluate_with_policy(&input, &policy_enabled());

        assert!(output.signals.is_empty());
    }

    #[test]
    fn evidence_evicted_by_the_event_bound_does_not_contribute() {
        let mut events = influence_events();
        for index in 0..498_u64 {
            events.push(event(
                index + 3,
                index + 3_000,
                EXTERNAL_ACTOR,
                DomainTemporalActorRole::External,
                DomainEventKind::SuspiciousSource,
                DomainTemporalSpeechAct::Assert,
                index + 100,
            ));
        }
        events.push(event(
            501,
            10_000,
            EXTERNAL_ACTOR,
            DomainTemporalActorRole::External,
            DomainEventKind::IntelGathering,
            DomainTemporalSpeechAct::Solicit,
            10_000,
        ));
        let input = input(10_000, EXTERNAL_ACTOR, 10_000, events);

        let output = evaluate_with_policy(&input, &policy_enabled());

        assert!(output.signals.is_empty());
    }
}
