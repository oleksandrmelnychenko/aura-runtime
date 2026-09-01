use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, Write};
use std::time::{Duration, Instant};

use aura_core::config::CulturalContext;
use aura_core::{
    predicted_score_for_threat, AccountType, Action, Analyzer, AuraConfig, ContentType,
    ConversationType, DomainMode, MessageInput, ProtectionLevel, RelationshipTrustSource,
    RuntimeBackend, SenderRelationship, ThreatType,
};
use aura_patterns::PatternDatabase;
use serde::{Deserialize, Serialize};

const ALL_THREATS: [ThreatType; 18] = [
    ThreatType::Bullying,
    ThreatType::Grooming,
    ThreatType::Explicit,
    ThreatType::Threat,
    ThreatType::SelfHarm,
    ThreatType::Spam,
    ThreatType::Scam,
    ThreatType::Phishing,
    ThreatType::Manipulation,
    ThreatType::Nsfw,
    ThreatType::HateSpeech,
    ThreatType::Doxxing,
    ThreatType::PiiLeakage,
    ThreatType::Propaganda,
    ThreatType::OpsecViolation,
    ThreatType::Psyops,
    ThreatType::MilitarySocialEng,
    ThreatType::CoordinateLeak,
];

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProbeSpeaker {
    Protected,
    Other,
}

#[derive(Debug, Deserialize)]
struct ProbeMessage {
    text: String,
    speaker: ProbeSpeaker,
    #[serde(default)]
    language: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConversationProbeInput {
    id: String,
    default_language: String,
    account_type: AccountType,
    account_holder_age: u16,
    #[serde(default)]
    conversation_type: ConversationType,
    #[serde(default)]
    sender_relationship: SenderRelationship,
    #[serde(default)]
    relationship_trust_source: RelationshipTrustSource,
    messages: Vec<ProbeMessage>,
}

#[derive(Debug, Serialize)]
struct ProbeTurnOutput {
    turn_index: usize,
    backend: RuntimeBackend,
    primary: ThreatType,
    primary_score: f32,
    action: Action,
    scores: BTreeMap<String, f32>,
    reason_codes: Vec<String>,
    analysis_time_us: u64,
}

#[derive(Debug, Serialize)]
struct ConversationProbeOutput {
    id: String,
    turns: Vec<ProbeTurnOutput>,
    analyzer_init_us: Option<u64>,
    runtime_reset_us: u64,
    probe_wall_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ProbeAccountType {
    Child,
    Teen,
}

impl ProbeAccountType {
    fn from_validated(account_type: AccountType) -> Self {
        match account_type {
            AccountType::Child => Self::Child,
            AccountType::Teen => Self::Teen,
            AccountType::Adult => unreachable!("input validation rejects adult accounts"),
        }
    }

    fn account_type(self) -> AccountType {
        match self {
            Self::Child => AccountType::Child,
            Self::Teen => AccountType::Teen,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AnalyzerProfile {
    default_language: String,
    account_type: ProbeAccountType,
    account_holder_age: u16,
}

impl AnalyzerProfile {
    fn from_input(input: &ConversationProbeInput) -> Self {
        Self {
            default_language: input.default_language.clone(),
            account_type: ProbeAccountType::from_validated(input.account_type),
            account_holder_age: input.account_holder_age,
        }
    }

    fn config(&self) -> AuraConfig {
        AuraConfig {
            account_type: self.account_type.account_type(),
            protection_level: ProtectionLevel::High,
            language: self.default_language.clone(),
            cultural_context: cultural_context(&self.default_language),
            account_holder_age: Some(self.account_holder_age),
            protected_account_id: Some("protected_profile_account".to_string()),
            domain_mode: DomainMode::Kids,
            ..AuraConfig::default()
        }
    }
}

fn main() {
    let db = PatternDatabase::default_mvp();
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let mut analyzers = HashMap::new();

    for line in stdin.lock().lines() {
        let line = line.expect("read JSONL input");
        if line.trim().is_empty() {
            continue;
        }
        let input: ConversationProbeInput =
            serde_json::from_str(&line).expect("valid conversation probe input");
        let output = process_conversation(input, &db, &mut analyzers);
        serde_json::to_writer(&mut stdout, &output).expect("serialize conversation probe output");
        writeln!(&mut stdout).expect("write newline");
    }
}

fn process_conversation(
    input: ConversationProbeInput,
    db: &PatternDatabase,
    analyzers: &mut HashMap<AnalyzerProfile, Analyzer>,
) -> ConversationProbeOutput {
    validate_input(&input);
    let probe_started = Instant::now();
    let profile = AnalyzerProfile::from_input(&input);
    let mut analyzer_init_us = None;
    let analyzer = match analyzers.entry(profile) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => {
            let init_started = Instant::now();
            let config = entry.key().config();
            config.validate().expect("valid conversation probe config");
            let analyzer = Analyzer::new(config, db);
            analyzer_init_us = Some(duration_us(init_started.elapsed()));
            entry.insert(analyzer)
        }
    };

    let protected_id = "protected_profile_account".to_string();
    let external_id = format!("external_{}", input.id);
    let conversation_id = format!("conversation_{}", input.id);
    let mut turns = Vec::with_capacity(input.messages.len());
    for (turn_index, message) in input.messages.into_iter().enumerate() {
        let protected_sender = matches!(message.speaker, ProbeSpeaker::Protected);
        let result = analyzer.analyze(&MessageInput {
            content_type: ContentType::Text,
            text: Some(message.text),
            image_data: None,
            sender_id: if protected_sender {
                protected_id.clone().into()
            } else {
                external_id.clone().into()
            },
            conversation_id: conversation_id.clone().into(),
            language: message
                .language
                .or_else(|| Some(input.default_language.clone())),
            language_evidence: None,
            conversation_type: input.conversation_type,
            member_count: match input.conversation_type {
                ConversationType::Direct => None,
                ConversationType::Group => Some(4),
            },
            sender_relationship: if protected_sender {
                SenderRelationship::Unknown
            } else {
                input.sender_relationship
            },
            relationship_trust_source: if protected_sender {
                RelationshipTrustSource::Unknown
            } else {
                input.relationship_trust_source
            },
        });
        let scores = ALL_THREATS
            .iter()
            .copied()
            .map(|threat| {
                (
                    threat_label(threat),
                    predicted_score_for_threat(&result, threat),
                )
            })
            .collect();
        turns.push(ProbeTurnOutput {
            turn_index,
            backend: analyzer.runtime_capabilities().backend,
            primary: result.threat_type,
            primary_score: result.score,
            action: result.action,
            scores,
            reason_codes: result.reason_codes,
            analysis_time_us: result.analysis_time_us,
        });
    }

    let reset_started = Instant::now();
    analyzer.reset_runtime_state();
    let runtime_reset_us = duration_us(reset_started.elapsed());
    ConversationProbeOutput {
        id: input.id,
        turns,
        analyzer_init_us,
        runtime_reset_us,
        probe_wall_us: duration_us(probe_started.elapsed()),
    }
}

fn duration_us(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn validate_input(input: &ConversationProbeInput) {
    assert!(!input.id.trim().is_empty(), "id must not be empty");
    assert!(
        matches!(input.account_type, AccountType::Child | AccountType::Teen),
        "holdout probe accepts child or teen accounts only"
    );
    assert!(
        !input.messages.is_empty() && input.messages.len() <= 8,
        "conversation must contain 1..=8 messages"
    );
    assert!(
        input
            .messages
            .iter()
            .all(|message| { !message.text.trim().is_empty() && message.text.len() <= 2_000 }),
        "every message must contain at most 2,000 bytes of non-empty text"
    );
}

fn cultural_context(language: &str) -> CulturalContext {
    match language {
        "en" => CulturalContext::English,
        "ru" => CulturalContext::Russian,
        "uk" => CulturalContext::Ukrainian,
        other => CulturalContext::Custom(other.to_string()),
    }
}

fn threat_label(threat: ThreatType) -> String {
    serde_json::to_value(threat)
        .expect("serializable threat")
        .as_str()
        .expect("threat serializes as string")
        .to_string()
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn profile_cache_reuses_only_matching_immutable_configuration() {
        let db = PatternDatabase::default_mvp();
        let mut analyzers = HashMap::new();
        process_conversation(input("first", AccountType::Child, 12), &db, &mut analyzers);
        process_conversation(input("second", AccountType::Child, 12), &db, &mut analyzers);
        process_conversation(input("third", AccountType::Teen, 15), &db, &mut analyzers);
        assert_eq!(analyzers.len(), 2);
    }

    #[test]
    fn reset_prevents_previous_conversation_from_changing_next_decision() {
        let db = PatternDatabase::default_mvp();
        let mut reused = HashMap::new();
        let risky = input_with_text("risky", "Keep this secret and meet me alone tomorrow.");
        process_conversation(risky, &db, &mut reused);
        let after_risky =
            process_conversation(input("safe", AccountType::Child, 12), &db, &mut reused);

        let mut fresh = HashMap::new();
        let in_isolation =
            process_conversation(input("safe", AccountType::Child, 12), &db, &mut fresh);
        assert_eq!(decision_value(after_risky), decision_value(in_isolation));
    }

    fn input(id: &str, account_type: AccountType, age: u16) -> ConversationProbeInput {
        ConversationProbeInput {
            id: id.to_string(),
            default_language: "en".to_string(),
            account_type,
            account_holder_age: age,
            conversation_type: ConversationType::Direct,
            sender_relationship: SenderRelationship::Unknown,
            relationship_trust_source: RelationshipTrustSource::Unknown,
            messages: vec![ProbeMessage {
                text: "The weather is calm today.".to_string(),
                speaker: ProbeSpeaker::Other,
                language: None,
            }],
        }
    }

    fn input_with_text(id: &str, text: &str) -> ConversationProbeInput {
        let mut value = input(id, AccountType::Child, 12);
        value.messages[0].text = text.to_string();
        value
    }

    fn decision_value(output: ConversationProbeOutput) -> Value {
        let mut value = serde_json::to_value(output).expect("serializable output");
        let object = value.as_object_mut().expect("output is an object");
        object.remove("analyzer_init_us");
        object.remove("runtime_reset_us");
        object.remove("probe_wall_us");
        for turn in object["turns"].as_array_mut().expect("turns is an array") {
            turn.as_object_mut()
                .expect("turn is an object")
                .remove("analysis_time_us");
        }
        value
    }
}
