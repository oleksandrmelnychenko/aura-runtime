use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, Write};

use aura_core::{
    predicted_score_for_threat, AccountType, Action, Analyzer, AuraConfig, ContentType,
    ConversationType, DomainMode, MessageInput, ProtectionLevel, RuntimeBackend, ThreatType,
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

#[derive(Debug, Deserialize)]
struct ProbeInput {
    id: String,
    text: String,
    #[serde(default)]
    language: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProbeOutput {
    id: String,
    backend: RuntimeBackend,
    primary: ThreatType,
    primary_score: f32,
    action: Action,
    scores: BTreeMap<String, f32>,
    reason_codes: Vec<String>,
    analysis_time_us: u64,
}

fn main() {
    let db = PatternDatabase::default_mvp();
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let mut analyzers: HashMap<String, Analyzer> = HashMap::new();

    for line in stdin.lock().lines() {
        let line = line.expect("read JSONL input");
        if line.trim().is_empty() {
            continue;
        }
        let input: ProbeInput = serde_json::from_str(&line).expect("valid probe input");
        let analyzer_key = input.language.as_deref().unwrap_or("multilingual");
        let analyzer = analyzers
            .entry(analyzer_key.to_string())
            .or_insert_with(|| {
                let config = AuraConfig {
                    account_type: AccountType::Child,
                    protection_level: ProtectionLevel::High,
                    domain_mode: DomainMode::Kids,
                    language: input.language.clone().unwrap_or_else(|| "en".to_string()),
                    account_holder_age: Some(12),
                    ..AuraConfig::default()
                };
                Analyzer::new(config, &db)
            });
        analyzer.reset_runtime_state();
        let result = analyzer.analyze(&MessageInput {
            content_type: ContentType::Text,
            text: Some(input.text),
            image_data: None,
            sender_id: format!("sender_{}", input.id).into(),
            conversation_id: format!("conversation_{}", input.id).into(),
            language: input.language,
            language_evidence: None,
            conversation_type: ConversationType::Direct,
            member_count: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        });
        let backend = analyzer.runtime_capabilities().backend;
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
        let output = ProbeOutput {
            id: input.id,
            backend,
            primary: result.threat_type,
            primary_score: result.score,
            action: result.action,
            scores,
            reason_codes: result.reason_codes,
            analysis_time_us: result.analysis_time_us,
        };
        serde_json::to_writer(&mut stdout, &output).expect("serialize probe output");
        writeln!(&mut stdout).expect("write newline");
    }
}

fn threat_label(threat: ThreatType) -> String {
    serde_json::to_value(threat)
        .expect("serializable threat")
        .as_str()
        .expect("threat serializes as string")
        .to_string()
}
