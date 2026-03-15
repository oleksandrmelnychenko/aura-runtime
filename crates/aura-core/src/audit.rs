use std::cmp::Ordering;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ActionRecommendation, AlertPriority, AnalysisResult, BehavioralTrend, CircleTier,
    FollowUpAction, ProtectionLevel, ThreatType, UiAction,
};

pub const AUDIT_SCHEMA_VERSION: &str = "aura.audit_record.v1";
pub const AUDIT_IDENTIFIER_SCHEME: &str = "sha256_truncated_24hex_process_salted";
const AUDIT_IDENTIFIER_HEX_LEN: usize = 24;
const AUDIT_TOKEN_SALT_ENV: &str = "AURA_AUDIT_TOKEN_SALT";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedIdentifier {
    pub token: String,
    pub scheme: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditThreatScore {
    pub threat_type: ThreatType,
    pub score: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub schema_version: String,
    pub event_timestamp_ms: u64,
    pub runtime_version: String,
    pub wire_package: String,
    pub state_schema_version: u32,
    pub protection_level: ProtectionLevel,
    pub threat_type: ThreatType,
    pub primary_score: f32,
    pub top_threat_scores: Vec<AuditThreatScore>,
    pub reason_codes: Vec<String>,
    pub ui_actions: Vec<UiAction>,
    pub parent_alert: AlertPriority,
    pub follow_ups: Vec<FollowUpAction>,
    pub crisis_resources: bool,
    pub contact_trend: Option<BehavioralTrend>,
    pub contact_circle_tier: Option<CircleTier>,
    pub request_id: String,
    pub sender_token: Option<ProtectedIdentifier>,
    pub conversation_token: Option<ProtectedIdentifier>,
}

pub fn tokenize_identifier(identifier: &str) -> ProtectedIdentifier {
    tokenize_identifier_with_salt(identifier, audit_token_salt())
}

fn tokenize_identifier_with_salt(identifier: &str, salt: &[u8]) -> ProtectedIdentifier {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(identifier.as_bytes());
    let digest = hasher.finalize();

    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }

    ProtectedIdentifier {
        token: hex[..AUDIT_IDENTIFIER_HEX_LEN].to_string(),
        scheme: AUDIT_IDENTIFIER_SCHEME.to_string(),
    }
}

fn audit_token_salt() -> &'static [u8] {
    static SALT: OnceLock<Vec<u8>> = OnceLock::new();
    SALT.get_or_init(resolve_audit_token_salt).as_slice()
}

fn resolve_audit_token_salt() -> Vec<u8> {
    if let Ok(value) = std::env::var(AUDIT_TOKEN_SALT_ENV) {
        if !value.trim().is_empty() {
            return value.into_bytes();
        }
    }

    let mut salt = [0u8; 32];
    if getrandom(&mut salt).is_ok() {
        return salt.to_vec();
    }

    let fallback = format!(
        "pid:{}-epoch_nanos:{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    Sha256::digest(fallback.as_bytes()).to_vec()
}

impl AuditRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn from_analysis_result(
        request_id: impl Into<String>,
        event_timestamp_ms: u64,
        runtime_version: impl Into<String>,
        wire_package: impl Into<String>,
        state_schema_version: u32,
        protection_level: ProtectionLevel,
        sender_id: Option<&str>,
        conversation_id: Option<&str>,
        result: &AnalysisResult,
    ) -> Self {
        let recommendation = result.recommended_action.as_ref();
        let contact_snapshot = result.contact_snapshot.as_ref();

        Self {
            schema_version: AUDIT_SCHEMA_VERSION.to_string(),
            event_timestamp_ms,
            runtime_version: runtime_version.into(),
            wire_package: wire_package.into(),
            state_schema_version,
            protection_level,
            threat_type: result.threat_type,
            primary_score: result.score,
            top_threat_scores: top_threat_scores(result),
            reason_codes: result.reason_codes.clone(),
            ui_actions: ui_actions(recommendation),
            parent_alert: parent_alert(recommendation),
            follow_ups: follow_ups(recommendation),
            crisis_resources: recommendation
                .map(|recommendation| recommendation.crisis_resources)
                .unwrap_or(false),
            contact_trend: contact_snapshot.map(|snapshot| snapshot.trend),
            contact_circle_tier: contact_snapshot.map(|snapshot| snapshot.circle_tier),
            request_id: request_id.into(),
            sender_token: sender_id.map(tokenize_identifier),
            conversation_token: conversation_id.map(tokenize_identifier),
        }
    }
}

fn top_threat_scores(result: &AnalysisResult) -> Vec<AuditThreatScore> {
    let mut scores = result
        .detected_threats
        .iter()
        .map(|(threat_type, score)| AuditThreatScore {
            threat_type: *threat_type,
            score: *score,
        })
        .collect::<Vec<_>>();

    if scores.is_empty() && result.threat_type != ThreatType::None {
        scores.push(AuditThreatScore {
            threat_type: result.threat_type,
            score: result.score,
        });
    }

    scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));
    scores.truncate(3);
    scores
}

fn ui_actions(recommendation: Option<&ActionRecommendation>) -> Vec<UiAction> {
    recommendation
        .map(|recommendation| recommendation.ui_actions.clone())
        .unwrap_or_default()
}

fn parent_alert(recommendation: Option<&ActionRecommendation>) -> AlertPriority {
    recommendation
        .map(|recommendation| recommendation.parent_alert)
        .unwrap_or(AlertPriority::None)
}

fn follow_ups(recommendation: Option<&ActionRecommendation>) -> Vec<FollowUpAction> {
    recommendation
        .map(|recommendation| recommendation.follow_ups.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, Confidence, ContactSnapshot, DetectionSignal, RiskBreakdown, ThreatType};

    fn sample_result() -> AnalysisResult {
        AnalysisResult {
            threat_type: ThreatType::Grooming,
            confidence: Confidence::High,
            action: Action::Warn,
            score: 0.91,
            explanation: "detected grooming pattern".to_string(),
            detected_threats: vec![
                (ThreatType::Grooming, 0.91),
                (ThreatType::Manipulation, 0.72),
            ],
            signals: vec![DetectionSignal::pattern(
                ThreatType::Grooming,
                0.91,
                Confidence::High,
                "conversation.grooming.stage_sequence",
                "stage sequence",
            )],
            recommended_action: Some(ActionRecommendation {
                parent_alert: AlertPriority::High,
                follow_ups: vec![FollowUpAction::MonitorConversation],
                crisis_resources: false,
                ui_actions: vec![UiAction::SuggestBlockContact, UiAction::SuggestReport],
                reason_codes: vec!["conversation.grooming.stage_sequence".to_string()],
            }),
            risk_breakdown: RiskBreakdown {
                content: 0.3,
                conversation: 0.8,
                link: 0.0,
                abuse: 0.1,
            },
            contact_snapshot: Some(ContactSnapshot {
                sender_id: "coach_realistic".to_string(),
                rating: 14.0,
                trust_level: 0.2,
                circle_tier: CircleTier::New,
                trend: BehavioralTrend::RapidWorsening,
                is_trusted: false,
                is_new_contact: true,
                first_seen_ms: 1_000,
                last_seen_ms: 2_000,
                conversation_count: 1,
            }),
            reason_codes: vec![
                "conversation.grooming.stage_sequence".to_string(),
                "conversation.grooming.new_contact_flattery".to_string(),
            ],
            inference: Default::default(),
            analysis_time_us: 420,
        }
    }

    #[test]
    fn tokenize_identifier_is_deterministic_and_not_plaintext() {
        let first = tokenize_identifier("child_sender_42");
        let second = tokenize_identifier("child_sender_42");

        assert_eq!(first, second);
        assert_ne!(first.token, "child_sender_42");
        assert_eq!(first.scheme, AUDIT_IDENTIFIER_SCHEME);
        assert_eq!(first.token.len(), AUDIT_IDENTIFIER_HEX_LEN);
    }

    #[test]
    fn tokenize_identifier_changes_when_salt_changes() {
        let first = tokenize_identifier_with_salt("child_sender_42", b"salt-a");
        let second = tokenize_identifier_with_salt("child_sender_42", b"salt-b");

        assert_ne!(first.token, second.token);
    }

    #[test]
    fn audit_record_omits_raw_identifiers_from_serialized_json() {
        let record = AuditRecord::from_analysis_result(
            "req_1",
            10_000,
            "0.1.0",
            "aura.messenger.v1",
            2,
            ProtectionLevel::High,
            Some("coach_realistic"),
            Some("conv_secret"),
            &sample_result(),
        );

        let value = serde_json::to_value(&record).expect("serialize audit record");
        assert!(value.get("sender_id").is_none());
        assert!(value.get("conversation_id").is_none());
        assert!(value.get("text").is_none());
        assert!(value.get("message_text").is_none());

        let json = serde_json::to_string(&record).expect("serialize audit record json");
        assert!(!json.contains("coach_realistic"));
        assert!(!json.contains("conv_secret"));
        assert!(!json.contains("detected grooming pattern"));
    }

    #[test]
    fn audit_record_carries_reason_codes_actions_and_top_scores() {
        let record = AuditRecord::from_analysis_result(
            "req_2",
            20_000,
            "0.1.0",
            "aura.messenger.v1",
            2,
            ProtectionLevel::High,
            Some("coach_realistic"),
            Some("conv_secret"),
            &sample_result(),
        );

        assert_eq!(record.reason_codes.len(), 2);
        assert_eq!(record.ui_actions.len(), 2);
        assert_eq!(record.parent_alert, AlertPriority::High);
        assert_eq!(record.top_threat_scores.len(), 2);
        assert_eq!(
            record.top_threat_scores[0].threat_type,
            ThreatType::Grooming
        );
        assert_eq!(record.contact_trend, Some(BehavioralTrend::RapidWorsening));
        assert_eq!(record.contact_circle_tier, Some(CircleTier::New));
    }
}
