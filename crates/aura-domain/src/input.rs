use serde::{Deserialize, Serialize};

/// Maximum UTF-8 byte length exposed to on-device domain detectors.
pub const MAX_DOMAIN_TEXT_BYTES: usize = 10_000;

/// Returns a UTF-8-safe prefix within [`MAX_DOMAIN_TEXT_BYTES`].
#[must_use]
pub fn truncate_domain_text(text: &str) -> &str {
    if text.len() <= MAX_DOMAIN_TEXT_BYTES {
        return text;
    }
    let mut end = MAX_DOMAIN_TEXT_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Sensitivity profile selected by the owning account policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainRiskProfile {
    /// Default sensitivity and escalation thresholds.
    #[default]
    Normal,
    /// More conservative thresholds for higher-risk operation.
    Strict,
}

/// Conversation topology exposed to domain modules.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DomainConversationType {
    /// One-to-one conversation.
    #[default]
    Direct,
    /// Multi-participant conversation.
    Group,
}

/// ML safety scores passed as hints from the ML pipeline to domain modules.
///
/// Allows domain modules (e.g., aura-kids) to incorporate ML confidence
/// into their conversation memory and escalation logic even when no
/// lexicon rule fires.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct MlSafetyHint {
    /// Normalized grooming-model score.
    pub grooming: f32,
    /// Normalized bullying-model score.
    pub bullying: f32,
    /// Normalized self-harm-model score.
    pub self_harm: f32,
    /// Normalized manipulation-model score.
    pub manipulation: f32,
}

impl MlSafetyHint {
    /// Returns whether every model score is finite and normalized to `0..=1`.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        [
            self.grooming,
            self.bullying,
            self.self_harm,
            self.manipulation,
        ]
        .into_iter()
        .all(|score| score.is_finite() && (0.0..=1.0).contains(&score))
    }

    /// Replaces each invalid score with zero while preserving valid channels.
    #[must_use]
    pub fn sanitized(self) -> Self {
        fn normalized_or_zero(score: f32) -> f32 {
            if score.is_finite() && (0.0..=1.0).contains(&score) {
                score
            } else {
                0.0
            }
        }
        Self {
            grooming: normalized_or_zero(self.grooming),
            bullying: normalized_or_zero(self.bullying),
            self_harm: normalized_or_zero(self.self_harm),
            manipulation: normalized_or_zero(self.manipulation),
        }
    }

    /// Returns whether a valid score reaches a valid normalized threshold.
    #[must_use]
    pub fn has_any_signal(&self, threshold: f32) -> bool {
        let hint = self.sanitized();
        threshold.is_finite()
            && (0.0..=1.0).contains(&threshold)
            && (hint.grooming >= threshold
                || hint.bullying >= threshold
                || hint.self_harm >= threshold
                || hint.manipulation >= threshold)
    }

    /// Returns the largest valid model score after invalid channels are zeroed.
    #[must_use]
    pub fn max_score(&self) -> f32 {
        let hint = self.sanitized();
        hint.grooming
            .max(hint.bullying)
            .max(hint.self_harm)
            .max(hint.manipulation)
    }
}

/// Bounded message projection supplied to a selected domain module.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainInput {
    /// Message text when content analysis is permitted.
    pub text: Option<String>,
    /// Optional language hint; detectors must tolerate its absence.
    pub language: Option<String>,
    /// Validated language evidence from the local protobuf boundary.
    #[serde(skip)]
    pub language_evidence: Option<crate::LanguageEvidence>,
    /// Sender identity scoped to the local runtime.
    pub sender_id: Option<String>,
    /// Conversation identity scoped to the local runtime.
    pub conversation_id: Option<String>,
    /// Account-selected risk sensitivity.
    #[serde(default)]
    pub risk_profile: DomainRiskProfile,
    /// Direct or group conversation topology.
    #[serde(default)]
    pub conversation_type: DomainConversationType,
    /// ML safety scores from the unified model, if available.
    /// Domain modules use these to feed sub-threshold ML detections
    /// into conversation memory for trend tracking.
    #[serde(default)]
    pub ml_safety_hint: Option<MlSafetyHint>,
}

#[cfg(test)]
mod tests {
    use super::{truncate_domain_text, MlSafetyHint, MAX_DOMAIN_TEXT_BYTES};

    #[test]
    fn domain_text_bound_preserves_utf8_boundary() {
        let text = format!("{}🙂suffix", "a".repeat(MAX_DOMAIN_TEXT_BYTES - 1));
        let truncated = truncate_domain_text(&text);

        assert!(truncated.len() <= MAX_DOMAIN_TEXT_BYTES);
        assert!(text.starts_with(truncated));
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }

    #[test]
    fn non_finite_ml_channel_is_zeroed_without_losing_valid_channels() {
        let hint = MlSafetyHint {
            grooming: f32::NAN,
            bullying: 0.9,
            ..MlSafetyHint::default()
        };

        assert!(!hint.is_valid());
        assert!(hint.has_any_signal(0.8));
        assert!((hint.max_score() - 0.9).abs() < f32::EPSILON);
        assert!(hint.sanitized().grooming.abs() < f32::EPSILON);
    }

    #[test]
    fn normalized_ml_hint_reports_maximum_signal() {
        let hint = MlSafetyHint {
            grooming: 0.2,
            bullying: 0.8,
            self_harm: 0.4,
            manipulation: 0.6,
        };

        assert!(hint.is_valid());
        assert!(hint.has_any_signal(0.8));
        assert!((hint.max_score() - 0.8).abs() < f32::EPSILON);
    }
}
