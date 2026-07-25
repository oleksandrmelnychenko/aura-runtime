use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::context::events::EventKind;
use crate::types::{DetectionLayer, DetectionSignal, ThreatType};

pub const CONTEXT_RULE_SCHEMA_VERSION: u32 = 1;
pub const INTERPRETATION_POLICY_VERSION: &str = "aura.context.interpretation.v1";
pub const MEMORY_POLICY_VERSION: &str = "aura.context.memory.v1";
pub const POLICY_POLICY_VERSION: &str = "aura.context.policy.v1";

const MAX_RULES_PER_PACK: usize = 64;
const MAX_RULE_ID_BYTES: usize = 96;
const MAX_POLICY_VERSION_BYTES: usize = 96;
const MAX_SELECTORS_PER_RULE: usize = 32;
const MAX_STRING_BYTES: usize = 160;

const INTERPRETATION_RULES_JSON: &str =
    include_str!("../../data/context_interpretation_rules.json");
const MEMORY_RULES_JSON: &str = include_str!("../../data/context_memory_rules.json");
const POLICY_RULES_JSON: &str = include_str!("../../data/context_policy_rules.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextRulePackKind {
    Interpretation,
    Memory,
    Policy,
}

impl std::fmt::Display for ContextRulePackKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Interpretation => "interpretation",
            Self::Memory => "memory",
            Self::Policy => "policy",
        })
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ContextRuleError {
    #[error("{pack} context rule pack JSON is invalid: {message}")]
    InvalidJson {
        pack: ContextRulePackKind,
        message: String,
    },
    #[error("{pack} context rule pack schema_version mismatch: expected {supported}, got {found}")]
    UnsupportedSchema {
        pack: ContextRulePackKind,
        found: u32,
        supported: u32,
    },
    #[error(
        "{pack} context rule pack policy_version mismatch: expected `{expected}`, got `{found}`"
    )]
    UnsupportedPolicyVersion {
        pack: ContextRulePackKind,
        found: String,
        expected: &'static str,
    },
    #[error("{pack} context rule pack is invalid: {message}")]
    InvalidPack {
        pack: ContextRulePackKind,
        message: String,
    },
    #[error("{pack} context rule `{rule_id}` is invalid: {message}")]
    InvalidRule {
        pack: ContextRulePackKind,
        rule_id: String,
        message: String,
    },
    #[error("{pack} context rule pack contains duplicate rule id `{rule_id}`")]
    DuplicateRuleId {
        pack: ContextRulePackKind,
        rule_id: String,
    },
    #[error("{pack} context rule pack contains conflicting condition `{condition}`")]
    ConflictingCondition {
        pack: ContextRulePackKind,
        condition: String,
    },
    #[error("failed to serialize canonical {pack} context rule pack: {message}")]
    CanonicalSerialization {
        pack: ContextRulePackKind,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InterpretationRulePack {
    schema_version: u32,
    policy_version: String,
    rules: Vec<InterpretationRule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemoryRulePack {
    schema_version: u32,
    policy_version: String,
    rules: Vec<MemoryRule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyRulePack {
    schema_version: u32,
    policy_version: String,
    rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InterpretationRule {
    pub(crate) id: String,
    pub(crate) priority: u16,
    pub(crate) condition: InterpretationCondition,
    pub(crate) effect: InterpretationEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InterpretationCondition {
    SupportiveNeutralOrOpposed,
    DirectedNewContactOneSided,
    Defender,
    SafeMediaContext,
    FriendlyTiming,
    SafeGamingBanter,
    DeescalatingPeerConflict,
    FriendlyPlayfulBanter,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum InterpretationEffect {
    SuppressSignals {
        selectors: Vec<SignalSelector>,
    },
    CorroborationBoost {
        threat_type: ThreatType,
        pattern_reason_prefix: String,
        ml_reason_code: String,
        score_add: f32,
        score_cap: f32,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemoryRule {
    pub(crate) id: String,
    pub(crate) priority: u16,
    pub(crate) condition: MemoryCondition,
    #[serde(default)]
    pub(crate) signal_selectors: Vec<SignalSelector>,
    #[serde(default)]
    pub(crate) event_selectors: Vec<EventSelector>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemoryCondition {
    Always,
    SubstancePressureContext,
    SelfReferentialDistressProfanity,
    DeescalatingPeerConflict,
    PlainPeerCompliment,
    NonRomanticGroupPraise,
    CompetitiveGamingBanter,
    CasualMediaShare,
    PlayfulBanter,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventSelector {
    pub(crate) kind: EventKind,
    #[serde(default)]
    pub(crate) unless_high_risk_grooming: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignalSelector {
    #[serde(default)]
    pub(crate) threat_types: Vec<ThreatType>,
    #[serde(default)]
    pub(crate) layer: Option<DetectionLayer>,
    #[serde(default)]
    pub(crate) max_score: Option<f32>,
    #[serde(default)]
    pub(crate) reason_code: Option<String>,
    #[serde(default)]
    pub(crate) reason_code_prefix: Option<String>,
    #[serde(default)]
    pub(crate) explanation_contains_any: Vec<String>,
    #[serde(default)]
    pub(crate) unless_high_risk_grooming: bool,
}

impl SignalSelector {
    pub(crate) fn matches(&self, signal: &DetectionSignal) -> bool {
        if !self.threat_types.is_empty() && !self.threat_types.contains(&signal.threat_type) {
            return false;
        }
        if self.layer.is_some_and(|layer| layer != signal.layer) {
            return false;
        }
        if self.max_score.is_some_and(|maximum| signal.score > maximum) {
            return false;
        }
        if self
            .reason_code
            .as_ref()
            .is_some_and(|reason| signal.reason_code != *reason)
        {
            return false;
        }
        if self
            .reason_code_prefix
            .as_ref()
            .is_some_and(|prefix| !signal.reason_code.starts_with(prefix))
        {
            return false;
        }
        if !self.explanation_contains_any.is_empty()
            && !self
                .explanation_contains_any
                .iter()
                .any(|needle| signal.explanation.contains(needle))
        {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyRule {
    pub(crate) id: String,
    pub(crate) priority: u16,
    pub(crate) condition: PolicyCondition,
    pub(crate) effect: PolicyEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyCondition {
    UnknownAdultMinor,
    SelfDeclared,
    SelfDeclaredPrivileged,
    SelfDeclaredPrivilegedMinor,
    VerifiedFamily,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyEffect {
    #[serde(default)]
    pub(crate) context_marker: Option<String>,
    #[serde(default)]
    pub(crate) reason_code: Option<String>,
    #[serde(default)]
    pub(crate) score_add: f32,
    #[serde(default)]
    pub(crate) threat_types: Vec<ThreatType>,
}

#[derive(Debug)]
pub(crate) struct ContextRulePacks {
    interpretation: InterpretationRulePack,
    memory: MemoryRulePack,
    policy: PolicyRulePack,
}

impl ContextRulePacks {
    pub(crate) fn parse(
        interpretation_json: &str,
        memory_json: &str,
        policy_json: &str,
    ) -> Result<Self, ContextRuleError> {
        let mut interpretation =
            parse_pack(interpretation_json, ContextRulePackKind::Interpretation)?;
        let mut memory = parse_pack(memory_json, ContextRulePackKind::Memory)?;
        let mut policy = parse_pack(policy_json, ContextRulePackKind::Policy)?;

        validate_interpretation_pack(&interpretation)?;
        validate_memory_pack(&memory)?;
        validate_policy_pack(&policy)?;

        sort_rules(&mut interpretation.rules);
        sort_rules(&mut memory.rules);
        sort_rules(&mut policy.rules);

        Ok(Self {
            interpretation,
            memory,
            policy,
        })
    }

    pub(crate) fn interpretation_rules(&self) -> &[InterpretationRule] {
        &self.interpretation.rules
    }

    pub(crate) fn memory_rules(&self) -> &[MemoryRule] {
        &self.memory.rules
    }

    pub(crate) fn policy_rules(&self) -> &[PolicyRule] {
        &self.policy.rules
    }

    fn evidence(&self) -> Result<ContextRulePackEvidence, ContextRuleError> {
        Ok(ContextRulePackEvidence {
            schema_version: CONTEXT_RULE_SCHEMA_VERSION,
            interpretation: pack_evidence(
                &self.interpretation,
                ContextRulePackKind::Interpretation,
                &self.interpretation.policy_version,
                self.interpretation.rules.len(),
            )?,
            memory: pack_evidence(
                &self.memory,
                ContextRulePackKind::Memory,
                &self.memory.policy_version,
                self.memory.rules.len(),
            )?,
            policy: pack_evidence(
                &self.policy,
                ContextRulePackKind::Policy,
                &self.policy.policy_version,
                self.policy.rules.len(),
            )?,
        })
    }
}

trait PrioritizedRule {
    fn id(&self) -> &str;
    fn priority(&self) -> u16;
}

impl PrioritizedRule for InterpretationRule {
    fn id(&self) -> &str {
        &self.id
    }

    fn priority(&self) -> u16 {
        self.priority
    }
}

impl PrioritizedRule for MemoryRule {
    fn id(&self) -> &str {
        &self.id
    }

    fn priority(&self) -> u16 {
        self.priority
    }
}

impl PrioritizedRule for PolicyRule {
    fn id(&self) -> &str {
        &self.id
    }

    fn priority(&self) -> u16 {
        self.priority
    }
}

fn sort_rules<T: PrioritizedRule>(rules: &mut [T]) {
    rules.sort_by(|left, right| {
        right
            .priority()
            .cmp(&left.priority())
            .then_with(|| left.id().cmp(right.id()))
    });
}

fn parse_pack<T>(json: &str, pack: ContextRulePackKind) -> Result<T, ContextRuleError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(json).map_err(|error| ContextRuleError::InvalidJson {
        pack,
        message: error.to_string(),
    })
}

fn validate_interpretation_pack(pack: &InterpretationRulePack) -> Result<(), ContextRuleError> {
    validate_pack_header(
        ContextRulePackKind::Interpretation,
        pack.schema_version,
        &pack.policy_version,
        INTERPRETATION_POLICY_VERSION,
        pack.rules.len(),
    )?;
    validate_rule_identity_and_conditions(
        ContextRulePackKind::Interpretation,
        &pack.rules,
        |rule| (&rule.id, rule.priority, format!("{:?}", rule.condition)),
    )?;
    for rule in &pack.rules {
        match &rule.effect {
            InterpretationEffect::SuppressSignals { selectors } => {
                validate_selector_count(
                    ContextRulePackKind::Interpretation,
                    &rule.id,
                    selectors.len(),
                )?;
                for selector in selectors {
                    validate_signal_selector(
                        ContextRulePackKind::Interpretation,
                        &rule.id,
                        selector,
                    )?;
                }
            }
            InterpretationEffect::CorroborationBoost {
                pattern_reason_prefix,
                ml_reason_code,
                score_add,
                score_cap,
                ..
            } => {
                validate_bounded_string(
                    ContextRulePackKind::Interpretation,
                    &rule.id,
                    "pattern_reason_prefix",
                    pattern_reason_prefix,
                )?;
                validate_bounded_string(
                    ContextRulePackKind::Interpretation,
                    &rule.id,
                    "ml_reason_code",
                    ml_reason_code,
                )?;
                if !score_add.is_finite() || !(0.0..=1.0).contains(score_add) {
                    return invalid_rule(
                        ContextRulePackKind::Interpretation,
                        &rule.id,
                        format!("score_add must be finite and within 0..=1, got {score_add}"),
                    );
                }
                if !score_cap.is_finite() || !(0.0..=1.0).contains(score_cap) {
                    return invalid_rule(
                        ContextRulePackKind::Interpretation,
                        &rule.id,
                        format!("score_cap must be finite and within 0..=1, got {score_cap}"),
                    );
                }
                if score_add > score_cap {
                    return invalid_rule(
                        ContextRulePackKind::Interpretation,
                        &rule.id,
                        "score_add must not exceed score_cap",
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_memory_pack(pack: &MemoryRulePack) -> Result<(), ContextRuleError> {
    validate_pack_header(
        ContextRulePackKind::Memory,
        pack.schema_version,
        &pack.policy_version,
        MEMORY_POLICY_VERSION,
        pack.rules.len(),
    )?;
    validate_rule_identity_and_conditions(ContextRulePackKind::Memory, &pack.rules, |rule| {
        (&rule.id, rule.priority, format!("{:?}", rule.condition))
    })?;
    for rule in &pack.rules {
        let selector_count = rule.signal_selectors.len() + rule.event_selectors.len();
        validate_selector_count(ContextRulePackKind::Memory, &rule.id, selector_count)?;
        if selector_count == 0 {
            return invalid_rule(
                ContextRulePackKind::Memory,
                &rule.id,
                "at least one signal or event selector is required",
            );
        }
        for selector in &rule.signal_selectors {
            validate_signal_selector(ContextRulePackKind::Memory, &rule.id, selector)?;
        }
        let mut event_kinds = HashSet::new();
        for selector in &rule.event_selectors {
            if !event_kinds.insert(&selector.kind) {
                return invalid_rule(
                    ContextRulePackKind::Memory,
                    &rule.id,
                    format!("duplicate event selector {:?}", selector.kind),
                );
            }
        }
    }
    Ok(())
}

fn validate_policy_pack(pack: &PolicyRulePack) -> Result<(), ContextRuleError> {
    validate_pack_header(
        ContextRulePackKind::Policy,
        pack.schema_version,
        &pack.policy_version,
        POLICY_POLICY_VERSION,
        pack.rules.len(),
    )?;
    validate_rule_identity_and_conditions(ContextRulePackKind::Policy, &pack.rules, |rule| {
        (&rule.id, rule.priority, format!("{:?}", rule.condition))
    })?;
    for rule in &pack.rules {
        if let Some(context_marker) = &rule.effect.context_marker {
            validate_bounded_string(
                ContextRulePackKind::Policy,
                &rule.id,
                "context_marker",
                context_marker,
            )?;
        }
        if let Some(reason_code) = &rule.effect.reason_code {
            validate_bounded_string(
                ContextRulePackKind::Policy,
                &rule.id,
                "reason_code",
                reason_code,
            )?;
        }
        if !rule.effect.score_add.is_finite() || !(0.0..=1.0).contains(&rule.effect.score_add) {
            return invalid_rule(
                ContextRulePackKind::Policy,
                &rule.id,
                format!(
                    "score_add must be finite and within 0..=1, got {}",
                    rule.effect.score_add
                ),
            );
        }
        if rule.effect.score_add > 0.0 && rule.effect.threat_types.is_empty() {
            return invalid_rule(
                ContextRulePackKind::Policy,
                &rule.id,
                "score_add requires at least one threat_type",
            );
        }
        if rule.effect.context_marker.is_none()
            && rule.effect.reason_code.is_none()
            && rule.effect.score_add == 0.0
        {
            return invalid_rule(
                ContextRulePackKind::Policy,
                &rule.id,
                "at least one context_marker, reason_code, or score_add is required",
            );
        }
        ensure_unique_threat_types(
            ContextRulePackKind::Policy,
            &rule.id,
            &rule.effect.threat_types,
        )?;
    }
    Ok(())
}

fn validate_pack_header(
    pack: ContextRulePackKind,
    schema_version: u32,
    policy_version: &str,
    expected_policy_version: &'static str,
    rule_count: usize,
) -> Result<(), ContextRuleError> {
    if schema_version != CONTEXT_RULE_SCHEMA_VERSION {
        return Err(ContextRuleError::UnsupportedSchema {
            pack,
            found: schema_version,
            supported: CONTEXT_RULE_SCHEMA_VERSION,
        });
    }
    if policy_version != expected_policy_version {
        return Err(ContextRuleError::UnsupportedPolicyVersion {
            pack,
            found: policy_version.to_string(),
            expected: expected_policy_version,
        });
    }
    if policy_version.is_empty() || policy_version.len() > MAX_POLICY_VERSION_BYTES {
        return Err(ContextRuleError::InvalidPack {
            pack,
            message: format!(
                "policy_version length must be within 1..={MAX_POLICY_VERSION_BYTES} bytes"
            ),
        });
    }
    if rule_count == 0 || rule_count > MAX_RULES_PER_PACK {
        return Err(ContextRuleError::InvalidPack {
            pack,
            message: format!(
                "rule count must be within 1..={MAX_RULES_PER_PACK}, got {rule_count}"
            ),
        });
    }
    Ok(())
}

fn validate_rule_identity_and_conditions<T, F>(
    pack: ContextRulePackKind,
    rules: &[T],
    fields: F,
) -> Result<(), ContextRuleError>
where
    F: Fn(&T) -> (&str, u16, String),
{
    let mut ids = HashSet::with_capacity(rules.len());
    let mut conditions = HashSet::with_capacity(rules.len());
    for rule in rules {
        let (id, priority, condition) = fields(rule);
        if id.trim().is_empty() || id.len() > MAX_RULE_ID_BYTES {
            return invalid_rule(
                pack,
                id,
                format!("id length must be within 1..={MAX_RULE_ID_BYTES} bytes"),
            );
        }
        if priority == 0 {
            return invalid_rule(pack, id, "priority must be at least 1");
        }
        if !ids.insert(id) {
            return Err(ContextRuleError::DuplicateRuleId {
                pack,
                rule_id: id.to_string(),
            });
        }
        if !conditions.insert(condition.clone()) {
            return Err(ContextRuleError::ConflictingCondition { pack, condition });
        }
    }
    Ok(())
}

fn validate_selector_count(
    pack: ContextRulePackKind,
    rule_id: &str,
    count: usize,
) -> Result<(), ContextRuleError> {
    if count == 0 || count > MAX_SELECTORS_PER_RULE {
        return invalid_rule(
            pack,
            rule_id,
            format!("selector count must be within 1..={MAX_SELECTORS_PER_RULE}, got {count}"),
        );
    }
    Ok(())
}

fn validate_signal_selector(
    pack: ContextRulePackKind,
    rule_id: &str,
    selector: &SignalSelector,
) -> Result<(), ContextRuleError> {
    if selector.threat_types.is_empty()
        && selector.layer.is_none()
        && selector.max_score.is_none()
        && selector.reason_code.is_none()
        && selector.reason_code_prefix.is_none()
        && selector.explanation_contains_any.is_empty()
    {
        return invalid_rule(
            pack,
            rule_id,
            "signal selector must constrain at least one field",
        );
    }
    if let Some(max_score) = selector.max_score {
        if !max_score.is_finite() || !(0.0..=1.0).contains(&max_score) {
            return invalid_rule(
                pack,
                rule_id,
                format!("selector max_score must be finite and within 0..=1, got {max_score}"),
            );
        }
    }
    if let Some(reason_code) = &selector.reason_code {
        validate_bounded_string(pack, rule_id, "reason_code", reason_code)?;
    }
    if let Some(prefix) = &selector.reason_code_prefix {
        validate_bounded_string(pack, rule_id, "reason_code_prefix", prefix)?;
    }
    if selector.reason_code.is_some() && selector.reason_code_prefix.is_some() {
        return invalid_rule(
            pack,
            rule_id,
            "signal selector cannot define both reason_code and reason_code_prefix",
        );
    }
    if selector.explanation_contains_any.len() > MAX_SELECTORS_PER_RULE {
        return invalid_rule(
            pack,
            rule_id,
            format!(
                "explanation_contains_any must contain at most {MAX_SELECTORS_PER_RULE} values"
            ),
        );
    }
    for needle in &selector.explanation_contains_any {
        validate_bounded_string(pack, rule_id, "explanation_contains_any", needle)?;
    }
    ensure_unique_threat_types(pack, rule_id, &selector.threat_types)
}

fn ensure_unique_threat_types(
    pack: ContextRulePackKind,
    rule_id: &str,
    threat_types: &[ThreatType],
) -> Result<(), ContextRuleError> {
    let mut unique = HashSet::with_capacity(threat_types.len());
    for threat_type in threat_types {
        if !unique.insert(*threat_type) {
            return invalid_rule(
                pack,
                rule_id,
                format!("duplicate threat_type {threat_type:?}"),
            );
        }
    }
    Ok(())
}

fn validate_bounded_string(
    pack: ContextRulePackKind,
    rule_id: &str,
    field: &str,
    value: &str,
) -> Result<(), ContextRuleError> {
    if value.trim().is_empty() || value.len() > MAX_STRING_BYTES {
        return invalid_rule(
            pack,
            rule_id,
            format!("{field} length must be within 1..={MAX_STRING_BYTES} bytes"),
        );
    }
    Ok(())
}

fn invalid_rule<T>(
    pack: ContextRulePackKind,
    rule_id: &str,
    message: impl Into<String>,
) -> Result<T, ContextRuleError> {
    Err(ContextRuleError::InvalidRule {
        pack,
        rule_id: rule_id.to_string(),
        message: message.into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextRulePackDigest {
    pub policy_version: String,
    pub sha256: String,
    pub rule_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextRulePackEvidence {
    pub schema_version: u32,
    pub interpretation: ContextRulePackDigest,
    pub memory: ContextRulePackDigest,
    pub policy: ContextRulePackDigest,
}

fn pack_evidence<T: Serialize>(
    pack: &T,
    kind: ContextRulePackKind,
    policy_version: &str,
    rule_count: usize,
) -> Result<ContextRulePackDigest, ContextRuleError> {
    let canonical =
        serde_json::to_vec(pack).map_err(|error| ContextRuleError::CanonicalSerialization {
            pack: kind,
            message: error.to_string(),
        })?;
    let digest = Sha256::digest(canonical);
    let mut sha256 = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(sha256, "{byte:02x}");
    }
    Ok(ContextRulePackDigest {
        policy_version: policy_version.to_string(),
        sha256,
        rule_count,
    })
}

static BUILTIN_RULE_PACKS: OnceLock<Result<Arc<ContextRulePacks>, ContextRuleError>> =
    OnceLock::new();

pub(crate) fn builtin_context_rule_packs() -> Result<Arc<ContextRulePacks>, ContextRuleError> {
    BUILTIN_RULE_PACKS
        .get_or_init(|| {
            ContextRulePacks::parse(
                INTERPRETATION_RULES_JSON,
                MEMORY_RULES_JSON,
                POLICY_RULES_JSON,
            )
            .map(Arc::new)
        })
        .clone()
}

pub fn builtin_context_rule_pack_evidence() -> Result<ContextRulePackEvidence, ContextRuleError> {
    builtin_context_rule_packs()?.evidence()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rule_packs_parse_validate_and_emit_canonical_evidence() {
        let evidence = builtin_context_rule_pack_evidence();

        assert!(evidence.is_ok(), "rule pack error: {evidence:?}");
    }

    #[test]
    fn parser_rejects_unknown_top_level_field() {
        let invalid = INTERPRETATION_RULES_JSON.replacen(
            "\"schema_version\": 1,",
            "\"schema_version\": 1, \"unknown\": true,",
            1,
        );
        let error = ContextRulePacks::parse(&invalid, MEMORY_RULES_JSON, POLICY_RULES_JSON)
            .expect_err("unknown field must fail");

        assert!(matches!(error, ContextRuleError::InvalidJson { .. }));
    }

    #[test]
    fn parser_rejects_future_schema_version() {
        let invalid =
            MEMORY_RULES_JSON.replacen("\"schema_version\": 1", "\"schema_version\": 99", 1);
        let error = ContextRulePacks::parse(INTERPRETATION_RULES_JSON, &invalid, POLICY_RULES_JSON)
            .expect_err("future schema must fail");

        assert!(matches!(
            error,
            ContextRuleError::UnsupportedSchema {
                pack: ContextRulePackKind::Memory,
                found: 99,
                ..
            }
        ));
    }

    #[test]
    fn parser_rejects_unknown_policy_version() {
        let invalid =
            POLICY_RULES_JSON.replacen(POLICY_POLICY_VERSION, "aura.context.policy.future", 1);
        let error = ContextRulePacks::parse(INTERPRETATION_RULES_JSON, MEMORY_RULES_JSON, &invalid)
            .expect_err("unknown policy version must fail");

        assert!(matches!(
            error,
            ContextRuleError::UnsupportedPolicyVersion {
                pack: ContextRulePackKind::Policy,
                ..
            }
        ));
    }

    #[test]
    fn parser_rejects_duplicate_rule_id() {
        let mut value: serde_json::Value =
            serde_json::from_str(POLICY_RULES_JSON).expect("test JSON");
        let duplicate = value["rules"][0].clone();
        value["rules"]
            .as_array_mut()
            .expect("rules array")
            .push(duplicate);
        let invalid = serde_json::to_string(&value).expect("test JSON");
        let error = ContextRulePacks::parse(INTERPRETATION_RULES_JSON, MEMORY_RULES_JSON, &invalid)
            .expect_err("duplicate id must fail");

        assert!(matches!(
            error,
            ContextRuleError::DuplicateRuleId {
                pack: ContextRulePackKind::Policy,
                ..
            }
        ));
    }

    #[test]
    fn parser_rejects_conflicting_condition_even_with_different_priority() {
        let mut value: serde_json::Value =
            serde_json::from_str(INTERPRETATION_RULES_JSON).expect("test JSON");
        let mut conflict = value["rules"][0].clone();
        conflict["id"] = serde_json::Value::String("conflicting-rule".to_string());
        conflict["priority"] = serde_json::json!(999);
        value["rules"]
            .as_array_mut()
            .expect("rules array")
            .push(conflict);
        let invalid = serde_json::to_string(&value).expect("test JSON");
        let error = ContextRulePacks::parse(&invalid, MEMORY_RULES_JSON, POLICY_RULES_JSON)
            .expect_err("conflicting condition must fail");

        assert!(matches!(
            error,
            ContextRuleError::ConflictingCondition {
                pack: ContextRulePackKind::Interpretation,
                ..
            }
        ));
    }

    #[test]
    fn parser_rejects_rule_id_over_boundary() {
        let mut value: serde_json::Value =
            serde_json::from_str(MEMORY_RULES_JSON).expect("test JSON");
        value["rules"][0]["id"] = serde_json::Value::String("x".repeat(MAX_RULE_ID_BYTES + 1));
        let invalid = serde_json::to_string(&value).expect("test JSON");
        let error = ContextRulePacks::parse(INTERPRETATION_RULES_JSON, &invalid, POLICY_RULES_JSON)
            .expect_err("overlong rule id must fail");

        assert!(matches!(
            error,
            ContextRuleError::InvalidRule {
                pack: ContextRulePackKind::Memory,
                ..
            }
        ));
    }

    #[test]
    fn policy_pack_cannot_define_product_action() {
        let mut value: serde_json::Value =
            serde_json::from_str(POLICY_RULES_JSON).expect("test JSON");
        value["rules"][0]["effect"]["action"] = serde_json::json!("block");
        let invalid = serde_json::to_string(&value).expect("test JSON");
        let error = ContextRulePacks::parse(INTERPRETATION_RULES_JSON, MEMORY_RULES_JSON, &invalid)
            .expect_err("product action must not be part of a context rule");

        assert!(matches!(error, ContextRuleError::InvalidJson { .. }));
    }

    #[test]
    fn parser_sorts_rules_by_priority_then_id() {
        let mut value: serde_json::Value =
            serde_json::from_str(MEMORY_RULES_JSON).expect("test JSON");
        let rules = value["rules"].as_array_mut().expect("rules array");
        rules.reverse();
        rules[0]["priority"] = serde_json::json!(1_000);
        rules[0]["id"] = serde_json::json!("z-tiebreak");
        rules[1]["priority"] = serde_json::json!(1_000);
        rules[1]["id"] = serde_json::json!("a-tiebreak");
        let reversed = serde_json::to_string(&value).expect("test JSON");
        let packs =
            ContextRulePacks::parse(INTERPRETATION_RULES_JSON, &reversed, POLICY_RULES_JSON)
                .expect("valid packs");
        let rules = packs.memory_rules();
        let priorities = rules.iter().map(|rule| rule.priority).collect::<Vec<_>>();

        assert!(priorities.windows(2).all(|pair| pair[0] >= pair[1]));
        assert_eq!(rules[0].id, "a-tiebreak");
        assert_eq!(rules[1].id, "z-tiebreak");
    }
}
