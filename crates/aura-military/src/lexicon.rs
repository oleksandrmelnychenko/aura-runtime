use std::sync::OnceLock;

use aura_domain::{
    validate_lexical_rules, validate_schema_version, DomainPolicyThresholds, LexicalRuleRecord,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MilitaryLexicon {
    schema_version: u32,
    #[serde(default)]
    policy: MilitaryPolicy,
    opsec: Vec<LexicalRuleRecord>,
    coordinate_leak: Vec<LexicalRuleRecord>,
    psyops: Vec<LexicalRuleRecord>,
    social_eng: Vec<LexicalRuleRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MilitaryPolicy {
    #[serde(default = "default_warn_priority")]
    warn_priority: u8,
    #[serde(default = "default_critical_warn_priority")]
    critical_warn_priority: u8,
    #[serde(default = "default_priority_escalation_priority")]
    priority_escalation_priority: u8,
}

impl Default for MilitaryPolicy {
    fn default() -> Self {
        Self {
            warn_priority: default_warn_priority(),
            critical_warn_priority: default_critical_warn_priority(),
            priority_escalation_priority: default_priority_escalation_priority(),
        }
    }
}

fn default_warn_priority() -> u8 {
    95
}

fn default_critical_warn_priority() -> u8 {
    100
}

fn default_priority_escalation_priority() -> u8 {
    90
}

static MILITARY_LEXICON: OnceLock<MilitaryLexicon> = OnceLock::new();

fn military_lexicon() -> &'static MilitaryLexicon {
    MILITARY_LEXICON.get_or_init(|| {
        let raw = include_str!("../data/lexicon.json");
        let lexicon: MilitaryLexicon =
            serde_json::from_str(raw).expect("invalid military lexical rule pack");
        validate_schema_version(lexicon.schema_version, "military lexicon")
            .expect("unsupported military lexicon schema version");
        validate_lexical_rules(&lexicon.opsec).expect("invalid military.opsec rules");
        validate_lexical_rules(&lexicon.coordinate_leak)
            .expect("invalid military.coordinate_leak rules");
        validate_lexical_rules(&lexicon.psyops).expect("invalid military.psyops rules");
        validate_lexical_rules(&lexicon.social_eng).expect("invalid military.social_eng rules");
        validate_policy(&lexicon.policy).expect("invalid military.policy");
        lexicon
    })
}

fn validate_policy(policy: &MilitaryPolicy) -> Result<(), String> {
    if policy.warn_priority == 0 {
        return Err("warn_priority must be >= 1".to_string());
    }
    if policy.critical_warn_priority == 0 {
        return Err("critical_warn_priority must be >= 1".to_string());
    }
    if policy.critical_warn_priority < policy.warn_priority {
        return Err("critical_warn_priority must be >= warn_priority".to_string());
    }
    if policy.priority_escalation_priority == 0 {
        return Err("priority_escalation_priority must be >= 1".to_string());
    }
    Ok(())
}

pub fn opsec_rules() -> &'static [LexicalRuleRecord] {
    &military_lexicon().opsec
}

pub fn coordinate_rules() -> &'static [LexicalRuleRecord] {
    &military_lexicon().coordinate_leak
}

pub fn psyops_rules() -> &'static [LexicalRuleRecord] {
    &military_lexicon().psyops
}

pub fn social_eng_rules() -> &'static [LexicalRuleRecord] {
    &military_lexicon().social_eng
}

pub fn policy_thresholds() -> DomainPolicyThresholds {
    let policy = &military_lexicon().policy;
    DomainPolicyThresholds {
        warn_priority: policy.warn_priority,
        critical_warn_priority: policy.critical_warn_priority,
    }
}

pub fn priority_escalation_priority() -> u8 {
    military_lexicon().policy.priority_escalation_priority
}

#[cfg(test)]
mod tests {
    use super::military_lexicon;

    #[test]
    fn military_lexicon_pack_loads_and_validates() {
        let _ = military_lexicon();
    }
}
