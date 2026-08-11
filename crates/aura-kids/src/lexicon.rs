use std::sync::OnceLock;

use aura_domain::{
    validate_lexical_rules, validate_schema_version, DomainPolicyPackEvidence,
    DomainPolicyThresholds, LexicalRuleRecord,
};
use serde::Deserialize;

const KIDS_LEXICON_JSON: &str = include_str!("../data/lexicon.json");

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct KidsLexicon {
    schema_version: u32,
    #[serde(default)]
    policy: KidsPolicy,
    grooming: Vec<LexicalRuleRecord>,
    bullying: Vec<LexicalRuleRecord>,
    selfharm: Vec<LexicalRuleRecord>,
    manipulation: Vec<LexicalRuleRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct KidsPolicy {
    #[serde(default = "default_warn_priority")]
    warn_priority: u8,
    #[serde(default = "default_critical_warn_priority")]
    critical_warn_priority: u8,
    #[serde(default = "default_guardian_escalation_priority")]
    guardian_escalation_priority: u8,
}

impl Default for KidsPolicy {
    fn default() -> Self {
        Self {
            warn_priority: default_warn_priority(),
            critical_warn_priority: default_critical_warn_priority(),
            guardian_escalation_priority: default_guardian_escalation_priority(),
        }
    }
}

fn default_warn_priority() -> u8 {
    90
}

fn default_critical_warn_priority() -> u8 {
    95
}

fn default_guardian_escalation_priority() -> u8 {
    92
}

static KIDS_LEXICON: OnceLock<KidsLexicon> = OnceLock::new();

fn kids_lexicon() -> &'static KidsLexicon {
    KIDS_LEXICON.get_or_init(|| {
        let lexicon: KidsLexicon =
            serde_json::from_str(KIDS_LEXICON_JSON).expect("invalid kids lexical rule pack");
        validate_schema_version(lexicon.schema_version, "kids lexicon")
            .expect("unsupported kids lexicon schema version");
        validate_lexical_rules(&lexicon.grooming).expect("invalid kids.grooming rules");
        validate_lexical_rules(&lexicon.bullying).expect("invalid kids.bullying rules");
        validate_lexical_rules(&lexicon.selfharm).expect("invalid kids.selfharm rules");
        validate_lexical_rules(&lexicon.manipulation).expect("invalid kids.manipulation rules");
        validate_policy(&lexicon.policy).expect("invalid kids.policy");
        lexicon
    })
}

pub(crate) fn evidence() -> DomainPolicyPackEvidence {
    let lexicon = kids_lexicon();
    let rule_count = lexicon.grooming.len()
        + lexicon.bullying.len()
        + lexicon.selfharm.len()
        + lexicon.manipulation.len();
    DomainPolicyPackEvidence::from_source(
        "aura.kids.lexical_policy",
        lexicon.schema_version,
        KIDS_LEXICON_JSON.as_bytes(),
        rule_count,
    )
}

fn validate_policy(policy: &KidsPolicy) -> Result<(), String> {
    if policy.warn_priority == 0 {
        return Err("warn_priority must be >= 1".to_string());
    }
    if policy.critical_warn_priority == 0 {
        return Err("critical_warn_priority must be >= 1".to_string());
    }
    if policy.critical_warn_priority < policy.warn_priority {
        return Err("critical_warn_priority must be >= warn_priority".to_string());
    }
    if policy.guardian_escalation_priority == 0 {
        return Err("guardian_escalation_priority must be >= 1".to_string());
    }
    Ok(())
}

pub fn grooming_rules() -> &'static [LexicalRuleRecord] {
    &kids_lexicon().grooming
}

pub fn bullying_rules() -> &'static [LexicalRuleRecord] {
    &kids_lexicon().bullying
}

pub fn selfharm_rules() -> &'static [LexicalRuleRecord] {
    &kids_lexicon().selfharm
}

pub fn manipulation_rules() -> &'static [LexicalRuleRecord] {
    &kids_lexicon().manipulation
}

pub fn policy_thresholds() -> DomainPolicyThresholds {
    let policy = &kids_lexicon().policy;
    DomainPolicyThresholds {
        warn_priority: policy.warn_priority,
        critical_warn_priority: policy.critical_warn_priority,
    }
}

pub fn guardian_escalation_priority() -> u8 {
    kids_lexicon().policy.guardian_escalation_priority
}

#[cfg(test)]
mod tests {
    use super::{evidence, kids_lexicon};

    #[test]
    fn kids_lexicon_pack_loads_and_validates() {
        let _ = kids_lexicon();
    }

    #[test]
    fn kids_lexicon_evidence_is_release_pinned() {
        let evidence = evidence();

        assert_eq!(evidence.schema_version, 1);
        assert_eq!(evidence.rule_count, 23);
        assert_eq!(
            evidence.sha256,
            "9ceeacde143a5bb1449530a92227acf8e9538cc364af92511bcb7364d105f841"
        );
    }
}
