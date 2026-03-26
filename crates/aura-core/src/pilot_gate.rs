use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ProtectionLevel, ShadowModeBundle};

pub const PILOT_GATE_SCHEMA_VERSION: &str = "aura.pilot_gate_report.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotGateStatus {
    Pass,
    Fail,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotReviewArea {
    FalsePositiveHotspots,
    SelfHarmBoundaryCases,
    TrustedAdultScenarios,
    ReputationImageAbuse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotReviewSignoffStatus {
    Approved,
    Pending,
    NeedsChanges,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotRollbackSeverity {
    High,
    Urgent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PilotGateConfig {
    pub min_shadow_runs: usize,
    pub min_shadow_total_events: usize,
    pub require_release_pass: bool,
    pub require_pilot_regression_pass: bool,
    pub require_kids_memory_pass: bool,
    pub require_kids_preprod_dry_run_pass: bool,
    pub required_review_areas: Vec<PilotReviewArea>,
}

impl Default for PilotGateConfig {
    fn default() -> Self {
        Self {
            min_shadow_runs: 2,
            min_shadow_total_events: 500,
            require_release_pass: true,
            require_pilot_regression_pass: true,
            require_kids_memory_pass: false,
            require_kids_preprod_dry_run_pass: false,
            required_review_areas: vec![
                PilotReviewArea::FalsePositiveHotspots,
                PilotReviewArea::SelfHarmBoundaryCases,
                PilotReviewArea::TrustedAdultScenarios,
                PilotReviewArea::ReputationImageAbuse,
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PilotReleaseSnapshot {
    pub schema_version: Option<String>,
    pub overall_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PilotRegressionSnapshot {
    pub schema_version: Option<String>,
    pub overall_status: String,
    pub suite_id: Option<String>,
    pub scenario_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PilotShadowSnapshot {
    pub schema_version: String,
    pub source_kind: String,
    pub source_label: String,
    pub wire_package: String,
    pub protection_level: ProtectionLevel,
    pub total_events: usize,
    pub threat_events: usize,
    pub finding_count: usize,
    pub raw_text_present: bool,
    pub raw_identifier_fields_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PilotReviewSignoff {
    pub area: PilotReviewArea,
    pub reviewer: String,
    pub status: PilotReviewSignoffStatus,
    pub reviewed_at_utc: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KidsMemoryHealthSnapshot {
    pub schema_version: Option<String>,
    pub overall_status: String,
    pub total_memory_hits: usize,
    pub missing_mandatory_reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KidsPreprodDryRunSnapshot {
    pub schema_version: Option<String>,
    pub overall_status: String,
    pub checks_failed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PilotGateCheck {
    pub check_id: String,
    pub status: PilotGateStatus,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PilotRollbackTrigger {
    pub trigger_id: String,
    pub severity: PilotRollbackSeverity,
    pub condition: String,
    pub operator_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PilotGateReport {
    pub schema_version: String,
    pub overall_status: PilotGateStatus,
    pub config: PilotGateConfig,
    pub release: PilotReleaseSnapshot,
    pub pilot_regression: PilotRegressionSnapshot,
    pub shadow_runs: Vec<PilotShadowSnapshot>,
    pub kids_memory_health: Option<KidsMemoryHealthSnapshot>,
    pub kids_preprod_dry_run: Option<KidsPreprodDryRunSnapshot>,
    pub signoffs: Vec<PilotReviewSignoff>,
    pub checks: Vec<PilotGateCheck>,
    pub rollback_triggers: Vec<PilotRollbackTrigger>,
    pub operator_review_cadence: String,
}

pub fn parse_pilot_release_snapshot(json: &str) -> Result<PilotReleaseSnapshot, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|err| format!("invalid release report json: {err}"))?;
    let overall_status = value
        .get("overall_status")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "release report missing overall_status".to_string())?;
    Ok(PilotReleaseSnapshot {
        schema_version: value
            .get("schema_version")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        overall_status: overall_status.to_string(),
    })
}

pub fn parse_pilot_regression_snapshot(json: &str) -> Result<PilotRegressionSnapshot, String> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|err| format!("invalid pilot regression json: {err}"))?;
    let overall_status = value
        .get("overall_status")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "pilot regression report missing overall_status".to_string())?;
    let scenario_count = value
        .get("scenarios")
        .and_then(|value| value.as_array())
        .map(|items| items.len())
        .ok_or_else(|| "pilot regression report missing scenarios".to_string())?;
    Ok(PilotRegressionSnapshot {
        schema_version: value
            .get("schema_version")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        overall_status: overall_status.to_string(),
        suite_id: value
            .get("manifest")
            .and_then(|value| value.get("suite_id"))
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        scenario_count,
    })
}

pub fn parse_pilot_shadow_snapshot(json: &str) -> Result<PilotShadowSnapshot, String> {
    let bundle: ShadowModeBundle = serde_json::from_str(json)
        .map_err(|err| format!("invalid pilot shadow bundle json: {err}"))?;
    Ok(PilotShadowSnapshot {
        schema_version: bundle.schema_version,
        source_kind: bundle.source_kind,
        source_label: bundle.source_label,
        wire_package: bundle.wire_package,
        protection_level: bundle.protection_level,
        total_events: bundle.summary.total_events,
        threat_events: bundle.summary.threat_events,
        finding_count: bundle.summary.finding_count,
        raw_text_present: bundle.privacy.raw_text_present,
        raw_identifier_fields_present: bundle.privacy.raw_identifier_fields_present,
    })
}

pub fn parse_pilot_review_signoffs(json: &str) -> Result<Vec<PilotReviewSignoff>, String> {
    serde_json::from_str(json).map_err(|err| format!("invalid pilot review signoffs json: {err}"))
}

pub fn parse_kids_memory_health_snapshot(json: &str) -> Result<KidsMemoryHealthSnapshot, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|err| format!("invalid kids memory health json: {err}"))?;
    let overall_status = value
        .get("overall_status")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "kids memory health report missing overall_status".to_string())?;
    let total_memory_hits = value
        .get("total_memory_hits")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| "kids memory health report missing total_memory_hits".to_string())?;
    let missing_mandatory_reason_codes = value
        .get("missing_mandatory_reason_codes")
        .and_then(|value| value.as_array())
        .ok_or_else(|| {
            "kids memory health report missing missing_mandatory_reason_codes".to_string()
        })?;
    let mut missing = Vec::new();
    for reason in missing_mandatory_reason_codes {
        let Some(reason) = reason.as_str() else {
            return Err(
                "kids memory health report has non-string missing_mandatory_reason_codes"
                    .to_string(),
            );
        };
        missing.push(reason.to_string());
    }
    Ok(KidsMemoryHealthSnapshot {
        schema_version: value
            .get("schema_version")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        overall_status: overall_status.to_string(),
        total_memory_hits: total_memory_hits as usize,
        missing_mandatory_reason_codes: missing,
    })
}

pub fn parse_kids_preprod_dry_run_snapshot(json: &str) -> Result<KidsPreprodDryRunSnapshot, String> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|err| format!("invalid kids preprod dry-run json: {err}"))?;
    let overall_status = value
        .get("overall_status")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "kids preprod dry-run report missing overall_status".to_string())?;
    let checks = value
        .get("checks")
        .and_then(|value| value.as_object())
        .ok_or_else(|| "kids preprod dry-run report missing checks".to_string())?;
    let mut checks_failed = 0usize;
    for check_value in checks.values() {
        let Some(check_value) = check_value.as_bool() else {
            return Err("kids preprod dry-run report has non-boolean checks value".to_string());
        };
        if !check_value {
            checks_failed += 1;
        }
    }
    Ok(KidsPreprodDryRunSnapshot {
        schema_version: value
            .get("schema_version")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned),
        overall_status: overall_status.to_string(),
        checks_failed,
    })
}

pub fn run_pilot_gate(
    config: PilotGateConfig,
    release: PilotReleaseSnapshot,
    pilot_regression: PilotRegressionSnapshot,
    shadow_runs: Vec<PilotShadowSnapshot>,
    kids_memory_health: Option<KidsMemoryHealthSnapshot>,
    kids_preprod_dry_run: Option<KidsPreprodDryRunSnapshot>,
    signoffs: Vec<PilotReviewSignoff>,
) -> PilotGateReport {
    let mut checks = Vec::new();

    if config.require_release_pass {
        checks.push(if release.overall_status == "pass" {
            pass_check("release_gate", "Phase 2 release gate passed")
        } else {
            fail_check(
                "release_gate",
                format!("release report status was {}", release.overall_status),
            )
        });
    }

    if config.require_pilot_regression_pass {
        checks.push(if pilot_regression.overall_status == "pass" {
            pass_check("pilot_regression", "pilot regression corpus passed")
        } else {
            fail_check(
                "pilot_regression",
                format!(
                    "pilot regression status was {}",
                    pilot_regression.overall_status
                ),
            )
        });
    }

    if config.require_kids_memory_pass {
        let kids_memory_health = kids_memory_health.as_ref();
        checks.push(match kids_memory_health {
            Some(report)
                if report.overall_status == "pass"
                    && report.total_memory_hits > 0
                    && report.missing_mandatory_reason_codes.is_empty() =>
            {
                pass_check(
                    "kids_memory_health",
                    format!(
                        "kids memory health passed (total_hits={})",
                        report.total_memory_hits
                    ),
                )
            }
            Some(report) => fail_check(
                "kids_memory_health",
                format!(
                    "kids memory health failed (overall_status={}, total_hits={}, missing_mandatory={})",
                    report.overall_status,
                    report.total_memory_hits,
                    report.missing_mandatory_reason_codes.len()
                ),
            ),
            None => blocked_check(
                "kids_memory_health",
                "kids memory health report is required but missing".to_string(),
            ),
        });
    }
    if config.require_kids_preprod_dry_run_pass {
        let kids_preprod_dry_run = kids_preprod_dry_run.as_ref();
        checks.push(match kids_preprod_dry_run {
            Some(report) if report.overall_status == "pass" && report.checks_failed == 0 => {
                pass_check(
                    "kids_preprod_dry_run",
                    "kids preprod dry-run matrix passed with no failed checks",
                )
            }
            Some(report) => fail_check(
                "kids_preprod_dry_run",
                format!(
                    "kids preprod dry-run failed (overall_status={}, checks_failed={})",
                    report.overall_status, report.checks_failed
                ),
            ),
            None => blocked_check(
                "kids_preprod_dry_run",
                "kids preprod dry-run report is required but missing".to_string(),
            ),
        });
    }

    checks.push(if shadow_runs.len() >= config.min_shadow_runs {
        pass_check(
            "shadow_run_count",
            format!(
                "observed {} shadow runs (required {})",
                shadow_runs.len(),
                config.min_shadow_runs
            ),
        )
    } else {
        blocked_check(
            "shadow_run_count",
            format!(
                "observed {} shadow runs but require at least {}",
                shadow_runs.len(),
                config.min_shadow_runs
            ),
        )
    });

    let mut total_shadow_events = 0usize;
    for run in &shadow_runs {
        total_shadow_events += run.total_events;
    }
    checks.push(if total_shadow_events >= config.min_shadow_total_events {
        pass_check(
            "shadow_event_volume",
            format!(
                "shadow runs cover {} total events (required >= {})",
                total_shadow_events, config.min_shadow_total_events
            ),
        )
    } else {
        blocked_check(
            "shadow_event_volume",
            format!(
                "shadow runs cover {} total events but require >= {}",
                total_shadow_events, config.min_shadow_total_events
            ),
        )
    });

    let mut clean_shadow = true;
    for run in &shadow_runs {
        if run.raw_text_present || run.raw_identifier_fields_present || run.finding_count != 0 {
            clean_shadow = false;
            break;
        }
    }
    checks.push(if clean_shadow {
        pass_check(
            "shadow_privacy_and_findings",
            "all shadow runs are clean and privacy-safe",
        )
    } else {
        fail_check(
            "shadow_privacy_and_findings",
            "one or more shadow runs contain findings or forbidden plaintext".to_string(),
        )
    });

    let stable_wire_contract = if let Some(first) = shadow_runs.first() {
        let mut stable = true;
        for run in &shadow_runs {
            if run.schema_version != first.schema_version
                || run.wire_package != first.wire_package
                || run.protection_level != first.protection_level
            {
                stable = false;
                break;
            }
        }
        stable
    } else {
        false
    };
    checks.push(if stable_wire_contract {
        pass_check(
            "shadow_contract_stability",
            "shadow runs share stable schema, wire package, and protection level",
        )
    } else {
        blocked_check(
            "shadow_contract_stability",
            "shadow runs do not share stable schema/protection contract".to_string(),
        )
    });

    let latest_signoffs = latest_signoffs_by_area(&signoffs);
    for area in &config.required_review_areas {
        let check_id = format!("review_signoff.{}", area_key(*area));
        match latest_signoffs.get(area) {
            Some(signoff) if signoff.status == PilotReviewSignoffStatus::Approved => {
                checks.push(pass_check(
                    check_id,
                    format!("{} approved by {}", area_key(*area), signoff.reviewer),
                ));
            }
            Some(signoff) if signoff.status == PilotReviewSignoffStatus::Pending => {
                checks.push(blocked_check(
                    check_id,
                    format!("{} signoff is still pending", area_key(*area)),
                ));
            }
            Some(signoff) => {
                checks.push(fail_check(
                    check_id,
                    format!(
                        "{} signoff needs changes from {}",
                        area_key(*area),
                        signoff.reviewer
                    ),
                ));
            }
            None => checks.push(blocked_check(
                check_id,
                format!("{} signoff is missing", area_key(*area)),
            )),
        }
    }

    let mut overall_status = PilotGateStatus::Pass;
    for check in &checks {
        match check.status {
            PilotGateStatus::Fail => {
                overall_status = PilotGateStatus::Fail;
                break;
            }
            PilotGateStatus::Blocked => {
                overall_status = PilotGateStatus::Blocked;
            }
            PilotGateStatus::Pass => {}
        }
    }

    PilotGateReport {
        schema_version: PILOT_GATE_SCHEMA_VERSION.to_string(),
        overall_status,
        config,
        release,
        pilot_regression,
        shadow_runs,
        kids_memory_health,
        kids_preprod_dry_run,
        signoffs,
        checks,
        rollback_triggers: default_pilot_rollback_triggers(),
        operator_review_cadence: "daily for the first 7 pilot days, then every 3 days while stable"
            .to_string(),
    }
}

fn latest_signoffs_by_area(
    signoffs: &[PilotReviewSignoff],
) -> BTreeMap<PilotReviewArea, PilotReviewSignoff> {
    let mut by_area = BTreeMap::new();
    for signoff in signoffs {
        by_area.insert(signoff.area, signoff.clone());
    }
    by_area
}

fn default_pilot_rollback_triggers() -> Vec<PilotRollbackTrigger> {
    vec![
        PilotRollbackTrigger {
            trigger_id: "privacy_shadow_plaintext".to_string(),
            severity: PilotRollbackSeverity::Urgent,
            condition: "any pilot shadow bundle contains raw text or raw identifiers".to_string(),
            operator_action: "disable pilot capture and revert to offline replay only".to_string(),
        },
        PilotRollbackTrigger {
            trigger_id: "self_harm_boundary_disagreement".to_string(),
            severity: PilotRollbackSeverity::Urgent,
            condition:
                "human review finds self-harm boundary cases where supportive replies are escalated or crisis content is suppressed"
                    .to_string(),
            operator_action: "pause live guardian-enabled pilot and return to shadow mode".to_string(),
        },
        PilotRollbackTrigger {
            trigger_id: "trusted_adult_false_positive_hotspot".to_string(),
            severity: PilotRollbackSeverity::High,
            condition:
                "trusted-adult educational or supportive traffic accumulates repeated high-severity interventions"
                    .to_string(),
            operator_action: "disable child-facing enforcement for the affected slice and review recent bundles".to_string(),
        },
        PilotRollbackTrigger {
            trigger_id: "pilot_slice_regression".to_string(),
            severity: PilotRollbackSeverity::High,
            condition:
                "pilot regression corpus or repeated shadow runs regress below the approved baseline"
                    .to_string(),
            operator_action: "block further rollout promotion until the slice is re-approved".to_string(),
        },
    ]
}

fn area_key(area: PilotReviewArea) -> &'static str {
    match area {
        PilotReviewArea::FalsePositiveHotspots => "false_positive_hotspots",
        PilotReviewArea::SelfHarmBoundaryCases => "self_harm_boundary_cases",
        PilotReviewArea::TrustedAdultScenarios => "trusted_adult_scenarios",
        PilotReviewArea::ReputationImageAbuse => "reputation_image_abuse",
    }
}

fn pass_check(check_id: impl Into<String>, summary: impl Into<String>) -> PilotGateCheck {
    PilotGateCheck {
        check_id: check_id.into(),
        status: PilotGateStatus::Pass,
        summary: summary.into(),
    }
}

fn fail_check(check_id: impl Into<String>, summary: impl Into<String>) -> PilotGateCheck {
    PilotGateCheck {
        check_id: check_id.into(),
        status: PilotGateStatus::Fail,
        summary: summary.into(),
    }
}

fn blocked_check(check_id: impl Into<String>, summary: impl Into<String>) -> PilotGateCheck {
    PilotGateCheck {
        check_id: check_id.into(),
        status: PilotGateStatus::Blocked,
        summary: summary.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release_snapshot() -> PilotReleaseSnapshot {
        PilotReleaseSnapshot {
            schema_version: Some("aura.release_report.v3".to_string()),
            overall_status: "pass".to_string(),
        }
    }

    fn regression_snapshot() -> PilotRegressionSnapshot {
        PilotRegressionSnapshot {
            schema_version: Some("aura.pilot_simulation_regression_report.v1".to_string()),
            overall_status: "pass".to_string(),
            suite_id: Some("pilot_suite".to_string()),
            scenario_count: 12,
        }
    }

    fn shadow_snapshot(source_label: &str) -> PilotShadowSnapshot {
        PilotShadowSnapshot {
            schema_version: "aura.shadow_mode_bundle.v1".to_string(),
            source_kind: "world_sim".to_string(),
            source_label: source_label.to_string(),
            wire_package: "aura.messenger.v1".to_string(),
            protection_level: ProtectionLevel::High,
            total_events: 1000,
            threat_events: 300,
            finding_count: 0,
            raw_text_present: false,
            raw_identifier_fields_present: false,
        }
    }

    fn approved_signoffs() -> Vec<PilotReviewSignoff> {
        vec![
            PilotReviewSignoff {
                area: PilotReviewArea::FalsePositiveHotspots,
                reviewer: "ops_1".to_string(),
                status: PilotReviewSignoffStatus::Approved,
                reviewed_at_utc: "2026-03-16T10:00:00Z".to_string(),
                notes: None,
            },
            PilotReviewSignoff {
                area: PilotReviewArea::SelfHarmBoundaryCases,
                reviewer: "ops_2".to_string(),
                status: PilotReviewSignoffStatus::Approved,
                reviewed_at_utc: "2026-03-16T10:05:00Z".to_string(),
                notes: None,
            },
            PilotReviewSignoff {
                area: PilotReviewArea::TrustedAdultScenarios,
                reviewer: "ops_3".to_string(),
                status: PilotReviewSignoffStatus::Approved,
                reviewed_at_utc: "2026-03-16T10:10:00Z".to_string(),
                notes: None,
            },
            PilotReviewSignoff {
                area: PilotReviewArea::ReputationImageAbuse,
                reviewer: "ops_4".to_string(),
                status: PilotReviewSignoffStatus::Approved,
                reviewed_at_utc: "2026-03-16T10:15:00Z".to_string(),
                notes: None,
            },
        ]
    }

    fn healthy_kids_memory_snapshot() -> KidsMemoryHealthSnapshot {
        KidsMemoryHealthSnapshot {
            schema_version: Some("aura.kids_memory_health_snapshot.v1".to_string()),
            overall_status: "pass".to_string(),
            total_memory_hits: 6,
            missing_mandatory_reason_codes: Vec::new(),
        }
    }

    fn healthy_kids_preprod_dry_run_snapshot() -> KidsPreprodDryRunSnapshot {
        KidsPreprodDryRunSnapshot {
            schema_version: Some("aura.kids_preprod_dry_run_matrix.v1".to_string()),
            overall_status: "pass".to_string(),
            checks_failed: 0,
        }
    }

    #[test]
    fn pilot_gate_passes_with_repeated_clean_runs_and_signoffs() {
        let report = run_pilot_gate(
            PilotGateConfig::default(),
            release_snapshot(),
            regression_snapshot(),
            vec![shadow_snapshot("run_a"), shadow_snapshot("run_b")],
            None,
            None,
            approved_signoffs(),
        );
        assert_eq!(report.overall_status, PilotGateStatus::Pass);
    }

    #[test]
    fn pilot_gate_blocks_without_repeated_shadow_runs() {
        let report = run_pilot_gate(
            PilotGateConfig::default(),
            release_snapshot(),
            regression_snapshot(),
            vec![shadow_snapshot("run_a")],
            None,
            None,
            approved_signoffs(),
        );
        assert_eq!(report.overall_status, PilotGateStatus::Blocked);
        assert!(report
            .checks
            .iter()
            .any(|check| check.check_id == "shadow_run_count"
                && check.status == PilotGateStatus::Blocked));
    }

    #[test]
    fn pilot_gate_fails_when_review_needs_changes() {
        let mut signoffs = approved_signoffs();
        signoffs[0].status = PilotReviewSignoffStatus::NeedsChanges;
        let report = run_pilot_gate(
            PilotGateConfig::default(),
            release_snapshot(),
            regression_snapshot(),
            vec![shadow_snapshot("run_a"), shadow_snapshot("run_b")],
            None,
            None,
            signoffs,
        );
        assert_eq!(report.overall_status, PilotGateStatus::Fail);
    }

    #[test]
    fn pilot_gate_fails_when_kids_memory_health_is_required_but_not_pass() {
        let mut config = PilotGateConfig::default();
        config.require_kids_memory_pass = true;
        let mut kids_memory = healthy_kids_memory_snapshot();
        kids_memory.overall_status = "warn".to_string();
        kids_memory.missing_mandatory_reason_codes =
            vec!["kids.memory.sustained_sextortion".to_string()];
        let report = run_pilot_gate(
            config,
            release_snapshot(),
            regression_snapshot(),
            vec![shadow_snapshot("run_a"), shadow_snapshot("run_b")],
            Some(kids_memory),
            None,
            approved_signoffs(),
        );
        assert_eq!(report.overall_status, PilotGateStatus::Fail);
        assert!(report
            .checks
            .iter()
            .any(|check| check.check_id == "kids_memory_health"
                && check.status == PilotGateStatus::Fail));
    }

    #[test]
    fn pilot_gate_fails_when_kids_preprod_dry_run_is_required_but_not_pass() {
        let mut config = PilotGateConfig::default();
        config.require_kids_preprod_dry_run_pass = true;
        let mut dry_run = healthy_kids_preprod_dry_run_snapshot();
        dry_run.overall_status = "fail".to_string();
        dry_run.checks_failed = 2;
        let report = run_pilot_gate(
            config,
            release_snapshot(),
            regression_snapshot(),
            vec![shadow_snapshot("run_a"), shadow_snapshot("run_b")],
            None,
            Some(dry_run),
            approved_signoffs(),
        );
        assert_eq!(report.overall_status, PilotGateStatus::Fail);
        assert!(report
            .checks
            .iter()
            .any(|check| check.check_id == "kids_preprod_dry_run"
                && check.status == PilotGateStatus::Fail));
    }
}
