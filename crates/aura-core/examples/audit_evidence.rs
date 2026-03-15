use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use aura_core::context::tracker::TRACKER_STATE_VERSION;
use aura_core::{
    Action, ActionRecommendation, AlertPriority, AnalysisResult, AuditRecord, BehavioralTrend,
    CircleTier, Confidence, ContactSnapshot, FollowUpAction, ProtectionLevel, RiskBreakdown,
    ThreatType, UiAction, AUDIT_IDENTIFIER_SCHEME, AUDIT_SCHEMA_VERSION,
};
use chrono::Utc;
use serde::Serialize;

const WIRE_PACKAGE: &str = "aura.messenger.v1";

struct CliArgs {
    output: Option<PathBuf>,
}

enum ParseArgsResult {
    Run(CliArgs),
    Help,
}

#[derive(Serialize)]
struct AuditEvidenceReport {
    generated_at_utc: String,
    status: String,
    audit_schema_version: String,
    identifier_scheme: String,
    forbidden_fields_absent: bool,
    top_level_fields: Vec<String>,
    sample_record: AuditRecord,
}

fn usage() -> &'static str {
    "usage: cargo run --example audit_evidence -p aura-core -- [--output PATH]"
}

fn parse_args() -> Result<ParseArgsResult, String> {
    let mut args = env::args().skip(1);
    let mut output = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing path after --output".to_string())?;
                output = Some(PathBuf::from(path));
            }
            "--help" | "-h" => return Ok(ParseArgsResult::Help),
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(ParseArgsResult::Run(CliArgs { output }))
}

fn main() {
    let args = match parse_args() {
        Ok(ParseArgsResult::Run(args)) => args,
        Ok(ParseArgsResult::Help) => {
            println!("{}", usage());
            process::exit(0);
        }
        Err(message) => {
            eprintln!("{message}\n{}", usage());
            process::exit(2);
        }
    };

    let report = build_audit_evidence();
    let json = serde_json::to_string_pretty(&report).expect("serializable audit evidence");

    let exit_code = if report.status == "pass" { 0 } else { 1 };

    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).expect("create audit evidence directory");
            }
        }
        fs::write(&path, &json).expect("write audit evidence");
        eprintln!("audit evidence written to {}", path.display());
    } else {
        println!("{json}");
    }

    if exit_code != 0 {
        process::exit(exit_code);
    }
}

fn build_audit_evidence() -> AuditEvidenceReport {
    let sample_record = AuditRecord::from_analysis_result(
        "audit_req_example",
        1_773_492_300_000,
        env!("CARGO_PKG_VERSION"),
        WIRE_PACKAGE,
        TRACKER_STATE_VERSION,
        ProtectionLevel::High,
        Some("coach_realistic"),
        Some("conv_secret"),
        &sample_result(),
    );

    let value = serde_json::to_value(&sample_record).expect("serialize sample audit record");
    let object = value.as_object().expect("audit record object");
    let mut top_level_fields = object.keys().cloned().collect::<Vec<_>>();
    top_level_fields.sort();

    AuditEvidenceReport {
        generated_at_utc: Utc::now().to_rfc3339(),
        status: if !object.contains_key("sender_id")
            && !object.contains_key("conversation_id")
            && !object.contains_key("text")
            && !object.contains_key("message_text")
        {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        audit_schema_version: AUDIT_SCHEMA_VERSION.to_string(),
        identifier_scheme: AUDIT_IDENTIFIER_SCHEME.to_string(),
        forbidden_fields_absent: !object.contains_key("sender_id")
            && !object.contains_key("conversation_id")
            && !object.contains_key("text")
            && !object.contains_key("message_text"),
        top_level_fields,
        sample_record,
    }
}

fn sample_result() -> AnalysisResult {
    AnalysisResult {
        threat_type: ThreatType::Grooming,
        confidence: Confidence::High,
        action: Action::Warn,
        score: 0.91,
        explanation: "grooming signal recorded".to_string(),
        detected_threats: vec![
            (ThreatType::Grooming, 0.91),
            (ThreatType::Manipulation, 0.72),
        ],
        signals: Vec::new(),
        recommended_action: Some(ActionRecommendation {
            parent_alert: AlertPriority::High,
            follow_ups: vec![FollowUpAction::MonitorConversation],
            crisis_resources: false,
            ui_actions: vec![UiAction::SuggestBlockContact, UiAction::SuggestReport],
            reason_codes: vec!["conversation.grooming.stage_sequence".to_string()],
        }),
        risk_breakdown: RiskBreakdown {
            content: 0.25,
            conversation: 0.80,
            link: 0.0,
            abuse: 0.05,
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
