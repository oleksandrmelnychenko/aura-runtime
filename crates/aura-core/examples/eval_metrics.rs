use aura_core::{
    build_calibration_report, evaluate_lead_time, LeadTimeCase, LeadTimePoint, RiskExample,
    ThreatType,
};

fn main() {
    let calibration = build_calibration_report(
        &[
            RiskExample {
                threat_type: ThreatType::Grooming,
                language: "en".to_string(),
                predicted_score: 0.91,
                observed: true,
                target_probability: 1.0,
            },
            RiskExample {
                threat_type: ThreatType::Grooming,
                language: "en".to_string(),
                predicted_score: 0.63,
                observed: true,
                target_probability: 1.0,
            },
            RiskExample {
                threat_type: ThreatType::Grooming,
                language: "en".to_string(),
                predicted_score: 0.27,
                observed: false,
                target_probability: 0.0,
            },
            RiskExample {
                threat_type: ThreatType::Bullying,
                language: "en".to_string(),
                predicted_score: 0.74,
                observed: false,
                target_probability: 0.0,
            },
            RiskExample {
                threat_type: ThreatType::SelfHarm,
                language: "en".to_string(),
                predicted_score: 0.88,
                observed: true,
                target_probability: 1.0,
            },
        ],
        5,
    );

    println!("Calibration report");
    println!("  count: {}", calibration.count);
    println!("  brier: {:.4}", calibration.brier_score);
    println!("  ece: {:.4}", calibration.expected_calibration_error);
    for bin in &calibration.bins {
        println!(
            "  bin [{:.1}, {:.1}) count={} avg_pred={:.3} observed={:.3} gap={:.3}",
            bin.lower_bound,
            bin.upper_bound,
            bin.count,
            bin.avg_prediction,
            bin.observed_rate,
            bin.gap
        );
    }

    let lead_time = evaluate_lead_time(&LeadTimeCase {
        threat_type: ThreatType::SelfHarm,
        onset_ms: 10_000,
        detection_threshold: 0.7,
        timeline: vec![
            LeadTimePoint {
                timestamp_ms: 2_000,
                score: 0.35,
            },
            LeadTimePoint {
                timestamp_ms: 6_500,
                score: 0.76,
            },
            LeadTimePoint {
                timestamp_ms: 11_000,
                score: 0.92,
            },
        ],
    });

    println!();
    println!("Lead-time evaluation");
    println!("  first_detection_ms: {:?}", lead_time.first_detection_ms);
    println!(
        "  detected_before_onset: {}",
        lead_time.detected_before_onset
    );
    println!("  lead_time_ms: {:?}", lead_time.lead_time_ms);
}
