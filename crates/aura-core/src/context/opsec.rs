use regex::Regex;

use crate::types::{Confidence, DetectionSignal, SignalFamily, ThreatType};

use super::contact::ContactProfiler;
use super::events::EventKind;
use super::tracker::ConversationTimeline;

/// A validated geographic coordinate match within Ukraine's territory.
#[derive(Debug, Clone)]
pub struct CoordinateMatch {
    pub lat: f64,
    pub lon: f64,
    pub format: CoordinateFormat,
    pub raw_text: String,
}

/// The format in which coordinates were expressed.
#[derive(Debug, Clone)]
pub enum CoordinateFormat {
    DecimalDegrees,
    Dms,
    Mgrs,
    PlusCode,
    MilitaryGrid,
}

/// Ukraine bounding box constants.
const UKRAINE_LAT_MIN: f64 = 44.0;
const UKRAINE_LAT_MAX: f64 = 52.5;
const UKRAINE_LON_MIN: f64 = 22.0;
const UKRAINE_LON_MAX: f64 = 40.5;

/// Validates text for geographic coordinates that fall within Ukraine's territory.
///
/// Recognizes decimal degrees, MGRS zone references (zones 34-37, bands T/U),
/// and Ukrainian military grid references (квадрат/кв. notation).
pub fn validate_ukraine_coordinates(text: &str) -> Vec<CoordinateMatch> {
    let mut results = Vec::new();

    let dd_re = Regex::new(r"(\d{2})\.(\d{4,7})\s*[,;/\s]\s*(\d{2})\.(\d{4,7})").unwrap();
    for cap in dd_re.captures_iter(text) {
        let lat_str = format!("{}.{}", &cap[1], &cap[2]);
        let lon_str = format!("{}.{}", &cap[3], &cap[4]);
        if let (Ok(lat), Ok(lon)) = (lat_str.parse::<f64>(), lon_str.parse::<f64>()) {
            if lat >= UKRAINE_LAT_MIN
                && lat <= UKRAINE_LAT_MAX
                && lon >= UKRAINE_LON_MIN
                && lon <= UKRAINE_LON_MAX
            {
                results.push(CoordinateMatch {
                    lat,
                    lon,
                    format: CoordinateFormat::DecimalDegrees,
                    raw_text: cap[0].to_string(),
                });
            }
        }
    }

    let mgrs_re = Regex::new(r"3[4-7][TU]\s*[A-Z]{2}\s*\d{4,10}").unwrap();
    for m in mgrs_re.find_iter(text) {
        results.push(CoordinateMatch {
            lat: 0.0,
            lon: 0.0,
            format: CoordinateFormat::Mgrs,
            raw_text: m.as_str().to_string(),
        });
    }

    let grid_re = Regex::new(r"(?:квадрат|кв\.?)\s*\d{2,4}[-/]\d{2,4}").unwrap();
    for m in grid_re.find_iter(text) {
        results.push(CoordinateMatch {
            lat: 0.0,
            lon: 0.0,
            format: CoordinateFormat::MilitaryGrid,
            raw_text: m.as_str().to_string(),
        });
    }

    results
}

/// Detects OPSEC violations — outgoing leaks of military operational information.
///
/// Unlike most detectors, this primarily watches for the user's OWN messages
/// that contain sensitive military info (coordinates, positions, unit data).
/// It also detects incoming intel probing from contacts.
pub struct OpsecDetector {
    /// Lookback window in milliseconds (default 1 hour for OPSEC).
    window_ms: u64,
}

impl Default for OpsecDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OpsecDetector {
    /// Creates a new OPSEC detector with default settings.
    pub fn new() -> Self {
        Self {
            window_ms: 60 * 60 * 1000, // 1 hour lookback
        }
    }

    /// Analyzes a conversation timeline for OPSEC violations.
    pub fn analyze(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        now_ms: u64,
        contact_profiler: &ContactProfiler,
    ) -> Vec<DetectionSignal> {
        let mut signals = Vec::with_capacity(4);
        let window_start = now_ms.saturating_sub(self.window_ms);

        let mut coordinate_leaks = 0usize;
        let mut position_leaks = 0usize;
        let mut unit_info_leaks = 0usize;
        let mut equipment_leaks = 0usize;
        let mut intel_gathering = 0usize;
        let mut intel_senders = std::collections::HashSet::new();

        for event in timeline.events_since(window_start) {
            if &*event.sender_id == sender_id {
                // Outgoing OPSEC violations (user is leaking)
                match event.kind {
                    EventKind::CoordinateMention => coordinate_leaks += 1,
                    EventKind::PositionLeak => position_leaks += 1,
                    EventKind::UnitInfoLeak => unit_info_leaks += 1,
                    EventKind::EquipmentLeak => equipment_leaks += 1,
                    _ => {}
                }
            } else {
                // Incoming intel probing from contacts
                match event.kind {
                    EventKind::IntelGathering => {
                        intel_gathering += 1;
                        intel_senders.insert(event.sender_id.0.clone());
                    }
                    EventKind::MilitaryPhishing => {
                        intel_gathering += 1;
                        intel_senders.insert(event.sender_id.0.clone());
                    }
                    _ => {}
                }
            }
        }

        // Coordinate leak — highest priority
        if coordinate_leaks >= 1 {
            signals.push(DetectionSignal::context(
                ThreatType::CoordinateLeak,
                0.95,
                Confidence::High,
                SignalFamily::Content,
                "conversation.opsec.coordinate_leak",
                format!(
                    "Detected {} geographic coordinate(s) in outgoing message",
                    coordinate_leaks
                ),
            ));
        }

        // Position leak
        if position_leaks >= 1 {
            let score = if position_leaks >= 2 { 0.9 } else { 0.75 };
            signals.push(DetectionSignal::context(
                ThreatType::OpsecViolation,
                score,
                Confidence::High,
                SignalFamily::Content,
                "conversation.opsec.position_leak",
                format!(
                    "Detected {} position/location mention(s) in outgoing message",
                    position_leaks
                ),
            ));
        }

        // Unit info leak
        if unit_info_leaks >= 1 {
            let score = if unit_info_leaks >= 2 { 0.75 } else { 0.6 };
            signals.push(DetectionSignal::context(
                ThreatType::OpsecViolation,
                score,
                Confidence::Medium,
                SignalFamily::Content,
                "conversation.opsec.unit_info_leak",
                format!(
                    "Detected {} unit/formation reference(s) in outgoing message",
                    unit_info_leaks
                ),
            ));
        }

        // Equipment leak
        if equipment_leaks >= 1 {
            let score = if equipment_leaks >= 3 { 0.6 } else { 0.45 };
            signals.push(DetectionSignal::context(
                ThreatType::OpsecViolation,
                score,
                Confidence::Medium,
                SignalFamily::Content,
                "conversation.opsec.equipment_leak",
                format!(
                    "Detected {} equipment/capability reference(s) in outgoing message",
                    equipment_leaks
                ),
            ));
        }

        // Incoming intel probing
        if intel_gathering >= 1 {
            let is_new = intel_senders
                .iter()
                .any(|s| contact_profiler.is_new_contact(s));
            let base_score: f32 = if intel_gathering >= 3 {
                0.85
            } else if intel_gathering >= 2 {
                0.7
            } else {
                0.55
            };
            let score = if is_new {
                (base_score + 0.1).min(0.95f32)
            } else {
                base_score
            };
            signals.push(DetectionSignal::context(
                ThreatType::MilitarySocialEng,
                score,
                if intel_gathering >= 2 {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                SignalFamily::Conversation,
                "conversation.opsec.intel_probing",
                format!(
                    "Detected {} intelligence gathering attempt(s) from {} contact(s)",
                    intel_gathering,
                    intel_senders.len()
                ),
            ));
        }

        signals
    }
}

#[cfg(test)]
mod tests {
    use super::super::events::ContextEvent;
    use super::*;

    fn make_event(sender: &str, conv: &str, kind: EventKind, ts: u64) -> ContextEvent {
        ContextEvent {
            event_id: 0,
            timestamp_ms: ts,
            sender_id: sender.into(),
            conversation_id: conv.into(),
            kind,
            confidence: 0.8,
            subtype: None,
            content_hash: None,
        }
    }

    fn setup_profiler(events: &[ContextEvent]) -> ContactProfiler {
        let mut profiler = ContactProfiler::new();
        for event in events {
            profiler.record_event(event);
        }
        profiler
    }

    #[test]
    fn no_opsec_in_normal_conversation() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![make_event(
            "soldier",
            "conv_1",
            EventKind::NormalConversation,
            1000,
        )];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = OpsecDetector::new();
        let signals = detector.analyze(&timeline, "soldier", 5000, &profiler);
        assert!(signals.is_empty());
    }

    #[test]
    fn coordinate_leak_highest_priority() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![make_event(
            "soldier",
            "conv_1",
            EventKind::CoordinateMention,
            1000,
        )];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = OpsecDetector::new();
        let signals = detector.analyze(&timeline, "soldier", 5000, &profiler);
        assert!(!signals.is_empty());
        assert_eq!(signals[0].threat_type, ThreatType::CoordinateLeak);
        assert!(
            signals[0].score >= 0.9,
            "Coordinate leak should be critical"
        );
    }

    #[test]
    fn position_leak_detected() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![make_event(
            "soldier",
            "conv_1",
            EventKind::PositionLeak,
            1000,
        )];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = OpsecDetector::new();
        let signals = detector.analyze(&timeline, "soldier", 5000, &profiler);
        assert!(!signals.is_empty());
        assert_eq!(signals[0].threat_type, ThreatType::OpsecViolation);
    }

    #[test]
    fn incoming_intel_probing_detected() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("spy", "conv_1", EventKind::IntelGathering, 1000),
            make_event("spy", "conv_1", EventKind::IntelGathering, 2000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = OpsecDetector::new();
        let signals = detector.analyze(&timeline, "soldier", 5000, &profiler);
        assert!(!signals.is_empty());
        assert_eq!(signals[0].threat_type, ThreatType::MilitarySocialEng);
    }

    #[test]
    fn only_counts_own_outgoing_leaks() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            // Someone else mentions coordinates — not our OPSEC violation
            make_event("other", "conv_1", EventKind::CoordinateMention, 1000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = OpsecDetector::new();
        let signals = detector.analyze(&timeline, "soldier", 5000, &profiler);
        // Should not trigger coordinate leak for someone else's message
        let has_coord_leak = signals
            .iter()
            .any(|s| s.threat_type == ThreatType::CoordinateLeak);
        assert!(
            !has_coord_leak,
            "Should not flag other sender's coordinates"
        );
    }

    #[test]
    fn test_valid_ukraine_coordinates() {
        let matches = validate_ukraine_coordinates("48.8566, 30.3522");
        assert_eq!(
            matches.len(),
            1,
            "Should find one coordinate within Ukraine"
        );
        let m = &matches[0];
        assert!((m.lat - 48.8566).abs() < 0.001);
        assert!((m.lon - 30.3522).abs() < 0.001);
    }

    #[test]
    fn test_out_of_range_coordinates() {
        let matches = validate_ukraine_coordinates("55.7558, 37.6173");
        assert!(
            matches.is_empty(),
            "Moscow coordinates should be outside Ukraine bounding box"
        );
    }

    #[test]
    fn test_mgrs_detection() {
        let matches = validate_ukraine_coordinates("36TUQ 12345 67890");
        assert_eq!(matches.len(), 1, "Should detect MGRS zone within Ukraine");
        assert!(matches[0].raw_text.contains("36T"));
    }

    #[test]
    fn test_military_grid() {
        let matches = validate_ukraine_coordinates("квадрат 34-56");
        assert_eq!(
            matches.len(),
            1,
            "Should detect Ukrainian military grid reference"
        );
        assert!(matches[0].raw_text.contains("квадрат"));
    }

    #[test]
    fn equipment_leak_lower_severity() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![make_event(
            "soldier",
            "conv_1",
            EventKind::EquipmentLeak,
            1000,
        )];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = OpsecDetector::new();
        let signals = detector.analyze(&timeline, "soldier", 5000, &profiler);
        assert!(!signals.is_empty());
        assert!(
            signals[0].score < 0.6,
            "Equipment leak should be lower severity than coordinates"
        );
    }
}
