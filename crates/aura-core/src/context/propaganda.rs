use std::collections::HashSet;

use crate::types::{AnalysisMode, Confidence, DetectionSignal, SignalFamily, ThreatType};

use super::contact::ContactProfiler;
use super::events::EventKind;
use super::tracker::ConversationTimeline;

/// Classifies the specific propaganda narrative type for fine-grained analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PropagandaNarrativeType {
    /// "Special military operation" / war denial / "civil war" framing.
    WarDenial,
    /// Nazi/fascist accusations against Ukraine.
    NaziNarrative,
    /// Surrender / defeatism / "give up" messaging.
    Capitulation,
    /// "One people" / "brotherly nations" / statehood denial.
    Brotherhood,
    /// "Zrada" (betrayal) weaponization against Ukrainian leadership.
    Betrayal,
    /// Anti-Western conspiracy narratives (biolabs, NATO, "Anglo-Saxons").
    WesternConspiracy,
    /// Holodomor denial, historical revisionism.
    HistoricalRevisionism,
    /// Dehumanizing language targeting Ukrainians.
    Dehumanization,
    /// Whataboutism technique ("what about Iraq", "double standards").
    Whataboutism,
    /// Nuclear threats, WW3 fearmongering.
    FearAppeal,
}

impl PropagandaNarrativeType {
    /// Maps a pattern rule ID prefix to a narrative type.
    pub fn from_rule_id(rule_id: &str) -> Option<Self> {
        if rule_id.contains("denial") || rule_id.contains("war_denial") {
            Some(Self::WarDenial)
        } else if rule_id.contains("nazi") {
            Some(Self::NaziNarrative)
        } else if rule_id.contains("capitulation") || rule_id.contains("surrender") {
            Some(Self::Capitulation)
        } else if rule_id.contains("brotherhood") {
            Some(Self::Brotherhood)
        } else if rule_id.contains("betrayal") || rule_id.contains("zrada") {
            Some(Self::Betrayal)
        } else if rule_id.contains("western") || rule_id.contains("conspiracy") {
            Some(Self::WesternConspiracy)
        } else if rule_id.contains("historical") || rule_id.contains("revisionism") {
            Some(Self::HistoricalRevisionism)
        } else if rule_id.contains("dehumanize") || rule_id.contains("dehumanization") {
            Some(Self::Dehumanization)
        } else if rule_id.contains("whataboutism") {
            Some(Self::Whataboutism)
        } else if rule_id.contains("fear") || rule_id.contains("nuclear") {
            Some(Self::FearAppeal)
        } else {
            None
        }
    }

    /// Returns the string identifier used in reason codes and event subtypes.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WarDenial => "war_denial",
            Self::NaziNarrative => "nazi_narrative",
            Self::Capitulation => "capitulation",
            Self::Brotherhood => "brotherhood",
            Self::Betrayal => "betrayal",
            Self::WesternConspiracy => "western_conspiracy",
            Self::HistoricalRevisionism => "historical_revisionism",
            Self::Dehumanization => "dehumanization",
            Self::Whataboutism => "whataboutism",
            Self::FearAppeal => "fear_appeal",
        }
    }
}

/// Detects propaganda and disinformation narratives in conversations.
///
/// Tracks repeated propaganda events per sender and generates signals when
/// a sender consistently pushes disinformation narratives or shares
/// suspicious source links. Supports multi-narrative analysis to detect
/// coordinated bot-like behavior and false-positive mitigation for
/// quotations, negations, and counter-narratives.
pub struct PropagandaDetector {
    mode: AnalysisMode,
    /// Minimum propaganda events before generating a signal.
    min_events: usize,
    /// Lookback window in milliseconds (default 7 days).
    window_ms: u64,
}

impl Default for PropagandaDetector {
    fn default() -> Self {
        Self::new(AnalysisMode::Standard)
    }
}

impl PropagandaDetector {
    /// Creates a new propaganda detector with the given analysis mode.
    pub fn new(mode: AnalysisMode) -> Self {
        Self {
            mode,
            min_events: if mode.is_strict() { 1 } else { 2 },
            window_ms: 7 * 24 * 60 * 60 * 1000,
        }
    }

    /// Checks whether a propaganda pattern match is likely a false positive.
    ///
    /// Returns `true` when the matched text appears in a quotation, negation,
    /// or counter-narrative context — indicating the user is discussing or
    /// debunking propaganda rather than spreading it.
    pub fn check_false_positive_context(text: &str, match_start: usize) -> bool {
        let window = 60;
        let start = match_start.saturating_sub(window);
        let before = &text[start..match_start];
        let lower = before.to_lowercase();

        // Quotation framing: «», "", --, : before the match
        let quote_markers = ['\u{ab}', '\u{bb}', '\u{201c}', '\u{201d}', '"', ':', '\u{2014}'];
        if lower.chars().rev().take(5).any(|c| quote_markers.contains(&c)) {
            return true;
        }

        // Negation patterns (uk/ru/en)
        let negation_phrases = [
            "це не ",
            "це не\u{a0}",
            "это не ",
            "это не\u{a0}",
            "this is not ",
            "not a ",
            "не вірте",
            "не верьте",
            "don't believe",
            "do not believe",
        ];
        for phrase in &negation_phrases {
            if lower.contains(phrase) {
                return true;
            }
        }

        // Counter-narrative framing (discussing propaganda, not spreading it)
        let counter_phrases = [
            "пропагандисти кажуть",
            "пропагандисти стверджують",
            "пропагандисты говорят",
            "пропагандисты утверждают",
            "propagandists say",
            "propagandists claim",
            "стверджує ворог",
            "утверждает враг",
            "ворожа пропаганда",
            "вражеская пропаганда",
            "enemy propaganda",
            "fake news",
            "фейк",
            "спростування",
            "опровержение",
            "debunking",
        ];
        for phrase in &counter_phrases {
            if lower.contains(phrase) {
                return true;
            }
        }

        false
    }

    /// Analyzes a conversation timeline for propaganda patterns from a specific sender.
    ///
    /// Tracks narrative subtypes via event.subtype to enable multi-narrative analysis
    /// and compound pattern detection.
    pub fn analyze(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        now_ms: u64,
        contact_profiler: &ContactProfiler,
    ) -> Vec<DetectionSignal> {
        let mut signals = Vec::with_capacity(6);
        let window_start = now_ms.saturating_sub(self.window_ms);

        let mut propaganda_count = 0usize;
        let mut suspicious_source_count = 0usize;
        let mut disinfo_count = 0usize;
        let mut narrative_types: HashSet<String> = HashSet::new();

        for event in timeline.events_since(window_start) {
            if &*event.sender_id != sender_id {
                continue;
            }
            match event.kind {
                EventKind::PropagandaNarrative => {
                    propaganda_count += 1;
                    if let Some(ref st) = event.subtype {
                        narrative_types.insert(st.clone());
                    }
                }
                EventKind::SuspiciousSource => suspicious_source_count += 1,
                EventKind::MilitaryDisinfo => disinfo_count += 1,
                _ => {}
            }
        }

        let total_propaganda = propaganda_count + disinfo_count;
        let is_new = contact_profiler.is_new_contact(sender_id);

        // Repeated propaganda narrative pushing
        if total_propaganda >= self.min_events {
            let base_score: f32 = if total_propaganda >= 5 {
                0.85
            } else if total_propaganda >= 3 {
                0.7
            } else {
                0.55
            };
            let score = if is_new {
                (base_score + 0.1).min(0.95f32)
            } else {
                base_score
            };
            let confidence = if total_propaganda >= 3 {
                Confidence::High
            } else {
                Confidence::Medium
            };
            signals.push(DetectionSignal::context(
                ThreatType::Propaganda,
                score,
                confidence,
                SignalFamily::Content,
                "conversation.propaganda.repeated_narrative",
                format!(
                    "Sender pushed {} propaganda narrative(s) in conversation",
                    total_propaganda
                ),
            ));
        }

        // Multi-narrative analysis: sender pushes 3+ distinct narrative types = coordinated
        let distinct_count = narrative_types.len();
        if distinct_count >= 3 {
            let base_score: f32 = if distinct_count >= 5 {
                0.92
            } else if distinct_count >= 4 {
                0.88
            } else {
                0.82
            };
            let score = if is_new {
                (base_score + 0.05).min(0.95f32)
            } else {
                base_score
            };
            signals.push(DetectionSignal::context(
                ThreatType::Propaganda,
                score,
                Confidence::High,
                SignalFamily::Content,
                "conversation.propaganda.coordinated_multi_narrative",
                format!(
                    "Sender pushes {} distinct propaganda narrative types: {}",
                    distinct_count,
                    narrative_types
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }

        // Compound pattern: capitulation package (war_denial + capitulation + western_conspiracy)
        let has_war_denial = narrative_types.contains("war_denial");
        let has_capitulation = narrative_types.contains("capitulation");
        let has_western = narrative_types.contains("western_conspiracy");
        let has_brotherhood = narrative_types.contains("brotherhood");
        let has_revisionism = narrative_types.contains("historical_revisionism");
        let has_dehumanization = narrative_types.contains("dehumanization");

        if has_war_denial && has_capitulation && has_western {
            signals.push(DetectionSignal::context(
                ThreatType::Propaganda,
                0.88,
                Confidence::High,
                SignalFamily::Content,
                "conversation.propaganda.compound_capitulation",
                "Capitulation package: war denial + capitulation + western conspiracy",
            ));
        }

        // Compound pattern: historical package
        if has_revisionism && has_brotherhood {
            signals.push(DetectionSignal::context(
                ThreatType::Propaganda,
                0.85,
                Confidence::High,
                SignalFamily::Content,
                "conversation.propaganda.compound_historical",
                "Historical package: revisionism + brotherhood/statehood denial",
            ));
        }

        // Dehumanization always high severity
        if has_dehumanization {
            signals.push(DetectionSignal::context(
                ThreatType::Propaganda,
                0.90,
                Confidence::High,
                SignalFamily::Content,
                "conversation.propaganda.dehumanization",
                "Dehumanizing language targeting Ukrainians detected",
            ));
        }

        // Suspicious source links
        if suspicious_source_count >= 1 {
            let score = if suspicious_source_count >= 3 {
                0.8
            } else if suspicious_source_count >= 2 {
                0.65
            } else {
                0.5
            };
            signals.push(DetectionSignal::context(
                ThreatType::Propaganda,
                score,
                Confidence::Medium,
                SignalFamily::Link,
                "conversation.propaganda.suspicious_source",
                format!(
                    "Sender shared {} link(s) from suspicious source(s)",
                    suspicious_source_count
                ),
            ));
        }

        // Combined: propaganda narrative + suspicious sources = higher threat
        if total_propaganda >= 1 && suspicious_source_count >= 1 {
            let combined_count = total_propaganda + suspicious_source_count;
            let score = (0.6 + combined_count as f32 * 0.05).min(0.95f32);
            signals.push(DetectionSignal::context(
                ThreatType::Propaganda,
                score,
                Confidence::High,
                SignalFamily::Content,
                "conversation.propaganda.narrative_with_sources",
                format!(
                    "Sender combines propaganda narratives ({}) with suspicious links ({})",
                    total_propaganda, suspicious_source_count
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
    fn no_propaganda_in_normal_conversation() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("alice", "conv_1", EventKind::NormalConversation, 1000),
            make_event("bob", "conv_1", EventKind::NormalConversation, 2000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Standard);
        let signals = detector.analyze(&timeline, "alice", 5000, &profiler);
        assert!(signals.is_empty(), "Normal conversation should not trigger");
    }

    #[test]
    fn single_propaganda_event_not_enough_in_standard_mode() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![make_event(
            "troll",
            "conv_1",
            EventKind::PropagandaNarrative,
            1000,
        )];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Standard);
        let signals = detector.analyze(&timeline, "troll", 5000, &profiler);
        assert!(
            signals.is_empty(),
            "Single propaganda event should not trigger in standard mode"
        );
    }

    #[test]
    fn single_propaganda_event_triggers_in_strict_mode() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![make_event(
            "troll",
            "conv_1",
            EventKind::PropagandaNarrative,
            1000,
        )];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Strict);
        let signals = detector.analyze(&timeline, "troll", 5000, &profiler);
        assert!(!signals.is_empty(), "Should trigger in strict mode");
        assert_eq!(signals[0].threat_type, ThreatType::Propaganda);
    }

    #[test]
    fn repeated_propaganda_generates_signal() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("troll", "conv_1", EventKind::PropagandaNarrative, 1000),
            make_event("troll", "conv_1", EventKind::PropagandaNarrative, 2000),
            make_event("troll", "conv_1", EventKind::PropagandaNarrative, 3000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Standard);
        let signals = detector.analyze(&timeline, "troll", 5000, &profiler);
        assert!(!signals.is_empty(), "3 propaganda events should trigger");
        assert_eq!(signals[0].threat_type, ThreatType::Propaganda);
        assert!(signals[0].score >= 0.7, "Score should be >= 0.7");
    }

    #[test]
    fn suspicious_source_link_generates_signal() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![make_event(
            "troll",
            "conv_1",
            EventKind::SuspiciousSource,
            1000,
        )];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Standard);
        let signals = detector.analyze(&timeline, "troll", 5000, &profiler);
        assert!(!signals.is_empty(), "Suspicious source should trigger");
        assert!(
            signals[0]
                .reason_code
                .contains("suspicious_source"),
            "Should have suspicious_source reason code"
        );
    }

    #[test]
    fn combined_narrative_and_sources_high_score() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("troll", "conv_1", EventKind::PropagandaNarrative, 1000),
            make_event("troll", "conv_1", EventKind::PropagandaNarrative, 2000),
            make_event("troll", "conv_1", EventKind::SuspiciousSource, 3000),
            make_event("troll", "conv_1", EventKind::SuspiciousSource, 4000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Standard);
        let signals = detector.analyze(&timeline, "troll", 5000, &profiler);
        let combined = signals.iter().find(|s| {
            s.reason_code
                .contains("narrative_with_sources")
        });
        assert!(
            combined.is_some(),
            "Should have combined narrative+sources signal"
        );
        assert!(
            combined.unwrap().score >= 0.7,
            "Combined score should be high"
        );
    }

    #[test]
    fn new_contact_gets_higher_score() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("troll", "conv_1", EventKind::PropagandaNarrative, 1000),
            make_event("troll", "conv_1", EventKind::PropagandaNarrative, 2000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Standard);
        let signals = detector.analyze(&timeline, "troll", 5000, &profiler);
        assert!(!signals.is_empty());
        // New contact should get boosted score
        assert!(
            signals[0].score > 0.55,
            "New contact should boost score above base"
        );
    }

    #[test]
    fn events_outside_window_ignored() {
        let now = 10 * 24 * 60 * 60 * 1000u64; // day 10
        let old_ts = 1000u64; // day 0

        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("troll", "conv_1", EventKind::PropagandaNarrative, old_ts),
            make_event(
                "troll",
                "conv_1",
                EventKind::PropagandaNarrative,
                old_ts + 1000,
            ),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Standard);
        let signals = detector.analyze(&timeline, "troll", now, &profiler);
        assert!(
            signals.is_empty(),
            "Old events outside 7-day window should be ignored"
        );
    }

    #[test]
    fn other_sender_events_not_counted() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_event("alice", "conv_1", EventKind::PropagandaNarrative, 1000),
            make_event("alice", "conv_1", EventKind::PropagandaNarrative, 2000),
            make_event("alice", "conv_1", EventKind::PropagandaNarrative, 3000),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Standard);
        let signals = detector.analyze(&timeline, "bob", 5000, &profiler);
        assert!(
            signals.is_empty(),
            "Other sender's events should not be counted"
        );
    }

    // --- False-positive context checks ---

    #[test]
    fn false_positive_quotation_detected() {
        let text = "Як каже ворог: «спецоперація»";
        let pos = text.find("спецоперація").unwrap();
        assert!(
            PropagandaDetector::check_false_positive_context(text, pos),
            "Quotation mark before match should trigger false-positive"
        );
    }

    #[test]
    fn false_positive_negation_detected() {
        let text = "Це не спецоперація а повномасштабна війна";
        let pos = text.find("спецоперація").unwrap();
        assert!(
            PropagandaDetector::check_false_positive_context(text, pos),
            "Negation 'це не' before match should trigger false-positive"
        );
    }

    #[test]
    fn false_positive_counter_narrative_detected() {
        let text = "пропагандисти кажуть що це спецоперація але це неправда";
        let pos = text.find("спецоперація").unwrap();
        assert!(
            PropagandaDetector::check_false_positive_context(text, pos),
            "Counter-narrative framing should trigger false-positive"
        );
    }

    #[test]
    fn false_positive_debunking_detected() {
        let text = "спростування: так званий один народ це міф";
        let pos = text.find("один народ").unwrap();
        assert!(
            PropagandaDetector::check_false_positive_context(text, pos),
            "'спростування' framing should trigger false-positive"
        );
    }

    #[test]
    fn genuine_propaganda_not_false_positive() {
        let text = "Росія проводить спецоперацію для захисту Донбасу";
        let pos = text.find("спецоперацію").unwrap();
        assert!(
            !PropagandaDetector::check_false_positive_context(text, pos),
            "Genuine propaganda text should NOT be marked as false positive"
        );
    }

    #[test]
    fn false_positive_russian_negation() {
        let text = "Это не специальная военная операция, а война";
        let pos = text.find("специальная").unwrap();
        assert!(
            PropagandaDetector::check_false_positive_context(text, pos),
            "Russian negation 'это не' should trigger false-positive"
        );
    }

    #[test]
    fn false_positive_english_negation() {
        let text = "This is not a special military operation, it is a war";
        let pos = text.find("special").unwrap();
        assert!(
            PropagandaDetector::check_false_positive_context(text, pos),
            "English negation should trigger false-positive"
        );
    }

    // --- Narrative type mapping ---

    #[test]
    fn narrative_type_from_rule_id() {
        assert_eq!(
            PropagandaNarrativeType::from_rule_id("propaganda_denial_uk_001"),
            Some(PropagandaNarrativeType::WarDenial)
        );
        assert_eq!(
            PropagandaNarrativeType::from_rule_id("propaganda_nazi_uk_001"),
            Some(PropagandaNarrativeType::NaziNarrative)
        );
        assert_eq!(
            PropagandaNarrativeType::from_rule_id("propaganda_brotherhood_ru_001"),
            Some(PropagandaNarrativeType::Brotherhood)
        );
        assert_eq!(
            PropagandaNarrativeType::from_rule_id("propaganda_dehumanize_uk_001"),
            Some(PropagandaNarrativeType::Dehumanization)
        );
        assert_eq!(
            PropagandaNarrativeType::from_rule_id("propaganda_whataboutism_ru_001"),
            Some(PropagandaNarrativeType::Whataboutism)
        );
        assert_eq!(
            PropagandaNarrativeType::from_rule_id("some_unrelated_rule"),
            None
        );
    }

    // --- Multi-narrative and compound pattern tests ---

    fn make_subtyped_event(
        sender: &str,
        conv: &str,
        kind: EventKind,
        ts: u64,
        subtype: &str,
    ) -> ContextEvent {
        ContextEvent {
            event_id: 0,
            timestamp_ms: ts,
            sender_id: sender.into(),
            conversation_id: conv.into(),
            kind,
            confidence: 0.8,
            subtype: Some(subtype.into()),
        }
    }

    #[test]
    fn multi_narrative_coordinated_detection() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_subtyped_event("bot", "conv_1", EventKind::PropagandaNarrative, 1000, "war_denial"),
            make_subtyped_event("bot", "conv_1", EventKind::PropagandaNarrative, 2000, "brotherhood"),
            make_subtyped_event("bot", "conv_1", EventKind::PropagandaNarrative, 3000, "capitulation"),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Standard);
        let signals = detector.analyze(&timeline, "bot", 5000, &profiler);
        let coordinated = signals.iter().find(|s| {
            s.reason_code.contains("coordinated_multi_narrative")
        });
        assert!(
            coordinated.is_some(),
            "3 distinct narrative types should trigger coordinated detection"
        );
        assert!(
            coordinated.unwrap().score >= 0.8,
            "Coordinated propaganda score should be high"
        );
    }

    #[test]
    fn compound_capitulation_package() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_subtyped_event("bot", "conv_1", EventKind::PropagandaNarrative, 1000, "war_denial"),
            make_subtyped_event("bot", "conv_1", EventKind::PropagandaNarrative, 2000, "capitulation"),
            make_subtyped_event("bot", "conv_1", EventKind::PropagandaNarrative, 3000, "western_conspiracy"),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Standard);
        let signals = detector.analyze(&timeline, "bot", 5000, &profiler);
        let compound = signals.iter().find(|s| {
            s.reason_code.contains("compound_capitulation")
        });
        assert!(
            compound.is_some(),
            "War denial + capitulation + western conspiracy should trigger compound"
        );
        assert!(
            compound.unwrap().score >= 0.85,
            "Compound capitulation score should be >= 0.85"
        );
    }

    #[test]
    fn compound_historical_package() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_subtyped_event("bot", "conv_1", EventKind::PropagandaNarrative, 1000, "historical_revisionism"),
            make_subtyped_event("bot", "conv_1", EventKind::PropagandaNarrative, 2000, "brotherhood"),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Standard);
        let signals = detector.analyze(&timeline, "bot", 5000, &profiler);
        let compound = signals.iter().find(|s| {
            s.reason_code.contains("compound_historical")
        });
        assert!(
            compound.is_some(),
            "Historical revisionism + brotherhood should trigger compound"
        );
    }

    #[test]
    fn dehumanization_always_high_severity() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![make_subtyped_event(
            "troll",
            "conv_1",
            EventKind::PropagandaNarrative,
            1000,
            "dehumanization",
        )];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Strict);
        let signals = detector.analyze(&timeline, "troll", 5000, &profiler);
        let dehumanize = signals.iter().find(|s| {
            s.reason_code.contains("dehumanization")
        });
        assert!(
            dehumanize.is_some(),
            "Dehumanization should always generate signal"
        );
        assert!(
            dehumanize.unwrap().score >= 0.9,
            "Dehumanization score should be >= 0.9"
        );
    }

    #[test]
    fn two_same_narratives_not_coordinated() {
        let mut timeline = ConversationTimeline::new("conv_1".into(), 500);
        let events = vec![
            make_subtyped_event("bot", "conv_1", EventKind::PropagandaNarrative, 1000, "war_denial"),
            make_subtyped_event("bot", "conv_1", EventKind::PropagandaNarrative, 2000, "war_denial"),
        ];
        let profiler = setup_profiler(&events);
        for e in events {
            timeline.push(e);
        }

        let detector = PropagandaDetector::new(AnalysisMode::Standard);
        let signals = detector.analyze(&timeline, "bot", 5000, &profiler);
        let coordinated = signals.iter().find(|s| {
            s.reason_code.contains("coordinated_multi_narrative")
        });
        assert!(
            coordinated.is_none(),
            "Same narrative type repeated should NOT trigger coordinated detection"
        );
    }
}
