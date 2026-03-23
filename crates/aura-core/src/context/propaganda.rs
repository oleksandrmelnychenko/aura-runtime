use std::collections::HashMap;

use crate::types::{AnalysisMode, Confidence, DetectionSignal, SignalFamily, ThreatType};

use super::contact::ContactProfiler;
use super::events::EventKind;
use super::tracker::ConversationTimeline;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NarrativeId {
    WarDenial = 0,
    NaziNarrative = 1,
    Capitulation = 2,
    Brotherhood = 3,
    Betrayal = 4,
    WesternConspiracy = 5,
    HistoricalRevisionism = 6,
    Dehumanization = 7,
    Whataboutism = 8,
    FearAppeal = 9,
    Victimhood = 10,
    ReligiousManipulation = 11,
    EconomicCollapse = 12,
    RefugeeWeaponization = 13,
    LanguageOppression = 14,
}

struct NarrativeSpec {
    id: NarrativeId,
    tag: &'static str,
    rule_markers: &'static [&'static str],
    severity: f32,
}

const NARRATIVES: &[NarrativeSpec] = &[
    NarrativeSpec {
        id: NarrativeId::WarDenial,
        tag: "war_denial",
        rule_markers: &["denial", "war_denial", "donbas_8years", "svo_marker"],
        severity: 0.85,
    },
    NarrativeSpec {
        id: NarrativeId::NaziNarrative,
        tag: "nazi_narrative",
        rule_markers: &["nazi", "denazification"],
        severity: 0.90,
    },
    NarrativeSpec {
        id: NarrativeId::Capitulation,
        tag: "capitulation",
        rule_markers: &["capitulation", "surrender"],
        severity: 0.80,
    },
    NarrativeSpec {
        id: NarrativeId::Brotherhood,
        tag: "brotherhood",
        rule_markers: &["brotherhood"],
        severity: 0.70,
    },
    NarrativeSpec {
        id: NarrativeId::Betrayal,
        tag: "betrayal",
        rule_markers: &["betrayal", "zrada"],
        severity: 0.65,
    },
    NarrativeSpec {
        id: NarrativeId::WesternConspiracy,
        tag: "western_conspiracy",
        rule_markers: &["western", "conspiracy"],
        severity: 0.70,
    },
    NarrativeSpec {
        id: NarrativeId::HistoricalRevisionism,
        tag: "historical_revisionism",
        rule_markers: &["historical", "revisionism"],
        severity: 0.75,
    },
    NarrativeSpec {
        id: NarrativeId::Dehumanization,
        tag: "dehumanization",
        rule_markers: &["dehumanize", "dehumanization"],
        severity: 1.00,
    },
    NarrativeSpec {
        id: NarrativeId::Whataboutism,
        tag: "whataboutism",
        rule_markers: &["whataboutism"],
        severity: 0.55,
    },
    NarrativeSpec {
        id: NarrativeId::FearAppeal,
        tag: "fear_appeal",
        rule_markers: &["fear", "nuclear"],
        severity: 0.80,
    },
    NarrativeSpec {
        id: NarrativeId::Victimhood,
        tag: "victimhood",
        rule_markers: &["victimhood", "sanction"],
        severity: 0.65,
    },
    NarrativeSpec {
        id: NarrativeId::ReligiousManipulation,
        tag: "religious_manipulation",
        rule_markers: &["religious", "church", "canonical"],
        severity: 0.75,
    },
    NarrativeSpec {
        id: NarrativeId::EconomicCollapse,
        tag: "economic_collapse",
        rule_markers: &["economic_collapse", "fatigue"],
        severity: 0.60,
    },
    NarrativeSpec {
        id: NarrativeId::RefugeeWeaponization,
        tag: "refugee_weaponization",
        rule_markers: &["refugee"],
        severity: 0.70,
    },
    NarrativeSpec {
        id: NarrativeId::LanguageOppression,
        tag: "language_oppression",
        rule_markers: &["language_oppression"],
        severity: 0.65,
    },
];

struct CompoundRule {
    required: &'static [NarrativeId],
    any_of: &'static [NarrativeId],
    reason: &'static str,
    label: &'static str,
    score: f32,
}

const COMPOUND_RULES: &[CompoundRule] = &[
    CompoundRule {
        required: &[
            NarrativeId::WarDenial,
            NarrativeId::Capitulation,
            NarrativeId::WesternConspiracy,
        ],
        any_of: &[],
        reason: "conversation.propaganda.compound_capitulation",
        label: "Capitulation package: war denial + capitulation + western conspiracy",
        score: 0.88,
    },
    CompoundRule {
        required: &[NarrativeId::HistoricalRevisionism, NarrativeId::Brotherhood],
        any_of: &[],
        reason: "conversation.propaganda.compound_historical",
        label: "Historical package: revisionism + brotherhood/statehood denial",
        score: 0.85,
    },
    CompoundRule {
        required: &[
            NarrativeId::WarDenial,
            NarrativeId::NaziNarrative,
            NarrativeId::Victimhood,
        ],
        any_of: &[],
        reason: "conversation.propaganda.compound_justification",
        label: "Justification package: war denial + nazi accusations + victimhood",
        score: 0.90,
    },
    CompoundRule {
        required: &[NarrativeId::FearAppeal, NarrativeId::Capitulation],
        any_of: &[NarrativeId::EconomicCollapse],
        reason: "conversation.propaganda.compound_pressure",
        label: "Pressure package: fear appeal + capitulation + economic collapse",
        score: 0.87,
    },
    CompoundRule {
        required: &[NarrativeId::Brotherhood],
        any_of: &[
            NarrativeId::LanguageOppression,
            NarrativeId::ReligiousManipulation,
        ],
        reason: "conversation.propaganda.compound_identity_erasure",
        label: "Identity erasure package: brotherhood + language/religious manipulation",
        score: 0.85,
    },
    CompoundRule {
        required: &[NarrativeId::RefugeeWeaponization],
        any_of: &[
            NarrativeId::EconomicCollapse,
            NarrativeId::WesternConspiracy,
        ],
        reason: "conversation.propaganda.compound_wedge",
        label: "Wedge package: refugee weaponization + economic/western fatigue",
        score: 0.80,
    },
    CompoundRule {
        required: &[NarrativeId::Dehumanization, NarrativeId::NaziNarrative],
        any_of: &[],
        reason: "conversation.propaganda.compound_hate",
        label: "Hate package: dehumanization + nazi accusations",
        score: 0.93,
    },
    CompoundRule {
        required: &[NarrativeId::Betrayal, NarrativeId::EconomicCollapse],
        any_of: &[NarrativeId::Capitulation],
        reason: "conversation.propaganda.compound_demoralization",
        label: "Demoralization package: betrayal + economic collapse",
        score: 0.82,
    },
];

struct ScoreTier {
    min_count: usize,
    score: f32,
}

const REPETITION_TIERS: &[ScoreTier] = &[
    ScoreTier {
        min_count: 5,
        score: 0.85,
    },
    ScoreTier {
        min_count: 3,
        score: 0.70,
    },
    ScoreTier {
        min_count: 1,
        score: 0.55,
    },
];

const SOURCE_TIERS: &[ScoreTier] = &[
    ScoreTier {
        min_count: 3,
        score: 0.80,
    },
    ScoreTier {
        min_count: 2,
        score: 0.65,
    },
    ScoreTier {
        min_count: 1,
        score: 0.50,
    },
];

const COORDINATION_TIERS: &[ScoreTier] = &[
    ScoreTier {
        min_count: 5,
        score: 0.92,
    },
    ScoreTier {
        min_count: 4,
        score: 0.88,
    },
    ScoreTier {
        min_count: 3,
        score: 0.82,
    },
];

const CROSS_CONV_TIERS: &[ScoreTier] = &[
    ScoreTier {
        min_count: 5,
        score: 0.95,
    },
    ScoreTier {
        min_count: 3,
        score: 0.90,
    },
    ScoreTier {
        min_count: 2,
        score: 0.82,
    },
];

fn tier_score(tiers: &[ScoreTier], count: usize) -> Option<f32> {
    for tier in tiers {
        if count >= tier.min_count {
            return Some(tier.score);
        }
    }
    None
}

const FALSE_POSITIVE_QUOTE_CHARS: &[char] = &[
    '\u{ab}', '\u{bb}', '\u{201c}', '\u{201d}', '"', ':', '\u{2014}',
];

const FALSE_POSITIVE_NEGATIONS: &[&str] = &[
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

const FALSE_POSITIVE_COUNTER: &[&str] = &[
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

impl NarrativeId {
    pub fn from_rule_id(rule_id: &str) -> Option<Self> {
        for spec in NARRATIVES {
            for marker in spec.rule_markers {
                if rule_id.contains(marker) {
                    return Some(spec.id);
                }
            }
        }
        None
    }

    pub fn tag(self) -> &'static str {
        for spec in NARRATIVES {
            if spec.id == self {
                return spec.tag;
            }
        }
        ""
    }

    pub fn severity(self) -> f32 {
        for spec in NARRATIVES {
            if spec.id == self {
                return spec.severity;
            }
        }
        0.5
    }
}

struct SenderSnapshot {
    propaganda_count: usize,
    source_count: usize,
    disinfo_count: usize,
    burst_count: usize,
    narrative_hits: HashMap<NarrativeId, usize>,
    timestamps: Vec<u64>,
}

impl SenderSnapshot {
    fn collect(
        timeline: &ConversationTimeline,
        sender_id: &str,
        window_start: u64,
        burst_start: u64,
    ) -> Self {
        let mut snap = Self {
            propaganda_count: 0,
            source_count: 0,
            disinfo_count: 0,
            burst_count: 0,
            narrative_hits: HashMap::new(),
            timestamps: Vec::new(),
        };

        for event in timeline.events_since(window_start) {
            if &*event.sender_id != sender_id {
                continue;
            }
            match event.kind {
                EventKind::PropagandaNarrative => {
                    snap.propaganda_count += 1;
                    snap.timestamps.push(event.timestamp_ms);
                    if event.timestamp_ms >= burst_start {
                        snap.burst_count += 1;
                    }
                    if let Some(ref st) = event.subtype {
                        let narrative_id = NarrativeId::from_subtype(st);
                        if let Some(nid) = narrative_id {
                            *snap.narrative_hits.entry(nid).or_insert(0) += 1;
                        }
                    }
                }
                EventKind::SuspiciousSource => snap.source_count += 1,
                EventKind::MilitaryDisinfo => snap.disinfo_count += 1,
                _ => {}
            }
        }

        snap
    }

    fn total(&self) -> usize {
        self.propaganda_count + self.disinfo_count
    }

    fn distinct_narratives(&self) -> usize {
        self.narrative_hits.len()
    }

    fn has(&self, id: NarrativeId) -> bool {
        self.narrative_hits.contains_key(&id)
    }

    fn velocity_per_hour(&self) -> Option<f64> {
        if self.timestamps.len() < 3 {
            return None;
        }
        let mut sorted = self.timestamps.clone();
        sorted.sort_unstable();
        let span = sorted.last().unwrap() - sorted.first().unwrap();
        if span == 0 {
            return None;
        }
        Some(sorted.len() as f64 / (span as f64 / 3_600_000.0))
    }
}

impl NarrativeId {
    pub fn from_subtype(subtype: &str) -> Option<Self> {
        for spec in NARRATIVES {
            if spec.tag == subtype {
                return Some(spec.id);
            }
        }
        None
    }
}

pub struct PropagandaDetector {
    min_events: usize,
    window_ms: u64,
    burst_window_ms: u64,
    burst_threshold: usize,
    hammering_threshold: usize,
    velocity_threshold: f64,
    min_velocity_events: usize,
    min_radicalization_events: u64,
    min_copy_paste_events: u64,
}

impl Default for PropagandaDetector {
    fn default() -> Self {
        Self::new(AnalysisMode::Standard)
    }
}

impl PropagandaDetector {
    pub fn new(mode: AnalysisMode) -> Self {
        let strict = mode.is_strict();
        Self {
            min_events: if strict { 1 } else { 2 },
            window_ms: 7 * 24 * 60 * 60 * 1000,
            burst_window_ms: 30 * 60 * 1000,
            burst_threshold: if strict { 2 } else { 3 },
            hammering_threshold: 5,
            velocity_threshold: 10.0,
            min_velocity_events: if strict { 5 } else { 6 },
            min_radicalization_events: if strict { 8 } else { 12 },
            min_copy_paste_events: if strict { 10 } else { 12 },
        }
    }

    pub fn check_false_positive_context(text: &str, match_start: usize) -> bool {
        let window = 60;
        let mut start = match_start.saturating_sub(window);
        while start > 0 && !text.is_char_boundary(start) {
            start -= 1;
        }
        let before = &text[start..match_start];
        let lower = before.to_lowercase();

        if lower
            .chars()
            .rev()
            .take(5)
            .any(|c| FALSE_POSITIVE_QUOTE_CHARS.contains(&c))
        {
            return true;
        }

        for phrase in FALSE_POSITIVE_NEGATIONS {
            if lower.contains(phrase) {
                return true;
            }
        }

        for phrase in FALSE_POSITIVE_COUNTER {
            if lower.contains(phrase) {
                return true;
            }
        }

        false
    }

    pub fn analyze(
        &self,
        timeline: &ConversationTimeline,
        sender_id: &str,
        now_ms: u64,
        contact_profiler: &ContactProfiler,
    ) -> Vec<DetectionSignal> {
        let window_start = now_ms.saturating_sub(self.window_ms);
        let burst_start = now_ms.saturating_sub(self.burst_window_ms);
        let snap = SenderSnapshot::collect(timeline, sender_id, window_start, burst_start);
        let is_new = contact_profiler.is_new_contact(sender_id);

        let mut signals = Vec::with_capacity(8);

        self.check_repetition(&snap, is_new, &mut signals);
        self.check_burst(&snap, &mut signals);
        self.check_coordination(&snap, is_new, &mut signals);
        self.check_compounds(&snap, &mut signals);
        self.check_dehumanization(&snap, &mut signals);
        self.check_hammering(&snap, &mut signals);
        self.check_sources(&snap, &mut signals);
        self.check_combined(&snap, &mut signals);
        self.check_velocity(&snap, &mut signals);

        self.check_behavioral(sender_id, contact_profiler, &mut signals);

        signals
    }

    fn check_repetition(
        &self,
        snap: &SenderSnapshot,
        is_new: bool,
        signals: &mut Vec<DetectionSignal>,
    ) {
        let total = snap.total();
        if total < self.min_events {
            return;
        }
        let Some(base) = tier_score(REPETITION_TIERS, total) else {
            return;
        };
        let score = if is_new { (base + 0.1).min(0.95) } else { base };
        let confidence = if total >= 3 {
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
                total
            ),
        ));
    }

    fn check_burst(&self, snap: &SenderSnapshot, signals: &mut Vec<DetectionSignal>) {
        if snap.burst_count < self.burst_threshold {
            return;
        }
        let score = (0.75 + snap.burst_count as f32 * 0.03).min(0.95);
        signals.push(DetectionSignal::context(
            ThreatType::Propaganda,
            score,
            Confidence::High,
            SignalFamily::Content,
            "conversation.propaganda.burst",
            format!(
                "Propaganda burst: {} messages in {} minutes",
                snap.burst_count,
                self.burst_window_ms / 60_000
            ),
        ));
    }

    fn check_coordination(
        &self,
        snap: &SenderSnapshot,
        is_new: bool,
        signals: &mut Vec<DetectionSignal>,
    ) {
        let distinct = snap.distinct_narratives();
        if distinct < 3 {
            return;
        }
        let Some(base) = tier_score(COORDINATION_TIERS, distinct) else {
            return;
        };
        let score = if is_new {
            (base + 0.05).min(0.95)
        } else {
            base
        };

        let mut names: Vec<&str> = snap.narrative_hits.keys().map(|id| id.tag()).collect();
        names.sort_unstable();
        signals.push(DetectionSignal::context(
            ThreatType::Propaganda,
            score,
            Confidence::High,
            SignalFamily::Content,
            "conversation.propaganda.coordinated_multi_narrative",
            format!(
                "Sender pushes {} distinct propaganda narrative types: {}",
                distinct,
                names.join(", ")
            ),
        ));
    }

    fn check_compounds(&self, snap: &SenderSnapshot, signals: &mut Vec<DetectionSignal>) {
        for rule in COMPOUND_RULES {
            let all_required = rule.required.iter().all(|id| snap.has(*id));
            if !all_required {
                continue;
            }
            let any_met = rule.any_of.is_empty() || rule.any_of.iter().any(|id| snap.has(*id));
            if !any_met {
                continue;
            }
            signals.push(DetectionSignal::context(
                ThreatType::Propaganda,
                rule.score,
                Confidence::High,
                SignalFamily::Content,
                rule.reason,
                rule.label,
            ));
        }
    }

    fn check_dehumanization(&self, snap: &SenderSnapshot, signals: &mut Vec<DetectionSignal>) {
        if !snap.has(NarrativeId::Dehumanization) {
            return;
        }
        signals.push(DetectionSignal::context(
            ThreatType::Propaganda,
            0.90,
            Confidence::High,
            SignalFamily::Content,
            "conversation.propaganda.dehumanization",
            "Dehumanizing language targeting Ukrainians detected",
        ));
    }

    fn check_hammering(&self, snap: &SenderSnapshot, signals: &mut Vec<DetectionSignal>) {
        for (nid, count) in &snap.narrative_hits {
            if *count >= self.hammering_threshold {
                signals.push(DetectionSignal::context(
                    ThreatType::Propaganda,
                    0.80,
                    Confidence::High,
                    SignalFamily::Content,
                    "conversation.propaganda.narrative_hammering",
                    format!("Sender repeated '{}' narrative {} times", nid.tag(), count),
                ));
            }
        }
    }

    fn check_sources(&self, snap: &SenderSnapshot, signals: &mut Vec<DetectionSignal>) {
        if snap.source_count == 0 {
            return;
        }
        let Some(score) = tier_score(SOURCE_TIERS, snap.source_count) else {
            return;
        };
        signals.push(DetectionSignal::context(
            ThreatType::Propaganda,
            score,
            Confidence::Medium,
            SignalFamily::Link,
            "conversation.propaganda.suspicious_source",
            format!(
                "Sender shared {} link(s) from suspicious source(s)",
                snap.source_count
            ),
        ));
    }

    fn check_combined(&self, snap: &SenderSnapshot, signals: &mut Vec<DetectionSignal>) {
        if snap.total() < 1 || snap.source_count < 1 {
            return;
        }
        let combined = snap.total() + snap.source_count;
        let score = (0.6 + combined as f32 * 0.05).min(0.95);
        signals.push(DetectionSignal::context(
            ThreatType::Propaganda,
            score,
            Confidence::High,
            SignalFamily::Content,
            "conversation.propaganda.narrative_with_sources",
            format!(
                "Sender combines propaganda narratives ({}) with suspicious links ({})",
                snap.total(),
                snap.source_count
            ),
        ));
    }

    fn check_velocity(&self, snap: &SenderSnapshot, signals: &mut Vec<DetectionSignal>) {
        if snap.propaganda_count < self.min_velocity_events {
            return;
        }
        let Some(rate) = snap.velocity_per_hour() else {
            return;
        };
        if rate < self.velocity_threshold {
            return;
        }
        signals.push(DetectionSignal::context(
            ThreatType::Propaganda,
            0.88,
            Confidence::High,
            SignalFamily::Content,
            "conversation.propaganda.high_velocity",
            format!("High propaganda velocity: {:.1} narratives/hour", rate),
        ));
    }

    fn check_behavioral(
        &self,
        sender_id: &str,
        profiler: &ContactProfiler,
        signals: &mut Vec<DetectionSignal>,
    ) {
        let Some(profile) = profiler.profile(sender_id) else {
            return;
        };

        if profile.propaganda_event_count == 0 {
            return;
        }

        self.check_new_account_immediate(profile, signals);
        self.check_concentration(profile, signals);
        self.check_multi_chat_spreader(profile, signals);
        self.check_radicalization(profile, signals);
        self.check_narrative_escalation(profile, signals);
        self.check_temporal_patterns(profile, signals);
        self.check_persistent_hammering(profile, signals);
        self.check_copy_paste(profile, signals);
    }

    fn check_new_account_immediate(
        &self,
        profile: &super::contact::ContactProfile,
        signals: &mut Vec<DetectionSignal>,
    ) {
        if profile.first_propaganda_ms == 0 {
            return;
        }
        let onset_delay = profile
            .first_propaganda_ms
            .saturating_sub(profile.first_seen_ms);
        let one_day = 24 * 60 * 60 * 1000;
        if onset_delay >= one_day || profile.propaganda_event_count < 3 {
            return;
        }
        let score = (0.80 + profile.propaganda_event_count as f32 * 0.02).min(0.92);
        signals.push(DetectionSignal::context(
            ThreatType::Propaganda,
            score,
            Confidence::High,
            SignalFamily::Content,
            "conversation.propaganda.behavioral.new_account_immediate",
            format!(
                "New account started propaganda within {}h ({} events)",
                onset_delay / 3_600_000,
                profile.propaganda_event_count
            ),
        ));
    }

    fn check_concentration(
        &self,
        profile: &super::contact::ContactProfile,
        signals: &mut Vec<DetectionSignal>,
    ) {
        if profile.total_messages < 10 {
            return;
        }
        let ratio = profile.propaganda_event_count as f32 / profile.total_messages as f32;
        if ratio <= 0.5 {
            return;
        }
        let score = (ratio * 0.9).min(0.95);
        signals.push(DetectionSignal::context(
            ThreatType::Propaganda,
            score,
            Confidence::High,
            SignalFamily::Content,
            "conversation.propaganda.behavioral.high_concentration",
            format!(
                "Propaganda concentration: {:.0}% of {} messages",
                ratio * 100.0,
                profile.total_messages
            ),
        ));
    }

    fn check_multi_chat_spreader(
        &self,
        profile: &super::contact::ContactProfile,
        signals: &mut Vec<DetectionSignal>,
    ) {
        let conv_count = profile.propaganda_conversations.len();
        if conv_count < 3 || profile.propaganda_event_count < 10 {
            return;
        }
        let score = if conv_count >= 5 {
            0.95
        } else if conv_count >= 4 {
            0.92
        } else {
            0.90
        };
        signals.push(DetectionSignal::context(
            ThreatType::Propaganda,
            score,
            Confidence::High,
            SignalFamily::Content,
            "conversation.propaganda.behavioral.multi_chat_spreader",
            format!(
                "Sender spreads propaganda across {} conversations ({} total events)",
                conv_count, profile.propaganda_event_count
            ),
        ));
    }

    fn check_radicalization(
        &self,
        profile: &super::contact::ContactProfile,
        signals: &mut Vec<DetectionSignal>,
    ) {
        if profile.propaganda_event_count < self.min_radicalization_events {
            return;
        }
        let counts = &profile.weekly_propaganda_counts;
        if counts.len() < 3 {
            return;
        }
        let half = counts.len() / 2;
        let early_avg: f32 = counts
            .iter()
            .take(half)
            .map(|(_, c)| *c as f32)
            .sum::<f32>()
            / half as f32;
        let late_avg: f32 = counts
            .iter()
            .skip(half)
            .map(|(_, c)| *c as f32)
            .sum::<f32>()
            / (counts.len() - half) as f32;

        if late_avg <= early_avg || early_avg >= late_avg * 0.8 || late_avg < 2.0 {
            return;
        }

        let score = if late_avg > early_avg * 3.0 {
            0.85
        } else {
            0.70
        };
        signals.push(DetectionSignal::context(
            ThreatType::Propaganda,
            score,
            Confidence::High,
            SignalFamily::Content,
            "conversation.propaganda.behavioral.radicalization",
            format!(
                "Radicalization trajectory: early avg {:.1}, recent avg {:.1} propaganda/week",
                early_avg, late_avg
            ),
        ));
    }

    fn check_narrative_escalation(
        &self,
        profile: &super::contact::ContactProfile,
        signals: &mut Vec<DetectionSignal>,
    ) {
        let tl = &profile.narrative_timeline;
        if tl.len() < 6 {
            return;
        }
        let half = tl.len() / 2;

        let early_severity: f32 = tl
            .iter()
            .take(half)
            .filter_map(|(_, nid_u8)| {
                for spec in NARRATIVES {
                    if spec.id as u8 == *nid_u8 {
                        return Some(spec.severity);
                    }
                }
                None
            })
            .sum::<f32>()
            / half as f32;

        let late_severity: f32 = tl
            .iter()
            .skip(half)
            .filter_map(|(_, nid_u8)| {
                for spec in NARRATIVES {
                    if spec.id as u8 == *nid_u8 {
                        return Some(spec.severity);
                    }
                }
                None
            })
            .sum::<f32>()
            / (tl.len() - half) as f32;

        if late_severity <= early_severity + 0.1 {
            return;
        }
        signals.push(DetectionSignal::context(
            ThreatType::Propaganda,
            0.82,
            Confidence::High,
            SignalFamily::Content,
            "conversation.propaganda.behavioral.narrative_escalation",
            format!(
                "Narrative escalation: early severity {:.2} → recent {:.2}",
                early_severity, late_severity
            ),
        ));
    }

    fn check_temporal_patterns(
        &self,
        profile: &super::contact::ContactProfile,
        signals: &mut Vec<DetectionSignal>,
    ) {
        let total: u32 = profile
            .hourly_activity
            .iter()
            .copied()
            .map(|x| x as u32)
            .sum();
        if total < 10 {
            return;
        }
        let total_f = total as f32;

        let night_sum: u32 = profile.hourly_activity[0..6]
            .iter()
            .copied()
            .map(|x| x as u32)
            .sum();
        if night_sum as f32 / total_f > 0.6 {
            signals.push(DetectionSignal::context(
                ThreatType::Propaganda,
                0.75,
                Confidence::Medium,
                SignalFamily::Content,
                "conversation.propaganda.behavioral.nocturnal_posting",
                format!(
                    "Nocturnal propaganda posting: {:.0}% between 0-6h",
                    night_sum as f32 / total_f * 100.0
                ),
            ));
        }

        let mean = total_f / 24.0;
        if mean < 1.0 {
            return;
        }
        let variance: f32 = profile
            .hourly_activity
            .iter()
            .map(|&x| {
                let diff = x as f32 - mean;
                diff * diff
            })
            .sum::<f32>()
            / 24.0;
        let std_dev = variance.sqrt();
        if std_dev < mean * 0.5 && total >= 20 {
            signals.push(DetectionSignal::context(
                ThreatType::Propaganda,
                0.80,
                Confidence::High,
                SignalFamily::Content,
                "conversation.propaganda.behavioral.uniform_timing",
                format!(
                    "Uniform posting distribution (std_dev={:.1}, mean={:.1}) — bot-like",
                    std_dev, mean
                ),
            ));
        }
    }

    fn check_persistent_hammering(
        &self,
        profile: &super::contact::ContactProfile,
        signals: &mut Vec<DetectionSignal>,
    ) {
        for &(nid_u8, count) in &profile.narrative_hits {
            if count >= 20 {
                let tag = NARRATIVES
                    .iter()
                    .find(|s| s.id as u8 == nid_u8)
                    .map(|s| s.tag)
                    .unwrap_or("unknown");
                signals.push(DetectionSignal::context(
                    ThreatType::Propaganda,
                    0.83,
                    Confidence::High,
                    SignalFamily::Content,
                    "conversation.propaganda.behavioral.persistent_hammering",
                    format!(
                        "Persistent narrative hammering: '{}' repeated {} times (lifetime)",
                        tag, count
                    ),
                ));
            }
        }
    }

    fn check_copy_paste(
        &self,
        profile: &super::contact::ContactProfile,
        signals: &mut Vec<DetectionSignal>,
    ) {
        if profile.propaganda_event_count < self.min_copy_paste_events {
            return;
        }
        let total = profile.message_fingerprints.len();
        if total < self.min_copy_paste_events as usize {
            return;
        }

        let mut counts: HashMap<u64, usize> = HashMap::new();
        for hash in &profile.message_fingerprints {
            let entry = counts.entry(*hash).or_insert(0);
            *entry += 1;
        }

        let mut max_repeats = 0usize;
        for count in counts.values() {
            if *count > max_repeats {
                max_repeats = *count;
            }
        }

        let ratio = max_repeats as f32 / total as f32;
        if max_repeats < 6 || ratio < 0.55 {
            return;
        }

        let score = (0.72 + ratio * 0.2).min(0.9);
        signals.push(DetectionSignal::context(
            ThreatType::Propaganda,
            score,
            Confidence::High,
            SignalFamily::Content,
            "conversation.propaganda.behavioral.copy_paste_reuse",
            format!(
                "Repeated copy-paste pattern: top message repeated {}/{} times ({:.0}%)",
                max_repeats,
                total,
                ratio * 100.0
            ),
        ));
    }

    pub fn analyze_cross_conversation(
        &self,
        timelines: &[&ConversationTimeline],
        sender_id: &str,
        now_ms: u64,
    ) -> Vec<DetectionSignal> {
        let window_start = now_ms.saturating_sub(self.window_ms);
        let mut conv_count = 0usize;
        let mut unique_narratives: HashMap<NarrativeId, bool> = HashMap::new();

        for timeline in timelines {
            let mut has_propaganda = false;
            for event in timeline.events_since(window_start) {
                if &*event.sender_id != sender_id {
                    continue;
                }
                if event.kind == EventKind::PropagandaNarrative {
                    has_propaganda = true;
                    if let Some(ref st) = event.subtype {
                        if let Some(nid) = NarrativeId::from_subtype(st) {
                            unique_narratives.insert(nid, true);
                        }
                    }
                }
            }
            if has_propaganda {
                conv_count += 1;
            }
        }

        let mut signals = Vec::new();
        if let Some(score) = tier_score(CROSS_CONV_TIERS, conv_count) {
            signals.push(DetectionSignal::context(
                ThreatType::Propaganda,
                score,
                Confidence::High,
                SignalFamily::Content,
                "cross_conversation.propaganda.coordinated",
                format!(
                    "Sender pushes propaganda in {} conversations with {} narrative types",
                    conv_count,
                    unique_narratives.len()
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

    fn event(sender: &str, conv: &str, kind: EventKind, ts: u64) -> ContextEvent {
        ContextEvent::new(ts, sender, conv, kind, 0.8)
    }

    fn typed_event(sender: &str, conv: &str, ts: u64, subtype: &str) -> ContextEvent {
        ContextEvent::with_subtype(
            ts,
            sender,
            conv,
            EventKind::PropagandaNarrative,
            0.8,
            subtype,
        )
    }

    fn profiler(events: &[ContextEvent]) -> ContactProfiler {
        let mut p = ContactProfiler::new();
        for e in events {
            p.record_event(e);
        }
        p
    }

    fn build(events: Vec<ContextEvent>) -> (ConversationTimeline, ContactProfiler) {
        let mut tl = ConversationTimeline::new("conv_1".into(), 500);
        let pr = profiler(&events);
        for e in events {
            tl.push(e);
        }
        (tl, pr)
    }

    fn has_reason(signals: &[DetectionSignal], needle: &str) -> bool {
        signals.iter().any(|s| s.reason_code.contains(needle))
    }

    #[test]
    fn clean_conversation_no_signals() {
        let (tl, pr) = build(vec![
            event("alice", "conv_1", EventKind::NormalConversation, 1000),
            event("bob", "conv_1", EventKind::NormalConversation, 2000),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        assert!(d.analyze(&tl, "alice", 5000, &pr).is_empty());
    }

    #[test]
    fn single_event_standard_no_trigger() {
        let (tl, pr) = build(vec![event(
            "troll",
            "conv_1",
            EventKind::PropagandaNarrative,
            1000,
        )]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        assert!(d.analyze(&tl, "troll", 5000, &pr).is_empty());
    }

    #[test]
    fn single_event_strict_triggers() {
        let (tl, pr) = build(vec![event(
            "troll",
            "conv_1",
            EventKind::PropagandaNarrative,
            1000,
        )]);
        let d = PropagandaDetector::new(AnalysisMode::Strict);
        let s = d.analyze(&tl, "troll", 5000, &pr);
        assert!(!s.is_empty());
        assert_eq!(s[0].threat_type, ThreatType::Propaganda);
    }

    #[test]
    fn repeated_propaganda_scores_high() {
        let (tl, pr) = build(vec![
            event("troll", "conv_1", EventKind::PropagandaNarrative, 1000),
            event("troll", "conv_1", EventKind::PropagandaNarrative, 2000),
            event("troll", "conv_1", EventKind::PropagandaNarrative, 3000),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "troll", 5000, &pr);
        assert!(has_reason(&s, "repeated_narrative"));
        assert!(s[0].score >= 0.7);
    }

    #[test]
    fn suspicious_source_generates_signal() {
        let (tl, pr) = build(vec![event(
            "troll",
            "conv_1",
            EventKind::SuspiciousSource,
            1000,
        )]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "troll", 5000, &pr);
        assert!(has_reason(&s, "suspicious_source"));
    }

    #[test]
    fn combined_narrative_and_sources() {
        let (tl, pr) = build(vec![
            event("troll", "conv_1", EventKind::PropagandaNarrative, 1000),
            event("troll", "conv_1", EventKind::PropagandaNarrative, 2000),
            event("troll", "conv_1", EventKind::SuspiciousSource, 3000),
            event("troll", "conv_1", EventKind::SuspiciousSource, 4000),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "troll", 5000, &pr);
        assert!(has_reason(&s, "narrative_with_sources"));
        let combined = s
            .iter()
            .find(|x| x.reason_code.contains("narrative_with_sources"))
            .unwrap();
        assert!(combined.score >= 0.7);
    }

    #[test]
    fn new_contact_boosted_score() {
        let (tl, pr) = build(vec![
            event("troll", "conv_1", EventKind::PropagandaNarrative, 1000),
            event("troll", "conv_1", EventKind::PropagandaNarrative, 2000),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "troll", 5000, &pr);
        assert!(!s.is_empty());
        assert!(s[0].score > 0.55);
    }

    #[test]
    fn old_events_outside_window_ignored() {
        let now = 10 * 24 * 60 * 60 * 1000u64;
        let old = 1000u64;
        let (tl, pr) = build(vec![
            event("troll", "conv_1", EventKind::PropagandaNarrative, old),
            event(
                "troll",
                "conv_1",
                EventKind::PropagandaNarrative,
                old + 1000,
            ),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        assert!(d.analyze(&tl, "troll", now, &pr).is_empty());
    }

    #[test]
    fn other_sender_not_counted() {
        let (tl, pr) = build(vec![
            event("alice", "conv_1", EventKind::PropagandaNarrative, 1000),
            event("alice", "conv_1", EventKind::PropagandaNarrative, 2000),
            event("alice", "conv_1", EventKind::PropagandaNarrative, 3000),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        assert!(d.analyze(&tl, "bob", 5000, &pr).is_empty());
    }

    #[test]
    fn false_positive_quotation() {
        let text = "\u{041a}\u{0430}\u{043a} \u{043a}\u{0430}\u{0436}\u{0435} \u{0432}\u{043e}\u{0440}\u{043e}\u{0433}: \u{00ab}\u{0441}\u{043f}\u{0435}\u{0446}\u{043e}\u{043f}\u{0435}\u{0440}\u{0430}\u{0446}\u{0456}\u{044f}\u{00bb}";
        let pos = text.find("\u{0441}\u{043f}\u{0435}\u{0446}\u{043e}\u{043f}\u{0435}\u{0440}\u{0430}\u{0446}\u{0456}\u{044f}").unwrap();
        assert!(PropagandaDetector::check_false_positive_context(text, pos));
    }

    #[test]
    fn false_positive_negation_uk() {
        let text = "\u{0426}\u{0435} \u{043d}\u{0435} \u{0441}\u{043f}\u{0435}\u{0446}\u{043e}\u{043f}\u{0435}\u{0440}\u{0430}\u{0446}\u{0456}\u{044f} \u{0430} \u{043f}\u{043e}\u{0432}\u{043d}\u{043e}\u{043c}\u{0430}\u{0441}\u{0448}\u{0442}\u{0430}\u{0431}\u{043d}\u{0430} \u{0432}\u{0456}\u{0439}\u{043d}\u{0430}";
        let pos = text.find("\u{0441}\u{043f}\u{0435}\u{0446}\u{043e}\u{043f}\u{0435}\u{0440}\u{0430}\u{0446}\u{0456}\u{044f}").unwrap();
        assert!(PropagandaDetector::check_false_positive_context(text, pos));
    }

    #[test]
    fn false_positive_counter_narrative() {
        let text = "\u{043f}\u{0440}\u{043e}\u{043f}\u{0430}\u{0433}\u{0430}\u{043d}\u{0434}\u{0438}\u{0441}\u{0442}\u{0438} \u{043a}\u{0430}\u{0436}\u{0443}\u{0442}\u{044c} \u{0449}\u{043e} \u{0446}\u{0435} \u{0441}\u{043f}\u{0435}\u{0446}\u{043e}\u{043f}\u{0435}\u{0440}\u{0430}\u{0446}\u{0456}\u{044f} \u{0430}\u{043b}\u{0435} \u{0446}\u{0435} \u{043d}\u{0435}\u{043f}\u{0440}\u{0430}\u{0432}\u{0434}\u{0430}";
        let pos = text.find("\u{0441}\u{043f}\u{0435}\u{0446}\u{043e}\u{043f}\u{0435}\u{0440}\u{0430}\u{0446}\u{0456}\u{044f}").unwrap();
        assert!(PropagandaDetector::check_false_positive_context(text, pos));
    }

    #[test]
    fn false_positive_debunking() {
        let text = "\u{0441}\u{043f}\u{0440}\u{043e}\u{0441}\u{0442}\u{0443}\u{0432}\u{0430}\u{043d}\u{043d}\u{044f}: \u{0442}\u{0430}\u{043a} \u{0437}\u{0432}\u{0430}\u{043d}\u{0438}\u{0439} \u{043e}\u{0434}\u{0438}\u{043d} \u{043d}\u{0430}\u{0440}\u{043e}\u{0434} \u{0446}\u{0435} \u{043c}\u{0456}\u{0444}";
        let pos = text
            .find("\u{043e}\u{0434}\u{0438}\u{043d} \u{043d}\u{0430}\u{0440}\u{043e}\u{0434}")
            .unwrap();
        assert!(PropagandaDetector::check_false_positive_context(text, pos));
    }

    #[test]
    fn genuine_propaganda_not_false_positive() {
        let text = "\u{0420}\u{043e}\u{0441}\u{0456}\u{044f} \u{043f}\u{0440}\u{043e}\u{0432}\u{043e}\u{0434}\u{0438}\u{0442}\u{044c} \u{0441}\u{043f}\u{0435}\u{0446}\u{043e}\u{043f}\u{0435}\u{0440}\u{0430}\u{0446}\u{0456}\u{044e} \u{0434}\u{043b}\u{044f} \u{0437}\u{0430}\u{0445}\u{0438}\u{0441}\u{0442}\u{0443} \u{0414}\u{043e}\u{043d}\u{0431}\u{0430}\u{0441}\u{0443}";
        let pos = text.find("\u{0441}\u{043f}\u{0435}\u{0446}\u{043e}\u{043f}\u{0435}\u{0440}\u{0430}\u{0446}\u{0456}\u{044e}").unwrap();
        assert!(!PropagandaDetector::check_false_positive_context(text, pos));
    }

    #[test]
    fn false_positive_russian_negation() {
        let text = "\u{042d}\u{0442}\u{043e} \u{043d}\u{0435} \u{0441}\u{043f}\u{0435}\u{0446}\u{0438}\u{0430}\u{043b}\u{044c}\u{043d}\u{0430}\u{044f} \u{0432}\u{043e}\u{0435}\u{043d}\u{043d}\u{0430}\u{044f} \u{043e}\u{043f}\u{0435}\u{0440}\u{0430}\u{0446}\u{0438}\u{044f}, \u{0430} \u{0432}\u{043e}\u{0439}\u{043d}\u{0430}";
        let pos = text.find("\u{0441}\u{043f}\u{0435}\u{0446}\u{0438}\u{0430}\u{043b}\u{044c}\u{043d}\u{0430}\u{044f}").unwrap();
        assert!(PropagandaDetector::check_false_positive_context(text, pos));
    }

    #[test]
    fn false_positive_english_negation() {
        let text = "This is not a special military operation, it is a war";
        let pos = text.find("special").unwrap();
        assert!(PropagandaDetector::check_false_positive_context(text, pos));
    }

    #[test]
    fn narrative_id_from_rule_id() {
        assert_eq!(
            NarrativeId::from_rule_id("propaganda_denial_uk_001"),
            Some(NarrativeId::WarDenial)
        );
        assert_eq!(
            NarrativeId::from_rule_id("propaganda_nazi_uk_001"),
            Some(NarrativeId::NaziNarrative)
        );
        assert_eq!(
            NarrativeId::from_rule_id("propaganda_brotherhood_ru_001"),
            Some(NarrativeId::Brotherhood)
        );
        assert_eq!(
            NarrativeId::from_rule_id("propaganda_dehumanize_uk_001"),
            Some(NarrativeId::Dehumanization)
        );
        assert_eq!(
            NarrativeId::from_rule_id("propaganda_whataboutism_ru_001"),
            Some(NarrativeId::Whataboutism)
        );
        assert_eq!(
            NarrativeId::from_rule_id("propaganda_victimhood_001"),
            Some(NarrativeId::Victimhood)
        );
        assert_eq!(
            NarrativeId::from_rule_id("propaganda_religious_001"),
            Some(NarrativeId::ReligiousManipulation)
        );
        assert_eq!(
            NarrativeId::from_rule_id("propaganda_refugee_001"),
            Some(NarrativeId::RefugeeWeaponization)
        );
        assert_eq!(NarrativeId::from_rule_id("some_unrelated_rule"), None);
    }

    #[test]
    fn multi_narrative_coordinated() {
        let (tl, pr) = build(vec![
            typed_event("bot", "conv_1", 1000, "war_denial"),
            typed_event("bot", "conv_1", 2000, "brotherhood"),
            typed_event("bot", "conv_1", 3000, "capitulation"),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 5000, &pr);
        assert!(has_reason(&s, "coordinated_multi_narrative"));
        let sig = s
            .iter()
            .find(|x| x.reason_code.contains("coordinated_multi_narrative"))
            .unwrap();
        assert!(sig.score >= 0.8);
    }

    #[test]
    fn compound_capitulation_package() {
        let (tl, pr) = build(vec![
            typed_event("bot", "conv_1", 1000, "war_denial"),
            typed_event("bot", "conv_1", 2000, "capitulation"),
            typed_event("bot", "conv_1", 3000, "western_conspiracy"),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 5000, &pr);
        assert!(has_reason(&s, "compound_capitulation"));
    }

    #[test]
    fn compound_historical_package() {
        let (tl, pr) = build(vec![
            typed_event("bot", "conv_1", 1000, "historical_revisionism"),
            typed_event("bot", "conv_1", 2000, "brotherhood"),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 5000, &pr);
        assert!(has_reason(&s, "compound_historical"));
    }

    #[test]
    fn compound_justification_package() {
        let (tl, pr) = build(vec![
            typed_event("bot", "conv_1", 1000, "war_denial"),
            typed_event("bot", "conv_1", 2000, "nazi_narrative"),
            typed_event("bot", "conv_1", 3000, "victimhood"),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 5000, &pr);
        assert!(has_reason(&s, "compound_justification"));
    }

    #[test]
    fn compound_pressure_package() {
        let (tl, pr) = build(vec![
            typed_event("bot", "conv_1", 1000, "fear_appeal"),
            typed_event("bot", "conv_1", 2000, "capitulation"),
            typed_event("bot", "conv_1", 3000, "economic_collapse"),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 5000, &pr);
        assert!(has_reason(&s, "compound_pressure"));
    }

    #[test]
    fn compound_identity_erasure() {
        let (tl, pr) = build(vec![
            typed_event("bot", "conv_1", 1000, "brotherhood"),
            typed_event("bot", "conv_1", 2000, "language_oppression"),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 5000, &pr);
        assert!(has_reason(&s, "compound_identity_erasure"));
    }

    #[test]
    fn compound_wedge_package() {
        let (tl, pr) = build(vec![
            typed_event("bot", "conv_1", 1000, "refugee_weaponization"),
            typed_event("bot", "conv_1", 2000, "economic_collapse"),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 5000, &pr);
        assert!(has_reason(&s, "compound_wedge"));
    }

    #[test]
    fn compound_hate_package() {
        let (tl, pr) = build(vec![
            typed_event("bot", "conv_1", 1000, "dehumanization"),
            typed_event("bot", "conv_1", 2000, "nazi_narrative"),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 5000, &pr);
        assert!(has_reason(&s, "compound_hate"));
    }

    #[test]
    fn compound_demoralization_package() {
        let (tl, pr) = build(vec![
            typed_event("bot", "conv_1", 1000, "betrayal"),
            typed_event("bot", "conv_1", 2000, "economic_collapse"),
            typed_event("bot", "conv_1", 3000, "capitulation"),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 5000, &pr);
        assert!(has_reason(&s, "compound_demoralization"));
    }

    #[test]
    fn dehumanization_always_high() {
        let (tl, pr) = build(vec![typed_event("troll", "conv_1", 1000, "dehumanization")]);
        let d = PropagandaDetector::new(AnalysisMode::Strict);
        let s = d.analyze(&tl, "troll", 5000, &pr);
        assert!(has_reason(&s, "dehumanization"));
        let sig = s
            .iter()
            .find(|x| x.reason_code.contains("dehumanization"))
            .unwrap();
        assert!(sig.score >= 0.9);
    }

    #[test]
    fn same_narrative_not_coordinated() {
        let (tl, pr) = build(vec![
            typed_event("bot", "conv_1", 1000, "war_denial"),
            typed_event("bot", "conv_1", 2000, "war_denial"),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 5000, &pr);
        assert!(!has_reason(&s, "coordinated_multi_narrative"));
    }

    #[test]
    fn burst_detection() {
        let base = 100_000u64;
        let (tl, pr) = build(vec![
            typed_event("bot", "conv_1", base, "war_denial"),
            typed_event("bot", "conv_1", base + 60_000, "nazi_narrative"),
            typed_event("bot", "conv_1", base + 120_000, "capitulation"),
            typed_event("bot", "conv_1", base + 180_000, "brotherhood"),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", base + 200_000, &pr);
        assert!(has_reason(&s, "burst"));
    }

    #[test]
    fn narrative_hammering() {
        let (tl, pr) = build(vec![
            typed_event("bot", "conv_1", 1000, "war_denial"),
            typed_event("bot", "conv_1", 2000, "war_denial"),
            typed_event("bot", "conv_1", 3000, "war_denial"),
            typed_event("bot", "conv_1", 4000, "war_denial"),
            typed_event("bot", "conv_1", 5000, "war_denial"),
        ]);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 6000, &pr);
        assert!(has_reason(&s, "narrative_hammering"));
    }

    #[test]
    fn high_velocity_detection() {
        let base = 100_000u64;
        let mut events = Vec::new();
        for i in 0..15 {
            events.push(typed_event(
                "bot",
                "conv_1",
                base + i * 10_000,
                "war_denial",
            ));
        }
        let (tl, pr) = build(events);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", base + 200_000, &pr);
        assert!(has_reason(&s, "high_velocity"));
    }

    #[test]
    fn behavioral_copy_paste_reuse_detected() {
        let mut events = Vec::new();
        for i in 0..12 {
            let mut event = ContextEvent::with_subtype(
                1_000 + i * 1_000,
                "bot",
                "conv_1",
                EventKind::PropagandaNarrative,
                0.8,
                "war_denial",
            );
            event.content_hash = Some(if i < 8 { 777 } else { 888 + i });
            events.push(event);
        }

        let (tl, pr) = build(events);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 20_000, &pr);
        assert!(has_reason(&s, "copy_paste_reuse"));
    }

    #[test]
    fn behavioral_copy_paste_not_triggered_on_low_volume() {
        let mut events = Vec::new();
        for i in 0..9 {
            let mut event = ContextEvent::with_subtype(
                1_000 + i * 1_000,
                "bot",
                "conv_1",
                EventKind::PropagandaNarrative,
                0.8,
                "war_denial",
            );
            event.content_hash = Some(123);
            events.push(event);
        }

        let (tl, pr) = build(events);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", 20_000, &pr);
        assert!(!has_reason(&s, "copy_paste_reuse"));
    }

    #[test]
    fn high_velocity_not_triggered_below_min_event_count() {
        let base = 100_000u64;
        let mut events = Vec::new();
        for i in 0..5 {
            events.push(typed_event(
                "bot",
                "conv_1",
                base + i * 10_000,
                "war_denial",
            ));
        }

        let (tl, pr) = build(events);
        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze(&tl, "bot", base + 200_000, &pr);
        assert!(!has_reason(&s, "high_velocity"));
    }

    #[test]
    fn cross_conversation_coordination() {
        let mut tl1 = ConversationTimeline::new("conv_1".into(), 500);
        let mut tl2 = ConversationTimeline::new("conv_2".into(), 500);
        let mut tl3 = ConversationTimeline::new("conv_3".into(), 500);

        tl1.push(typed_event("bot", "conv_1", 1000, "war_denial"));
        tl2.push(typed_event("bot", "conv_2", 2000, "nazi_narrative"));
        tl3.push(typed_event("bot", "conv_3", 3000, "capitulation"));

        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze_cross_conversation(&[&tl1, &tl2, &tl3], "bot", 5000);
        assert!(has_reason(&s, "cross_conversation"));
        assert!(s[0].score >= 0.9);
    }

    #[test]
    fn cross_conversation_single_conv_no_trigger() {
        let mut tl1 = ConversationTimeline::new("conv_1".into(), 500);
        tl1.push(typed_event("bot", "conv_1", 1000, "war_denial"));

        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze_cross_conversation(&[&tl1], "bot", 5000);
        assert!(s.is_empty());
    }

    #[test]
    fn cross_conversation_narrative_count_is_unique() {
        let mut tl1 = ConversationTimeline::new("conv_1".into(), 500);
        let mut tl2 = ConversationTimeline::new("conv_2".into(), 500);
        let mut tl3 = ConversationTimeline::new("conv_3".into(), 500);

        tl1.push(typed_event("bot", "conv_1", 1000, "war_denial"));
        tl2.push(typed_event("bot", "conv_2", 2000, "war_denial"));
        tl3.push(typed_event("bot", "conv_3", 3000, "war_denial"));

        let d = PropagandaDetector::new(AnalysisMode::Standard);
        let s = d.analyze_cross_conversation(&[&tl1, &tl2, &tl3], "bot", 5000);
        assert!(has_reason(&s, "cross_conversation"));
        let sig = s
            .iter()
            .find(|signal| signal.reason_code.contains("cross_conversation"))
            .unwrap();
        assert!(
            sig.explanation.contains("with 1 narrative types"),
            "Expected unique narrative count in explanation, got: {}",
            sig.explanation
        );
    }

    #[test]
    fn severity_weight_dehumanization_highest() {
        assert!(NarrativeId::Dehumanization.severity() >= NarrativeId::Whataboutism.severity());
        assert!(NarrativeId::Dehumanization.severity() >= 1.0);
    }

    #[test]
    fn all_narrative_tags_unique() {
        let mut tags = std::collections::HashSet::new();
        for spec in NARRATIVES {
            assert!(tags.insert(spec.tag), "duplicate tag: {}", spec.tag);
        }
    }

    #[test]
    fn all_compound_rules_have_required() {
        for rule in COMPOUND_RULES {
            assert!(
                !rule.required.is_empty(),
                "compound rule '{}' has no required narratives",
                rule.reason
            );
        }
    }
}
