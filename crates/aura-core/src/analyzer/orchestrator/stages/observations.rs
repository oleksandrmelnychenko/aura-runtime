use super::*;

pub(super) fn military_coordinate_crumb_observation(
    text: &str,
    content_hash: Option<u64>,
) -> Option<RawObservation> {
    let normalized = normalize_location_crumb_text(text);
    if normalized.is_empty() || looks_like_coordinate_warning_fragment(&normalized) {
        return None;
    }

    let has_area = contains_any(
        &normalized,
        &[
            "місто ",
            "місот ",
            "село ",
            "селище ",
            "район ",
            "західній частині",
            "східній частині",
        ],
    ) || contains_token(
        &normalized,
        &["місто", "міст", "місо", "місот", "село", "селище"],
    );
    let has_relative = contains_any(
        &normalized,
        &[
            "околиц",
            "південн",
            "північн",
            "західн",
            "східн",
            "за струм",
            "поряд струм",
            "на іншому березі",
            "далі за",
        ],
    );
    let has_site = contains_any(
        &normalized,
        &[
            "завод",
            "заво ",
            "цемент",
            "цех",
            "лісосмуг",
            "силос",
            "шосе",
            "антенн",
            "веж",
            "горбі",
        ],
    );
    let has_current_position = has_site
        && contains_any(
            &normalized,
            &[
                "наш цех",
                "наш це",
                "аш цех",
                "наша позиц",
                "наш пункт",
                "там ми",
                "ми тут",
                "видно нас",
            ],
        );

    let (subtype, confidence) = if has_current_position {
        ("coordinate_crumb.current_position", 0.55)
    } else if has_site {
        ("coordinate_crumb.site", 0.45)
    } else if has_relative {
        ("coordinate_crumb.relative", 0.40)
    } else if has_area {
        ("coordinate_crumb.area", 0.35)
    } else {
        return None;
    };

    Some(RawObservation::event(
        EventKind::CoordinateMention,
        confidence,
        Some(subtype.to_string()),
        content_hash,
    ))
}

pub(super) fn doxxing_crumb_observations(
    text: &str,
    content_hash: Option<u64>,
) -> Vec<RawObservation> {
    let normalized = normalize_doxxing_crumb_text(text);
    if normalized.is_empty() || looks_like_benign_doxxing_fragment(&normalized) {
        return Vec::new();
    }

    let mut crumbs = Vec::with_capacity(4);
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_distribution_intent(&normalized),
        "doxxing_crumb.intent",
        0.48,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_name_fragment(&normalized),
        "doxxing_crumb.name",
        0.34,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_address_fragment(&normalized),
        "doxxing_crumb.address",
        0.42,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_city_fragment(&normalized),
        "doxxing_crumb.city",
        0.34,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_school_fragment(&normalized),
        "doxxing_crumb.school",
        0.40,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_phone_fragment(&normalized),
        "doxxing_crumb.phone",
        0.42,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_family_fragment(&normalized),
        "doxxing_crumb.family",
        0.38,
        content_hash,
    );
    push_doxxing_crumb_if(
        &mut crumbs,
        doxxing_has_work_fragment(&normalized),
        "doxxing_crumb.work",
        0.36,
        content_hash,
    );

    crumbs
}

pub(super) fn push_doxxing_crumb_if(
    crumbs: &mut Vec<RawObservation>,
    condition: bool,
    subtype: &str,
    confidence: f32,
    content_hash: Option<u64>,
) {
    if condition {
        crumbs.push(RawObservation::event(
            EventKind::DoxxingAttempt,
            confidence,
            Some(subtype.to_string()),
            content_hash,
        ));
    }
}

pub(super) fn normalize_doxxing_crumb_text(text: &str) -> String {
    let normalized = TextNormalizer::new().normalize(text);
    normalize_location_crumb_text(&normalized)
}

pub(super) fn looks_like_benign_doxxing_fragment(normalized: &str) -> bool {
    contains_any(
        normalized,
        &[
            "my address",
            "my place",
            "my bakery",
            "business contact",
            "for the conference",
            "open house",
            "listing agent",
            "all welcome",
            "courier",
            "pickup address",
            "for the package",
            "thanks for sending",
            "patient",
            "consent",
            "on file",
            "public library",
            "safest place",
            "reporting it",
            "won t repeat",
            "news article",
            "this piece",
            "interviews with victims",
            "doxxing campaigns",
            "address leaks",
            "не повторюйте",
            "закидайте скаргами",
        ],
    )
}

pub(super) fn doxxing_has_distribution_intent(normalized: &str) -> bool {
    contains_any(
        normalized,
        &[
            "find everything",
            "knock yourself out",
            "knock yourselves out",
            "go for it",
            "go forth",
            "pass it around",
            "pass it along",
            "repost the address",
            "drop the bundle",
            "drop the dox",
            "post the full dox",
            "full dox",
            "dox in the group",
            "bundle in the discord",
            "burner accounts",
            "send pizzas",
            "fake deliveries",
            "call the school",
            "scaring her",
            "info is out forever",
        ],
    )
}

pub(super) fn doxxing_has_name_fragment(normalized: &str) -> bool {
    normalized.starts_with("name ")
        || contains_any(
            normalized,
            &[
                " first name ",
                " last name ",
                " real name ",
                "full name",
                "is her handle",
            ],
        )
}

pub(super) fn doxxing_has_address_fragment(normalized: &str) -> bool {
    let has_street_type = contains_token(
        normalized,
        &[
            "st", "street", "ave", "avenue", "rd", "road", "drive", "dr", "ln", "lane", "court",
            "ct", "blvd", "way",
        ],
    );
    let has_digit = normalized.chars().any(|ch| ch.is_ascii_digit());

    has_street_type
        && (has_digit
            || contains_any(
                normalized,
                &[
                    "lives at",
                    "live at",
                    "lives on",
                    "live on",
                    "they live",
                    "address",
                    "county records",
                ],
            ))
}

pub(super) fn doxxing_has_city_fragment(normalized: &str) -> bool {
    (normalized.starts_with("city ") || contains_any(normalized, &[" city ", " zip "]))
        && (has_zip_token(normalized)
            || contains_token(
                normalized,
                &[
                    "il", "ca", "pa", "or", "az", "ny", "wa", "tx", "fl", "oh", "mi", "ma",
                ],
            ))
}

pub(super) fn doxxing_has_school_fragment(normalized: &str) -> bool {
    let has_school_identifier = contains_any(
        normalized,
        &[
            " school",
            " high",
            " hs",
            " elementary",
            " locker",
            " junior",
            " sophomore",
            " freshman",
            " senior",
            " grade",
            " class",
            " period",
            " bus ",
        ],
    );
    let has_sensitive_context = normalized.starts_with("school ")
        || contains_any(
            normalized,
            &[
                " goes to ",
                " attends ",
                " junior at ",
                " locker",
                " class ",
                " period",
                " call the school",
                " her ",
                " his ",
                " she ",
                " he ",
                " they ",
                " target",
                "@",
            ],
        );

    has_school_identifier && has_sensitive_context
}

pub(super) fn doxxing_has_phone_fragment(normalized: &str) -> bool {
    let digit_count = normalized.chars().filter(|ch| ch.is_ascii_digit()).count();
    if !(10..=12).contains(&digit_count) {
        return false;
    }

    contains_any(
        normalized,
        &[
            " phone",
            " cell",
            " number",
            " called",
            " call em",
            " call them",
            "verified i called",
        ],
    ) || normalized
        .split_whitespace()
        .all(|token| token.chars().all(|ch| ch.is_ascii_digit()))
}

pub(super) fn doxxing_has_family_fragment(normalized: &str) -> bool {
    contains_token(
        normalized,
        &[
            "mom", "mother", "dad", "father", "parents", "brother", "sister", "son", "daughter",
            "aunt", "uncle", "grandma", "grandpa",
        ],
    )
}

pub(super) fn doxxing_has_work_fragment(normalized: &str) -> bool {
    contains_any(
        normalized,
        &[
            " works at",
            " work at",
            " works as",
            " work as",
            " works night",
            " it guy",
            " credit union",
            " pharmacy",
            " nurse",
            " consultant",
        ],
    )
}

pub(super) fn has_zip_token(normalized: &str) -> bool {
    normalized
        .split_whitespace()
        .any(|token| token.len() == 5 && token.chars().all(|ch| ch.is_ascii_digit()))
}

pub(super) fn normalize_location_crumb_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(
            ch,
            '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{FEFF}'
                | '\u{00AD}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2060}'
                | '\u{2061}'
                | '\u{2062}'
                | '\u{2063}'
                | '\u{2064}'
                | '\u{034F}'
        ) {
            continue;
        }
        for lower in ch.to_lowercase() {
            if lower.is_alphanumeric() {
                out.push(lower);
            } else {
                out.push(' ');
            }
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

pub(super) fn contains_token(text: &str, tokens: &[&str]) -> bool {
    text.split_whitespace().any(|word| tokens.contains(&word))
}

pub(super) fn looks_like_coordinate_warning_fragment(normalized: &str) -> bool {
    contains_any(
        normalized,
        &[
            "не публіку",
            "не публику",
            "не пиш",
            "не скидай",
            "нагадую",
            "інструкція",
            "стирались",
            "видаліть",
            "видаляй",
        ],
    )
}

pub(super) fn append_reason_codes(reason_codes: &mut Vec<String>, extras: &[String]) {
    for priority in 0..=2 {
        for extra in extras {
            if context_reason_priority(extra) != Some(priority) {
                continue;
            }
            if !push_reason_code(reason_codes, extra) {
                return;
            }
        }
    }

    for extra in extras {
        if context_reason_priority(extra).is_some() {
            continue;
        }
        if !push_reason_code(reason_codes, extra) {
            return;
        }
    }
}

pub(super) fn append_context_markers(context_markers: &mut Vec<String>, extras: &[String]) {
    for extra in extras {
        if !context_markers.iter().any(|existing| existing == extra) {
            context_markers.push(extra.clone());
        }
    }
}

pub(super) fn push_reason_code(reason_codes: &mut Vec<String>, extra: &str) -> bool {
    if reason_codes.iter().any(|existing| existing == extra) {
        return true;
    }
    reason_codes.push(extra.to_string());
    reason_codes.len() < 12
}

pub(super) fn context_reason_priority(code: &str) -> Option<u8> {
    if code.starts_with("context.trajectory.") {
        return Some(0);
    }
    if code == "context.filter.applied"
        || matches!(
            code,
            "context.speech_act.quote"
                | "context.speech_act.report"
                | "context.speech_act.counter"
                | "context.speech_act.support"
                | "context.direction.directed_at_user"
                | "context.direction.self_referential"
                | "context.direction.third_party"
        )
    {
        return Some(1);
    }
    if code.starts_with("context.relationship.") || matches!(code, "context.reciprocity.one_sided")
    {
        return Some(2);
    }
    None
}

pub(super) fn build_signal_observations(
    signals: Vec<DetectionSignal>,
    content_hash: Option<u64>,
) -> Vec<RawObservation> {
    let mut observations = Vec::with_capacity(signals.len());

    for signal in signals {
        let event_kind = if signal.layer == DetectionLayer::MlClassification {
            map_ml_signal_to_event_kind(signal.threat_type)
        } else {
            None
        };

        let observation = match event_kind {
            Some(kind) => {
                let score = signal.score;
                RawObservation::signal_with_event(signal, kind, score, None, content_hash)
            }
            None => RawObservation::signal(signal),
        };
        observations.push(observation);
    }

    observations
}

/// Boosts signal scores for contacts with accumulated threat history.
///
/// A contact with prior grooming/bullying/manipulation events gets a score boost
/// on matching signals, making it easier to cross action thresholds. This ensures
/// the app receives progressively stronger signals from repeat offenders.
pub(super) fn apply_contact_risk_boost(
    signals: &mut [DetectionSignal],
    profiler: &crate::context::contact::ContactProfiler,
    sender_id: &str,
) {
    let profile = match profiler.profile(sender_id) {
        Some(p) => p,
        None => return,
    };

    if profile.is_trusted {
        return;
    }

    for signal in signals.iter_mut() {
        let prior_count = match signal.threat_type {
            ThreatType::Grooming => profile.grooming_event_count,
            ThreatType::Bullying => profile.bullying_event_count,
            ThreatType::Manipulation => profile.manipulation_event_count,
            _ => 0,
        };

        if prior_count < 2 {
            continue;
        }

        // Boost: 3% per prior event, max 20%
        let boost = (prior_count.min(7) as f32 * 0.03).min(0.20);
        signal.score = (signal.score * (1.0 + boost)).min(0.98);
    }
}

pub(super) fn is_escalation_bonus_threat(threat_type: ThreatType) -> bool {
    threat_type == ThreatType::Bullying
        || threat_type == ThreatType::Threat
        || threat_type == ThreatType::Explicit
        || threat_type == ThreatType::Grooming
        || threat_type == ThreatType::Manipulation
        || threat_type == ThreatType::SelfHarm
        || threat_type == ThreatType::Doxxing
        || threat_type == ThreatType::HateSpeech
        || threat_type == ThreatType::Propaganda
        || threat_type == ThreatType::Psyops
        || threat_type == ThreatType::MilitarySocialEng
}
