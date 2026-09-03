use crate::ids::{ConversationId, SenderId};
use crate::types::{DetectionLayer, DetectionSignal, ThreatType};

use super::events::ContextEvent;
use super::EventKind;

/// Raw detector-layer output before the interpreter decides whether the behavior
/// should be affirmed and persisted.
#[derive(Debug, Clone)]
pub struct RawObservation {
    pub signal: Option<DetectionSignal>,
    pub event_hint: Option<RawEventHint>,
    signal_evidence_origin: DetectorEvidenceOrigin,
}

/// Typed detector provenance used by contextual attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorEvidenceOrigin {
    /// A lexical or pattern matcher produced the evidence.
    Lexical,
    /// A bounded semantic composition produced the evidence.
    Compositional,
    /// A non-lexical detector, model, or contextual derivation produced it.
    Derived,
}

impl DetectorEvidenceOrigin {
    pub(crate) fn from_detection_layer(layer: DetectionLayer) -> Self {
        match layer {
            DetectionLayer::PatternMatching => Self::Lexical,
            DetectionLayer::MlClassification | DetectionLayer::ContextAnalysis => Self::Derived,
        }
    }
}

/// One detector signal paired with provenance that cannot be inferred from its
/// human-readable reason code.
#[derive(Debug, Clone)]
pub struct RawSignal {
    pub signal: DetectionSignal,
    pub evidence_origin: DetectorEvidenceOrigin,
}

/// Event candidate metadata carried into the interpreter without immediately
/// materializing it into tracker-ready state.
#[derive(Debug, Clone)]
pub struct RawEventHint {
    pub kind: EventKind,
    pub confidence: f32,
    pub subtype: Option<String>,
    pub content_hash: Option<u64>,
    /// Source signal family when the event was emitted alongside a detector
    /// signal. Event-only observations leave this empty and use the canonical
    /// event-kind fallback during interpretation.
    pub source_threat_type: Option<ThreatType>,
    pub evidence_origin: DetectorEvidenceOrigin,
}

impl RawObservation {
    pub fn signal(signal: DetectionSignal) -> Self {
        let evidence_origin = DetectorEvidenceOrigin::from_detection_layer(signal.layer);
        Self::signal_with_origin(signal, evidence_origin)
    }

    pub fn signal_with_origin(
        signal: DetectionSignal,
        evidence_origin: DetectorEvidenceOrigin,
    ) -> Self {
        Self {
            signal: Some(signal),
            event_hint: None,
            signal_evidence_origin: evidence_origin,
        }
    }

    pub fn event(
        kind: EventKind,
        confidence: f32,
        subtype: Option<String>,
        content_hash: Option<u64>,
    ) -> Self {
        Self::event_with_origin(
            kind,
            confidence,
            subtype,
            content_hash,
            DetectorEvidenceOrigin::Derived,
        )
    }

    pub fn event_with_origin(
        kind: EventKind,
        confidence: f32,
        subtype: Option<String>,
        content_hash: Option<u64>,
        evidence_origin: DetectorEvidenceOrigin,
    ) -> Self {
        Self {
            signal: None,
            event_hint: Some(RawEventHint {
                kind,
                confidence,
                subtype,
                content_hash,
                source_threat_type: None,
                evidence_origin,
            }),
            signal_evidence_origin: DetectorEvidenceOrigin::Derived,
        }
    }

    pub fn signal_with_event(
        signal: DetectionSignal,
        kind: EventKind,
        confidence: f32,
        subtype: Option<String>,
        content_hash: Option<u64>,
    ) -> Self {
        let evidence_origin = DetectorEvidenceOrigin::from_detection_layer(signal.layer);
        Self::signal_with_event_origin(
            signal,
            kind,
            confidence,
            subtype,
            content_hash,
            evidence_origin,
        )
    }

    pub fn signal_with_event_origin(
        signal: DetectionSignal,
        kind: EventKind,
        confidence: f32,
        subtype: Option<String>,
        content_hash: Option<u64>,
        evidence_origin: DetectorEvidenceOrigin,
    ) -> Self {
        let source_threat_type =
            (signal.threat_type != ThreatType::None).then_some(signal.threat_type);
        Self {
            signal: Some(signal),
            event_hint: Some(RawEventHint {
                kind,
                confidence,
                subtype,
                content_hash,
                source_threat_type,
                evidence_origin,
            }),
            signal_evidence_origin: evidence_origin,
        }
    }

    pub fn signal_matches(&self, predicate: impl FnOnce(&DetectionSignal) -> bool) -> bool {
        self.signal.as_ref().is_some_and(predicate)
    }

    pub fn event_kind_matches(&self, predicate: impl FnOnce(&EventKind) -> bool) -> bool {
        self.event_hint
            .as_ref()
            .is_some_and(|hint| predicate(&hint.kind))
    }
}

pub fn split_observations(
    observations: Vec<RawObservation>,
) -> (Vec<RawSignal>, Vec<RawEventHint>) {
    let mut signals = Vec::with_capacity(observations.len());
    let mut event_hints = Vec::with_capacity(observations.len());

    for observation in observations {
        if let Some(signal) = observation.signal {
            signals.push(RawSignal {
                signal,
                evidence_origin: observation.signal_evidence_origin,
            });
        }
        if let Some(event_hint) = observation.event_hint {
            event_hints.push(event_hint);
        }
    }

    (signals, event_hints)
}

pub fn materialize_event_hints(
    event_hints: Vec<RawEventHint>,
    timestamp_ms: Option<u64>,
    sender_id: &SenderId,
    conversation_id: &ConversationId,
) -> Vec<ContextEvent> {
    let mut context_events = Vec::with_capacity(event_hints.len());

    for event_hint in event_hints {
        let Some(timestamp_ms) = timestamp_ms else {
            break;
        };

        let event = match event_hint.subtype {
            Some(subtype) => ContextEvent::with_subtype(
                timestamp_ms,
                sender_id.clone(),
                conversation_id.clone(),
                event_hint.kind,
                event_hint.confidence,
                subtype,
            ),
            None => ContextEvent::new(
                timestamp_ms,
                sender_id.clone(),
                conversation_id.clone(),
                event_hint.kind,
                event_hint.confidence,
            ),
        };
        let mut event = event;
        event.content_hash = event_hint.content_hash;
        context_events.push(event);
    }

    context_events
}

#[cfg(test)]
mod tests {
    use super::{DetectorEvidenceOrigin, RawObservation};
    use crate::context::EventKind;
    use crate::types::{Confidence, DetectionSignal, SignalFamily, ThreatType};

    #[test]
    fn reason_code_text_cannot_change_typed_evidence_origin() {
        let lexical = RawObservation::signal(DetectionSignal::pattern(
            ThreatType::Grooming,
            0.8,
            Confidence::High,
            "kids.composition.forged",
            "test",
        ));
        assert_eq!(
            lexical
                .signal
                .as_ref()
                .map(|_| lexical.signal_evidence_origin),
            Some(DetectorEvidenceOrigin::Lexical)
        );

        let derived = RawObservation::signal_with_event(
            DetectionSignal::context(
                ThreatType::Grooming,
                0.8,
                Confidence::High,
                SignalFamily::Content,
                "pattern.forged",
                "test",
            ),
            EventKind::SecrecyRequest,
            0.8,
            None,
            None,
        );
        assert_eq!(
            derived
                .signal
                .as_ref()
                .map(|_| derived.signal_evidence_origin),
            Some(DetectorEvidenceOrigin::Derived)
        );
        assert_eq!(
            derived.event_hint.as_ref().map(|hint| hint.evidence_origin),
            Some(DetectorEvidenceOrigin::Derived)
        );
    }

    #[test]
    fn compositional_origin_is_explicit_for_signal_and_event() {
        let observation = RawObservation::signal_with_event_origin(
            DetectionSignal::context(
                ThreatType::Grooming,
                0.8,
                Confidence::High,
                SignalFamily::Content,
                "opaque.detector",
                "test",
            ),
            EventKind::SecrecyRequest,
            0.8,
            None,
            None,
            DetectorEvidenceOrigin::Compositional,
        );

        assert_eq!(
            observation
                .signal
                .as_ref()
                .map(|_| observation.signal_evidence_origin),
            Some(DetectorEvidenceOrigin::Compositional)
        );
        assert_eq!(
            observation
                .event_hint
                .as_ref()
                .map(|hint| hint.evidence_origin),
            Some(DetectorEvidenceOrigin::Compositional)
        );
        assert_eq!(
            observation
                .event_hint
                .as_ref()
                .and_then(|hint| hint.source_threat_type),
            Some(ThreatType::Grooming)
        );
    }

    #[test]
    fn shared_event_kind_keeps_the_source_signal_family() {
        let observation = RawObservation::signal_with_event_origin(
            DetectionSignal::context(
                ThreatType::Nsfw,
                0.8,
                Confidence::High,
                SignalFamily::Content,
                "opaque.detector",
                "test",
            ),
            EventKind::SexualContent,
            0.8,
            None,
            None,
            DetectorEvidenceOrigin::Compositional,
        );

        assert_eq!(
            observation
                .event_hint
                .as_ref()
                .and_then(|hint| hint.source_threat_type),
            Some(ThreatType::Nsfw)
        );
    }
}
