use crate::ids::{ConversationId, SenderId};
use crate::types::DetectionSignal;

use super::events::ContextEvent;
use super::EventKind;

/// Raw detector-layer output before the interpreter decides whether the behavior
/// should be affirmed and persisted.
#[derive(Debug, Clone)]
pub struct RawObservation {
    pub signal: Option<DetectionSignal>,
    pub event_hint: Option<RawEventHint>,
}

/// Event candidate metadata carried into the interpreter without immediately
/// materializing it into tracker-ready state.
#[derive(Debug, Clone)]
pub struct RawEventHint {
    pub kind: EventKind,
    pub confidence: f32,
    pub subtype: Option<String>,
    pub content_hash: Option<u64>,
}

impl RawObservation {
    pub fn signal(signal: DetectionSignal) -> Self {
        Self {
            signal: Some(signal),
            event_hint: None,
        }
    }

    pub fn event(
        kind: EventKind,
        confidence: f32,
        subtype: Option<String>,
        content_hash: Option<u64>,
    ) -> Self {
        Self {
            signal: None,
            event_hint: Some(RawEventHint {
                kind,
                confidence,
                subtype,
                content_hash,
            }),
        }
    }

    pub fn signal_with_event(
        signal: DetectionSignal,
        kind: EventKind,
        confidence: f32,
        subtype: Option<String>,
        content_hash: Option<u64>,
    ) -> Self {
        Self {
            signal: Some(signal),
            event_hint: Some(RawEventHint {
                kind,
                confidence,
                subtype,
                content_hash,
            }),
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
) -> (Vec<DetectionSignal>, Vec<RawEventHint>) {
    let mut signals = Vec::with_capacity(observations.len());
    let mut event_hints = Vec::with_capacity(observations.len());

    for observation in observations {
        if let Some(signal) = observation.signal {
            signals.push(signal);
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
