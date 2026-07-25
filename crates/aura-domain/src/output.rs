use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainAction {
    Allow,
    Mark,
    Warn,
    Block,
}

/// Domain-owned semantic event emitted for a detector signal.
///
/// The shared contract deliberately carries behavior, not detector rule names.
/// `aura-core` converts this enum into its internal context event without
/// inspecting `reason_code` or `threat_key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainEventKind {
    Flattery,
    GiftOffer,
    SecrecyRequest,
    PlatformSwitch,
    PersonalInfoRequest,
    PhotoRequest,
    VideoCallRequest,
    FinancialGrooming,
    MeetingRequest,
    SexualContent,
    AgeInappropriate,
    Insult,
    Denigration,
    HarmEncouragement,
    PhysicalThreat,
    RumorSpreading,
    Exclusion,
    Mockery,
    GuiltTripping,
    Gaslighting,
    EmotionalBlackmail,
    PeerPressure,
    LoveBombing,
    Darvo,
    Devaluation,
    SuicidalIdeation,
    Hopelessness,
    FarewellMessage,
    DoxxingAttempt,
    ScreenshotThreat,
    HateSpeech,
    LocationRequest,
    MoneyOffer,
    PiiSelfDisclosure,
    CasualMeetingRequest,
    DareChallenge,
    SuicideCoercion,
    FalseConsensus,
    DebtCreation,
    ReputationThreat,
    IdentityErosion,
    NetworkPoisoning,
    FakeVulnerability,
    PropagandaNarrative,
    SuspiciousSource,
    PositionLeak,
    UnitInfoLeak,
    EquipmentLeak,
    CoordinateMention,
    PsyopsPattern,
    IntelGathering,
    MilitaryPhishing,
    MilitaryDisinfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainSignal {
    pub threat_key: String,
    pub score: f32,
    pub reason_code: String,
    #[serde(default)]
    pub threat_type: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub priority: Option<u8>,
    #[serde(default)]
    pub action: Option<DomainAction>,
}

/// Typed routing metadata for a signal in [`DomainOutput::signals`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainSignalRoute {
    pub signal_index: usize,
    pub event_kind: DomainEventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainOutput {
    pub signals: Vec<DomainSignal>,
    pub action: Option<DomainAction>,
    /// In-process registry metadata. It is intentionally absent from the
    /// pre-existing serialized `DomainOutput` shape.
    #[serde(skip)]
    pub routes: Vec<DomainSignalRoute>,
}

impl DomainOutput {
    /// Builds an output and asks the owning domain to classify each signal.
    pub fn routed(
        signals: Vec<DomainSignal>,
        action: Option<DomainAction>,
        classify: impl Fn(&DomainSignal) -> Option<DomainEventKind>,
    ) -> Self {
        let routes = signals
            .iter()
            .enumerate()
            .filter_map(|(signal_index, signal)| {
                classify(signal).map(|event_kind| DomainSignalRoute {
                    signal_index,
                    event_kind,
                })
            })
            .collect();
        Self {
            signals,
            action,
            routes,
        }
    }

    pub fn event_kind_for_signal(&self, signal_index: usize) -> Option<DomainEventKind> {
        self.routes
            .iter()
            .find(|route| route.signal_index == signal_index)
            .map(|route| route.event_kind)
    }

    pub fn has_complete_routing(&self) -> bool {
        self.signals.len() == self.routes.len()
            && self
                .routes
                .iter()
                .enumerate()
                .all(|(signal_index, route)| route.signal_index == signal_index)
    }
}

#[cfg(test)]
mod tests {
    use super::{DomainEventKind, DomainOutput, DomainSignal};

    #[test]
    fn routed_output_keeps_signal_indices_stable() {
        let signals = vec![
            DomainSignal {
                threat_key: "first".to_string(),
                ..DomainSignal::default()
            },
            DomainSignal {
                threat_key: "second".to_string(),
                ..DomainSignal::default()
            },
        ];

        let output = DomainOutput::routed(signals, None, |signal| {
            (signal.threat_key == "first")
                .then_some(DomainEventKind::SecrecyRequest)
                .or(Some(DomainEventKind::Insult))
        });

        assert!(output.has_complete_routing());
        assert_eq!(
            output.event_kind_for_signal(1),
            Some(DomainEventKind::Insult)
        );
        let json = serde_json::to_value(&output).expect("test output must serialize");
        assert!(json.get("routes").is_none());
    }
}
