use serde::{Deserialize, Serialize};

/// Ordered action recommendation emitted by a domain policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainAction {
    /// Continue without a user-facing intervention.
    Allow,
    /// Record or annotate the signal without interruption.
    Mark,
    /// Present a warning or require heightened attention.
    Warn,
    /// Prevent the guarded operation.
    Block,
}

/// Domain-owned semantic event emitted for a detector signal.
///
/// The shared contract deliberately carries behavior, not detector rule names.
/// `aura-core` converts this enum into its internal context event without
/// inspecting `reason_code` or `threat_key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainEventKind {
    /// Trust-building praise or flattery.
    Flattery,
    /// Offer of a gift or material incentive.
    GiftOffer,
    /// Request to conceal the interaction.
    SecrecyRequest,
    /// Attempt to move the interaction to another platform.
    PlatformSwitch,
    /// Request for personal information.
    PersonalInfoRequest,
    /// Request for a photograph.
    PhotoRequest,
    /// Request for a video call.
    VideoCallRequest,
    /// Financial incentive used in grooming.
    FinancialGrooming,
    /// Request or plan for an in-person meeting.
    MeetingRequest,
    /// Sexual or explicitly intimate content.
    SexualContent,
    /// Content inappropriate for the protected age.
    AgeInappropriate,
    /// Direct insult.
    Insult,
    /// Sustained denigration of the protected person.
    Denigration,
    /// Encouragement to cause harm.
    HarmEncouragement,
    /// Threat of physical harm.
    PhysicalThreat,
    /// Attempt to spread a damaging rumor.
    RumorSpreading,
    /// Deliberate social exclusion.
    Exclusion,
    /// Ridicule or mockery.
    Mockery,
    /// Manipulation through guilt.
    GuiltTripping,
    /// Manipulation that denies or rewrites experienced reality.
    Gaslighting,
    /// Emotional coercion or blackmail.
    EmotionalBlackmail,
    /// Coercive peer pressure.
    PeerPressure,
    /// Excessive affection used to gain control.
    LoveBombing,
    /// Deny-attack-reverse-victim-and-offender pattern.
    Darvo,
    /// Systematic erosion of another person's value.
    Devaluation,
    /// Expression of suicidal intent or ideation.
    SuicidalIdeation,
    /// Expression of severe hopelessness.
    Hopelessness,
    /// Message consistent with a final farewell.
    FarewellMessage,
    /// Attempt to expose identifying information.
    DoxxingAttempt,
    /// Threat to publish captured private content.
    ScreenshotThreat,
    /// Hateful attack against a protected group.
    HateSpeech,
    /// Request for the protected person's location.
    LocationRequest,
    /// Offer of money as influence or leverage.
    MoneyOffer,
    /// Self-disclosure of personally identifying information.
    PiiSelfDisclosure,
    /// Casual framing of a proposed in-person meeting.
    CasualMeetingRequest,
    /// Coercive or dangerous dare.
    DareChallenge,
    /// Coercion toward suicide or self-harm.
    SuicideCoercion,
    /// Manufactured appearance of social consensus.
    FalseConsensus,
    /// Creation of a real or perceived debt obligation.
    DebtCreation,
    /// Threat to damage reputation.
    ReputationThreat,
    /// Manipulation intended to weaken personal identity.
    IdentityErosion,
    /// Attempt to isolate or corrupt a trusted social network.
    NetworkPoisoning,
    /// Fabricated vulnerability used as manipulation.
    FakeVulnerability,
    /// Propaganda or hostile-influence narrative.
    PropagandaNarrative,
    /// Source with a relevant trust or authenticity concern.
    SuspiciousSource,
    /// Disclosure of a military position.
    PositionLeak,
    /// Disclosure of unit identity or composition.
    UnitInfoLeak,
    /// Disclosure of military equipment.
    EquipmentLeak,
    /// Operationally relevant coordinate reference.
    CoordinateMention,
    /// Psychological-operations influence pattern.
    PsyopsPattern,
    /// Attempt to collect operational intelligence.
    IntelGathering,
    /// Phishing directed at military personnel or systems.
    MilitaryPhishing,
    /// Military disinformation narrative.
    MilitaryDisinfo,
}

/// One normalized detector result owned by a domain module.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DomainSignal {
    /// Stable detector identity internal to the owning domain.
    pub threat_key: String,
    /// Normalized detector score in `0..=1`.
    pub score: f32,
    /// Stable explainability code exposed to policy and product layers.
    pub reason_code: String,
    /// Optional domain-neutral threat taxonomy label.
    #[serde(default)]
    pub threat_type: Option<String>,
    /// Optional severity label: `low`, `medium`, `high`, or `critical`.
    #[serde(default)]
    pub severity: Option<String>,
    /// Optional policy priority in `1..=255`.
    #[serde(default)]
    pub priority: Option<u8>,
    /// Optional explicit action floor supplied by the rule.
    #[serde(default)]
    pub action: Option<DomainAction>,
}

/// Typed routing metadata for a signal in [`DomainOutput::signals`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainSignalRoute {
    /// Index of the routed signal in [`DomainOutput::signals`].
    pub signal_index: usize,
    /// Domain-owned semantic event kind for that signal.
    pub event_kind: DomainEventKind,
}

/// Complete result of one message-level domain analysis.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainOutput {
    /// Normalized detector signals in deterministic order.
    pub signals: Vec<DomainSignal>,
    /// Strongest monotonic action recommended for the signal set.
    pub action: Option<DomainAction>,
    /// In-process registry metadata. It is intentionally absent from the
    /// pre-existing serialized `DomainOutput` shape.
    #[serde(skip)]
    pub routes: Vec<DomainSignalRoute>,
}

impl DomainOutput {
    /// Builds an output and asks the owning domain to classify each signal.
    #[must_use]
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

    /// Returns the typed event route for one signal index.
    #[must_use]
    pub fn event_kind_for_signal(&self, signal_index: usize) -> Option<DomainEventKind> {
        self.routes
            .iter()
            .find(|route| route.signal_index == signal_index)
            .map(|route| route.event_kind)
    }

    /// Returns whether every signal has one stable, ordered typed route.
    #[must_use]
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
