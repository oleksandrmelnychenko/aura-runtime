use super::*;

/// Indicates how a contact's age was determined.
///
/// The source affects confidence weighting in age-gap detection:
/// - `ParentVerified`: score used as-is (full confidence).
/// - `UserReported`: score multiplied by 0.85 (self-report may be false).
/// - `MlInferred`: score multiplied by 0.7 (ML estimate is noisy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgeSource {
    /// Age verified by a parent or guardian (highest confidence).
    ParentVerified,
    /// Age self-reported by the contact during conversation.
    #[default]
    UserReported,
    /// Age inferred by the ML pipeline from linguistic features.
    MlInferred,
}

impl AgeSource {
    /// Returns a confidence multiplier for age-gap scoring.
    pub fn confidence_factor(self) -> f32 {
        match self {
            AgeSource::ParentVerified => 1.0,
            AgeSource::UserReported => 0.85,
            AgeSource::MlInferred => 0.7,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroomingTrajectoryStage {
    TrustBuilding,
    SecrecyOrMigration,
    PersonalProbing,
    MediaOrSexualPressure,
    MeetingPressure,
    ManipulationSetup,
}

impl GroomingTrajectoryStage {
    fn bit(self) -> u8 {
        match self {
            Self::TrustBuilding => 1 << 0,
            Self::SecrecyOrMigration => 1 << 1,
            Self::PersonalProbing => 1 << 2,
            Self::MediaOrSexualPressure => 1 << 3,
            Self::MeetingPressure => 1 << 4,
            Self::ManipulationSetup => 1 << 5,
        }
    }

    fn is_high_risk(self) -> bool {
        matches!(
            self,
            Self::SecrecyOrMigration
                | Self::PersonalProbing
                | Self::MediaOrSexualPressure
                | Self::MeetingPressure
        )
    }
}

/// Compact contact-level memory for child-safety grooming trajectory.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct ChildSafetyTrajectory {
    pub first_grooming_ms: u64,
    pub last_grooming_ms: u64,
    pub grooming_stage_mask: u8,
    pub grooming_event_count: u16,
    pub high_risk_event_count: u16,
    pub rapid_escalation_ms: u64,
}

impl ChildSafetyTrajectory {
    pub(super) fn record_grooming_event(&mut self, kind: &EventKind, timestamp_ms: u64) {
        let Some(stage) = grooming_trajectory_stage(kind) else {
            return;
        };

        if self.first_grooming_ms == 0 {
            self.first_grooming_ms = timestamp_ms;
        }
        self.last_grooming_ms = self.last_grooming_ms.max(timestamp_ms);
        self.grooming_stage_mask |= stage.bit();
        self.grooming_event_count = self.grooming_event_count.saturating_add(1);

        if stage.is_high_risk() {
            self.high_risk_event_count = self.high_risk_event_count.saturating_add(1);
            let elapsed_ms = timestamp_ms.saturating_sub(self.first_grooming_ms);
            if self.rapid_escalation_ms == 0 || elapsed_ms < self.rapid_escalation_ms {
                self.rapid_escalation_ms = elapsed_ms;
            }
        }
    }

    pub fn stage_count(&self) -> u8 {
        (self.grooming_stage_mask & 0b0011_1111).count_ones() as u8
    }

    pub fn high_risk_stage_count(&self) -> u8 {
        let high_risk_mask = GroomingTrajectoryStage::SecrecyOrMigration.bit()
            | GroomingTrajectoryStage::PersonalProbing.bit()
            | GroomingTrajectoryStage::MediaOrSexualPressure.bit()
            | GroomingTrajectoryStage::MeetingPressure.bit();
        (self.grooming_stage_mask & high_risk_mask).count_ones() as u8
    }

    pub fn has_rapid_escalation(&self) -> bool {
        self.rapid_escalation_ms > 0 && self.rapid_escalation_ms <= DAY_MS
    }
}

fn grooming_trajectory_stage(kind: &EventKind) -> Option<GroomingTrajectoryStage> {
    match kind {
        EventKind::Flattery
        | EventKind::LoveBombing
        | EventKind::GiftOffer
        | EventKind::MoneyOffer
        | EventKind::FinancialGrooming
        | EventKind::CasualMeetingRequest => Some(GroomingTrajectoryStage::TrustBuilding),
        EventKind::SecrecyRequest | EventKind::PlatformSwitch => {
            Some(GroomingTrajectoryStage::SecrecyOrMigration)
        }
        EventKind::PersonalInfoRequest | EventKind::LocationRequest => {
            Some(GroomingTrajectoryStage::PersonalProbing)
        }
        EventKind::PhotoRequest
        | EventKind::VideoCallRequest
        | EventKind::SexualContent
        | EventKind::AgeInappropriate => Some(GroomingTrajectoryStage::MediaOrSexualPressure),
        EventKind::MeetingRequest => Some(GroomingTrajectoryStage::MeetingPressure),
        EventKind::IdentityErosion
        | EventKind::NetworkPoisoning
        | EventKind::FakeVulnerability
        | EventKind::FalseConsensus
        | EventKind::DebtCreation => Some(GroomingTrajectoryStage::ManipulationSetup),
        _ => None,
    }
}

/// Captures aggregated behavioral statistics for a single weekly period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralSnapshot {
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub total_messages: u32,
    pub hostile_count: u32,
    pub supportive_count: u32,
    pub neutral_count: u32,
    pub grooming_count: u32,
    pub manipulation_count: u32,
    pub propaganda_count: u32,
    pub avg_severity: f32,
}

/// Represents the exportable state of a behavioral snapshot.
#[derive(Debug, Clone)]
pub struct BehavioralSnapshotState {
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub total_messages: u32,
    pub hostile_count: u32,
    pub supportive_count: u32,
    pub neutral_count: u32,
    pub grooming_count: u32,
    pub manipulation_count: u32,
    pub propaganda_count: u32,
    pub avg_severity: f32,
}

impl From<&BehavioralSnapshot> for BehavioralSnapshotState {
    fn from(snapshot: &BehavioralSnapshot) -> Self {
        Self {
            period_start_ms: snapshot.period_start_ms,
            period_end_ms: snapshot.period_end_ms,
            total_messages: snapshot.total_messages,
            hostile_count: snapshot.hostile_count,
            supportive_count: snapshot.supportive_count,
            neutral_count: snapshot.neutral_count,
            grooming_count: snapshot.grooming_count,
            manipulation_count: snapshot.manipulation_count,
            propaganda_count: snapshot.propaganda_count,
            avg_severity: snapshot.avg_severity,
        }
    }
}

impl From<BehavioralSnapshotState> for BehavioralSnapshot {
    fn from(snapshot: BehavioralSnapshotState) -> Self {
        Self {
            period_start_ms: snapshot.period_start_ms,
            period_end_ms: snapshot.period_end_ms,
            total_messages: snapshot.total_messages,
            hostile_count: snapshot.hostile_count,
            supportive_count: snapshot.supportive_count,
            neutral_count: snapshot.neutral_count,
            grooming_count: snapshot.grooming_count,
            manipulation_count: snapshot.manipulation_count,
            propaganda_count: snapshot.propaganda_count,
            avg_severity: snapshot.avg_severity,
        }
    }
}

impl BehavioralSnapshot {
    pub(super) fn new(start_ms: u64) -> Self {
        Self {
            period_start_ms: start_ms,
            period_end_ms: 0,
            total_messages: 0,
            hostile_count: 0,
            supportive_count: 0,
            neutral_count: 0,
            grooming_count: 0,
            manipulation_count: 0,
            propaganda_count: 0,
            avg_severity: 0.0,
        }
    }

    /// Returns the ratio of hostile messages to total messages in this period.
    pub fn hostile_ratio(&self) -> f32 {
        if self.total_messages == 0 {
            0.0
        } else {
            self.hostile_count as f32 / self.total_messages as f32
        }
    }

    /// Returns the ratio of supportive messages to total messages in this period.
    pub fn supportive_ratio(&self) -> f32 {
        if self.total_messages == 0 {
            0.0
        } else {
            self.supportive_count as f32 / self.total_messages as f32
        }
    }

    pub(super) fn merge_from(&mut self, incoming: Self) {
        if incoming.total_messages > self.total_messages {
            *self = incoming;
            return;
        }
        if incoming.total_messages < self.total_messages {
            return;
        }

        self.period_end_ms = self.period_end_ms.max(incoming.period_end_ms);
        self.hostile_count = self.hostile_count.max(incoming.hostile_count);
        self.supportive_count = self.supportive_count.max(incoming.supportive_count);
        self.neutral_count = self.neutral_count.max(incoming.neutral_count);
        self.grooming_count = self.grooming_count.max(incoming.grooming_count);
        self.manipulation_count = self.manipulation_count.max(incoming.manipulation_count);
        self.propaganda_count = self.propaganda_count.max(incoming.propaganda_count);
        self.avg_severity = self.avg_severity.max(incoming.avg_severity);
    }
}

pub(super) fn merge_weekly_snapshot(
    snapshots: &mut VecDeque<BehavioralSnapshot>,
    mut incoming: BehavioralSnapshot,
) {
    if incoming.period_end_ms == 0 {
        incoming.period_end_ms = incoming.period_start_ms.saturating_add(WEEK_MS);
    }
    if let Some(local) = snapshots
        .iter_mut()
        .find(|local| local.period_start_ms == incoming.period_start_ms)
    {
        local.merge_from(incoming);
    } else {
        snapshots.push_back(incoming);
    }
    snapshots
        .make_contiguous()
        .sort_by_key(|snapshot| snapshot.period_start_ms);
    while snapshots.len() > MAX_SNAPSHOTS {
        snapshots.pop_front();
    }
}
