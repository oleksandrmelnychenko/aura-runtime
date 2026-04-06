use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SpeechAct {
    #[default]
    Assert,
    Ask,
    Quote,
    Report,
    Counter,
    Support,
    Joke,
    Coordinate,
    Solicit,
    Threaten,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Stance {
    Endorse,
    Oppose,
    Neutral,
    #[default]
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Directionality {
    DirectedAtUser,
    ThirdParty,
    SelfReferential,
    Broadcast,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipTag {
    Trusted,
    NewContact,
    Established,
    Authority,
    Peer,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrajectoryTag {
    RepeatedSender,
    Escalating,
    CrossConversation,
    Bursty,
    Stable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ThreatContextFrame {
    #[serde(default)]
    pub speech_act: SpeechAct,
    #[serde(default)]
    pub stance: Stance,
    #[serde(default)]
    pub directionality: Directionality,
    #[serde(default)]
    pub relationship: Vec<RelationshipTag>,
    #[serde(default)]
    pub trajectory: Vec<TrajectoryTag>,
    #[serde(default)]
    pub confidence: f32,
}

impl ThreatContextFrame {
    pub fn has_relationship(&self, tag: RelationshipTag) -> bool {
        self.relationship.contains(&tag)
    }

    pub fn has_trajectory(&self, tag: TrajectoryTag) -> bool {
        self.trajectory.contains(&tag)
    }
}
