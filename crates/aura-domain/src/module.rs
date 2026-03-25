use serde::{Deserialize, Serialize};

use crate::{DomainInput, DomainOutput};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainModuleId {
    Kids,
    Military,
}

pub trait DomainModule: Send + Sync {
    fn id(&self) -> DomainModuleId;
    fn analyze(&self, input: &DomainInput) -> DomainOutput;
}
