use serde::{Deserialize, Serialize};

use crate::types::{AccountType, ProtectionLevel};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuraConfig {
    pub protection_level: ProtectionLevel,

    pub account_type: AccountType,

    pub language: String,

    pub cultural_context: CulturalContext,

    pub enabled: bool,

    pub patterns_path: Option<String>,

    pub models_path: Option<String>,

    #[serde(default)]
    pub account_holder_age: Option<u16>,

    #[serde(default = "default_ttl_days")]
    pub ttl_days: u32,

    /// Timezone offset in minutes from UTC (e.g. +180 for UTC+3 Ukraine).
    #[serde(default)]
    pub timezone_offset_minutes: i32,
}

fn default_ttl_days() -> u32 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CulturalContext {
    #[default]
    Ukrainian,
    Russian,
    English,
    Custom(String),
}

impl AuraConfig {
    pub fn effective_protection_level(&self) -> ProtectionLevel {
        match self.account_type {
            AccountType::Child => ProtectionLevel::High,
            AccountType::Teen => match self.protection_level {
                ProtectionLevel::Off => ProtectionLevel::Low,
                other => other,
            },
            AccountType::Adult => {
                if self.enabled {
                    self.protection_level
                } else {
                    ProtectionLevel::Off
                }
            }
        }
    }

    pub fn can_disable(&self) -> bool {
        matches!(self.account_type, AccountType::Adult)
    }

    pub fn grooming_detection_enabled(&self) -> bool {
        self.enabled && self.effective_protection_level() != ProtectionLevel::Off
    }

    pub fn self_harm_detection_enabled(&self) -> bool {
        self.enabled && self.effective_protection_level() != ProtectionLevel::Off
    }

    pub fn bullying_detection_enabled(&self) -> bool {
        self.enabled && self.effective_protection_level() != ProtectionLevel::Off
    }

    pub fn validate(&self) -> Result<(), crate::error::AuraError> {
        if self.ttl_days == 0 || self.ttl_days > 365 {
            return Err(crate::error::AuraError::InvalidConfig(format!(
                "ttl_days must be 1..=365, got {}",
                self.ttl_days
            )));
        }
        if let Some(age) = self.account_holder_age {
            if !(5..=120).contains(&age) {
                return Err(crate::error::AuraError::InvalidConfig(format!(
                    "account_holder_age must be 5..=120, got {age}"
                )));
            }
        }
        Ok(())
    }
}

impl Default for AuraConfig {
    fn default() -> Self {
        Self {
            protection_level: ProtectionLevel::Medium,
            account_type: AccountType::Adult,
            language: "uk".to_string(),
            cultural_context: CulturalContext::default(),
            enabled: true,
            patterns_path: None,
            models_path: None,
            account_holder_age: None,
            ttl_days: 30,
            timezone_offset_minutes: 0,
        }
    }
}
