//! Configuration types for the AURA analysis engine.

use serde::{Deserialize, Serialize};

use crate::types::{AccountType, AuraModule, ProtectionLevel};

/// Holds the runtime configuration for the AURA protection system.
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

    /// Selects the active protection module. Defaults to `CoreOnly`.
    #[serde(default)]
    pub active_module: AuraModule,
}

fn default_ttl_days() -> u32 {
    30
}

/// Represents the cultural and linguistic context for content analysis.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CulturalContext {
    /// Ukrainian language and cultural norms.
    #[default]
    Ukrainian,
    /// Russian language and cultural norms.
    Russian,
    /// English language and cultural norms.
    English,
    /// Custom cultural context identified by a string tag.
    Custom(String),
}

impl AuraConfig {
    /// Returns the effective protection level after applying account-type policy overrides.
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

    /// Returns `true` if the account holder is allowed to disable protection.
    pub fn can_disable(&self) -> bool {
        match self.account_type {
            AccountType::Adult => true,
            AccountType::Teen | AccountType::Child => false,
        }
    }

    /// Returns the effective active module, applying backward-compat rules.
    ///
    /// When `active_module` is `CoreOnly` but `account_type` is `Child` or `Teen`,
    /// implicitly activates the Kids module for backward compatibility.
    pub fn effective_module(&self) -> AuraModule {
        match self.active_module {
            AuraModule::CoreOnly => match self.account_type {
                AccountType::Child | AccountType::Teen => AuraModule::Kids,
                AccountType::Adult => AuraModule::CoreOnly,
            },
            other => other,
        }
    }

    /// Returns `true` if the Kids module is active (explicitly or implicitly).
    pub fn is_kids_module(&self) -> bool {
        self.effective_module() == AuraModule::Kids
    }

    /// Returns `true` if the Military module is active.
    pub fn is_military_module(&self) -> bool {
        self.effective_module() == AuraModule::Military
    }

    /// Returns `true` if grooming detection is active under the current configuration.
    pub fn grooming_detection_enabled(&self) -> bool {
        self.enabled
            && self.is_kids_module()
            && self.effective_protection_level() != ProtectionLevel::Off
    }

    /// Returns `true` if self-harm detection is active under the current configuration.
    pub fn self_harm_detection_enabled(&self) -> bool {
        self.enabled
            && self.is_kids_module()
            && self.effective_protection_level() != ProtectionLevel::Off
    }

    /// Returns `true` if bullying detection is active under the current configuration.
    pub fn bullying_detection_enabled(&self) -> bool {
        self.enabled
            && self.is_kids_module()
            && self.effective_protection_level() != ProtectionLevel::Off
    }

    /// Returns `true` if anti-propaganda detection is active (always on in Core).
    pub fn propaganda_detection_enabled(&self) -> bool {
        self.enabled && self.effective_protection_level() != ProtectionLevel::Off
    }

    /// Returns `true` if OPSEC violation detection is active (Military module only).
    pub fn opsec_detection_enabled(&self) -> bool {
        self.enabled
            && self.is_military_module()
            && self.effective_protection_level() != ProtectionLevel::Off
    }

    /// Returns `true` if psyops detection is active (Military module only).
    pub fn psyops_detection_enabled(&self) -> bool {
        self.enabled
            && self.is_military_module()
            && self.effective_protection_level() != ProtectionLevel::Off
    }

    /// Validates the configuration and returns an error if any field is out of range.
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
            active_module: AuraModule::default(),
        }
    }
}
