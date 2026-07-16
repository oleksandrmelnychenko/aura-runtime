//! Configuration types for the AURA analysis engine.

use serde::{Deserialize, Serialize};

use crate::product::ProductRolloutMode;
use crate::types::{AccountType, AuraDomainModule, DomainMode, ProtectionLevel};

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

    /// Stable sender/account ID for the protected account holder.
    ///
    /// When set, conversation tracking keeps this sender in timelines but
    /// excludes them from external-contact risk profiling.
    #[serde(default)]
    pub protected_account_id: Option<String>,

    #[serde(default = "default_ttl_days")]
    pub ttl_days: u32,

    /// Timezone offset in minutes from UTC (e.g. +180 for UTC+3 Ukraine).
    #[serde(default)]
    pub timezone_offset_minutes: i32,

    /// Selects the account-level domain mode on top of base Aura.
    #[serde(default)]
    pub domain_mode: DomainMode,

    /// Controls whether product decisions are mirrored or applied.
    ///
    /// Missing persisted values fail safe to [`ProductRolloutMode::Shadow`].
    #[serde(default)]
    pub product_rollout_mode: ProductRolloutMode,
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

    /// Returns the effective account-level domain mode.
    pub fn effective_domain_mode(&self) -> DomainMode {
        match self.domain_mode {
            DomainMode::None => match self.account_type {
                AccountType::Child | AccountType::Teen => DomainMode::Kids,
                AccountType::Adult => DomainMode::None,
            },
            other => other,
        }
    }

    /// Returns the effective domain module for this account.
    pub fn effective_domain_module(&self) -> Option<AuraDomainModule> {
        self.effective_domain_mode().domain_module()
    }

    /// Returns `true` if the Kids module is active (explicitly or implicitly).
    pub fn is_kids_module(&self) -> bool {
        match self.effective_domain_module() {
            Some(AuraDomainModule::Kids) => true,
            Some(AuraDomainModule::Military) => false,
            None => match self.account_type {
                AccountType::Child | AccountType::Teen => true,
                AccountType::Adult => false,
            },
        }
    }

    /// Returns `true` if the Military module is active.
    pub fn is_military_module(&self) -> bool {
        match self.effective_domain_module() {
            Some(AuraDomainModule::Kids) => false,
            Some(AuraDomainModule::Military) => true,
            None => false,
        }
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
        if self
            .protected_account_id
            .as_deref()
            .is_some_and(|id| id.trim().is_empty())
        {
            return Err(crate::error::AuraError::InvalidConfig(
                "protected_account_id must not be empty".to_string(),
            ));
        }
        if !(-14 * 60..=14 * 60).contains(&self.timezone_offset_minutes) {
            return Err(crate::error::AuraError::InvalidConfig(format!(
                "timezone_offset_minutes must be within UTC-14..UTC+14, got {}",
                self.timezone_offset_minutes
            )));
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
            protected_account_id: None,
            ttl_days: 30,
            timezone_offset_minutes: 0,
            domain_mode: DomainMode::default(),
            product_rollout_mode: ProductRolloutMode::Shadow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AuraConfig;
    use crate::product::ProductRolloutMode;
    use crate::types::{AccountType, AuraDomainModule, DomainMode};

    #[test]
    fn default_product_rollout_is_shadow() {
        assert_eq!(
            AuraConfig::default().product_rollout_mode,
            ProductRolloutMode::Shadow
        );
    }

    #[test]
    fn child_account_defaults_to_kids_domain_module() {
        let config = AuraConfig {
            account_type: AccountType::Child,
            domain_mode: DomainMode::None,
            ..AuraConfig::default()
        };
        assert_eq!(
            config.effective_domain_module(),
            Some(AuraDomainModule::Kids)
        );
    }

    #[test]
    fn explicit_kids_module_enables_kids_domain_module() {
        let config = AuraConfig {
            account_type: AccountType::Adult,
            domain_mode: DomainMode::Kids,
            ..AuraConfig::default()
        };
        assert_eq!(
            config.effective_domain_module(),
            Some(AuraDomainModule::Kids)
        );
    }

    #[test]
    fn timezone_offset_validation_respects_utc_bounds() {
        let too_low = AuraConfig {
            timezone_offset_minutes: -14 * 60 - 1,
            ..AuraConfig::default()
        };
        assert!(too_low.validate().is_err());

        let too_high = AuraConfig {
            timezone_offset_minutes: 14 * 60 + 1,
            ..AuraConfig::default()
        };
        assert!(too_high.validate().is_err());

        let on_edge = AuraConfig {
            timezone_offset_minutes: 14 * 60,
            ..AuraConfig::default()
        };
        assert!(on_edge.validate().is_ok());
    }
}
