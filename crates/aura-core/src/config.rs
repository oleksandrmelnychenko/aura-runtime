//! Configuration types for the AURA analysis engine.

use serde::{Deserialize, Serialize};

use aura_domain::LanguageTag;

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

    pub account_holder_age: Option<u16>,

    /// Stable sender/account ID for the protected account holder.
    ///
    /// When set, conversation tracking keeps this sender in timelines but
    /// excludes them from external-contact risk profiling.
    pub protected_account_id: Option<String>,

    pub ttl_days: u32,

    /// Timezone offset in minutes from UTC (e.g. +180 for UTC+3 Ukraine).
    pub timezone_offset_minutes: i32,

    /// Selects the account-level domain mode on top of base Aura.
    pub domain_mode: DomainMode,

    /// Controls whether product decisions are mirrored or applied.
    pub product_rollout_mode: ProductRolloutMode,
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
    /// Returns whether protection is active after applying account-type policy.
    ///
    /// Adult account holders may disable protection explicitly. Protection for
    /// child and teen accounts remains active even if an untrusted caller
    /// constructs an invalid configuration without using [`Self::validate`].
    pub fn protection_enabled(&self) -> bool {
        match self.account_type {
            AccountType::Adult => self.enabled && self.protection_level != ProtectionLevel::Off,
            AccountType::Teen | AccountType::Child => true,
        }
    }

    /// Returns the effective protection level after applying account-type policy overrides.
    pub fn effective_protection_level(&self) -> ProtectionLevel {
        match self.account_type {
            AccountType::Child => ProtectionLevel::High,
            AccountType::Teen => match self.protection_level {
                ProtectionLevel::Off => ProtectionLevel::Low,
                other => other,
            },
            AccountType::Adult => {
                if self.protection_enabled() {
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
        match self.account_type {
            AccountType::Child | AccountType::Teen => DomainMode::Kids,
            AccountType::Adult => self.domain_mode,
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
        self.protection_enabled()
            && self.is_kids_module()
            && self.effective_protection_level() != ProtectionLevel::Off
    }

    /// Returns `true` if self-harm detection is active under the current configuration.
    pub fn self_harm_detection_enabled(&self) -> bool {
        self.protection_enabled()
            && self.is_kids_module()
            && self.effective_protection_level() != ProtectionLevel::Off
    }

    /// Returns `true` if bullying detection is active under the current configuration.
    pub fn bullying_detection_enabled(&self) -> bool {
        self.protection_enabled()
            && self.is_kids_module()
            && self.effective_protection_level() != ProtectionLevel::Off
    }

    /// Returns `true` if anti-propaganda detection is active (always on in Core).
    pub fn propaganda_detection_enabled(&self) -> bool {
        self.protection_enabled() && self.effective_protection_level() != ProtectionLevel::Off
    }

    /// Returns `true` if OPSEC violation detection is active (Military module only).
    pub fn opsec_detection_enabled(&self) -> bool {
        self.protection_enabled()
            && self.is_military_module()
            && self.effective_protection_level() != ProtectionLevel::Off
    }

    /// Returns `true` if psyops detection is active (Military module only).
    pub fn psyops_detection_enabled(&self) -> bool {
        self.protection_enabled()
            && self.is_military_module()
            && self.effective_protection_level() != ProtectionLevel::Off
    }

    /// Validates the configuration and returns an error if any field is out of range.
    pub fn validate(&self) -> Result<(), crate::error::AuraError> {
        let normalized_language =
            LanguageTag::try_from(self.language.as_str()).map_err(|error| {
                crate::error::AuraError::InvalidConfig(format!(
                    "language must be a bounded BCP-47-style tag: {error}"
                ))
            })?;
        if normalized_language.as_str() != self.language {
            return Err(crate::error::AuraError::InvalidConfig(
                "language must use canonical lowercase BCP-47-style form".to_string(),
            ));
        }
        if !self.can_disable() && !self.enabled {
            return Err(crate::error::AuraError::InvalidConfig(
                "minor protection cannot be disabled".to_string(),
            ));
        }
        if !self.can_disable() && self.domain_mode == DomainMode::Military {
            return Err(crate::error::AuraError::InvalidConfig(
                "minor accounts require the Kids domain".to_string(),
            ));
        }
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
    use crate::types::{AccountType, AuraDomainModule, DomainMode, ProtectionLevel};

    #[test]
    fn default_product_rollout_is_shadow() {
        assert_eq!(
            AuraConfig::default().product_rollout_mode,
            ProductRolloutMode::Shadow
        );
    }

    #[test]
    fn config_rejects_noncanonical_language_tag() {
        let config = AuraConfig {
            language: "en_US".to_string(),
            ..AuraConfig::default()
        };

        assert!(config.validate().is_err());
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
    fn minor_configuration_matrix_is_fail_closed() {
        let account_types = [AccountType::Child, AccountType::Teen];
        let enabled_values = [false, true];
        let protection_levels = [
            ProtectionLevel::Off,
            ProtectionLevel::Low,
            ProtectionLevel::Medium,
            ProtectionLevel::High,
        ];
        let domain_modes = [DomainMode::None, DomainMode::Kids, DomainMode::Military];

        for account_type in account_types {
            for enabled in enabled_values {
                for protection_level in protection_levels {
                    for domain_mode in domain_modes {
                        let config = AuraConfig {
                            account_type,
                            enabled,
                            protection_level,
                            domain_mode,
                            ..AuraConfig::default()
                        };

                        assert_ne!(
                            config.effective_protection_level(),
                            ProtectionLevel::Off,
                            "minor protection must remain active for {config:?}"
                        );
                        assert_eq!(
                            config.effective_domain_mode(),
                            DomainMode::Kids,
                            "minor accounts must remain in the Kids domain for {config:?}"
                        );
                        assert!(config.grooming_detection_enabled(), "{config:?}");
                        assert!(config.self_harm_detection_enabled(), "{config:?}");
                        assert!(config.bullying_detection_enabled(), "{config:?}");
                        assert!(config.propaganda_detection_enabled(), "{config:?}");

                        let should_validate = enabled && domain_mode != DomainMode::Military;
                        assert_eq!(
                            config.validate().is_ok(),
                            should_validate,
                            "unexpected minor validation result for {config:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn adult_disable_semantics_remain_explicit() {
        for protection_level in [
            ProtectionLevel::Off,
            ProtectionLevel::Low,
            ProtectionLevel::Medium,
            ProtectionLevel::High,
        ] {
            let disabled = AuraConfig {
                account_type: AccountType::Adult,
                enabled: false,
                protection_level,
                ..AuraConfig::default()
            };
            assert_eq!(disabled.effective_protection_level(), ProtectionLevel::Off);
            assert!(disabled.validate().is_ok());
            assert!(!disabled.propaganda_detection_enabled());
        }
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
