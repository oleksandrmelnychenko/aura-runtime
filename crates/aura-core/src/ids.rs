//! Strongly-typed identifier newtypes for compile-time safety.
//!
//! Prevents accidental mixing of sender IDs, conversation IDs, and reason codes.

use std::borrow::Borrow;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Identifies a unique message sender.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SenderId(pub String);

/// Identifies a unique conversation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConversationId(pub String);

/// Identifies a detection reason code.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReasonCode(pub String);

macro_rules! impl_id_traits {
    ($ty:ty) => {
        impl std::ops::Deref for $ty {
            type Target = str;
            fn deref(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $ty {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $ty {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }

        impl PartialEq<str> for $ty {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $ty {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

        impl Borrow<str> for $ty {
            fn borrow(&self) -> &str {
                &self.0
            }
        }
    };
}

impl_id_traits!(SenderId);
impl_id_traits!(ConversationId);
impl_id_traits!(ReasonCode);
