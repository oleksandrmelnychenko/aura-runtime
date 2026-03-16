use thiserror::Error;

/// Represents all errors that can occur within the AURA analysis engine.
#[derive(Debug, Error)]
pub enum AuraError {
    /// Indicates that no conversation timeline exists for the requested conversation.
    #[error("no timeline for conversation")]
    MissingTimeline,

    /// Indicates that the provided signal set is empty or invalid.
    #[error("invalid or empty signal set")]
    InvalidSignals,

    /// Wraps a JSON serialization or deserialization failure.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Wraps a standard I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Indicates that the provided configuration is invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Indicates that pattern data failed to load.
    #[error("pattern loading failed: {0}")]
    PatternLoadFailed(String),

    /// Indicates that an ML model file was not found at the expected path.
    #[error("ML model not found at path: {0}")]
    ModelNotFound(String),

    /// Indicates that ML model inference failed.
    #[error("ML inference failed: {0}")]
    MlInferenceFailed(String),

    /// Indicates that imported state has an incompatible version.
    #[error("incompatible state version: found {found}, max supported {supported}")]
    IncompatibleStateVersion {
        /// The version found in the imported state.
        found: u32,
        /// The maximum version supported by this build.
        supported: u32,
    },
}
