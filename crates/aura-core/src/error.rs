use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuraError {
    #[error("no timeline for conversation")]
    MissingTimeline,

    #[error("invalid or empty signal set")]
    InvalidSignals,

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("pattern loading failed: {0}")]
    PatternLoadFailed(String),

    #[error("ML model not found at path: {0}")]
    ModelNotFound(String),

    #[error("ML inference failed: {0}")]
    MlInferenceFailed(String),

    #[error("incompatible state version: found {found}, max supported {supported}")]
    IncompatibleStateVersion { found: u32, supported: u32 },
}
