use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Model manifest for SHA-256 hash validation of ONNX model files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelManifest {
    pub version: u32,
    pub models: HashMap<String, ModelEntry>,
}

/// A single model entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelEntry {
    pub filename: String,
    pub sha256: String,
    #[serde(default)]
    pub data_filename: Option<String>,
    #[serde(default)]
    pub data_sha256: Option<String>,
    #[serde(default)]
    pub quantized_filename: Option<String>,
    #[serde(default)]
    pub quantized_sha256: Option<String>,
    #[serde(default)]
    pub quantized_data_filename: Option<String>,
    #[serde(default)]
    pub quantized_data_sha256: Option<String>,
    #[serde(default)]
    pub num_outputs: Option<usize>,
    #[serde(default)]
    pub max_seq_length: Option<usize>,
}

/// Hashes retained from the exact manifest and artifacts validated at startup.
#[derive(Debug, Clone)]
pub struct ValidatedModelManifest {
    pub manifest_sha256: [u8; 32],
    artifact_sha256_by_canonical_path: HashMap<PathBuf, [u8; 32]>,
}

impl ValidatedModelManifest {
    pub fn artifact_sha256(&self, path: &str) -> Option<[u8; 32]> {
        let canonical_path = fs::canonicalize(path).ok()?;
        self.artifact_sha256_by_canonical_path
            .get(&canonical_path)
            .copied()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("failed to read manifest '{0}': {1}")]
    ReadFailed(String, String),

    #[error("failed to parse manifest '{0}': {1}")]
    ParseFailed(String, String),

    #[error("model file not found: {0}")]
    ModelNotFound(String),

    #[error("hash mismatch for '{0}': expected {1}, got {2}")]
    HashMismatch(String, String, String),

    #[error("failed to read model file '{0}': {1}")]
    FileReadFailed(String, String),

    #[error("invalid manifest entry '{0}': {1}")]
    InvalidEntry(String, String),
}

impl ModelManifest {
    /// Loads a manifest from a JSON file.
    pub fn from_file(path: &str) -> Result<Self, ManifestError> {
        let content = fs::read_to_string(path)
            .map_err(|e| ManifestError::ReadFailed(path.to_string(), e.to_string()))?;
        serde_json::from_str(&content)
            .map_err(|e| ManifestError::ParseFailed(path.to_string(), e.to_string()))
    }
}

/// Validates that a file matches the expected SHA-256 hash.
pub fn validate_file_hash(path: &Path, expected_sha256: &str) -> Result<(), ManifestError> {
    let path_str = path.display().to_string();
    if !path.exists() {
        return Err(ManifestError::ModelNotFound(path_str));
    }

    let data = fs::read(path)
        .map_err(|e| ManifestError::FileReadFailed(path_str.clone(), e.to_string()))?;

    let actual = sha256_hex(&data);

    if actual != expected_sha256 {
        return Err(ManifestError::HashMismatch(
            path_str,
            expected_sha256.to_string(),
            actual,
        ));
    }

    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();

    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }

    output
}

/// Validates all models listed in a manifest file against their expected hashes.
pub fn validate_models_from_manifest(
    manifest_path: &str,
) -> Result<ValidatedModelManifest, ManifestError> {
    let manifest_bytes = fs::read(manifest_path)
        .map_err(|e| ManifestError::ReadFailed(manifest_path.to_string(), e.to_string()))?;
    let manifest: ModelManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| ManifestError::ParseFailed(manifest_path.to_string(), e.to_string()))?;
    let manifest_dir = Path::new(manifest_path).parent().unwrap_or(Path::new("."));
    let mut artifact_sha256_by_canonical_path = HashMap::new();

    for (name, entry) in &manifest.models {
        let model_path = manifest_dir.join(&entry.filename);
        validate_file_hash(&model_path, &entry.sha256).map_err(|e| {
            tracing::warn!("Model validation failed for '{name}': {e}");
            e
        })?;
        register_validated_artifact(
            &mut artifact_sha256_by_canonical_path,
            &model_path,
            decode_sha256_hex(name, &entry.sha256)?,
        )?;

        for artifact in [
            validate_optional_artifact(
                name,
                manifest_dir,
                entry.data_filename.as_deref(),
                entry.data_sha256.as_deref(),
                "data",
            )?,
            validate_optional_artifact(
                name,
                manifest_dir,
                entry.quantized_filename.as_deref(),
                entry.quantized_sha256.as_deref(),
                "quantized",
            )?,
            validate_optional_artifact(
                name,
                manifest_dir,
                entry.quantized_data_filename.as_deref(),
                entry.quantized_data_sha256.as_deref(),
                "quantized_data",
            )?,
        ]
        .into_iter()
        .flatten()
        {
            register_validated_artifact(
                &mut artifact_sha256_by_canonical_path,
                &manifest_dir.join(artifact.0),
                artifact.1,
            )?;
        }
    }

    Ok(ValidatedModelManifest {
        manifest_sha256: Sha256::digest(&manifest_bytes).into(),
        artifact_sha256_by_canonical_path,
    })
}

fn register_validated_artifact(
    artifacts: &mut HashMap<PathBuf, [u8; 32]>,
    path: &Path,
    digest: [u8; 32],
) -> Result<(), ManifestError> {
    let canonical_path = fs::canonicalize(path).map_err(|error| {
        ManifestError::FileReadFailed(path.display().to_string(), error.to_string())
    })?;
    if artifacts
        .insert(canonical_path, digest)
        .is_some_and(|previous| previous != digest)
    {
        return Err(ManifestError::InvalidEntry(
            path.display().to_string(),
            "the same artifact path has conflicting digests".to_string(),
        ));
    }
    Ok(())
}

fn decode_sha256_hex(name: &str, value: &str) -> Result<[u8; 32], ManifestError> {
    if value.len() != 64 {
        return Err(ManifestError::InvalidEntry(
            name.to_string(),
            "sha256 must contain exactly 64 lowercase hexadecimal characters".to_string(),
        ));
    }
    let mut digest = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| {
            ManifestError::InvalidEntry(name.to_string(), "sha256 is not lowercase hex".to_string())
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| {
            ManifestError::InvalidEntry(name.to_string(), "sha256 is not lowercase hex".to_string())
        })?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn validate_optional_artifact(
    model_name: &str,
    manifest_dir: &Path,
    filename: Option<&str>,
    sha256: Option<&str>,
    artifact_label: &str,
) -> Result<Option<(String, [u8; 32])>, ManifestError> {
    match (filename, sha256) {
        (Some(file), Some(hash)) => {
            let path = manifest_dir.join(file);
            validate_file_hash(&path, hash)?;
            let digest = decode_sha256_hex(&format!("{model_name}.{artifact_label}"), hash)?;
            Ok(Some((file.to_string(), digest)))
        }
        (None, None) => Ok(None),
        (Some(_), None) => Err(ManifestError::InvalidEntry(
            model_name.to_string(),
            format!("{artifact_label} filename is present but sha256 is missing"),
        )),
        (None, Some(_)) => Err(ManifestError::InvalidEntry(
            model_name.to_string(),
            format!("{artifact_label} sha256 is present but filename is missing"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn manifest_parses_valid_json() {
        let json = r#"{
            "version": 1,
            "models": {
                "toxicity": {
                    "filename": "toxicity.onnx",
                    "sha256": "abc123",
                    "num_outputs": 6,
                    "max_seq_length": 128
                }
            }
        }"#;
        let manifest: ModelManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.version, 1);
        assert!(manifest.models.contains_key("toxicity"));
        assert_eq!(manifest.models["toxicity"].num_outputs, Some(6));
    }

    #[test]
    fn validate_file_hash_succeeds_for_correct_hash() {
        let dir = std::env::temp_dir().join("aura_manifest_test_ok");
        let _ = fs::create_dir_all(&dir);
        let file_path = dir.join("test_model.bin");
        let mut f = fs::File::create(&file_path).unwrap();
        f.write_all(b"test model content").unwrap();

        let expected = sha256_hex(b"test model content");

        assert!(validate_file_hash(&file_path, &expected).is_ok());
        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn validate_file_hash_fails_for_wrong_hash() {
        let dir = std::env::temp_dir().join("aura_manifest_test_bad");
        let _ = fs::create_dir_all(&dir);
        let file_path = dir.join("test_bad.bin");
        let mut f = fs::File::create(&file_path).unwrap();
        f.write_all(b"test model content").unwrap();

        let result = validate_file_hash(&file_path, "wrong_hash");
        assert!(matches!(result, Err(ManifestError::HashMismatch(..))));
        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn validate_file_hash_fails_for_missing_file() {
        let result = validate_file_hash(Path::new("/nonexistent/model.onnx"), "abc");
        assert!(matches!(result, Err(ManifestError::ModelNotFound(..))));
    }
}
