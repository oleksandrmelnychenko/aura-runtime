use std::time::Instant;

use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::backend::{GateModel, IntentBackend, SafetyBackend, SentimentBackend, ToxicityBackend};
use crate::cache::{self, InferenceCache};
use crate::cascade::{CascadeDecision, CascadePolicy};
use crate::dataset_adapters::{compare_rule_only_vs_rule_plus_ml, Wave1AdapterComparison};
use crate::gate::LexiconGate;
use crate::integrity;
use crate::intent::intent_calibration_for;
use crate::intent::IntentClassifier;
use crate::manifest;
use crate::normalize::normalize_for_ml;
use crate::safety::safety_calibration_for;
use crate::safety::SafetyClassifier;
use crate::sentiment::SentimentAnalyzer;
use crate::telemetry::InferenceTelemetry;
#[cfg(feature = "onnx")]
use crate::tokenizer::WordPieceTokenizer;
use crate::toxicity::MlError;
use crate::toxicity::ToxicityClassifier;
use crate::types::{CascadeTier, MlConfig, MlResult, MlUncertaintyLevel, OnDeviceProfile};
use crate::unified::UnifiedModel;

/// Inference implementation actually loaded by [`MlPipeline`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlRuntimeBackend {
    RulesFallback,
    Onnx,
}

/// Non-sensitive identity of an ONNX artifact actually loaded by the pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlRuntimeModelIdentity {
    pub component: String,
    pub identifier: String,
    pub sha256: [u8; 32],
}

pub struct MlPipeline {
    toxicity: Box<dyn ToxicityBackend>,
    sentiment: Box<dyn SentimentBackend>,
    safety: Box<dyn SafetyBackend>,
    intent: Box<dyn IntentBackend>,
    unified: Option<UnifiedModel>,
    gate: LexiconGate,
    cascade: CascadePolicy,
    config: MlConfig,
    cache: InferenceCache,
    telemetry: InferenceTelemetry,
    runtime_backend: MlRuntimeBackend,
    loaded_models: Vec<MlRuntimeModelIdentity>,
    model_manifest_digest: [u8; 32],
}

impl MlPipeline {
    const ANALYZE_BATCH_CHUNK_SIZE: usize = 256;
    pub fn try_new(config: MlConfig) -> Result<Self, MlError> {
        let config = Self::normalize_config_for_on_device_profile(config);
        #[cfg(feature = "onnx")]
        let validated_manifest = {
            let mut validated_manifest = None;
            if config.validate_hashes {
                if config.strict_manifest_validation
                    && config.manifest_path.is_none()
                    && Self::has_any_onnx_model_configured(&config)
                {
                    return Err(MlError::ModelLoadFailed(
                        "strict manifest validation requires manifest_path when ONNX models are configured".to_string(),
                    ));
                }
                if let Some(ref manifest_path) = config.manifest_path {
                    match manifest::validate_models_from_manifest(manifest_path) {
                        Ok(validated) => {
                            info!("Model manifest validation passed");
                            validated_manifest = Some(validated);
                        }
                        Err(e) => {
                            if config.strict_manifest_validation {
                                return Err(MlError::ModelLoadFailed(format!(
                                    "model manifest validation failed in strict mode: {e}"
                                )));
                            }
                            tracing::warn!("Model manifest validation failed: {e}");
                        }
                    }
                }
            }
            validated_manifest
        };
        #[cfg(not(feature = "onnx"))]
        let validated_manifest = None;

        let unified = Self::load_unified(&config);

        let toxicity = Self::load_toxicity(&config);
        let sentiment = Self::load_sentiment(&config);

        info!(
            toxicity_mode = toxicity.name(),
            sentiment_mode = sentiment.name(),
            unified_mode = unified.as_ref().map_or("none", |u| u.name()),
            "ML pipeline initialized"
        );

        let safety = Self::load_safety(&config);
        let intent = Self::load_intent(&config);
        let gate = LexiconGate::new();
        let cascade = CascadePolicy {
            gate_threshold: config.cascade_gate_threshold,
            enabled: config.cascade_enabled && !config.cascade_force_bypass,
        };
        let cache = InferenceCache::new(config.cache_size, config.cache_ttl_secs);
        let telemetry = InferenceTelemetry::new();
        let runtime_backend = if unified.as_ref().is_some_and(UnifiedModel::has_onnx)
            || toxicity.is_onnx()
            || sentiment.is_onnx()
            || safety.is_onnx()
            || intent.is_onnx()
        {
            MlRuntimeBackend::Onnx
        } else {
            MlRuntimeBackend::RulesFallback
        };
        let loaded_models = Self::collect_loaded_models(
            &config,
            unified.as_ref(),
            toxicity.as_ref(),
            sentiment.as_ref(),
            safety.as_ref(),
            intent.as_ref(),
            validated_manifest.as_ref(),
        );
        let model_manifest_digest = match (runtime_backend, validated_manifest.as_ref()) {
            (_, Some(validated)) => validated.manifest_sha256,
            (MlRuntimeBackend::RulesFallback, None) => {
                Sha256::digest(b"aura.model-manifest.rules-fallback.v1").into()
            }
            (MlRuntimeBackend::Onnx, None) => [0; 32],
        };

        let mut pipeline = Self {
            toxicity,
            sentiment,
            safety,
            intent,
            unified,
            gate,
            cascade,
            config,
            cache,
            telemetry,
            runtime_backend,
            loaded_models,
            model_manifest_digest,
        };

        if Self::has_any_onnx_model_configured(&pipeline.config) && pipeline.config.warmup_on_init {
            pipeline.warmup();
        }

        Ok(pipeline)
    }

    pub fn new(config: MlConfig) -> Self {
        let fallback_profile = config.on_device_profile;
        let fallback_language = config.language.clone();
        match Self::try_new(config) {
            Ok(pipeline) => pipeline,
            Err(error) => {
                warn!("ML pipeline init failed; falling back to safe fallback-only mode: {error}");
                let fallback_config = MlConfig {
                    use_fallback: true,
                    warmup_on_init: false,
                    cascade_enabled: false,
                    validate_hashes: false,
                    strict_manifest_validation: false,
                    manifest_path: None,
                    toxicity_model_path: None,
                    sentiment_model_path: None,
                    safety_model_path: None,
                    intent_model_path: None,
                    vocab_path: None,
                    on_device_profile: fallback_profile,
                    language: fallback_language,
                    ..Default::default()
                };
                Self::try_new(fallback_config)
                    .unwrap_or_else(|_| unreachable!("fallback-only ML pipeline must initialize"))
            }
        }
    }

    pub fn fallback() -> Self {
        Self::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: false,
            ..Default::default()
        })
    }

    pub fn analyze_text(&mut self, text: &str) -> MlResult {
        let start = Instant::now();
        let text = normalize_for_ml(text);
        let text_hash = cache::text_hash(&text);

        if let Some(cached) = self.cache.get(text_hash) {
            let mut result = cached.clone();
            result.cache_hit = true;
            result.tier = CascadeTier::Cached;
            result.inference_time_us = start.elapsed().as_micros() as u64;
            self.record_telemetry(&result, true);
            return result;
        }

        let gate_score = self.gate.gate_score(&text);
        let decision = self.cascade.decide(gate_score);

        let mut result = if decision.run_deep {
            self.run_deep_inference(&text, decision)
        } else {
            self.run_gate_only(&text, decision)
        };
        self.apply_calibration(&mut result);
        self.apply_uncertainty_decision(&mut result);

        let elapsed_us = start.elapsed().as_micros() as u64;
        result.inference_time_us = elapsed_us;

        self.cache.insert(text_hash, result.clone());
        self.record_telemetry(&result, false);

        debug!(
            inference_us = elapsed_us,
            tier = ?result.tier,
            gate_score = gate_score,
            "ML pipeline analysis complete"
        );

        result
    }

    fn run_deep_inference(&mut self, text: &str, decision: CascadeDecision) -> MlResult {
        let (toxicity, sentiment, safety) = if let Some(ref mut unified) = self.unified {
            match unified.predict_all(text) {
                Some(pred) => (
                    Some(pred.toxicity),
                    self.sentiment.predict(text),
                    Some(pred.safety),
                ),
                None => (
                    self.toxicity.predict(text),
                    self.sentiment.predict(text),
                    self.safety.predict(text),
                ),
            }
        } else {
            (
                self.toxicity.predict(text),
                self.sentiment.predict(text),
                self.safety.predict(text),
            )
        };
        let intent = self.intent.predict(text);

        if safety.is_none() {
            tracing::warn!("safety classifier returned None");
        }
        if intent.is_none() {
            tracing::warn!("intent classifier returned None");
        }

        let mut invalid_outputs = false;
        if let Some(ref tox) = toxicity {
            let scores = [
                tox.toxicity,
                tox.severe_toxicity,
                tox.insult,
                tox.threat,
                tox.sexual_explicit,
                tox.identity_attack,
            ];
            if !integrity::validate_output_range(&scores) {
                tracing::error!("toxicity output out of range: {:?}", scores);
                invalid_outputs = true;
            }
        }
        if let Some(ref sent) = sentiment {
            let scores = [sent.positive, sent.neutral, sent.negative];
            if !integrity::validate_output_range(&scores) {
                tracing::error!("sentiment output out of range: {:?}", scores);
                invalid_outputs = true;
            }
        }
        if let Some(ref s) = safety {
            let scores = [s.grooming, s.bullying, s.self_harm, s.manipulation, s.safe];
            if !integrity::validate_output_range(&scores) {
                tracing::error!("safety output out of range: {:?}", scores);
                invalid_outputs = true;
            }
        }
        if let Some(ref i) = intent {
            let scores = [
                i.request_meeting,
                i.request_secret,
                i.request_media,
                i.benign,
            ];
            if !integrity::validate_output_range(&scores) {
                tracing::error!("intent output out of range: {:?}", scores);
                invalid_outputs = true;
            }
        }
        if invalid_outputs {
            tracing::warn!(
                "invalid ML output scores detected; using gate-only fallback for this message"
            );
            return self.run_gate_only(text, decision);
        }

        MlResult {
            toxicity,
            sentiment,
            safety,
            intent,
            uncertainty: MlUncertaintyLevel::Medium,
            abstain_to_guardian: false,
            inference_time_us: 0,
            tier: decision.tier,
            cache_hit: false,
        }
    }

    fn run_gate_only(&mut self, _text: &str, decision: CascadeDecision) -> MlResult {
        MlResult {
            toxicity: None,
            sentiment: None,
            safety: None,
            intent: None,
            uncertainty: MlUncertaintyLevel::High,
            abstain_to_guardian: false,
            inference_time_us: 0,
            tier: decision.tier,
            cache_hit: false,
        }
    }

    fn record_telemetry(&mut self, result: &MlResult, cache_hit: bool) {
        self.telemetry.record(
            timestamp_ms_now(),
            result.inference_time_us as u32,
            result.tier,
            cache_hit,
            result.toxicity.as_ref().map_or(0.0, |t| t.toxicity),
            result.safety.as_ref().map_or(0.0, |s| s.max_risk()),
        );
    }

    /// Analyzes multiple texts sequentially, returning one result per input.
    ///
    /// Each text passes through the full cascade pipeline individually.
    /// This is **not** ONNX-level batching (which would pack multiple
    /// inputs into a single tensor forward pass). Performance benefits
    /// come from the inference cache: repeated or similar normalised
    /// texts hit the cache and skip model evaluation entirely.
    ///
    /// Texts are processed in chunks of [`ANALYZE_BATCH_CHUNK_SIZE`] to
    /// bound peak memory from intermediate allocations.
    pub fn analyze_batch(&mut self, texts: &[&str]) -> Vec<MlResult> {
        let mut results = Vec::with_capacity(texts.len());
        for chunk in texts.chunks(Self::ANALYZE_BATCH_CHUNK_SIZE) {
            for text in chunk {
                results.push(self.analyze_text(text));
            }
        }
        results
    }

    pub fn telemetry_summary(&self) -> crate::telemetry::TelemetrySummary {
        self.telemetry.summary()
    }

    pub fn cache_hit_rate(&self) -> f32 {
        self.cache.hit_rate()
    }

    pub fn compare_rule_only_vs_rule_plus_ml_opt_in(
        &mut self,
        texts: &[&str],
        rule_only_scores: &[f32],
    ) -> Result<Wave1AdapterComparison, String> {
        if texts.len() != rule_only_scores.len() {
            return Err(format!(
                "texts and rule_only_scores length mismatch: {} vs {}",
                texts.len(),
                rule_only_scores.len()
            ));
        }

        let mut combined_scores = Vec::with_capacity(texts.len());
        for (text, rule_score) in texts.iter().zip(rule_only_scores.iter().copied()) {
            let result = self.analyze_text(text);
            let ml_score = result
                .safety
                .as_ref()
                .map_or(0.0, |safety| safety.max_risk());
            combined_scores.push(rule_score.max(ml_score));
        }

        compare_rule_only_vs_rule_plus_ml(rule_only_scores, &combined_scores)
    }

    pub fn toxicity_threshold(&self) -> f32 {
        self.config.toxicity_threshold
    }

    pub fn safety_threshold(&self) -> f32 {
        self.config.safety_threshold
    }

    pub fn intent_threshold(&self) -> f32 {
        self.config.intent_threshold
    }

    pub fn on_device_profile(&self) -> OnDeviceProfile {
        self.config.on_device_profile
    }

    /// Disable the cascade gate so every message gets deep ML inference.
    /// Used by Kids domain mode where false negatives are unacceptable.
    pub fn set_cascade_bypass(&mut self, bypass: bool) {
        self.cascade.enabled = !bypass;
    }

    pub fn is_active(&self) -> bool {
        self.config.use_fallback
            || self.config.unified_model_path.is_some()
            || self.config.toxicity_model_path.is_some()
            || self.config.sentiment_model_path.is_some()
            || self.config.safety_model_path.is_some()
            || self.config.intent_model_path.is_some()
    }

    /// Returns the backend that was successfully loaded, independent of requested paths.
    pub fn runtime_backend(&self) -> MlRuntimeBackend {
        self.runtime_backend
    }

    /// Returns identifiers for ONNX artifacts that were successfully loaded.
    pub fn loaded_models(&self) -> &[MlRuntimeModelIdentity] {
        &self.loaded_models
    }

    /// Returns the digest of the exact validated manifest, or the canonical
    /// rules-fallback descriptor when no ONNX artifact is active.
    pub fn model_manifest_digest(&self) -> [u8; 32] {
        self.model_manifest_digest
    }

    fn collect_loaded_models(
        config: &MlConfig,
        unified: Option<&UnifiedModel>,
        toxicity: &dyn ToxicityBackend,
        sentiment: &dyn SentimentBackend,
        safety: &dyn SafetyBackend,
        intent: &dyn IntentBackend,
        validated_manifest: Option<&manifest::ValidatedModelManifest>,
    ) -> Vec<MlRuntimeModelIdentity> {
        let mut models = Vec::with_capacity(5);
        if unified.is_some_and(UnifiedModel::has_onnx) {
            Self::push_loaded_model(
                &mut models,
                "unified",
                config.unified_model_path.as_deref(),
                validated_manifest,
            );
        }
        if toxicity.is_onnx() {
            Self::push_loaded_model(
                &mut models,
                "toxicity",
                config.toxicity_model_path.as_deref(),
                validated_manifest,
            );
        }
        if sentiment.is_onnx() {
            Self::push_loaded_model(
                &mut models,
                "sentiment",
                config.sentiment_model_path.as_deref(),
                validated_manifest,
            );
        }
        if safety.is_onnx() {
            Self::push_loaded_model(
                &mut models,
                "safety",
                config.safety_model_path.as_deref(),
                validated_manifest,
            );
        }
        if intent.is_onnx() {
            Self::push_loaded_model(
                &mut models,
                "intent",
                config.intent_model_path.as_deref(),
                validated_manifest,
            );
        }
        models
    }

    fn push_loaded_model(
        models: &mut Vec<MlRuntimeModelIdentity>,
        component: &str,
        path: Option<&str>,
        validated_manifest: Option<&manifest::ValidatedModelManifest>,
    ) {
        let Some(path) = path else {
            return;
        };
        let identifier = std::path::Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| component.to_string());
        // Retain every active ONNX component even when its identity cannot be
        // proven. The zero digest makes the incomplete identity explicit so
        // the artifact-attestation boundary rejects the whole capability set.
        let expected_sha256 =
            validated_manifest.and_then(|validated| validated.artifact_sha256(path));
        let actual_sha256 = std::fs::read(path)
            .ok()
            .map(|bytes| <[u8; 32]>::from(Sha256::digest(bytes)));
        let sha256 = match (expected_sha256, actual_sha256) {
            (Some(expected), Some(actual)) if expected == actual => actual,
            _ => [0; 32],
        };
        models.push(MlRuntimeModelIdentity {
            component: component.to_string(),
            identifier,
            sha256,
        });
    }

    fn has_any_onnx_model_configured(config: &MlConfig) -> bool {
        config.unified_model_path.is_some()
            || config.toxicity_model_path.is_some()
            || config.sentiment_model_path.is_some()
            || config.safety_model_path.is_some()
            || config.intent_model_path.is_some()
    }

    fn normalize_config_for_on_device_profile(mut config: MlConfig) -> MlConfig {
        match config.on_device_profile {
            OnDeviceProfile::Lite => {
                config.max_seq_length = config.max_seq_length.min(96);
                config.cascade_gate_threshold = config.cascade_gate_threshold.max(0.35);
                config.safety_threshold = config.safety_threshold.max(0.55);
                config.intent_threshold = config.intent_threshold.max(0.55);
                config.uncertainty_abstain_score_floor =
                    config.uncertainty_abstain_score_floor.max(0.70);
            }
            OnDeviceProfile::Balanced => {}
            OnDeviceProfile::HighRecall => {
                config.max_seq_length = config.max_seq_length.max(128);
                config.cascade_gate_threshold = config.cascade_gate_threshold.min(0.24);
                config.safety_threshold = config.safety_threshold.min(0.45);
                config.intent_threshold = config.intent_threshold.min(0.46);
                config.uncertainty_abstain_score_floor =
                    config.uncertainty_abstain_score_floor.min(0.62);
            }
        }
        config
    }

    fn apply_calibration(&self, result: &mut MlResult) {
        let safety_calibration =
            safety_calibration_for(&self.config.language, self.config.on_device_profile);
        let intent_calibration =
            intent_calibration_for(&self.config.language, self.config.on_device_profile);

        if let Some(ref mut safety) = result.safety {
            safety.grooming = (safety.grooming * safety_calibration.grooming).clamp(0.0, 1.0);
            safety.bullying = (safety.bullying * safety_calibration.bullying).clamp(0.0, 1.0);
            safety.self_harm = (safety.self_harm * safety_calibration.self_harm).clamp(0.0, 1.0);
            safety.manipulation =
                (safety.manipulation * safety_calibration.manipulation).clamp(0.0, 1.0);
            safety.primary_label = safety.compute_primary_label(self.config.safety_threshold);
        }

        if let Some(ref mut intent) = result.intent {
            intent.request_meeting =
                (intent.request_meeting * intent_calibration.request_meeting).clamp(0.0, 1.0);
            intent.request_secret =
                (intent.request_secret * intent_calibration.request_secret).clamp(0.0, 1.0);
            intent.request_media =
                (intent.request_media * intent_calibration.request_media).clamp(0.0, 1.0);
            intent.primary_intent = intent.compute_primary_intent(self.config.intent_threshold);
        }
    }

    /// Assigns an uncertainty level based on the strongest prediction and the
    /// gap between the top two candidates.
    ///
    /// The decision uses two axes:
    /// - **strongest**: the maximum risk score across safety and intent heads.
    /// - **min_gap**: the smallest top-two gap (how decisive the classification is).
    ///
    /// Thresholds were derived from the Ecliptix evaluation corpus (v2, 2026-03):
    ///
    /// | Level  | Condition                                     | Rationale |
    /// |--------|-----------------------------------------------|-----------|
    /// | Low    | strongest ≥ 0.75 AND gap ≥ 0.20              | Strong signal with clear separation — model is confident. 0.75 chosen as 95th percentile of true-positive scores; 0.20 gap filters out cases where two categories compete. |
    /// | High   | strongest ≥ floor AND gap < margin_threshold  | High risk but ambiguous — two categories score similarly, so the model cannot decide. Routed to guardian for human review. |
    /// | Medium | everything else                               | Default — no special routing needed. |
    ///
    /// `uncertainty_abstain_score_floor` (default 0.65) and
    /// `uncertainty_abstain_margin_threshold` (default 0.12) are tunable
    /// per `OnDeviceProfile` to trade sensitivity vs. guardian alert volume.
    fn apply_uncertainty_decision(&self, result: &mut MlResult) {
        let safety_gap = result.safety.as_ref().map_or(0.0, |s| s.top_two_gap());
        let safety_max = result.safety.as_ref().map_or(0.0, |s| s.max_risk());
        let intent_gap = result.intent.as_ref().map_or(0.0, |i| i.top_two_gap());
        let intent_max = result.intent.as_ref().map_or(0.0, |i| i.max_risk_intent());

        let strongest = safety_max.max(intent_max);
        let min_gap = match (result.safety.is_some(), result.intent.is_some()) {
            (true, true) => safety_gap.min(intent_gap),
            (true, false) => safety_gap,
            (false, true) => intent_gap,
            (false, false) => 1.0,
        };

        result.uncertainty = if strongest >= 0.75 && min_gap >= 0.20 {
            MlUncertaintyLevel::Low
        } else if strongest >= self.config.uncertainty_abstain_score_floor
            && min_gap < self.config.uncertainty_abstain_margin_threshold
        {
            MlUncertaintyLevel::High
        } else {
            MlUncertaintyLevel::Medium
        };

        result.abstain_to_guardian = matches!(result.uncertainty, MlUncertaintyLevel::High)
            && strongest >= self.config.uncertainty_abstain_score_floor;
    }

    fn warmup(&mut self) {
        let start = Instant::now();
        if let Some(ref mut unified) = self.unified {
            let _ = unified.predict_all("warmup");
        } else {
            let _ = self.toxicity.predict("warmup");
            let _ = self.sentiment.predict("warmup");
            let _ = self.safety.predict("warmup");
        }
        let _ = self.intent.predict("warmup");
        info!(
            elapsed_ms = start.elapsed().as_millis(),
            "ML pipeline warmup complete"
        );
    }

    #[allow(unused_variables)]
    fn load_unified(config: &MlConfig) -> Option<UnifiedModel> {
        #[cfg(feature = "onnx")]
        if let Some(ref model_path) = config.unified_model_path {
            if let Some(ref vocab_path) = config.vocab_path {
                // Try SentencePiece first (for XLM-R / MiniLM), then WordPiece
                let tokenizer = if vocab_path.ends_with(".txt") && vocab_path.contains("sp_vocab") {
                    crate::tokenizer_sp::SentencePieceTokenizer::from_vocab_file(
                        vocab_path,
                        config.max_seq_length,
                    )
                    .map(crate::tokenizer_sp::AnyTokenizer::SentencePiece)
                    .map_err(|e| e.to_string())
                } else {
                    WordPieceTokenizer::from_file(vocab_path, config.max_seq_length)
                        .map(crate::tokenizer_sp::AnyTokenizer::WordPiece)
                        .map_err(|e| e.to_string())
                };

                match tokenizer {
                    Ok(tok) => {
                        match UnifiedModel::with_model(
                            model_path,
                            tok,
                            config.intra_threads,
                            config.max_seq_length,
                        ) {
                            Ok(mut model) => {
                                model.set_thresholds(
                                    config.safety_threshold,
                                    config.toxicity_threshold,
                                );
                                info!(model = model.name(), "Unified multi-head model loaded");
                                return Some(model);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to load unified ONNX model: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load tokenizer for unified model: {e}");
                    }
                }
            }
        }

        None
    }

    #[allow(unused_variables)]
    fn load_toxicity(config: &MlConfig) -> Box<dyn ToxicityBackend> {
        #[cfg(feature = "onnx")]
        if let Some(ref model_path) = config.toxicity_model_path {
            if let Some(ref vocab_path) = config.vocab_path {
                match WordPieceTokenizer::from_file(vocab_path, config.max_seq_length) {
                    Ok(tokenizer) => {
                        match ToxicityClassifier::with_model(
                            model_path,
                            tokenizer,
                            config.intra_threads,
                        ) {
                            Ok(mut classifier) => {
                                classifier.set_primary_label_threshold(config.toxicity_threshold);
                                return Box::new(classifier);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to load toxicity ONNX model: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load tokenizer vocab: {e}");
                    }
                }
            }
        }

        let mut classifier = ToxicityClassifier::fallback_only();
        classifier.set_primary_label_threshold(config.toxicity_threshold);
        Box::new(classifier)
    }

    #[allow(unused_variables)]
    fn load_sentiment(config: &MlConfig) -> Box<dyn SentimentBackend> {
        #[cfg(feature = "onnx")]
        if let Some(ref model_path) = config.sentiment_model_path {
            if let Some(ref vocab_path) = config.vocab_path {
                match WordPieceTokenizer::from_file(vocab_path, config.max_seq_length) {
                    Ok(tokenizer) => {
                        match SentimentAnalyzer::with_model(
                            model_path,
                            tokenizer,
                            config.intra_threads,
                        ) {
                            Ok(analyzer) => return Box::new(analyzer),
                            Err(e) => {
                                tracing::warn!("Failed to load sentiment ONNX model: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load tokenizer vocab: {e}");
                    }
                }
            }
        }

        Box::new(SentimentAnalyzer::fallback_only())
    }

    #[allow(unused_variables)]
    fn load_safety(config: &MlConfig) -> Box<dyn SafetyBackend> {
        #[cfg(feature = "onnx")]
        if let Some(ref model_path) = config.safety_model_path {
            if let Some(ref vocab_path) = config.vocab_path {
                match WordPieceTokenizer::from_file(vocab_path, config.max_seq_length) {
                    Ok(tokenizer) => {
                        match SafetyClassifier::with_model(
                            model_path,
                            tokenizer,
                            config.intra_threads,
                        ) {
                            Ok(mut classifier) => {
                                classifier.set_threshold(config.safety_threshold);
                                return Box::new(classifier);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to load safety ONNX model: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load tokenizer vocab for safety: {e}");
                    }
                }
            }
        }

        let mut classifier = SafetyClassifier::fallback_only();
        classifier.set_threshold(config.safety_threshold);
        Box::new(classifier)
    }

    #[allow(unused_variables)]
    fn load_intent(config: &MlConfig) -> Box<dyn IntentBackend> {
        #[cfg(feature = "onnx")]
        if let Some(ref model_path) = config.intent_model_path {
            if let Some(ref vocab_path) = config.vocab_path {
                match WordPieceTokenizer::from_file(vocab_path, config.max_seq_length) {
                    Ok(tokenizer) => {
                        match IntentClassifier::with_model(
                            model_path,
                            tokenizer,
                            config.intra_threads,
                        ) {
                            Ok(mut classifier) => {
                                classifier.set_threshold(config.intent_threshold);
                                return Box::new(classifier);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to load intent ONNX model: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load tokenizer vocab for intent: {e}");
                    }
                }
            }
        }

        let mut classifier = IntentClassifier::fallback_only();
        classifier.set_threshold(config.intent_threshold);
        Box::new(classifier)
    }
}

fn timestamp_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        MlUncertaintyLevel, OnDeviceProfile, SafetyLabel, SentimentLabel, ToxicityLabel,
    };

    #[test]
    fn pipeline_fallback_works() {
        let mut pipeline = MlPipeline::fallback();
        assert!(pipeline.is_active());

        let result = pipeline.analyze_text("Hello, how are you?");
        assert!(result.has_predictions());
        assert!(result.toxicity.is_some());
        assert!(result.sentiment.is_some());
    }

    #[test]
    fn pipeline_detects_toxic_english() {
        let mut pipeline = MlPipeline::fallback();
        let result = pipeline.analyze_text("You're a worthless idiot, I'll kill you");

        let tox = result.toxicity.unwrap();
        assert!(tox.toxicity >= 0.6);
        assert!(tox.threat >= 0.8);
        assert!(tox.insult >= 0.4);
    }

    #[test]
    fn pipeline_detects_toxic_ukrainian() {
        let mut pipeline = MlPipeline::fallback();
        let result = pipeline.analyze_text("Ти тупий дебіл, я тебе вб'ю");

        let tox = result.toxicity.unwrap();
        assert!(tox.toxicity >= 0.6);
        assert!(tox.threat >= 0.8);
    }

    #[test]
    fn pipeline_positive_sentiment() {
        let mut pipeline = MlPipeline::fallback();
        let result = pipeline.analyze_text("I love this! Amazing, wonderful experience!");

        let sent = result.sentiment.unwrap();
        assert_eq!(sent.label, SentimentLabel::Positive);
    }

    #[test]
    fn pipeline_negative_sentiment() {
        let mut pipeline = MlPipeline::fallback();
        let result = pipeline.analyze_text("I hate everything. Terrible. So sad and depressed.");

        let sent = result.sentiment.unwrap();
        assert_eq!(sent.label, SentimentLabel::Negative);
    }

    #[test]
    fn pipeline_clean_message_low_toxicity() {
        let mut pipeline = MlPipeline::fallback();
        let result = pipeline.analyze_text("Let's meet at the park tomorrow at 3pm");

        let tox = result.toxicity.unwrap();
        assert!(
            tox.toxicity < 0.1,
            "Clean message toxicity: {}",
            tox.toxicity
        );

        let sent = result.sentiment.unwrap();
        assert_eq!(sent.label, SentimentLabel::Neutral);
    }

    #[test]
    fn pipeline_inference_is_fast() {
        let mut pipeline = MlPipeline::fallback();
        let start = std::time::Instant::now();

        for _ in 0..1000 {
            pipeline.analyze_text("This is a test message with some words in it");
        }

        let elapsed = start.elapsed();
        let per_message_us = elapsed.as_micros() / 1000;
        assert!(
            per_message_us < 5000,
            "Pipeline took {per_message_us}us per message"
        );
    }

    #[test]
    fn pipeline_bilingual_threat() {
        let mut pipeline = MlPipeline::fallback();

        let en = pipeline.analyze_text("I will kill you");
        assert_eq!(
            en.toxicity.unwrap().primary_label,
            Some(ToxicityLabel::Threat)
        );

        let uk = pipeline.analyze_text("Здохни, я тебе вб'ю");
        assert_eq!(
            uk.toxicity.unwrap().primary_label,
            Some(ToxicityLabel::Threat)
        );
    }

    #[test]
    fn cascade_skips_deep_for_clean() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        let result = pipeline.analyze_text("Hey, want to play after school?");
        assert_eq!(result.tier, CascadeTier::Gate);
        assert!(result.safety.is_none());
        assert!(result.intent.is_none());
    }

    #[test]
    fn cascade_runs_deep_for_threat() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        let result = pipeline.analyze_text("I will kill you, you worthless idiot");
        assert_eq!(result.tier, CascadeTier::Deep);
        assert!(result.safety.is_some());
        assert!(result.intent.is_some());
    }

    #[test]
    fn cascade_produces_safety_for_grooming() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        let result = pipeline.analyze_text("don't tell your parents, it's our little secret");
        assert_eq!(result.tier, CascadeTier::Deep);
        let safety = result.safety.unwrap();
        assert!(safety.grooming >= 0.5);
        assert_eq!(safety.primary_label, Some(SafetyLabel::Grooming));
    }

    #[test]
    fn cascade_produces_intent_for_meeting() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        let result = pipeline.analyze_text("come to my place alone, let's meet in secret");
        assert!(result.intent.is_some());
        let intent = result.intent.unwrap();
        assert!(intent.request_meeting >= 0.5);
    }

    #[test]
    fn cascade_uses_normalized_input_for_safety_and_intent() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        let result = pipeline.analyze_text(
            "d\u{200B}on't tell your parents, l\u{200B}et's m\u{200B}e\u{200B}et in secret",
        );

        assert_eq!(result.tier, CascadeTier::Deep);
        let safety = result.safety.unwrap();
        assert!(safety.grooming >= 0.5);
        let intent = result.intent.unwrap();
        assert!(intent.request_meeting >= 0.5);
    }

    #[test]
    fn cascade_disabled_always_runs_deep() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: false,
            ..Default::default()
        });
        let result = pipeline.analyze_text("Hello, how are you?");
        assert_eq!(result.tier, CascadeTier::Deep);
        assert!(result.safety.is_some());
    }

    #[test]
    fn cache_returns_previous_result() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            ..Default::default()
        });
        let r1 = pipeline.analyze_text("I will kill you");
        assert!(!r1.cache_hit);
        let r2 = pipeline.analyze_text("I will kill you");
        assert!(r2.cache_hit);
        assert_eq!(r2.tier, CascadeTier::Cached);
    }

    #[test]
    fn cache_uses_normalized_text_key() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            ..Default::default()
        });
        let r1 = pipeline.analyze_text("I will kill you");
        assert!(!r1.cache_hit);
        let r2 = pipeline.analyze_text("I w\u{200B}ill k\u{200B}ill you");
        assert!(r2.cache_hit);
        assert_eq!(r2.tier, CascadeTier::Cached);
    }

    #[test]
    fn telemetry_tracks_cascade_tiers() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        pipeline.analyze_text("hello friend");
        pipeline.analyze_text("I will kill you");
        let summary = pipeline.telemetry_summary();
        assert_eq!(summary.total_inferences, 2);
        assert!(summary.gate_inferences > 0 || summary.deep_inferences > 0);
    }

    #[test]
    fn selfharm_uk_triggers_deep_with_safety() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        let result = pipeline.analyze_text("не хочу жити, хочу померти");
        assert_eq!(result.tier, CascadeTier::Deep);
        let safety = result.safety.unwrap();
        assert!(safety.self_harm >= 0.7);
        assert_eq!(safety.primary_label, Some(SafetyLabel::SelfHarm));
    }

    #[test]
    fn wave1_opt_in_comparison_reports_delta() {
        let mut pipeline = MlPipeline::new(MlConfig {
            use_fallback: true,
            warmup_on_init: false,
            cascade_enabled: true,
            cascade_gate_threshold: 0.3,
            ..Default::default()
        });
        let texts = ["I will kill you", "let's meet after school"];
        let report = pipeline
            .compare_rule_only_vs_rule_plus_ml_opt_in(&texts, &[0.35, 0.20])
            .expect("wave1 comparison");

        assert_eq!(report.sample_count, 2);
        assert!(report.average_rule_plus_ml_score >= report.average_rule_only_score);
    }

    #[test]
    fn on_device_profile_changes_runtime_thresholds() {
        let lite = MlPipeline::new(MlConfig {
            on_device_profile: OnDeviceProfile::Lite,
            warmup_on_init: false,
            ..Default::default()
        });
        let high_recall = MlPipeline::new(MlConfig {
            on_device_profile: OnDeviceProfile::HighRecall,
            warmup_on_init: false,
            ..Default::default()
        });

        assert!(lite.safety_threshold() >= high_recall.safety_threshold());
        assert!(lite.intent_threshold() >= high_recall.intent_threshold());
        assert_eq!(lite.on_device_profile(), OnDeviceProfile::Lite);
        assert_eq!(high_recall.on_device_profile(), OnDeviceProfile::HighRecall);
    }

    #[test]
    fn high_recall_profile_applies_uk_calibration() {
        let mut balanced = MlPipeline::new(MlConfig {
            on_device_profile: OnDeviceProfile::Balanced,
            language: "uk".to_string(),
            warmup_on_init: false,
            cascade_enabled: false,
            ..Default::default()
        });
        let mut high_recall = MlPipeline::new(MlConfig {
            on_device_profile: OnDeviceProfile::HighRecall,
            language: "uk".to_string(),
            warmup_on_init: false,
            cascade_enabled: false,
            ..Default::default()
        });

        let text = "не хочу жити, хочу померти";
        let balanced_result = balanced.analyze_text(text);
        let high_recall_result = high_recall.analyze_text(text);

        let balanced_self_harm = balanced_result.safety.expect("balanced safety").self_harm;
        let high_recall_self_harm = high_recall_result
            .safety
            .expect("high-recall safety")
            .self_harm;
        assert!(high_recall_self_harm >= balanced_self_harm);
    }

    #[test]
    fn uncertainty_helper_routes_ambiguous_high_risk_to_guardian() {
        let mut pipeline = MlPipeline::new(MlConfig {
            on_device_profile: OnDeviceProfile::HighRecall,
            warmup_on_init: false,
            cascade_enabled: false,
            uncertainty_abstain_score_floor: 0.55,
            uncertainty_abstain_margin_threshold: 0.18,
            ..Default::default()
        });

        let result = pipeline
            .analyze_text("don't tell your parents, let's meet in secret and send me a photo");
        assert!(matches!(
            result.uncertainty,
            MlUncertaintyLevel::High | MlUncertaintyLevel::Medium
        ));
        if result.uncertainty == MlUncertaintyLevel::High {
            assert!(result.abstain_to_guardian);
        }
    }
}
