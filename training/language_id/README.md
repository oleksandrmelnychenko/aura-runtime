# Client language-ID shadow pipeline

This directory builds a development-only, abstaining language-ID ensemble. It
does not approve production candidate or span emission.

The pipeline uses the local `textdetox_multilingual` Arrow snapshot with
English, Ukrainian, Russian, and Tatar. Tatar is an unsupported Cyrillic
control; it is not a governed detector language.

## Reproduce

Use a staging directory. The bundle builder refuses to replace an existing
output so a generated artifact cannot silently overwrite the reviewed one.

```bash
AURA_LID_WORK="$(mktemp -d /tmp/aura-language-id.XXXXXX)"
python3 -m pip install \
  --target "$AURA_LID_WORK/python" \
  -r training/language_id/requirements.txt
PYTHONPATH="$AURA_LID_WORK/python" \
  python3 training/language_id/prepare_textdetox_language_id.py \
  --source-root data/raw/hf/textdetox_multilingual \
  --output-dir "$AURA_LID_WORK/data"
python3 training/language_id/train_hashed_ngram.py \
  --input-dir "$AURA_LID_WORK/data" \
  --output-model "$AURA_LID_WORK/AuraLanguageIDNGramV1.bin" \
  --output-metrics "$AURA_LID_WORK/ngram-metrics.json"
xcrun swift training/language_id/train_coreml_language_id.swift \
  "$AURA_LID_WORK/data" \
  "$AURA_LID_WORK/AuraAbstainingLanguageID.mlmodel" \
  "$AURA_LID_WORK/coreml-metrics.json"
python3 training/language_id/build_shadow_bundle.py \
  --coreml-model "$AURA_LID_WORK/AuraAbstainingLanguageID.mlmodel" \
  --ngram-model "$AURA_LID_WORK/AuraLanguageIDNGramV1.bin" \
  --dataset-summary "$AURA_LID_WORK/data/dataset-summary.json" \
  --coreml-metrics "$AURA_LID_WORK/coreml-metrics.json" \
  --ngram-metrics "$AURA_LID_WORK/ngram-metrics.json" \
  --output-dir "$AURA_LID_WORK/LanguageID"
```

Review the generated model, metrics, manifest, and all artifact hashes before
changing the source-pinned manifest digest. Never point the builder directly at
the committed resource directory during routine experimentation.

The reviewed shadow bundle belongs only under
`swift/Tests/AuraAgentTests/Resources/LanguageID`. Adding it to
`swift/Sources/AuraAgent`, or adding production target resources in
`Package.swift`, is a release-blocking isolation failure.

## Evidence boundary

The deterministic split prevents train/calibration/test overlap inside this
snapshot. It does not make the test set independent. Production promotion still
requires source-license approval, native-speaker adjudication, broader
unsupported-language controls, physical-device profiling, and a separately
governed release decision.
