#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

output_path="${AURA_TEMPORAL_SHADOW_REPORT_PATH:-artifacts/temporal-shadow-report.json}"
telemetry_output_path="${AURA_TEMPORAL_SHADOW_TELEMETRY_VALIDATION_PATH:-artifacts/temporal-shadow-telemetry-validation.json}"

cargo run --quiet --locked -p aura-military --features evaluation \
  --example temporal_shadow_eval -- \
  --output "$output_path" \
  --require-pass

cargo run --quiet --locked -p aura-military --features evaluation \
  --example temporal_shadow_telemetry_validation -- \
  --output "$telemetry_output_path" \
  --require-pass

echo "AURA military temporal Shadow gate passed: $output_path"
echo "AURA military temporal Shadow telemetry validation passed: $telemetry_output_path"
