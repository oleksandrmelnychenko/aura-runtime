#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

output_path="${AURA_TEMPORAL_SHADOW_REPORT_PATH:-artifacts/temporal-shadow-report.json}"

cargo run --quiet --locked -p aura-military --features evaluation \
  --example temporal_shadow_eval -- \
  --output "$output_path" \
  --require-pass

echo "AURA military temporal Shadow gate passed: $output_path"
