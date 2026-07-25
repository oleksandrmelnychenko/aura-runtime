#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

artifact_dir="${AURA_REFACTOR_ARTIFACT_DIR:-artifacts/refactor}"
performance_dir="$artifact_dir/performance"
baseline_path="${AURA_REFACTOR_BASELINE_PATH:-crates/aura-core/data/refactor_baseline_v1.json}"
approvals_path="${AURA_REFACTOR_APPROVALS_PATH:-docs/refactor-diff-approvals.json}"
performance_tiers="${AURA_REFACTOR_PERF_TIERS:-10k}"

mkdir -p "$artifact_dir" "$performance_dir"

contract_report="$artifact_dir/contract-evidence.json"
release_report="$artifact_dir/release-report.json"
pilot_report="$artifact_dir/pilot-regression-report.json"
lifecycle_report="$artifact_dir/world-lifecycle-suite-report.json"
performance_report="$performance_dir/world-performance-summary.json"
candidate_snapshot="$artifact_dir/refactor-candidate.json"
diff_report="$artifact_dir/refactor-diff-report.json"

cargo run --quiet --locked --example contract_evidence -p aura-core -- \
  --output "$contract_report"
cargo run --quiet --locked --example release_report -p aura-core -- \
  --output "$release_report" \
  --require-pass
cargo run --quiet --locked --example pilot_regression -p aura-core -- \
  --output "$pilot_report" \
  --require-pass
cargo run --quiet --locked --example world_sim -p aura-core -- \
  --input crates/aura-core/data/world_lifecycle_suite \
  --summary-only \
  --output "$lifecycle_report" \
  --redact-text \
  --require-clean

AURA_PERF_TIERS="$performance_tiers" \
AURA_PERF_ARTIFACT_DIR="$performance_dir" \
  python3 ci/world_performance_gate.py

python3 ci/refactor_baseline.py snapshot \
  --output "$candidate_snapshot" \
  --baseline-id "local-$(git rev-parse --short=12 HEAD)" \
  --contract-evidence "$contract_report" \
  --release-report "$release_report" \
  --pilot-regression-report "$pilot_report" \
  --world-lifecycle-report "$lifecycle_report" \
  --world-performance-report "$performance_report"

compare_args=(
  --baseline "$baseline_path"
  --candidate "$candidate_snapshot"
  --output "$diff_report"
  --require-pass
)
if [[ -f "$approvals_path" ]]; then
  compare_args+=(--approvals "$approvals_path")
fi
python3 ci/refactor_baseline.py compare "${compare_args[@]}"

echo "AURA Core refactor baseline gate passed: $diff_report"
