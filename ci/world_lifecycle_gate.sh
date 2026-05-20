#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python_bin="${PYTHON:-python3}"
artifact_dir="${AURA_LIFECYCLE_ARTIFACT_DIR:-artifacts}"
repeat_multiplier="${AURA_LIFECYCLE_REPEAT_MULTIPLIER:-1}"
min_labeled_recall="${AURA_LIFECYCLE_MIN_RECALL:-0.95}"
max_clean_fp_rate="${AURA_LIFECYCLE_MAX_CLEAN_FP_RATE:-0.01}"
min_dense_events="${AURA_LIFECYCLE_MIN_DENSE_EVENTS:-6000}"
min_suite_events="${AURA_LIFECYCLE_MIN_SUITE_EVENTS:-19000}"
min_suite_worlds="${AURA_LIFECYCLE_MIN_SUITE_WORLDS:-11}"

mkdir -p "$artifact_dir"

dense_input="crates/aura-core/data/world_lifecycle_suite/sofia_13_to_15_dense_2y.json"
suite_input="crates/aura-core/data/world_lifecycle_suite"
dense_report="$artifact_dir/world-lifecycle-dense-2y-report.json"
suite_report="$artifact_dir/world-lifecycle-suite-report.json"

cargo run -p aura-core --example world_sim -- \
  --input "$dense_input" \
  --summary-only \
  --output "$dense_report" \
  --redact-text \
  --require-clean \
  --min-labeled-recall "$min_labeled_recall" \
  --max-clean-fp-rate "$max_clean_fp_rate" \
  --repeat-multiplier "$repeat_multiplier"

cargo run -p aura-core --example world_sim -- \
  --input "$suite_input" \
  --summary-only \
  --output "$suite_report" \
  --redact-text \
  --require-clean \
  --min-labeled-recall "$min_labeled_recall" \
  --max-clean-fp-rate "$max_clean_fp_rate" \
  --repeat-multiplier "$repeat_multiplier"

"$python_bin" - \
  "$dense_report" \
  "$suite_report" \
  "$min_dense_events" \
  "$min_suite_events" \
  "$min_suite_worlds" \
  "$min_labeled_recall" \
  "$max_clean_fp_rate" <<'PY'
import json
import sys
from pathlib import Path

dense_path = Path(sys.argv[1])
suite_path = Path(sys.argv[2])
min_dense_events = int(sys.argv[3])
min_suite_events = int(sys.argv[4])
min_suite_worlds = int(sys.argv[5])
min_labeled_recall = float(sys.argv[6])
max_clean_fp_rate = float(sys.argv[7])


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def check_redacted_text(value, path="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "text":
                require(child == "[redacted]", f"{path}.text was not redacted")
            else:
                check_redacted_text(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            check_redacted_text(child, f"{path}[{index}]")


def check_metrics(report, label):
    overall = report.get("metrics", {}).get("overall", {})
    positives = overall.get("labeled_positive_events", 0)
    clean = overall.get("labeled_clean_events", 0)
    recall = overall.get("positive_recall")
    clean_fp = overall.get("clean_false_positive_rate")

    require(positives > 0, f"{label}: no labeled positive events")
    require(clean > 0, f"{label}: no labeled clean events")
    require(recall is not None, f"{label}: missing positive_recall")
    require(clean_fp is not None, f"{label}: missing clean_false_positive_rate")
    require(
        recall >= min_labeled_recall,
        f"{label}: recall {recall:.4f} below {min_labeled_recall:.4f}",
    )
    require(
        clean_fp <= max_clean_fp_rate,
        f"{label}: clean FP {clean_fp:.4f} above {max_clean_fp_rate:.4f}",
    )


dense = load(dense_path)
suite = load(suite_path)

require(dense.get("schema_version") == "world_sim.v1", "dense report schema mismatch")
require(suite.get("schema_version") == "world_suite.v1", "suite report schema mismatch")
require(dense.get("total_events", 0) >= min_dense_events, "dense report below event floor")
require(suite.get("total_events", 0) >= min_suite_events, "suite report below event floor")
require(suite.get("total_worlds", 0) >= min_suite_worlds, "suite report below world floor")
require(not dense.get("findings"), "dense report has findings")
require(suite.get("total_findings", 0) == 0, "suite report has findings")

check_metrics(dense, "dense")
check_metrics(suite, "suite")
check_redacted_text(dense)
check_redacted_text(suite)

print(
    "Lifecycle gate passed: "
    f"dense_events={dense['total_events']} "
    f"suite_worlds={suite['total_worlds']} "
    f"suite_events={suite['total_events']}"
)
PY
