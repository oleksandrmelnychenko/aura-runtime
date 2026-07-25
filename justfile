set shell := ["pwsh", "-NoLogo", "-Command"]

verify:
    cargo run --quiet --example release_report -p aura-core -- --require-pass
    cargo run --quiet --example pilot_regression -p aura-core -- --require-pass

verify-full:
    cargo test --workspace --all-features --all-targets

verify-onnx:
    $env:AURA_RUN_SAFETY_INTENT_ONNX="1"; cargo test -p aura-ml --features onnx --test onnx_integration

kids-memory-health:
    python3 ci/kids_memory_health_snapshot.py --input artifacts/pilot-regression-report.json --input artifacts/pilot-shadow-run-a.json --input artifacts/pilot-shadow-run-b.json --output artifacts/kids-memory-health.json

kids-preprod-dry-run:
    python3 ci/kids_preprod_dry_run_matrix.py --policy-expectations crates/aura-core/data/action_policy_expectations.json --realistic-cases crates/aura-core/data/realistic_chat_cases.json --kids-memory-health artifacts/kids-memory-health.json --output artifacts/kids-preprod-dry-run-matrix.json

safety-world-v2-smoke:
    bash ci/safety_world_v2_smoke.sh

world-lifecycle-gate:
    bash ci/world_lifecycle_gate.sh

ffi-world-replay-gate:
    bash ci/ffi_world_replay_gate.sh

client-boundary-replay-gate:
    bash ci/client_boundary_replay_gate.sh

world-performance-gate:
    bash ci/world_performance_gate.sh

refactor-baseline-gate:
    bash ci/refactor_baseline_gate.sh

apple-artifact-build-local:
    $env:AURA_APPLE_DIST_DIR="artifacts/apple-local"; $env:ALLOW_DIRTY_SOURCE="1"; $env:AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH="dist/apple/execution-policy-trust-keyring.json"; bash scripts/release/build-apple-xcframework.sh
    python3 ci/apple_artifact.py verify --root . --dist-dir artifacts/apple-local --output artifacts/apple-local-verification.json

apple-artifact-build-release:
    $env:AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH="dist/apple/execution-policy-trust-keyring.json"; bash scripts/release/build-apple-xcframework.sh
    python3 ci/apple_artifact.py verify --root . --dist-dir dist/apple --output artifacts/apple-release-verification.json --require-clean-source

apple-artifact-verify-release:
    python3 ci/apple_artifact.py verify --root . --dist-dir dist/apple --output artifacts/apple-release-verification.json --require-clean-source

kids-memory-health-strict:
    cargo run --quiet --example world_sim -p aura-core -- --input crates/aura-core/data/world_sim_kids_memory_stress.json --summary-only --shadow-output artifacts/kids-memory-shadow-run-a.json --require-clean
    cargo run --quiet --example world_sim -p aura-core -- --input crates/aura-core/data/world_sim_kids_memory_stress.json --summary-only --shadow-output artifacts/kids-memory-shadow-run-b.json --require-clean
    cargo run --quiet --example world_sim -p aura-core -- --input crates/aura-core/data/world_lifecycle_suite/kateryna_16_recruitment_pressure_9mo.json --summary-only --shadow-output artifacts/pilot-shadow-run-a.json --require-clean
    cargo run --quiet --example world_sim -p aura-core -- --input crates/aura-core/data/world_lifecycle_suite/kateryna_16_recruitment_pressure_9mo.json --summary-only --shadow-output artifacts/pilot-shadow-run-b.json --require-clean
    cargo run --quiet --example pilot_regression -p aura-core -- --output artifacts/pilot-regression-report.json --require-pass
    python3 ci/kids_memory_health_snapshot.py --input artifacts/pilot-regression-report.json --input artifacts/kids-memory-shadow-run-a.json --input artifacts/kids-memory-shadow-run-b.json --output artifacts/kids-memory-health.json --require-mandatory-reasons
    python3 ci/kids_preprod_dry_run_matrix.py --policy-expectations crates/aura-core/data/action_policy_expectations.json --realistic-cases crates/aura-core/data/realistic_chat_cases.json --kids-memory-health artifacts/kids-memory-health.json --output artifacts/kids-preprod-dry-run-matrix.json

pilot-gate-strict:
    cargo run --example pilot_gate -p aura-core -- --release-report artifacts/release-report.json --pilot-regression-report artifacts/pilot-regression-report.json --shadow-bundle artifacts/pilot-shadow-run-a.json --shadow-bundle artifacts/pilot-shadow-run-b.json --review-signoffs docs/pilot-review-signoffs.json --kids-memory-health-report artifacts/kids-memory-health.json --kids-preprod-dry-run-report artifacts/kids-preprod-dry-run-matrix.json --output artifacts/pilot-gate-report.json --require-kids-memory-pass --require-kids-preprod-dry-run-pass --require-pass
