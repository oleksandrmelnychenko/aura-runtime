set shell := ["pwsh", "-NoLogo", "-Command"]

verify:
    cargo run --quiet --example release_report -p aura-core -- --require-pass
    cargo run --quiet --example pilot_regression -p aura-core -- --require-pass

verify-full:
    cargo test --workspace --all-features --all-targets

verify-onnx:
    $env:AURA_RUN_SAFETY_INTENT_ONNX="1"; cargo test -p aura-ml --features onnx --test onnx_integration
