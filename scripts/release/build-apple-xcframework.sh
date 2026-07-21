#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="$ROOT/dist/apple"
INCLUDE_DIR="$ROOT/target/include/aura-agent-ffi"
PROFILE="${PROFILE:-release}"
CARGO_PROFILE_FLAG=("--release")
CARGO_FEATURE_NAME=""
SOURCE_REVISION="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_TREE_DIRTY=false

if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=normal)" ]]; then
  SOURCE_TREE_DIRTY=true
fi

if [[ "$PROFILE" == "release" && "$SOURCE_TREE_DIRTY" == "true" && "${ALLOW_DIRTY_SOURCE:-0}" != "1" ]]; then
  echo "Refusing to build a release XCFramework from a dirty source tree." >&2
  echo "Commit the reviewed source or set ALLOW_DIRTY_SOURCE=1 for a non-shippable local artifact." >&2
  exit 2
fi

case "${AURA_AGENT_ONNX:-0}" in
  0) ;;
  1) CARGO_FEATURE_NAME="onnx" ;;
  *)
    echo "AURA_AGENT_ONNX must be 0 or 1" >&2
    exit 2
    ;;
esac

if [[ "$PROFILE" != "release" ]]; then
  CARGO_PROFILE_FLAG=("--profile" "$PROFILE")
fi

mkdir -p "$DIST_DIR" "$INCLUDE_DIR"
cp "$ROOT/include/aura_ffi.h" "$INCLUDE_DIR/aura_ffi.h"
cp "$ROOT/include/module.modulemap" "$INCLUDE_DIR/module.modulemap"

HEADER_SHA256="$(shasum -a 256 "$ROOT/include/aura_ffi.h" | awk '{print $1}')"
FEATURES_JSON="[]"
if [[ "${AURA_AGENT_ONNX:-0}" == "1" ]]; then
  FEATURES_JSON='["onnx"]'
fi

if [[ -z "${AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH:-}" ]]; then
  echo "AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH is required for an Apple artifact." >&2
  exit 2
fi
if [[ ! -f "$AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH" ]]; then
  echo "Execution-policy trust keyring does not exist: $AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH" >&2
  exit 2
fi
if [[ ! -s "$AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH" ]]; then
  echo "Execution-policy trust keyring must not be empty." >&2
  exit 2
fi
export AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH
export AURA_EXECUTION_POLICY_TRUST_KEYRING_SHA256
AURA_EXECUTION_POLICY_TRUST_KEYRING_SHA256="$(shasum -a 256 "$AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH" | awk '{print $1}')"
cp "$AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH" "$DIST_DIR/execution-policy-trust-keyring.json"

identity_args=(
  run
  --quiet
  --locked
  --release
  -p aura-agent-ffi
  --bin aura-agent-release-identity
  --manifest-path "$ROOT/Cargo.toml"
)
if [[ -n "$CARGO_FEATURE_NAME" ]]; then
  identity_args+=(--features "$CARGO_FEATURE_NAME")
fi
read -r RUNTIME_CAPABILITIES_SHA256 MODEL_MANIFEST_SHA256 < <(
  cargo "${identity_args[@]}"
)
if [[ ! "$RUNTIME_CAPABILITIES_SHA256" =~ ^[0-9a-f]{64}$ \
  || "$RUNTIME_CAPABILITIES_SHA256" == "0000000000000000000000000000000000000000000000000000000000000000" \
  || ! "$MODEL_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ \
  || "$MODEL_MANIFEST_SHA256" == "0000000000000000000000000000000000000000000000000000000000000000" ]]; then
  echo "Aura release identity emitter returned malformed artifact digests." >&2
  exit 2
fi

cat >"$DIST_DIR/runtime-artifact-descriptor.json" <<JSON
{
  "schema_version": 2,
  "source_revision": "$SOURCE_REVISION",
  "source_tree_dirty": $SOURCE_TREE_DIRTY,
  "cargo_profile": "$PROFILE",
  "cargo_features": $FEATURES_JSON,
  "ffi_contract_version": 1,
  "aura_ffi_header_sha256": "$HEADER_SHA256",
  "runtime_capabilities_sha256": "$RUNTIME_CAPABILITIES_SHA256",
  "model_manifest_sha256": "$MODEL_MANIFEST_SHA256",
  "execution_policy_trust_keyring_sha256": "$AURA_EXECUTION_POLICY_TRUST_KEYRING_SHA256"
}
JSON
export AURA_RELEASE_ARTIFACT_DESCRIPTOR_SHA256
AURA_RELEASE_ARTIFACT_DESCRIPTOR_SHA256="$(shasum -a 256 "$DIST_DIR/runtime-artifact-descriptor.json" | awk '{print $1}')"
RUNTIME_CAPABILITIES_SHA256_B64="$(printf '%s' "$RUNTIME_CAPABILITIES_SHA256" | xxd -r -p | openssl base64 -A)"
MODEL_MANIFEST_SHA256_B64="$(printf '%s' "$MODEL_MANIFEST_SHA256" | xxd -r -p | openssl base64 -A)"
RELEASE_ARTIFACT_DESCRIPTOR_SHA256_B64="$(printf '%s' "$AURA_RELEASE_ARTIFACT_DESCRIPTOR_SHA256" | xxd -r -p | openssl base64 -A)"
cat >"$DIST_DIR/runtime-artifact-identities.env" <<ENV
AURA_RUNTIME_CAPABILITIES_SHA256_B64=$RUNTIME_CAPABILITIES_SHA256_B64
AURA_MODEL_MANIFEST_SHA256_B64=$MODEL_MANIFEST_SHA256_B64
AURA_RELEASE_ARTIFACT_DESCRIPTOR_SHA256_B64=$RELEASE_ARTIFACT_DESCRIPTOR_SHA256_B64
ENV
RUNTIME_ARTIFACT_IDENTITIES_ENV_SHA256="$(shasum -a 256 "$DIST_DIR/runtime-artifact-identities.env" | awk '{print $1}')"

targets=(
  aarch64-apple-ios
  aarch64-apple-ios-sim
  x86_64-apple-ios
  aarch64-apple-ios-macabi
  x86_64-apple-ios-macabi
)

for target in "${targets[@]}"; do
  rustup target add "$target" >/dev/null
  cargo_args=(
    "${CARGO_PROFILE_FLAG[@]}"
    --locked
    -p aura-agent-ffi
    --lib
    --target "$target"
    --manifest-path "$ROOT/Cargo.toml"
  )
  if [[ -n "$CARGO_FEATURE_NAME" ]]; then
    cargo_args+=(--features "$CARGO_FEATURE_NAME")
  fi
  cargo build "${cargo_args[@]}"
done

profile_dir="$PROFILE"
if [[ "$PROFILE" == "release" ]]; then
  profile_dir="release"
fi

SIM_LIB="$DIST_DIR/libaura_agent_ffi_ios_sim.a"
MACABI_LIB="$DIST_DIR/libaura_agent_ffi_maccatalyst.a"

lipo -create \
  "$ROOT/target/aarch64-apple-ios-sim/$profile_dir/libaura_agent_ffi.a" \
  "$ROOT/target/x86_64-apple-ios/$profile_dir/libaura_agent_ffi.a" \
  -output "$SIM_LIB"

lipo -create \
  "$ROOT/target/aarch64-apple-ios-macabi/$profile_dir/libaura_agent_ffi.a" \
  "$ROOT/target/x86_64-apple-ios-macabi/$profile_dir/libaura_agent_ffi.a" \
  -output "$MACABI_LIB"

required_symbols=(
  _aura_agent_init
  _aura_agent_version
  _aura_attest_runtime_artifacts
  _aura_apply_execution_policy
  _aura_analyze_canonical_safety
  _aura_apply_safety_case_lifecycle
  _aura_activate_safety_case_successor
  _aura_remove_safety_case_account
  _aura_export_guardian_report_snapshot
  _aura_export_guardian_report_account_snapshot
  _aura_flush_deferred_guardian_report
  _aura_confirm_guardian_report_prepared
  _aura_suppress_guardian_report
  _aura_acknowledge_guardian_report
  _aura_export_context
  _aura_import_context
  _aura_export_safety_case_state
  _aura_import_safety_case_state
  _aura_last_error
  _aura_free
  _aura_free_string
  _aura_free_buffer
)

forbidden_symbols=(
  _aura_analyze
  _aura_analyze_context
  _aura_analyze_batch
  _aura_build_shadow_bundle
  _aura_update_config
  _aura_reload_patterns
  _aura_cleanup_context
  _aura_get_contacts_by_risk
  _aura_get_contact_profile
  _aura_mark_contact_trusted
  _aura_quick_check
  _aura_detect_suspicious_url
  _aura_get_conversation_summary
  _aura_get_runtime_capabilities
  _aura_analyze_for_relay
  _aura_record_relay_response
  _aura_guardian_feedback
)

verify_archive_symbols() {
  local archive="$1"
  local symbols
  # Newer Rust toolchains can emit LLVM attributes in compiler_builtins archive
  # members that the Apple nm bundled with the current Xcode cannot decode yet.
  # Keep the symbols it can read; the explicit allow/deny checks below still
  # fail closed if the Aura FFI object itself cannot be inspected.
  symbols="$({ xcrun nm -gU "$archive" 2>/dev/null || true; } | awk '{print $NF}')"

  for symbol in "${required_symbols[@]}"; do
    if ! grep -Fqx "$symbol" <<<"$symbols"; then
      echo "Missing required symbol $symbol in $archive" >&2
      exit 1
    fi
  done

  for symbol in "${forbidden_symbols[@]}"; do
    if grep -Fqx "$symbol" <<<"$symbols"; then
      echo "Forbidden legacy symbol $symbol is still exported by $archive" >&2
      exit 1
    fi
  done

  while IFS= read -r symbol; do
    [[ -z "$symbol" ]] && continue
    if ! printf '%s\n' "${required_symbols[@]}" | grep -Fqx "$symbol"; then
      echo "Unexpected Aura symbol $symbol is exported by $archive" >&2
      exit 1
    fi
  done < <(grep '^_aura_' <<<"$symbols" || true)
}

verify_archive_symbols "$ROOT/target/aarch64-apple-ios/$profile_dir/libaura_agent_ffi.a"
verify_archive_symbols "$SIM_LIB"
verify_archive_symbols "$MACABI_LIB"

rm -rf "$DIST_DIR/AuraAgentFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$ROOT/target/aarch64-apple-ios/$profile_dir/libaura_agent_ffi.a" -headers "$INCLUDE_DIR" \
  -library "$SIM_LIB" -headers "$INCLUDE_DIR" \
  -library "$MACABI_LIB" -headers "$INCLUDE_DIR" \
  -output "$DIST_DIR/AuraAgentFFI.xcframework"

# The Swift wrapper links by symbol name and does not import this C module.
# Removing nested module maps avoids ProcessXCFramework collisions with other
# local binary packages that also ship module.modulemap.
find "$DIST_DIR/AuraAgentFFI.xcframework" -name module.modulemap -delete

while IFS= read -r packaged_header; do
  if ! cmp -s "$ROOT/include/aura_ffi.h" "$packaged_header"; then
    echo "Packaged header does not match reviewed source header: $packaged_header" >&2
    exit 1
  fi
done < <(find "$DIST_DIR/AuraAgentFFI.xcframework" -path '*/Headers/aura_ffi.h' -type f -print)

HEADER_COUNT="$(find "$DIST_DIR/AuraAgentFFI.xcframework" -path '*/Headers/aura_ffi.h' -type f | wc -l | tr -d ' ')"
if [[ "$HEADER_COUNT" != "3" ]]; then
  echo "Expected 3 packaged aura_ffi.h copies, found $HEADER_COUNT" >&2
  exit 1
fi

INFO_SHA256="$(shasum -a 256 "$DIST_DIR/AuraAgentFFI.xcframework/Info.plist" | awk '{print $1}')"
IOS_LIBRARY_SHA256="$(shasum -a 256 "$DIST_DIR/AuraAgentFFI.xcframework/ios-arm64/libaura_agent_ffi.a" | awk '{print $1}')"
SIMULATOR_LIBRARY_SHA256="$(shasum -a 256 "$DIST_DIR/AuraAgentFFI.xcframework/ios-arm64_x86_64-simulator/libaura_agent_ffi_ios_sim.a" | awk '{print $1}')"
MACCATALYST_LIBRARY_SHA256="$(shasum -a 256 "$DIST_DIR/AuraAgentFFI.xcframework/ios-arm64_x86_64-maccatalyst/libaura_agent_ffi_maccatalyst.a" | awk '{print $1}')"
FINAL_TRUST_KEYRING_SHA256="$(shasum -a 256 "$AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH" | awk '{print $1}')"
PACKAGED_TRUST_KEYRING_SHA256="$(shasum -a 256 "$DIST_DIR/execution-policy-trust-keyring.json" | awk '{print $1}')"
if [[ "$FINAL_TRUST_KEYRING_SHA256" != "$AURA_EXECUTION_POLICY_TRUST_KEYRING_SHA256" \
  || "$PACKAGED_TRUST_KEYRING_SHA256" != "$AURA_EXECUTION_POLICY_TRUST_KEYRING_SHA256" ]]; then
  echo "Execution-policy trust keyring changed while the release artifact was built." >&2
  exit 1
fi
cat >"$DIST_DIR/release-manifest.json" <<JSON
{
  "schema_version": 4,
  "source_revision": "$SOURCE_REVISION",
  "source_tree_dirty": $SOURCE_TREE_DIRTY,
  "cargo_profile": "$PROFILE",
  "cargo_locked": true,
  "cargo_features": $FEATURES_JSON,
  "minimum_ios_version": "18.0",
  "target_triples": [
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "x86_64-apple-ios",
    "aarch64-apple-ios-macabi",
    "x86_64-apple-ios-macabi"
  ],
  "aura_ffi_header_sha256": "$HEADER_SHA256",
  "runtime_capabilities_sha256": "$RUNTIME_CAPABILITIES_SHA256",
  "runtime_artifact_descriptor_sha256": "$AURA_RELEASE_ARTIFACT_DESCRIPTOR_SHA256",
  "runtime_artifact_identities_env_sha256": "$RUNTIME_ARTIFACT_IDENTITIES_ENV_SHA256",
  "model_manifest_sha256": "$MODEL_MANIFEST_SHA256",
  "execution_policy_trust_keyring_sha256": "$AURA_EXECUTION_POLICY_TRUST_KEYRING_SHA256",
  "xcframework_info_plist_sha256": "$INFO_SHA256",
  "binary_sha256": {
    "ios-arm64": "$IOS_LIBRARY_SHA256",
    "ios-arm64_x86_64-simulator": "$SIMULATOR_LIBRARY_SHA256",
    "ios-arm64_x86_64-maccatalyst": "$MACCATALYST_LIBRARY_SHA256"
  },
  "model_bundle_included": false
}
JSON

echo "Wrote $DIST_DIR/AuraAgentFFI.xcframework"
echo "Wrote $DIST_DIR/runtime-artifact-descriptor.json"
echo "Wrote $DIST_DIR/runtime-artifact-identities.env"
echo "Wrote $DIST_DIR/release-manifest.json"
echo "Wrote $DIST_DIR/execution-policy-trust-keyring.json"
