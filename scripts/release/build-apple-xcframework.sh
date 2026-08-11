#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
DIST_DIR="${AURA_APPLE_DIST_DIR:-$ROOT/dist/apple}"
if [[ "$DIST_DIR" != /* ]]; then
  DIST_DIR="$ROOT/$DIST_DIR"
fi
PROFILE="${PROFILE:-release}"
CARGO_PROFILE_FLAG=("--release")
CARGO_FEATURE_NAME=""
SOURCE_REVISION="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_TREE_SHA256="$(
  python3 "$ROOT/ci/apple_artifact.py" source-digest --root "$ROOT"
)"
SOURCE_TREE_DIRTY="$(
  python3 "$ROOT/ci/apple_artifact.py" source-dirty --root "$ROOT"
)"
SHIPPABLE=false
if [[ "$PROFILE" == "release" && "$SOURCE_TREE_DIRTY" == "false" ]]; then
  SHIPPABLE=true
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

if [[ -n "${RUSTFLAGS:-}" || -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]]; then
  echo "Refusing ambient Rust compiler flags for an Apple release artifact." >&2
  exit 2
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aura-apple-release.XXXXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM
WORK_DIR="$(cd "$WORK_DIR" && pwd -P)"
INCLUDE_DIR="$WORK_DIR/include/aura-agent-ffi"
export CARGO_TARGET_DIR="$WORK_DIR/cargo-target"

RUST_HOST="$(rustc -vV | sed -n 's/^host: //p')"
RUST_SYSROOT="$(cd "$(rustc --print sysroot)" && pwd -P)"
AURA_CARGO_HOME_PATH="${CARGO_HOME:-${HOME:?HOME is required when CARGO_HOME is unset}/.cargo}"
if [[ ! -d "$AURA_CARGO_HOME_PATH" ]]; then
  echo "Cargo home is unavailable: $AURA_CARGO_HOME_PATH" >&2
  exit 2
fi
AURA_CARGO_HOME_PATH="$(cd "$AURA_CARGO_HOME_PATH" && pwd -P)"

remap_flags=(
  "--remap-path-prefix=$ROOT=/aura/source"
  "--remap-path-prefix=$WORK_DIR=/aura/build"
  "--remap-path-prefix=$AURA_CARGO_HOME_PATH=/aura/cargo"
  "--remap-path-prefix=$RUST_SYSROOT=/aura/rust"
)
printf -v CARGO_ENCODED_RUSTFLAGS '%s\x1f' "${remap_flags[@]}"
CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS%$'\x1f'}"
export CARGO_ENCODED_RUSTFLAGS

LLVM_NM="${AURA_LLVM_NM:-$RUST_SYSROOT/lib/rustlib/$RUST_HOST/bin/llvm-nm}"
LLVM_STRIP="${AURA_LLVM_STRIP:-$RUST_SYSROOT/lib/rustlib/$RUST_HOST/bin/llvm-strip}"
if [[ ! -x "$LLVM_NM" || ! -x "$LLVM_STRIP" ]]; then
  echo "Rust llvm-nm and llvm-strip are required to package Apple artifacts." >&2
  echo "Install them with: rustup component add llvm-tools-preview" >&2
  exit 2
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
AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH="$(
  cd "$(dirname "$AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH")"
  printf '%s/%s\n' "$PWD" "$(basename "$AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH")"
)"
export AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH
export AURA_EXECUTION_POLICY_TRUST_KEYRING_SHA256
AURA_EXECUTION_POLICY_TRUST_KEYRING_SHA256="$(shasum -a 256 "$AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH" | awk '{print $1}')"
PACKAGED_TRUST_KEYRING_PATH="$DIST_DIR/execution-policy-trust-keyring.json"
if [[ "$AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH" != "$PACKAGED_TRUST_KEYRING_PATH" ]]; then
  cp "$AURA_EXECUTION_POLICY_TRUST_KEYRING_PATH" "$PACKAGED_TRUST_KEYRING_PATH"
fi

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
read -r RUNTIME_CAPABILITIES_SHA256 MODEL_MANIFEST_SHA256 RUNTIME_RELEASE_VERSION STATE_SCHEMA_VERSION < <(
  cargo "${identity_args[@]}"
)
if [[ ! "$RUNTIME_CAPABILITIES_SHA256" =~ ^[0-9a-f]{64}$ \
  || "$RUNTIME_CAPABILITIES_SHA256" == "0000000000000000000000000000000000000000000000000000000000000000" \
  || ! "$MODEL_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ \
  || "$MODEL_MANIFEST_SHA256" == "0000000000000000000000000000000000000000000000000000000000000000" ]]; then
  echo "Aura release identity emitter returned malformed artifact digests." >&2
  exit 2
fi
if [[ ! "$RUNTIME_RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ \
  || ! "$STATE_SCHEMA_VERSION" =~ ^[1-9][0-9]*$ ]]; then
  echo "Aura release identity emitter returned malformed version metadata." >&2
  exit 2
fi

cat >"$DIST_DIR/runtime-artifact-descriptor.json" <<JSON
{
  "schema_version": 3,
  "source_revision": "$SOURCE_REVISION",
  "source_tree_dirty": $SOURCE_TREE_DIRTY,
  "source_tree_sha256": "$SOURCE_TREE_SHA256",
  "shippable": $SHIPPABLE,
  "cargo_profile": "$PROFILE",
  "cargo_features": $FEATURES_JSON,
  "runtime_release_version": "$RUNTIME_RELEASE_VERSION",
  "wire_package": "aura.messenger.v1",
  "wire_major_version": 1,
  "state_schema_version": $STATE_SCHEMA_VERSION,
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

DEVICE_LIB="$WORK_DIR/libaura_agent_ffi.a"
SIM_LIB="$WORK_DIR/libaura_agent_ffi_ios_sim.a"
MACABI_LIB="$WORK_DIR/libaura_agent_ffi_maccatalyst.a"

cp "$CARGO_TARGET_DIR/aarch64-apple-ios/$profile_dir/libaura_agent_ffi.a" "$DEVICE_LIB"

lipo -create \
  "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/$profile_dir/libaura_agent_ffi.a" \
  "$CARGO_TARGET_DIR/x86_64-apple-ios/$profile_dir/libaura_agent_ffi.a" \
  -output "$SIM_LIB"

lipo -create \
  "$CARGO_TARGET_DIR/aarch64-apple-ios-macabi/$profile_dir/libaura_agent_ffi.a" \
  "$CARGO_TARGET_DIR/x86_64-apple-ios-macabi/$profile_dir/libaura_agent_ffi.a" \
  -output "$MACABI_LIB"

# Cargo cannot strip every object embedded in a Mach-O static archive. Remove
# debug sections from the package copies with the matching Rust LLVM toolchain;
# keep all external symbols required by the final application link.
"$LLVM_STRIP" -S "$DEVICE_LIB"
"$LLVM_STRIP" -S "$SIM_LIB"
"$LLVM_STRIP" -S "$MACABI_LIB"

verify_archive_has_no_local_paths() {
  local archive="$1"
  local strings_file="$WORK_DIR/$(basename "$archive").strings"
  local forbidden_path

  /usr/bin/strings "$archive" >"$strings_file"
  for forbidden_path in \
    "$ROOT" \
    "$WORK_DIR" \
    "$AURA_CARGO_HOME_PATH" \
    "$RUST_SYSROOT"; do
    if grep -F "$forbidden_path" "$strings_file" >/dev/null; then
      echo "Release archive contains a local build path: $forbidden_path" >&2
      exit 1
    fi
  done
}

verify_archive_has_no_local_paths "$DEVICE_LIB"
verify_archive_has_no_local_paths "$SIM_LIB"
verify_archive_has_no_local_paths "$MACABI_LIB"

required_symbols=()
while IFS= read -r symbol; do
  [[ -z "$symbol" || "$symbol" == \#* ]] && continue
  required_symbols+=("_$symbol")
done <"$ROOT/include/aura_ffi.exports"
if [[ "${#required_symbols[@]}" -eq 0 ]]; then
  echo "Aura export allowlist is empty." >&2
  exit 2
fi

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
  local raw_symbols
  local symbols
  # Use llvm-nm from the active Rust toolchain. Apple nm can lag the LLVM
  # producer embedded in stable Rust and skip the exact Aura object while
  # successfully reading older compiler-builtins members.
  if ! raw_symbols="$(
    "$LLVM_NM" --defined-only --extern-only "$archive" 2>&1
  )"; then
    printf '%s\n' "$raw_symbols" >&2
    echo "Failed to inspect symbols in $archive" >&2
    exit 1
  fi
  symbols="$(
    printf '%s\n' "$raw_symbols" \
      | grep -v ': no symbols$' \
      | awk '{print $NF}'
  )"

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

verify_archive_symbols "$DEVICE_LIB"
verify_archive_symbols "$SIM_LIB"
verify_archive_symbols "$MACABI_LIB"

rm -rf "$DIST_DIR/AuraAgentFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$DEVICE_LIB" -headers "$INCLUDE_DIR" \
  -library "$SIM_LIB" -headers "$INCLUDE_DIR" \
  -library "$MACABI_LIB" -headers "$INCLUDE_DIR" \
  -output "$DIST_DIR/AuraAgentFFI.xcframework"

# xcodebuild does not guarantee the order of AvailableLibraries, which makes
# Info.plist and the release manifest drift even when every binary is
# byte-identical. Canonicalize the generated plist before hashing it.
python3 - "$DIST_DIR/AuraAgentFFI.xcframework/Info.plist" <<'PY'
import os
import plistlib
import sys
from pathlib import Path

plist_path = Path(sys.argv[1])
with plist_path.open("rb") as source:
    document = plistlib.load(source)

libraries = document.get("AvailableLibraries")
if not isinstance(libraries, list) or not libraries:
    raise SystemExit("XCFramework Info.plist has no AvailableLibraries array")
if any(not isinstance(item, dict) for item in libraries):
    raise SystemExit("XCFramework AvailableLibraries contains a non-dictionary item")

identifiers = [item.get("LibraryIdentifier") for item in libraries]
if any(not isinstance(identifier, str) or not identifier for identifier in identifiers):
    raise SystemExit("XCFramework library is missing LibraryIdentifier")
if len(set(identifiers)) != len(identifiers):
    raise SystemExit("XCFramework contains duplicate LibraryIdentifier values")

libraries.sort(key=lambda item: item["LibraryIdentifier"])
temporary_path = plist_path.with_suffix(".plist.tmp")
with temporary_path.open("wb") as output:
    plistlib.dump(document, output, fmt=plistlib.FMT_XML, sort_keys=True)
os.replace(temporary_path, plist_path)
PY

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
PACKAGED_TRUST_KEYRING_SHA256="$(shasum -a 256 "$PACKAGED_TRUST_KEYRING_PATH" | awk '{print $1}')"
if [[ "$FINAL_TRUST_KEYRING_SHA256" != "$AURA_EXECUTION_POLICY_TRUST_KEYRING_SHA256" \
  || "$PACKAGED_TRUST_KEYRING_SHA256" != "$AURA_EXECUTION_POLICY_TRUST_KEYRING_SHA256" ]]; then
  echo "Execution-policy trust keyring changed while the release artifact was built." >&2
  exit 1
fi
cat >"$DIST_DIR/release-manifest.json" <<JSON
{
  "schema_version": 5,
  "source_revision": "$SOURCE_REVISION",
  "source_tree_dirty": $SOURCE_TREE_DIRTY,
  "source_tree_sha256": "$SOURCE_TREE_SHA256",
  "shippable": $SHIPPABLE,
  "cargo_profile": "$PROFILE",
  "cargo_locked": true,
  "cargo_features": $FEATURES_JSON,
  "runtime_release_version": "$RUNTIME_RELEASE_VERSION",
  "wire_package": "aura.messenger.v1",
  "wire_major_version": 1,
  "state_schema_version": $STATE_SCHEMA_VERSION,
  "ffi_contract_version": 1,
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
