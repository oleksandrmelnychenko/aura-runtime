#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="$ROOT/dist/apple"
INCLUDE_DIR="$ROOT/target/include/aura-agent-ffi"
PROFILE="${PROFILE:-release}"
CARGO_PROFILE_FLAG=("--release")

if [[ "$PROFILE" != "release" ]]; then
  CARGO_PROFILE_FLAG=("--profile" "$PROFILE")
fi

mkdir -p "$DIST_DIR" "$INCLUDE_DIR"
cp "$ROOT/include/aura_ffi.h" "$INCLUDE_DIR/aura_ffi.h"
cp "$ROOT/include/module.modulemap" "$INCLUDE_DIR/module.modulemap"

targets=(
  aarch64-apple-ios
  aarch64-apple-ios-sim
  x86_64-apple-ios
  aarch64-apple-ios-macabi
  x86_64-apple-ios-macabi
)

for target in "${targets[@]}"; do
  rustup target add "$target" >/dev/null
  if [[ "${AURA_AGENT_EXTENDED_API:-0}" == "1" ]]; then
    cargo build "${CARGO_PROFILE_FLAG[@]}" --features extended-api -p aura-agent-ffi --target "$target" --manifest-path "$ROOT/Cargo.toml"
  else
    cargo build "${CARGO_PROFILE_FLAG[@]}" -p aura-agent-ffi --target "$target" --manifest-path "$ROOT/Cargo.toml"
  fi
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

echo "Wrote $DIST_DIR/AuraAgentFFI.xcframework"
