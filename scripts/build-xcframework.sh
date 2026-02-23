#!/usr/bin/env bash
set -euo pipefail

# AURA Core — Build XCFramework for Apple platforms
# Produces AuraKit/AuraFFI.xcframework with slices for:
#   - iOS (arm64)
#   - iOS Simulator (arm64 + x86_64)
#   - macOS (arm64 + x86_64)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
AURAKIT_DIR="$ROOT_DIR/AuraKit"
HEADERS_DIR="$AURAKIT_DIR/include"
XCFRAMEWORK_DIR="$AURAKIT_DIR/AuraFFI.xcframework"

cd "$ROOT_DIR"

echo "=== AURA Core: Building XCFramework ==="
echo ""

# Step 1: Install Rust targets
echo "[1/6] Installing Rust targets..."
rustup target add aarch64-apple-ios 2>/dev/null || true
rustup target add aarch64-apple-ios-sim 2>/dev/null || true
rustup target add x86_64-apple-ios 2>/dev/null || true
rustup target add aarch64-apple-darwin 2>/dev/null || true
rustup target add x86_64-apple-darwin 2>/dev/null || true
echo "       Targets installed."

# Step 2: Build for each target
echo "[2/6] Building aura-ffi for all targets..."

cargo build --release --target aarch64-apple-ios -p aura-ffi
echo "       ✓ iOS arm64"

cargo build --release --target aarch64-apple-ios-sim -p aura-ffi
echo "       ✓ iOS Simulator arm64"

cargo build --release --target x86_64-apple-ios -p aura-ffi
echo "       ✓ iOS Simulator x86_64"

cargo build --release --target aarch64-apple-darwin -p aura-ffi
echo "       ✓ macOS arm64"

cargo build --release --target x86_64-apple-darwin -p aura-ffi
echo "       ✓ macOS x86_64"

# Step 3: Create fat libraries with lipo
echo "[3/6] Creating fat libraries..."

mkdir -p target/universal

# iOS Simulator (arm64 + x86_64)
lipo -create \
    target/aarch64-apple-ios-sim/release/libaura_ffi.a \
    target/x86_64-apple-ios/release/libaura_ffi.a \
    -output target/universal/libaura_ffi-ios-sim.a
echo "       ✓ iOS Simulator universal"

# macOS (arm64 + x86_64)
lipo -create \
    target/aarch64-apple-darwin/release/libaura_ffi.a \
    target/x86_64-apple-darwin/release/libaura_ffi.a \
    -output target/universal/libaura_ffi-macos.a
echo "       ✓ macOS universal"

# Step 4: Remove existing XCFramework
echo "[4/6] Cleaning previous XCFramework..."
rm -rf "$XCFRAMEWORK_DIR"

# Step 5: Build XCFramework
echo "[5/6] Creating XCFramework..."

xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libaura_ffi.a \
    -headers "$HEADERS_DIR" \
    -library target/universal/libaura_ffi-ios-sim.a \
    -headers "$HEADERS_DIR" \
    -library target/universal/libaura_ffi-macos.a \
    -headers "$HEADERS_DIR" \
    -output "$XCFRAMEWORK_DIR"

echo "       ✓ XCFramework created"

# Step 6: Verify
echo "[6/6] Verifying..."
echo ""
echo "XCFramework slices:"
ls -d "$XCFRAMEWORK_DIR"/*/
echo ""

# Show sizes
echo "Library sizes:"
for lib in target/aarch64-apple-ios/release/libaura_ffi.a \
           target/universal/libaura_ffi-ios-sim.a \
           target/universal/libaura_ffi-macos.a; do
    if [ -f "$lib" ]; then
        size=$(du -h "$lib" | cut -f1)
        echo "  $lib: $size"
    fi
done
echo ""
echo "=== XCFramework ready at: $XCFRAMEWORK_DIR ==="
