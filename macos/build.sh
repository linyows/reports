#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MACOS_DIR="$ROOT_DIR/macos"
ZIG_OUT="$ROOT_DIR/zig-out"
XCFRAMEWORK_DIR="$MACOS_DIR/ReportsKit.xcframework"

echo "==> Building Zig static library..."
cd "$ROOT_DIR"
zig build

echo "==> Repacking static library for Xcode compatibility..."
# Zig's archive may have alignment issues with Xcode's linker.
# Extract and repack using Apple's libtool to fix alignment.
REPACK_DIR=$(mktemp -d)
cd "$REPACK_DIR"
/usr/bin/ar x "$ZIG_OUT/lib/libreports-core.a"
chmod 644 *.o
/usr/bin/libtool -static -o "$ZIG_OUT/lib/libreports-core.a" *.o
cd "$ROOT_DIR"
rm -rf "$REPACK_DIR"

echo "==> Preparing XCFramework..."
rm -rf "$XCFRAMEWORK_DIR"

# Copy header alongside modulemap
cp "$ZIG_OUT/include/reports.h" "$MACOS_DIR/ReportsKit/reports.h"

# Create XCFramework from static library + headers
xcodebuild -create-xcframework \
    -library "$ZIG_OUT/lib/libreports-core.a" \
    -headers "$MACOS_DIR/ReportsKit" \
    -output "$XCFRAMEWORK_DIR"

echo "==> XCFramework created at $XCFRAMEWORK_DIR"

# Generate Xcode project if xcodegen is available
if command -v xcodegen &>/dev/null; then
    echo "==> Generating Xcode project..."
    cd "$MACOS_DIR"
    xcodegen generate
    echo "==> Done. Open with: open macos/Reports.xcodeproj"
else
    echo "==> xcodegen not found. Install with: brew install xcodegen"
    echo "    Then run: cd macos && xcodegen generate"
fi
