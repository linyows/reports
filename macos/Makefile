.PHONY: all lib xcframework xcode build open clean

# Build everything: Zig library + XCFramework + Xcode project + app
all: xcframework xcode build

# Build the Zig static library (libreports-core.a)
lib:
	cd .. && zig build

# Build XCFramework (includes lib step)
xcframework:
	./build.sh

# Generate Xcode project using xcodegen
xcode:
	@command -v xcodegen >/dev/null 2>&1 || { echo "Install xcodegen: brew install xcodegen"; exit 1; }
	xcodegen generate

# Build the macOS app via xcodebuild
build: Reports.xcodeproj
	xcodebuild -project Reports.xcodeproj -scheme Reports -configuration Release build

# Build XCFramework + generate project + open in Xcode
open: xcframework xcode
	open Reports.xcodeproj

# Clean build artifacts
clean:
	rm -rf ReportsKit.xcframework
	rm -rf Reports.xcodeproj
	rm -rf ReportsKit/reports.h
