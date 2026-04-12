.PHONY: all lib xcframework xcode build dmg icon open clean

APP_NAME := Reports
ICON_SVG := ../misc/reports-icon.svg
ICON_DIR := Reports/Assets.xcassets/AppIcon.appiconset
BUILD_DIR := $(shell xcodebuild -project Reports.xcodeproj -scheme $(APP_NAME) -configuration Release -showBuildSettings 2>/dev/null | grep -m1 'BUILT_PRODUCTS_DIR' | awk '{print $$3}')
DMG_NAME := $(APP_NAME)-macOS-arm64

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
	xcodebuild -project Reports.xcodeproj -scheme $(APP_NAME) -configuration Release build

# Create DMG for distribution
dmg: build
	@echo "==> Creating DMG..."
	rm -rf dmg_staging $(DMG_NAME).dmg
	mkdir -p dmg_staging
	cp -R "$(BUILD_DIR)/$(APP_NAME).app" dmg_staging/
	ln -s /Applications dmg_staging/Applications
	hdiutil create -volname "$(APP_NAME)" -srcfolder dmg_staging \
		-ov -format UDZO "$(DMG_NAME).dmg"
	rm -rf dmg_staging
	@echo "==> Created $(DMG_NAME).dmg"

# Generate app icon PNGs from SVG
icon:
	@command -v magick >/dev/null 2>&1 || { echo "Install ImageMagick: brew install imagemagick"; exit 1; }
	@echo "==> Generating app icons from $(ICON_SVG)..."
	@for size in 16 32 64 128 256 512 1024; do \
		magick "$(ICON_SVG)" -resize $${size}x$${size} -background none "$(ICON_DIR)/icon_$${size}x$${size}.png"; \
	done
	@echo "==> App icons generated in $(ICON_DIR)"

# Build XCFramework + generate project + open in Xcode
open: xcframework xcode
	open Reports.xcodeproj

# Clean build artifacts
clean:
	rm -rf ReportsKit.xcframework
	rm -rf Reports.xcodeproj
	rm -rf ReportsKit/reports.h
	rm -rf dmg_staging *.dmg
