#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CPP_DIR="$ROOT_DIR/cpp"
BUILD_DIR="$CPP_DIR/build"
DIST_DIR="$CPP_DIR/dist"
DISPLAY_NAME="Network Tools"
APP_BUNDLE_NAME="$DISPLAY_NAME.app"
ZIP_BASENAME="Network-Tools-macos"
DMG_BASENAME="Network-Tools-macos-apple-silicon"
find_build_app() {
  if [[ ! -d "$BUILD_DIR" ]]; then
    return 0
  fi
  if [[ -d "$BUILD_DIR/NetworkToolsQt.app" ]]; then
    printf '%s\n' "$BUILD_DIR/NetworkToolsQt.app"
    return
  fi
  find "$BUILD_DIR" -maxdepth 1 -type d -name '*.app' | head -n 1
}
BUILD_APP_PATH="$(find_build_app)"
APP_PATH="$DIST_DIR/$APP_BUNDLE_NAME"
RESOURCES_DIR="$APP_PATH/Contents/Resources"
FRAMEWORKS_DIR="$APP_PATH/Contents/Frameworks"
SEED_DIR="$RESOURCES_DIR/data"
SEED_PATH="$SEED_DIR/manuf"
BIN_DIR="$RESOURCES_DIR/bin"
MANUF_URL="https://www.wireshark.org/download/automated/data/manuf"
FPING_SOURCE="/usr/bin/fping"
BREW_PREFIX="$(brew --prefix)"
QT_PREFIX="$(brew --prefix qt)"

mkdir -p "$DIST_DIR"

cmake -S "$CPP_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" --config Release
BUILD_APP_PATH="$(find_build_app)"

if [[ -z "$BUILD_APP_PATH" || ! -d "$BUILD_APP_PATH" ]]; then
  echo "Expected build app bundle not found in: $BUILD_DIR" >&2
  exit 1
fi

if ! command -v macdeployqt >/dev/null 2>&1; then
  echo "macdeployqt is required and was not found in PATH." >&2
  exit 1
fi

rm -rf "$APP_PATH"
cp -R "$BUILD_APP_PATH" "$APP_PATH"

macdeployqt "$APP_PATH" \
  -always-overwrite \
  -no-strip \
  "-libpath=$BREW_PREFIX/lib" \
  "-libpath=$BREW_PREFIX/Frameworks" \
  "-libpath=$QT_PREFIX/lib"

rm -rf "$APP_PATH/Contents/MacOS/data"
mkdir -p "$SEED_DIR"
curl -L --fail --silent --show-error "$MANUF_URL" -o "$SEED_PATH"
mkdir -p "$BIN_DIR"
if [[ -f "$FPING_SOURCE" ]]; then
  cp -f "$FPING_SOURCE" "$BIN_DIR/fping"
  chmod 755 "$BIN_DIR/fping"
fi

codesign --force --deep --sign - --timestamp=none "$APP_PATH"
codesign --verify --deep --strict --verbose=1 "$APP_PATH"

ZIP_PATH="$DIST_DIR/$ZIP_BASENAME.zip"
rm -f "$ZIP_PATH"
ditto -c -k --sequesterRsrc --keepParent "$APP_PATH" "$ZIP_PATH"

DMG_PATH="$DIST_DIR/$DMG_BASENAME.dmg"
STAGE_DIR="$(mktemp -d /tmp/networktools-dmg.XXXXXX)"
cp -R "$APP_PATH" "$STAGE_DIR/$APP_BUNDLE_NAME"
ln -s /Applications "$STAGE_DIR/Applications"
rm -f "$DMG_PATH"
hdiutil create -volname "$DISPLAY_NAME" -srcfolder "$STAGE_DIR" -format UDZO "$DMG_PATH" >/dev/null
rm -rf "$STAGE_DIR"

echo "Packaged app: $APP_PATH"
echo "Archive: $ZIP_PATH"
echo "Disk image: $DMG_PATH"
