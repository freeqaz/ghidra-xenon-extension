#!/usr/bin/env bash
#
# Package the GhidraXenon extension as a zip for distribution.
#
# Usage:
#   ./build_extension.sh [ghidra_version]
#
# Examples:
#   ./build_extension.sh              # defaults to 12.1
#   ./build_extension.sh 12.1.1       # specify version
#
# Output:
#   ghidra_<version>_PUBLIC_<date>_GhidraXenon.zip
#
set -euo pipefail

GHIDRA_VERSION="${1:-12.1}"
DATE="$(date +%Y%m%d)"
EXT_NAME="GhidraXenon"
ZIP_NAME="ghidra_${GHIDRA_VERSION}_PUBLIC_${DATE}_${EXT_NAME}.zip"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Stamp the version into extension.properties
PROPS_TMP=$(mktemp)
sed "s/@extversion@/${GHIDRA_VERSION}/" extension.properties > "$PROPS_TMP"

# Build the zip with the expected Ghidra extension layout:
#   GhidraXenon/
#     extension.properties
#     Module.manifest
#     data/languages/...
#     ghidra_scripts/...
rm -f "$ZIP_NAME"

# Create a temporary staging directory
STAGE_DIR=$(mktemp -d)
STAGE="$STAGE_DIR/$EXT_NAME"
mkdir -p "$STAGE"

cp "$PROPS_TMP" "$STAGE/extension.properties"
cp Module.manifest "$STAGE/"
cp -r data "$STAGE/"
cp -r ghidra_scripts "$STAGE/"

# SLEIGH source files (.sinc, .slaspec) are included in the distribution.
# Ghidra requires them present alongside the compiled .sla for validation,
# even though it doesn't recompile from scratch at runtime.

# Use zip if available, fall back to 7z
if command -v zip &>/dev/null; then
  (cd "$STAGE_DIR" && zip -r "$SCRIPT_DIR/$ZIP_NAME" "$EXT_NAME/")
elif command -v 7z &>/dev/null; then
  (cd "$STAGE_DIR" && 7z a -tzip "$SCRIPT_DIR/$ZIP_NAME" "$EXT_NAME/")
else
  echo "Error: neither zip nor 7z found. Install one of them." >&2
  rm -rf "$STAGE_DIR" "$PROPS_TMP"
  exit 1
fi

rm -rf "$STAGE_DIR" "$PROPS_TMP"

echo ""
echo "Built: $ZIP_NAME"
echo "Size:  $(du -h "$ZIP_NAME" | cut -f1)"
echo ""
echo "Install in Ghidra:"
echo "  File -> Install Extensions -> + -> select $ZIP_NAME"
