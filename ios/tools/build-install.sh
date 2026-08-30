#!/usr/bin/env bash
# Build + install AtlasApp to the physical iPhone, then RECLAIM the disk our build loop eats.
#
# Why this exists: the app embeds the 806 MB OLMo model and pulls the heavy MLX Swift packages,
# so every build regenerates a ~2.4 GB DerivedData tree. On a near-full 256 GB Mac, a dozen builds
# a session tips it over. After a successful install we prune the REGENERABLE heavy parts
# (intermediates, the build product that's now on the phone, the index) while KEEPING
# SourcePackages + ModuleCache so the next build stays fast (no MLX re-download).
set -euo pipefail

# Set ATLAS_DEVICE to your iPhone's UDID (Xcode ▸ Window ▸ Devices, or `xcrun xctrace list devices`).
DEVICE="${ATLAS_DEVICE:?set ATLAS_DEVICE to your device UDID (see: xcrun xctrace list devices)}"
PROJ="$(cd "$(dirname "$0")/.." && pwd)/AtlasApp.xcodeproj"
DD="$HOME/Library/Developer/Xcode/DerivedData"

echo "== build =="
xcodebuild -project "$PROJ" -scheme AtlasApp \
  -destination "id=$DEVICE" -configuration Debug -allowProvisioningUpdates build

APP="$(ls -d "$DD"/AtlasApp-*/Build/Products/Debug-iphoneos/AtlasApp.app | head -1)"
echo "== install $APP =="
xcrun devicectl device install app --device "$DEVICE" "$APP"

echo "== reclaim (keep SourcePackages + ModuleCache; drop regenerable heavy parts) =="
before=$(df -h /System/Volumes/Data | awk 'NR==2{print $4}')
for d in AtlasApp-*/Build/Intermediates.noindex AtlasApp-*/Build/Products \
         AtlasApp-*/Index.noindex AtlasApp-*/Logs; do
  rm -rf "$DD"/$d 2>/dev/null || true
done
after=$(df -h /System/Volumes/Data | awk 'NR==2{print $4}')
echo "free: $before -> $after"
