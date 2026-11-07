#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python packaging/build.py
mkdir -p out/installers
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
ditto out/packaging/dist/Vigia.app "$stage/Vigia.app"
ln -s /Applications "$stage/Applications"
hdiutil create -volname "Vigía" -srcfolder "$stage" -ov -format UDZO \
    "out/installers/Vigia-0.6.0-macos-$(uname -m).dmg"
