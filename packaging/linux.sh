#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python packaging/build.py
destination="$PWD/out/installers"
mkdir -p "$destination"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/DEBIAN" "$stage/opt/vigia" "$stage/usr/share/applications" "$stage/usr/bin"
cp -a out/packaging/dist/Vigia/. "$stage/opt/vigia/"
cat > "$stage/DEBIAN/control" <<'CONTROL'
Package: vigia
Version: 0.2.0
Section: utils
Priority: optional
Architecture: amd64
Maintainer: Marc's & Co.
Depends: libc6 (>= 2.36), libegl1, libgl1, libdbus-1-3, libfontconfig1, libx11-xcb1, libxcb-cursor0, libxcb-icccm4, libxcb-image0, libxcb-keysyms1, libxcb-randr0, libxcb-render-util0, libxcb-shape0, libxcb-xkb1, libxkbcommon-x11-0
Description: Mesa de trabajo del SOC de Tarvia
 Vigía consulta alertas, expedientes y evidencias del dataset local.
CONTROL
cat > "$stage/usr/share/applications/vigia.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Vigía
Comment=Mesa de trabajo del SOC de Tarvia
Exec=/usr/bin/vigia
Icon=/opt/vigia/_internal/apps/desktop/brand/vigia_icon_dark.svg
Terminal=false
Categories=Utility;Security;
DESKTOP
ln -s /opt/vigia/Vigia "$stage/usr/bin/vigia"
dpkg-deb --root-owner-group -Zxz -z3 --build "$stage" "$destination/Vigia-0.2.0-linux-amd64.deb"

# Archivo instalable por usuario en distribuciones fuera de Debian.
cp packaging/install-linux.sh "$stage/opt/vigia/install.sh"
chmod 755 "$stage/opt/vigia/install.sh"
tar -C "$stage/opt" -czf "$destination/Vigia-0.2.0-linux-x86_64.tar.gz" vigia
