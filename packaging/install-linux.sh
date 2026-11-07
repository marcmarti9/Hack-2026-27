#!/bin/sh
set -eu
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
data_dir=${XDG_DATA_HOME:-"$HOME/.local/share"}
install_dir="$data_dir/vigia-desktop/app-0.5.0"
desktop_dir="$data_dir/applications"
case "$install_dir" in
    /*) ;;
    *) printf '%s\n' 'XDG_DATA_HOME debe ser una ruta absoluta.' >&2; exit 1 ;;
esac
if [ ! -x "$source_dir/Vigia" ] || [ ! -d "$source_dir/_internal" ]; then
    printf '%s\n' 'Ejecuta este instalador desde la carpeta extraída de Vigía.' >&2
    exit 1
fi
if [ -e "$install_dir" ]; then
    printf 'Vigía ya está instalado en %s\n' "$install_dir" >&2
    exit 1
fi
mkdir -p "$(dirname "$install_dir")" "$desktop_dir"
stage=$(mktemp -d "$(dirname "$install_dir")/.instalacion.XXXXXX")
trap 'rm -rf "$stage"' EXIT
cp -R "$source_dir/Vigia" "$source_dir/_internal" "$stage/"
mv -T "$stage" "$install_dir"
# Los caracteres especiales de Exec se escapan según Desktop Entry.
exec_path=$(printf '%s' "$install_dir/Vigia" | sed 's/[%]/%%/g; s/["`$\\]/\\&/g; s/\\/\\\\/g')
printf '[Desktop Entry]\nType=Application\nName=Vigía\nExec="%s"\nIcon=%s\nTerminal=false\nCategories=Utility;Security;\n' \
    "$exec_path" "$install_dir/_internal/apps/desktop/brand/vigia_icon_dark.svg" > "$desktop_dir/vigia.desktop"
printf '[Desktop Entry]\nType=Application\nName=Vigía Demo\nExec="%s" --demo\nIcon=%s\nTerminal=false\nCategories=Utility;Security;\n' \
    "$exec_path" "$install_dir/_internal/apps/desktop/brand/vigia_icon_dark.svg" > "$desktop_dir/vigia-demo.desktop"
printf 'Vigía instalado en %s\n' "$install_dir"
