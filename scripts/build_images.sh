#!/usr/bin/env bash
# Gera os SVGs e converte para PNG (usados no README e em redes sociais).
# Requer: python3 e rsvg-convert (pacote librsvg).
set -euo pipefail
cd "$(dirname "$0")/.."

python3 scripts/generate_assets.py

if ! command -v rsvg-convert >/dev/null 2>&1; then
    echo "rsvg-convert não encontrado. Instale o pacote 'librsvg' para gerar os PNGs."
    echo "Arch: sudo pacman -S librsvg"
    exit 0
fi

cd assets/img
for svg in banner pipeline terminal; do
    rsvg-convert -o "${svg}.png" "${svg}.svg"
    echo "gerado: assets/img/${svg}.png"
done
