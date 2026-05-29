#!/usr/bin/env bash
set -euo pipefail

echo "Instalando dependências principais no Arch Linux..."
sudo pacman -S --needed apktool android-tools jdk-openjdk xz

echo
echo "Para apksigner/zipalign, instale Android SDK Build Tools se ainda não tiver:"
echo "  sudo pacman -S android-sdk-build-tools"
echo
echo "Se o pacote não existir no seu repositório, use o SDK Manager do Android Studio."
