from __future__ import annotations

import re
from pathlib import Path

from dexstrike.state import AppState
from dexstrike.utils import dedupe_keep_order, print_info, print_ok, print_warn

KNOWN_ABIS = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]

FRAMEWORK_HINTS = {
    "React Native": ["libreactnativejni.so", "libhermes.so", "libfbjni.so", "com/facebook/react"],
    "Flutter": ["libflutter.so", "io/flutter"],
    "Cordova/PhoneGap": ["org/apache/cordova", "cordova.js"],
    "Unity": ["libunity.so", "libil2cpp.so", "com/unity3d"],
    "Xamarin/.NET MAUI": ["libmonodroid.so", "mono/MonoPackageManager"],
}

NETWORK_LIB_HINTS = {
    "OkHttp": ["okhttp3/", "com/squareup/okhttp"],
    "Retrofit": ["retrofit2/"],
    "Volley": ["com/android/volley"],
    "Cronet": ["org/chromium/net", "libcronet"],
    "TrustKit": ["com/datatheorem/android/trustkit"],
    "RootBeer": ["com/scottyab/rootbeer"],
}


def detect_abis(decoded_dir: Path) -> list[str]:
    lib_dir = decoded_dir / "lib"
    if not lib_dir.exists():
        return []
    abis = [p.name for p in lib_dir.iterdir() if p.is_dir() and p.name in KNOWN_ABIS]
    return dedupe_keep_order(abis)


def _scan_names(decoded_dir: Path) -> list[str]:
    names: list[str] = []
    roots = [decoded_dir / "lib", decoded_dir / "assets"]
    # Inclui smali, smali_classes2, smali_classes3, ... (multidex)
    roots.extend(sorted(decoded_dir.glob("smali*")))
    for root in roots:
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            rel = p.relative_to(decoded_dir).as_posix()
            names.append(rel)
    return names


def detect_hints(decoded_dir: Path) -> dict[str, list[str]]:
    names = _scan_names(decoded_dir)
    haystack = "\n".join(names).lower()
    result: dict[str, list[str]] = {"frameworks": [], "network_security": []}

    for label, hints in FRAMEWORK_HINTS.items():
        if any(h.lower() in haystack for h in hints):
            result["frameworks"].append(label)

    for label, hints in NETWORK_LIB_HINTS.items():
        if any(h.lower() in haystack for h in hints):
            result["network_security"].append(label)

    return result


def list_manifest_components(decoded_dir: Path) -> dict[str, list[str]]:
    manifest = decoded_dir / "AndroidManifest.xml"
    if not manifest.exists():
        return {}
    text = manifest.read_text(encoding="utf-8", errors="ignore")
    components: dict[str, list[str]] = {}
    for tag in ["activity", "service", "receiver", "provider"]:
        pattern = rf"<{tag}[^>]+android:name=\"([^\"]+)\""
        components[tag] = re.findall(pattern, text)
    return components


def run_detection(state: AppState) -> None:
    if not state.decoded_dir or not state.decoded_dir.exists():
        print_warn("Descompile o APK antes de detectar.")
        return

    state.detected_abis = detect_abis(state.decoded_dir)
    hints = detect_hints(state.decoded_dir)
    components = list_manifest_components(state.decoded_dir)

    print_info("ABIs detectadas: " + (", ".join(state.detected_abis) if state.detected_abis else "nenhuma"))
    print_info("Frameworks: " + (", ".join(hints["frameworks"]) if hints["frameworks"] else "nenhum hint forte"))
    print_info("Libs de rede/segurança: " + (", ".join(hints["network_security"]) if hints["network_security"] else "nenhum hint forte"))

    for key, values in components.items():
        print_info(f"{key}: {len(values)} encontrado(s)")

    state.log_patch("Executada detecção de ABIs/frameworks/libs/components")
    print_ok("Detecção concluída.")
