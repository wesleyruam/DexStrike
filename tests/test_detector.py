from __future__ import annotations

from pathlib import Path

from dexstrike.detector import detect_abis, detect_hints, list_manifest_components
from dexstrike.frida import frida_gadget_url


def test_detect_abis(decoded_dir: Path) -> None:
    abis = detect_abis(decoded_dir)
    assert set(abis) == {"arm64-v8a", "armeabi-v7a"}


def test_detect_hints_scans_all_smali_dirs(decoded_dir: Path) -> None:
    """O hint de Flutter está em smali_classes3 (multidex)."""
    hints = detect_hints(decoded_dir)
    assert "Flutter" in hints["frameworks"]


def test_list_manifest_components(decoded_dir: Path) -> None:
    # Scanner leve por regex: retorna o android:name cru do Manifest.
    comps = list_manifest_components(decoded_dir)
    assert ".MainActivity" in comps["activity"]
    assert ".SyncService" in comps["service"]


def test_frida_url_mapping() -> None:
    url = frida_gadget_url("17.9.10", "arm64-v8a")
    assert url.endswith("frida-gadget-17.9.10-android-arm64.so.xz")
    assert "frida/frida/releases/download/17.9.10/" in url
