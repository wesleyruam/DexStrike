from __future__ import annotations

from pathlib import Path

from dexstrike.manifest import (
    ensure_network_security_config,
    find_application_class,
    find_launcher_activity,
    get_package_name,
    set_cleartext_traffic,
    set_debuggable,
    set_extract_native_libs,
)
from dexstrike.state import AppState


def _state(decoded_dir: Path) -> AppState:
    st = AppState()
    st.decoded_dir = decoded_dir
    return st


def test_package_and_targets(decoded_dir: Path) -> None:
    assert get_package_name(decoded_dir) == "com.example.app"
    assert find_application_class(decoded_dir) == "com.example.app.MyApp"
    assert find_launcher_activity(decoded_dir) == "com.example.app.MainActivity"


def test_patches_apply_and_persist(decoded_dir: Path) -> None:
    st = _state(decoded_dir)
    set_extract_native_libs(st, True)
    set_cleartext_traffic(st, True)
    set_debuggable(st, True)
    ensure_network_security_config(st, force_attr=True)

    out = (decoded_dir / "AndroidManifest.xml").read_text(encoding="utf-8")
    assert 'android:extractNativeLibs="true"' in out
    assert 'android:usesCleartextTraffic="true"' in out
    assert 'android:debuggable="true"' in out
    assert 'android:networkSecurityConfig="@xml/network_security_config"' in out
    assert (decoded_dir / "res" / "xml" / "network_security_config.xml").exists()


def test_namespaces_preserved_no_ns0_corruption(decoded_dir: Path) -> None:
    """O bug clássico: ElementTree reescrevendo namespaces como ns0/ns1."""
    st = _state(decoded_dir)
    set_extract_native_libs(st, True)

    out = (decoded_dir / "AndroidManifest.xml").read_text(encoding="utf-8")
    assert "xmlns:android=" in out
    assert "xmlns:tools=" in out
    assert "ns0:" not in out
    assert "ns1:" not in out
    assert 'package="com.example.app"' in out
