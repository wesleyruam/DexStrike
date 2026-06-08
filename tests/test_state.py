from __future__ import annotations

from pathlib import Path

from dexstrike.state import BUNDLED_KEYSTORE, PROJECT_FILENAME, AppState


def test_keystore_default_is_bundled_and_absolute() -> None:
    st = AppState()
    assert st.keystore_path == BUNDLED_KEYSTORE
    assert st.keystore_path.is_absolute()


def test_paths_rooted_in_apk_folder(tmp_path: Path) -> None:
    apk = tmp_path / "base.apk"
    apk.write_bytes(b"PK\x03\x04")
    st = AppState()
    st.apk_path = apk
    st.refresh_paths()
    assert st.project_dir == tmp_path
    assert st.signed_apk is not None
    assert st.signed_apk.parent == tmp_path / "outputs"
    assert st.decoded_dir == tmp_path / "workspace" / "base_decoded"


def test_save_and_load_project_roundtrip(tmp_path: Path) -> None:
    apk = tmp_path / "base.apk"
    apk.write_bytes(b"PK\x03\x04")
    st = AppState()
    st.apk_path = apk
    st.frida_version = "16.0.0"
    st.key_alias = "minha-key"
    st.detected_abis = ["arm64-v8a"]
    saved = st.save_project()
    assert saved == tmp_path / PROJECT_FILENAME
    assert saved.exists()

    fresh = AppState()
    assert fresh.load_project(saved) is True
    assert fresh.apk_path == apk
    assert fresh.frida_version == "16.0.0"
    assert fresh.key_alias == "minha-key"
    assert fresh.detected_abis == ["arm64-v8a"]
    assert fresh.project_dir == tmp_path


def test_load_project_rejects_garbage(tmp_path: Path) -> None:
    bad = tmp_path / PROJECT_FILENAME
    bad.write_text("{ not json", encoding="utf-8")
    st = AppState()
    assert st.load_project(bad) is False
