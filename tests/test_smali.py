from __future__ import annotations

from pathlib import Path

from dexstrike.smali import find_smali_file, inject_frida_load_library, patch_smali_file
from dexstrike.state import AppState


def test_patch_existing_oncreate_activity(decoded_dir: Path) -> None:
    smali = find_smali_file(decoded_dir, "com.example.app.MainActivity")
    assert smali is not None

    changed = patch_smali_file(smali, kind="activity")
    body = smali.read_text(encoding="utf-8")
    assert changed is True
    assert 'const-string v0, "frida-gadget"' in body
    assert "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V" in body


def test_patch_is_idempotent(decoded_dir: Path) -> None:
    smali = find_smali_file(decoded_dir, "com.example.app.MainActivity")
    assert smali is not None

    assert patch_smali_file(smali, kind="activity") is True
    # segunda passada não deve duplicar a injeção
    assert patch_smali_file(smali, kind="activity") is False
    assert smali.read_text(encoding="utf-8").count('"frida-gadget"') == 1


def test_creates_oncreate_when_absent(decoded_dir: Path) -> None:
    smali = find_smali_file(decoded_dir, "com.example.app.MyApp")
    assert smali is not None

    changed = patch_smali_file(smali, kind="application")
    body = smali.read_text(encoding="utf-8")
    assert changed is True
    assert ".method public onCreate()V" in body
    assert "Application;->onCreate()V" in body
    assert "Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V" in body


def test_inject_prefers_application_class(decoded_dir: Path) -> None:
    st = AppState()
    st.decoded_dir = decoded_dir
    target = inject_frida_load_library(st)
    # deve escolher a Application antes da Activity
    assert target.name == "MyApp.smali"
