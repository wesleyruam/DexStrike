from __future__ import annotations

import re
from pathlib import Path

from dexstrike.state import AppState
from dexstrike.utils import ToolError, ensure_dir, print_ok, print_warn, run_cmd, which


def zipalign_apk(state: AppState) -> Path:
    if not state.unsigned_apk or not state.unsigned_apk.exists():
        raise ToolError("APK unsigned não encontrado. Faça o build primeiro.")
    state.refresh_paths()
    assert state.aligned_apk is not None

    if which("zipalign"):
        ensure_dir(state.aligned_apk.parent)
        if state.aligned_apk.exists():
            state.aligned_apk.unlink()
        run_cmd(["zipalign", "-p", "-f", "4", str(state.unsigned_apk), str(state.aligned_apk)])
        state.log_patch(f"APK alinhado com zipalign em `{state.aligned_apk}`")
        print_ok(f"APK alinhado: {state.aligned_apk}")
        return state.aligned_apk

    print_warn("zipalign não encontrado. Vou assinar o APK unsigned diretamente.")
    state.aligned_apk = state.unsigned_apk
    return state.unsigned_apk


def detect_alias_with_keytool(keystore: Path, password: str) -> str | None:
    if not which("keytool"):
        return None
    result = run_cmd(
        ["keytool", "-list", "-keystore", str(keystore), "-storepass", password],
        check=False,
    )
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        # Exemplo: key, Apr 9, 2026, PrivateKeyEntry,
        if "PrivateKeyEntry" in line:
            return line.split(",", 1)[0].strip()
    return None


def sign_apk(state: AppState) -> Path:
    state.refresh_paths()
    preferred_aligned = state.aligned_apk
    preferred_unsigned = state.unsigned_apk
    input_apk = preferred_aligned if preferred_aligned and preferred_aligned.exists() else preferred_unsigned
    if not input_apk or not input_apk.exists():
        raise ToolError("APK para assinatura não encontrado. Faça build/zipalign primeiro.")
    if not state.keystore_path.exists():
        raise ToolError(f"Keystore não encontrado: {state.keystore_path}")
    assert state.signed_apk is not None
    ensure_dir(state.signed_apk.parent)

    alias = detect_alias_with_keytool(state.keystore_path, state.keystore_password) or state.key_alias
    state.key_alias = alias

    if which("apksigner"):
        run_cmd([
            "apksigner",
            "sign",
            "--ks", str(state.keystore_path),
            "--ks-pass", f"pass:{state.keystore_password}",
            "--key-pass", f"pass:{state.keystore_password}",
            "--out", str(state.signed_apk),
            str(input_apk),
        ])
        run_cmd(["apksigner", "verify", "--verbose", str(state.signed_apk)], check=False)
        state.log_patch(f"APK assinado com apksigner em `{state.signed_apk}`")
        print_ok(f"APK assinado: {state.signed_apk}")
        return state.signed_apk

    if which("jarsigner"):
        signed_tmp = state.output_dir / f"{state.apk_stem()}-jarsigned.apk"
        if signed_tmp.exists():
            signed_tmp.unlink()
        # jarsigner assina in-place; copiamos antes.
        signed_tmp.write_bytes(input_apk.read_bytes())
        run_cmd([
            "jarsigner",
            "-verbose",
            "-sigalg", "SHA256withRSA",
            "-digestalg", "SHA-256",
            "-keystore", str(state.keystore_path),
            "-storepass", state.keystore_password,
            "-keypass", state.keystore_password,
            str(signed_tmp),
            alias,
        ])
        state.signed_apk.write_bytes(signed_tmp.read_bytes())
        state.log_patch(f"APK assinado com jarsigner em `{state.signed_apk}`")
        print_ok(f"APK assinado: {state.signed_apk}")
        return state.signed_apk

    raise ToolError("Nem apksigner nem jarsigner foram encontrados no PATH.")
