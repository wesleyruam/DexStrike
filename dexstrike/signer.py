from __future__ import annotations

import re
from pathlib import Path

from dexstrike.state import AppState
from dexstrike.utils import ToolError, ensure_dir, print_ok, print_warn, run_cmd, which

_CERT_SHA256_RE = re.compile(r"certificate SHA-256 digest:\s*([0-9a-fA-F]+)")


def zipalign_file(src: Path, dst: Path) -> Path:
    """Alinha um APK em 4 bytes. Sem zipalign no PATH, apenas copia o arquivo."""
    if which("zipalign"):
        ensure_dir(dst.parent)
        if dst.exists():
            dst.unlink()
        run_cmd(["zipalign", "-p", "-f", "4", str(src), str(dst)])
        return dst

    print_warn("zipalign não encontrado. Usando o APK sem alinhar.")
    if src.resolve() != dst.resolve():
        ensure_dir(dst.parent)
        dst.write_bytes(src.read_bytes())
    return dst


def zipalign_apk(state: AppState) -> Path:
    if not state.unsigned_apk or not state.unsigned_apk.exists():
        raise ToolError("APK unsigned não encontrado. Faça o build primeiro.")
    state.refresh_paths()
    assert state.aligned_apk is not None

    zipalign_file(state.unsigned_apk, state.aligned_apk)
    state.log_patch(f"APK alinhado com zipalign em `{state.aligned_apk}`")
    print_ok(f"APK alinhado: {state.aligned_apk}")
    return state.aligned_apk


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


def sign_with_keystore(src: Path, dst: Path, keystore: Path, password: str, alias: str) -> str:
    """Assina ``src`` em ``dst`` com a keystore informada.

    Usa ``apksigner`` quando disponível e cai para ``jarsigner`` caso contrário.
    Retorna o nome da ferramenta utilizada. Mantém o ``alias`` explícito para que
    o conjunto base + splits seja assinado com a MESMA chave (requisito do
    ``adb install-multiple``).
    """
    ensure_dir(dst.parent)

    if which("apksigner"):
        run_cmd([
            "apksigner",
            "sign",
            "--ks", str(keystore),
            "--ks-pass", f"pass:{password}",
            "--key-pass", f"pass:{password}",
            "--ks-key-alias", alias,
            "--out", str(dst),
            str(src),
        ])
        return "apksigner"

    if which("jarsigner"):
        # jarsigner assina in-place; copiamos antes se necessário.
        if src.resolve() != dst.resolve():
            dst.write_bytes(src.read_bytes())
        run_cmd([
            "jarsigner",
            "-sigalg", "SHA256withRSA",
            "-digestalg", "SHA-256",
            "-keystore", str(keystore),
            "-storepass", password,
            "-keypass", password,
            str(dst),
            alias,
        ])
        return "jarsigner"

    raise ToolError("Nem apksigner nem jarsigner foram encontrados no PATH.")


def cert_sha256(apk: Path) -> str | None:
    """Retorna o digest SHA-256 (lowercase) do certificado do signatário, ou None.

    Requer ``apksigner`` no PATH. Útil para confirmar que base + splits
    compartilham a mesma assinatura.
    """
    if not which("apksigner"):
        return None
    result = run_cmd(["apksigner", "verify", "--print-certs", str(apk)], check=False)
    if result.returncode != 0:
        return None
    match = _CERT_SHA256_RE.search(result.stdout or "")
    return match.group(1).lower() if match else None


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

    alias = detect_alias_with_keytool(state.keystore_path, state.keystore_password) or state.key_alias
    state.key_alias = alias

    tool = sign_with_keystore(input_apk, state.signed_apk, state.keystore_path, state.keystore_password, alias)
    if which("apksigner"):
        run_cmd(["apksigner", "verify", "--verbose", str(state.signed_apk)], check=False)

    state.log_patch(f"APK assinado com {tool} em `{state.signed_apk}`")
    print_ok(f"APK assinado: {state.signed_apk}")
    return state.signed_apk
