from __future__ import annotations

from pathlib import Path

from dexstrike.manifest import get_package_name
from dexstrike.signer import cert_sha256, detect_alias_with_keytool, sign_with_keystore, zipalign_file
from dexstrike.state import AppState
from dexstrike.utils import (
    ToolError,
    ensure_dir,
    print_info,
    print_ok,
    print_warn,
    require_cmd,
    run_cmd,
)


def find_split_apks(base_apk: Path) -> list[Path]:
    """Localiza os split APKs ao lado do base (``split*.apk`` / ``*.config.*.apk``)."""
    base = base_apk.resolve()
    splits: list[Path] = []
    for candidate in sorted(base.parent.glob("*.apk")):
        if candidate.resolve() == base:
            continue
        name = candidate.name.lower()
        if name.startswith("split") or name.startswith("config.") or ".config." in name:
            splits.append(candidate)
    return splits


def verify_uniform_signature(apks: list[Path]) -> tuple[bool, dict[str, str | None]]:
    """Verifica se todos os APKs compartilham o mesmo certificado de assinatura.

    Retorna (uniforme, {nome: digest_sha256}). ``uniforme`` é True somente quando
    todos têm digest e ele é idêntico — requisito do ``adb install-multiple``.
    """
    digests: dict[str, str | None] = {apk.name: cert_sha256(apk) for apk in apks}
    values = list(digests.values())
    uniform = bool(values) and None not in values and len(set(values)) == 1
    return uniform, digests


def _print_signature_table(title: str, digests: dict[str, str | None]) -> None:
    print_info(title)
    for name, digest in digests.items():
        print_info(f"  {name}: {digest or '??? (apksigner ausente ou não assinado)'}")


def verify_set_signature(apks: list[Path], *, title: str) -> bool:
    uniform, digests = verify_uniform_signature(apks)
    _print_signature_table(title, digests)
    if uniform:
        print_ok("Todos os APKs compartilham o MESMO certificado.")
    else:
        print_warn("Assinaturas divergentes ou ausentes — install-multiple iria falhar.")
    return uniform


def sign_split_set(state: AppState, *, use_original_base: bool = False) -> list[Path]:
    """Assina o base + splits com a MESMA keystore em ``outputs/signed/``.

    Por padrão reaproveita o base patcheado já assinado (``state.signed_apk``).
    Com ``use_original_base=True`` re-assina o base ORIGINAL (sem patch) — útil
    quando só se quer instalar um conjunto base+splits de terceiros com a sua
    chave. Cada split é sempre re-assinado com a mesma chave. Retorna a lista de
    APKs assinados (base primeiro).
    """
    if not state.apk_path:
        raise ToolError("APK base não configurado.")
    if not state.keystore_path.exists():
        raise ToolError(f"Keystore não encontrado: {state.keystore_path}")

    state.refresh_paths()
    assert state.signed_dir is not None
    ensure_dir(state.signed_dir)

    alias = detect_alias_with_keytool(state.keystore_path, state.keystore_password) or state.key_alias
    state.key_alias = alias

    splits = find_split_apks(state.apk_path)
    if not splits:
        print_warn("Nenhum split encontrado ao lado do base. Vou assinar apenas o base.")

    signed_base = state.signed_dir / "base.apk"
    if use_original_base:
        # Base original -> zipalign + assina com a nossa chave.
        aligned = state.signed_dir / "aligned-base.apk"
        zipalign_file(state.apk_path, aligned)
        tool = sign_with_keystore(aligned, signed_base, state.keystore_path, state.keystore_password, alias)
        if aligned.exists() and aligned != signed_base:
            aligned.unlink()
        state.log_patch(f"Base original re-assinado com {tool}: `{signed_base}`")
        print_ok(f"Base original re-assinado: {signed_base}")
    else:
        if not state.signed_apk or not state.signed_apk.exists():
            raise ToolError(
                "Base patcheado ainda não assinado. Rode build+sign (8 e 9 ou o pipeline 10), "
                "ou escolha re-assinar o base ORIGINAL."
            )
        # Base patcheado (já alinhado/assinado) -> copia para a pasta do conjunto.
        signed_base.write_bytes(state.signed_apk.read_bytes())
        print_ok(f"Base patcheado incluído no conjunto: {signed_base}")
    signed: list[Path] = [signed_base]

    for split in splits:
        aligned = state.signed_dir / f"aligned-{split.name}"
        zipalign_file(split, aligned)
        out = state.signed_dir / split.name
        tool = sign_with_keystore(aligned, out, state.keystore_path, state.keystore_password, alias)
        if aligned.exists() and aligned != out:
            aligned.unlink()
        signed.append(out)
        state.log_patch(f"Split assinado com {tool}: `{out}`")
        print_ok(f"Split assinado: {split.name}")

    state.signed_split_apks = signed
    return signed


def install_split_set(state: AppState, *, replace: bool = True, uninstall_first: bool = False) -> None:
    """Instala o conjunto base + splits via ``adb install-multiple``."""
    require_cmd("adb")
    apks = state.signed_split_apks
    if not apks:
        raise ToolError("Assine o conjunto base+splits primeiro (opção 16).")

    if uninstall_first:
        package = None
        if state.decoded_dir and state.decoded_dir.exists():
            try:
                package = get_package_name(state.decoded_dir)
            except ToolError:
                package = None
        if package:
            print_info(f"Desinstalando versão existente de {package} (apaga dados)...")
            run_cmd(["adb", "uninstall", package], check=False)
        else:
            print_warn("Package name não resolvido; pulei o uninstall prévio.")

    # --no-incremental evita a tentativa de install-incremental (que falha com
    # traceback Java em muitos emuladores antes de cair no modo normal).
    cmd = ["adb", "install-multiple", "--no-incremental"]
    if replace:
        cmd.append("-r")
    cmd.extend(str(apk) for apk in apks)
    run_cmd(cmd)
    print_ok(f"Conjunto base + {len(apks) - 1} split(s) instalado via adb install-multiple.")
