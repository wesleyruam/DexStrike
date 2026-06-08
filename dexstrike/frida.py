from __future__ import annotations

import json
import lzma
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from dexstrike.detector import KNOWN_ABIS, detect_abis
from dexstrike.state import AppState
from dexstrike.utils import ToolError, copy_file, ensure_dir, print_info, print_ok, print_warn, which

GADGET_PORT = 27042


def installed_frida_version() -> str | None:
    """Retorna a versão do ``frida`` CLI instalado, ou None se ausente."""
    exe = which("frida")
    if not exe:
        return None
    try:
        result = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    out = (result.stdout or "").strip()
    return out or None


def warn_on_version_mismatch(state: AppState) -> None:
    """Avisa se o Frida CLI instalado difere da versão do Gadget a injetar.

    Um mismatch de versão entre CLI e Gadget faz o attach falhar. O Gadget já
    está sendo injetado nesta versão, então a correção mais leve é alinhar o CLI.
    """
    cli = installed_frida_version()
    if cli and cli != state.frida_version:
        print_warn(
            f"Frida CLI instalado é {cli}, mas o Gadget é {state.frida_version} — versões "
            "precisam bater para conectar."
        )
        print_warn(
            f"Alinhe com: pip install --user 'frida=={state.frida_version}'  "
            f"(ou configure a versão do Gadget para {cli} na opção 1 antes de injetar)."
        )


def gadget_connect_hint(scripts: str = "-l outputs/frida-scripts/config.js -l outputs/frida-scripts/android-certificate-unpinning.js") -> str:
    """Comando recomendado para conectar no Gadget em modo listen.

    Usa forward + ``-H`` (funciona em emulador adb-TCP e em USB), pois ``frida -U``
    falha em emuladores conectados via ``adb connect`` (não aparecem como device USB).
    """
    # -n (attach por nome), NÃO posicional: o Gadget é embarcado num app já em
    # execução e só pode ser atachado; passar o alvo posicional faz o frida tentar
    # SPAWN e falhar com "Failed to spawn".
    return (
        f"adb forward tcp:{GADGET_PORT} tcp:{GADGET_PORT} && "
        f"frida -H 127.0.0.1:{GADGET_PORT} -n Gadget {scripts}"
    )

FRIDA_PLATFORM_BY_ABI = {
    "armeabi-v7a": "android-arm",
    "arm64-v8a": "android-arm64",
    "x86": "android-x86",
    "x86_64": "android-x86_64",
}

ASSET_DIR = Path(__file__).resolve().parent / "assets" / "frida"


def frida_gadget_url(version: str, abi: str) -> str:
    platform = FRIDA_PLATFORM_BY_ABI.get(abi)
    if not platform:
        raise ToolError(f"ABI não suportada para Frida Gadget: {abi}")
    return (
        f"https://github.com/frida/frida/releases/download/{version}/"
        f"frida-gadget-{version}-{platform}.so.xz"
    )


def choose_abis_interactive(detected: list[str]) -> list[str]:
    if detected:
        print_info("ABIs detectadas no APK: " + ", ".join(detected))
        value = input("Usar todas as ABIs detectadas? [S/n]: ").strip().lower()
        if value in {"", "s", "sim", "y", "yes"}:
            return detected

    print("\nEscolha as ABIs manualmente, separadas por vírgula:")
    for i, abi in enumerate(KNOWN_ABIS, start=1):
        print(f"  {i}) {abi}")
    raw = input("ABIs [1,2,3,4 ou nomes]: ").strip()
    if not raw:
        raise ToolError("Nenhuma ABI selecionada.")

    selected: list[str] = []
    for part in [p.strip() for p in raw.split(",") if p.strip()]:
        if part.isdigit():
            idx = int(part) - 1
            if idx < 0 or idx >= len(KNOWN_ABIS):
                raise ToolError(f"Índice de ABI inválido: {part}")
            selected.append(KNOWN_ABIS[idx])
        elif part in KNOWN_ABIS:
            selected.append(part)
        else:
            raise ToolError(f"ABI inválida: {part}")
    return selected


def _download_xz(url: str, dest: Path) -> Path:
    ensure_dir(dest.parent)
    if dest.exists() and dest.stat().st_size > 0:
        print_info(f"Usando cache: {dest}")
        return dest

    print_info(f"Baixando: {url}")
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with urllib.request.urlopen(url) as response, tmp.open("wb") as out:
            shutil.copyfileobj(response, out)
    except urllib.error.HTTPError as exc:
        tmp.unlink(missing_ok=True)
        if exc.code == 404:
            raise ToolError(
                f"Frida Gadget não encontrado (HTTP 404): {url}\n"
                "Verifique se a versão do Frida configurada existe nas releases do GitHub."
            ) from exc
        raise ToolError(f"Falha HTTP {exc.code} ao baixar Frida Gadget: {url}") from exc
    except urllib.error.URLError as exc:
        tmp.unlink(missing_ok=True)
        raise ToolError(f"Falha de rede ao baixar Frida Gadget: {exc.reason}") from exc

    if tmp.stat().st_size == 0:
        tmp.unlink(missing_ok=True)
        raise ToolError(f"Download vazio do Frida Gadget: {url}")
    tmp.replace(dest)
    return dest


def _decompress_xz(src: Path, dst: Path) -> None:
    ensure_dir(dst.parent)
    try:
        with lzma.open(src, "rb") as inp, dst.open("wb") as out:
            shutil.copyfileobj(inp, out)
    except lzma.LZMAError as exc:
        # Cache corrompido: remove para forçar novo download na próxima vez.
        src.unlink(missing_ok=True)
        raise ToolError(
            f"Arquivo .xz inválido ({src}). Cache removido, tente novamente."
        ) from exc


def write_gadget_config(lib_dir: Path, *, on_load: str = "resume") -> Path:
    config = {
        "interaction": {
            "type": "listen",
            "address": "127.0.0.1",
            "port": 27042,
            "on_load": on_load,
        }
    }
    path = lib_dir / "libfrida-gadget.config.so"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def inject_frida_gadget(state: AppState, *, abis: list[str] | None = None, write_config: bool = True) -> list[Path]:
    if not state.decoded_dir:
        raise ToolError("decoded_dir não configurado.")

    detected = detect_abis(state.decoded_dir)
    state.detected_abis = detected

    if abis is None:
        abis = detected
    if not abis:
        raise ToolError("Nenhuma ABI selecionada para injeção do Frida Gadget.")

    warn_on_version_mismatch(state)

    installed: list[Path] = []
    for abi in abis:
        if abi not in FRIDA_PLATFORM_BY_ABI:
            raise ToolError(f"ABI não suportada: {abi}")
        url = frida_gadget_url(state.frida_version, abi)
        xz_path = state.downloads_dir / f"frida-gadget-{state.frida_version}-{FRIDA_PLATFORM_BY_ABI[abi]}.so.xz"
        downloaded = _download_xz(url, xz_path)
        lib_dir = ensure_dir(state.decoded_dir / "lib" / abi)
        gadget_path = lib_dir / "libfrida-gadget.so"
        _decompress_xz(downloaded, gadget_path)
        installed.append(gadget_path)
        state.log_patch(f"Frida Gadget {state.frida_version} injetado em `{gadget_path}`")
        if write_config:
            cfg = write_gadget_config(lib_dir)
            state.log_patch(f"Config do Frida Gadget criada em `{cfg}`")

    state.selected_abis = abis
    print_ok("Frida Gadget injetado em: " + ", ".join(abis))
    return installed


def copy_frida_scripts(state: AppState) -> None:
    if not state.decoded_dir:
        raise ToolError("decoded_dir não configurado.")

    output_scripts = ensure_dir(state.output_dir / "frida-scripts")
    decoded_assets = ensure_dir(state.decoded_dir / "assets" / "frida")

    config_js = ASSET_DIR / "config.js"
    unpin_js = ASSET_DIR / "android-certificate-unpinning.js"
    if not config_js.exists() or not unpin_js.exists():
        print_warn("Scripts Frida não encontrados em dexstrike/assets/frida.")
        return

    for src in [config_js, unpin_js]:
        copy_file(src, output_scripts / src.name)
        copy_file(src, decoded_assets / src.name)

    bundle = output_scripts / "ssl-unpinning-bundle.js"
    bundle.write_text(
        config_js.read_text(encoding="utf-8")
        + "\n\n// ---- android-certificate-unpinning.js ----\n\n"
        + unpin_js.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    state.log_patch("Scripts Frida copiados para `outputs/frida-scripts` e `assets/frida` dentro do APK descompilado")
    state.note("Gadget em modo listen. Conecte com: `" + gadget_connect_hint() + "`")
    state.note("Em emulador (adb-TCP) o `frida -U` não acha o device; use o forward + `-H` acima.")
    print_ok("Scripts Frida copiados e bundle gerado.")
