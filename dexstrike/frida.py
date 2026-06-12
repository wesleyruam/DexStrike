from __future__ import annotations

import base64
import json
import lzma
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from dexstrike.detector import KNOWN_ABIS, detect_abis
from dexstrike.state import AppState
from dexstrike.utils import (
    ToolError,
    check,
    copy_file,
    ensure_dir,
    human_size,
    print_info,
    print_ok,
    print_warn,
    which,
)

GADGET_PORT = 27042

# Nome do JS embutido ao lado do gadget no modo "script". É JS, mas nomeado
# ``.so`` para que o instalador o extraia junto com as libs nativas — assim o
# Gadget resolve o ``path`` relativo e roda o script sozinho no boot do app.
SCRIPT_LIB_NAME = "libfridascript.so"


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

    Usa ``frida -U`` (tunelado pelo adb): é o caminho padrão e funciona em
    dispositivo USB e em emulador adb. Evita o backend de socket ``-H``, cujo
    helper local falha em sistemas com ``ptrace_scope=1`` (erro de portal ao
    abrir ``/proc/<pid>/root``).
    """
    return f"frida -U Gadget {scripts}"


def gadget_connect_hint_remote(scripts: str = "-l outputs/frida-scripts/config.js -l outputs/frida-scripts/android-certificate-unpinning.js") -> str:
    """Fallback via forward + ``-H`` para quando ``frida -U`` não acha o device.

    Usa ``-n`` (attach por nome): o Gadget vive num app já em execução e só pode
    ser atachado — alvo posicional faz o frida tentar SPAWN e falhar. Em sistemas
    com ``ptrace_scope=1`` o helper local do ``-H`` falha; rode antes
    ``sudo sysctl kernel.yama.ptrace_scope=0`` ou prefira o ``-U``.
    """
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


def write_gadget_config(
    lib_dir: Path,
    *,
    mode: str = "listen",
    on_load: str = "resume",
    script_name: str = SCRIPT_LIB_NAME,
) -> Path:
    """Escreve o ``libfrida-gadget.config.so``.

    ``mode='listen'`` espera ``frida -U`` depois; ``mode='script'`` faz o Gadget
    carregar e executar ``script_name`` sozinho no boot (autoload).
    """
    if mode == "script":
        config = {"interaction": {"type": "script", "path": script_name, "on_change": "reload"}}
    else:
        config = {"interaction": {"type": "listen", "address": "127.0.0.1", "port": GADGET_PORT, "on_load": on_load}}
    path = lib_dir / "libfrida-gadget.config.so"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def load_ca_pem(path: Path) -> str:
    """Lê uma CA de ``path`` (PEM ou DER) e devolve o bloco PEM.

    Aceita o arquivo exportado do Burp tanto em ``Certificate in PEM format``
    quanto o ``cacert.der`` — converte DER → PEM sem dependências externas.
    """
    data = Path(path).expanduser().read_bytes()
    text = data.decode("latin-1", errors="ignore")
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    if begin in text and end in text:
        return text[text.index(begin): text.index(end) + len(end)]
    # Assume DER: empacota como PEM.
    b64 = base64.encodebytes(data).decode("ascii").strip()
    return f"{begin}\n{b64}\n{end}"


def render_config_js(
    *,
    ca_pem: str | None = None,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
    debug: bool = False,
) -> str:
    """Devolve o ``config.js`` do httptoolkit com a CA do proxy e host/porta cravados."""
    config_js = (ASSET_DIR / "config.js").read_text(encoding="utf-8")
    if ca_pem:
        config_js = re.sub(
            r"const CERT_PEM = `[\s\S]*?`;",
            "const CERT_PEM = `" + ca_pem.strip() + "`;",
            config_js,
            count=1,
        )
    config_js = re.sub(r"const PROXY_HOST = '[^']*';", f"const PROXY_HOST = '{proxy_host}';", config_js, count=1)
    config_js = re.sub(r"const PROXY_PORT = \d+;", f"const PROXY_PORT = {proxy_port};", config_js, count=1)
    if debug:
        config_js = re.sub(r"const DEBUG_MODE = (?:true|false);", "const DEBUG_MODE = true;", config_js, count=1)
    return config_js


def build_unpinning_bundle(
    *,
    ca_pem: str | None = None,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
    debug: bool = False,
) -> str:
    """Monta ``config.js`` + ``android-certificate-unpinning.js`` num único JS."""
    config_js = render_config_js(ca_pem=ca_pem, proxy_host=proxy_host, proxy_port=proxy_port, debug=debug)
    unpin_js = (ASSET_DIR / "android-certificate-unpinning.js").read_text(encoding="utf-8")
    return config_js + "\n\n// ===== android-certificate-unpinning.js =====\n\n" + unpin_js


def inject_frida_gadget(
    state: AppState,
    *,
    abis: list[str] | None = None,
    mode: str = "listen",
    ca_pem: str | None = None,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8080,
    debug: bool = False,
) -> list[Path]:
    """Baixa e injeta o Frida Gadget em cada ABI.

    ``mode='listen'`` (padrão): gadget escuta na 27042 (conecte com ``frida -U``).
    ``mode='script'``: embute ``config.js``+``unpinning.js`` como ``libfridascript.so``
    ao lado do gadget e configura o Gadget para rodar o script sozinho no boot
    (autoload do SSL unpinning + redirect pro proxy, sem ``frida -U``).
    """
    if not state.decoded_dir:
        raise ToolError("decoded_dir não configurado.")
    if mode not in {"listen", "script"}:
        raise ToolError(f"Modo de gadget inválido: {mode}")

    detected = detect_abis(state.decoded_dir)
    state.detected_abis = detected

    if abis is None:
        abis = detected
    if not abis:
        raise ToolError("Nenhuma ABI selecionada para injeção do Frida Gadget.")

    warn_on_version_mismatch(state)

    bundle = None
    if mode == "script":
        bundle = build_unpinning_bundle(
            ca_pem=ca_pem, proxy_host=proxy_host, proxy_port=proxy_port, debug=debug
        )

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

        cfg = write_gadget_config(lib_dir, mode=mode)
        if mode == "script":
            assert bundle is not None
            (lib_dir / SCRIPT_LIB_NAME).write_text(bundle, encoding="utf-8")
        state.log_patch(f"Config do Frida Gadget ({mode}) criada em `{cfg}`")

        _validate_gadget_injection(lib_dir, mode=mode)

    state.selected_abis = abis
    _write_outputs_scripts(state, ca_pem=ca_pem, proxy_host=proxy_host, proxy_port=proxy_port, debug=debug)

    if mode == "script":
        state.note("Gadget em modo SCRIPT (autoload): o unpinning roda sozinho no boot do app.")
        state.note(f"Garanta o proxy: `adb reverse tcp:{proxy_port} tcp:{proxy_port}` (device -> seu Burp/proxy).")
        if not ca_pem:
            state.note("CERT_PEM não foi trocado — o proxy precisa usar a CA de exemplo, senão o TLS falha.")
    else:
        state.note("Gadget em modo LISTEN. Conecte com: `" + gadget_connect_hint() + "`")
        state.note("Se o `-U` não achar o device, fallback: `" + gadget_connect_hint_remote() + "`")

    print_ok(f"Frida Gadget ({mode}) injetado em: " + ", ".join(abis))
    return installed


def _validate_gadget_injection(lib_dir: Path, *, mode: str) -> None:
    """Confere que o gadget (e o script, no modo script) ficaram no lugar certo."""
    gadget = lib_dir / "libfrida-gadget.so"
    cfg = lib_dir / "libfrida-gadget.config.so"
    print_info(f"Validação da injeção em {lib_dir.name}:")
    ok = check(gadget.exists() and gadget.stat().st_size > 1_000_000,
               f"gadget.so OK ({human_size(gadget.stat().st_size) if gadget.exists() else '0'})",
               "libfrida-gadget.so ausente ou pequeno demais")
    ok = check(cfg.exists() and mode in cfg.read_text(encoding="utf-8"),
               f"config.so OK (modo {mode})", "config do gadget ausente/errado") and ok
    if mode == "script":
        scr = lib_dir / SCRIPT_LIB_NAME
        ok = check(scr.exists() and scr.stat().st_size > 1000,
                   f"{SCRIPT_LIB_NAME} OK ({human_size(scr.stat().st_size) if scr.exists() else '0'})",
                   f"{SCRIPT_LIB_NAME} (script JS) ausente") and ok
    if not ok:
        raise ToolError("Validação da injeção do gadget falhou.")


def _write_outputs_scripts(
    state: AppState,
    *,
    ca_pem: str | None,
    proxy_host: str,
    proxy_port: int,
    debug: bool,
) -> None:
    """Grava os scripts (com CA/proxy aplicados) em ``outputs/frida-scripts`` para
    referência e para uso com ``frida -U -l`` no modo listen."""
    out = ensure_dir(state.output_dir / "frida-scripts")
    copy_file(ASSET_DIR / "android-certificate-unpinning.js", out / "android-certificate-unpinning.js")
    config_js = render_config_js(ca_pem=ca_pem, proxy_host=proxy_host, proxy_port=proxy_port, debug=debug)
    (out / "config.js").write_text(config_js, encoding="utf-8")
    bundle = build_unpinning_bundle(ca_pem=ca_pem, proxy_host=proxy_host, proxy_port=proxy_port, debug=debug)
    (out / "ssl-unpinning-bundle.js").write_text(bundle, encoding="utf-8")
    state.log_patch("Scripts Frida (config aplicado) gravados em `outputs/frida-scripts`")
