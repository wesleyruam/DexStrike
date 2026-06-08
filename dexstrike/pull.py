from __future__ import annotations

from pathlib import Path

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


def list_third_party_packages() -> list[str]:
    """Lista os pacotes de terceiros instalados no device (``pm list packages -3``)."""
    require_cmd("adb")
    result = run_cmd(["adb", "shell", "pm", "list", "packages", "-3"], check=False)
    if result.returncode != 0:
        raise ToolError("Falha ao listar pacotes. Há um device conectado e autorizado? (adb devices)")
    pkgs: list[str] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("package:"):
            pkgs.append(line[len("package:"):].strip())
    return sorted(pkgs)


def get_apk_paths(package: str) -> list[str]:
    """Retorna os caminhos remotos do base + splits (``pm path <pkg>``)."""
    require_cmd("adb")
    result = run_cmd(["adb", "shell", "pm", "path", package], check=False)
    if result.returncode != 0 or "package:" not in (result.stdout or ""):
        raise ToolError(f"Não consegui resolver os caminhos de {package} no device.")
    paths: list[str] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("package:"):
            paths.append(line[len("package:"):].strip())
    return paths


def pull_package(state: AppState, package: str, dest_dir: Path) -> Path:
    """Baixa base + splits de ``package`` para ``dest_dir`` e configura o state.

    Renomeia o APK base para ``base.apk`` e mantém os nomes originais dos splits
    (geralmente ``split_config.*.apk``), para que ``find_split_apks`` os encontre.
    Retorna o caminho local do base.
    """
    require_cmd("adb")
    remote_paths = get_apk_paths(package)
    if not remote_paths:
        raise ToolError(f"Nenhum APK encontrado para {package}.")

    ensure_dir(dest_dir)
    print_info(f"{len(remote_paths)} APK(s) remoto(s) para {package}.")

    local_base: Path | None = None
    splits: list[Path] = []
    for remote in remote_paths:
        remote_name = remote.rsplit("/", 1)[-1]
        is_base = "base" in remote_name.lower() or remote_name.lower() == f"{package}.apk".lower()
        local_name = "base.apk" if is_base else remote_name
        dest = dest_dir / local_name
        run_cmd(["adb", "pull", remote, str(dest)])
        if is_base and local_base is None:
            local_base = dest
        else:
            splits.append(dest)

    if local_base is None:
        # Sem nome "base" óbvio: assume o primeiro como base.
        first = dest_dir / remote_paths[0].rsplit("/", 1)[-1]
        local_base = dest_dir / "base.apk"
        if first.exists() and first != local_base:
            first.rename(local_base)
        if local_base in splits:
            splits.remove(local_base)

    state.apk_path = local_base
    state.project_dir = local_base.parent
    state.refresh_paths()
    print_ok(f"Base salvo em: {local_base}")
    if splits:
        print_ok(f"{len(splits)} split(s) baixado(s): " + ", ".join(s.name for s in splits))
    else:
        print_warn("Nenhum split encontrado — app de APK único.")
    return local_base
