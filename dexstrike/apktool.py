from __future__ import annotations

import shutil
from pathlib import Path

from dexstrike.state import AppState
from dexstrike.utils import ToolError, ensure_dir, print_ok, require_cmd, run_cmd


def decompile_apk(state: AppState, *, force: bool = False) -> Path:
    if not state.apk_path:
        raise ToolError("APK de entrada não configurado.")
    state.refresh_paths()
    assert state.decoded_dir is not None

    require_cmd("apktool")
    ensure_dir(state.workdir)

    if state.decoded_dir.exists():
        if force:
            shutil.rmtree(state.decoded_dir)
        else:
            raise ToolError(
                f"Diretório já existe: {state.decoded_dir}. "
                "Use a opção de limpar/recompilar ou apague manualmente."
            )

    run_cmd(["apktool", "d", "-f", str(state.apk_path), "-o", str(state.decoded_dir)])
    state.log_patch(f"APK descompilado em `{state.decoded_dir}`")
    print_ok(f"APK descompilado: {state.decoded_dir}")
    return state.decoded_dir


def build_apk(state: AppState) -> Path:
    if not state.decoded_dir or not state.decoded_dir.exists():
        raise ToolError("APK ainda não foi descompilado ou decoded_dir não existe.")
    state.refresh_paths()
    assert state.unsigned_apk is not None

    require_cmd("apktool")
    ensure_dir(state.output_dir)
    run_cmd(["apktool", "b", str(state.decoded_dir), "-o", str(state.unsigned_apk)])
    state.log_patch(f"APK recompilado em `{state.unsigned_apk}`")
    print_ok(f"APK recompilado: {state.unsigned_apk}")
    return state.unsigned_apk
