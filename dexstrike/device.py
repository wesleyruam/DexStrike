from __future__ import annotations

from dexstrike.state import AppState
from dexstrike.utils import ToolError, print_ok, require_cmd, run_cmd


def adb_install(state: AppState, *, replace: bool = True) -> None:
    if not state.signed_apk or not state.signed_apk.exists():
        raise ToolError("APK assinado não encontrado.")
    require_cmd("adb")
    cmd = ["adb", "install"]
    if replace:
        cmd.append("-r")
    cmd.append(str(state.signed_apk))
    run_cmd(cmd)
    print_ok("APK instalado via adb.")
