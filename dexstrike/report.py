from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from dexstrike.manifest import find_application_class, find_launcher_activity
from dexstrike.state import AppState
from dexstrike.utils import ensure_dir, print_ok


def generate_report(state: AppState) -> Path:
    state.refresh_paths()
    assert state.report_path is not None
    ensure_dir(state.report_path.parent)

    app_cls = None
    launcher = None
    if state.decoded_dir and state.decoded_dir.exists():
        try:
            app_cls = find_application_class(state.decoded_dir)
            launcher = find_launcher_activity(state.decoded_dir)
        except Exception:
            pass

    lines = [
        "# DexStrike - Relatório de Patch",
        "",
        f"Gerado em: `{datetime.now().isoformat(timespec='seconds')}`",
        "",
        "## Arquivos",
        "",
        f"- APK original: `{state.apk_path}`",
        f"- Diretório descompilado: `{state.decoded_dir}`",
        f"- APK unsigned: `{state.unsigned_apk}`",
        f"- APK aligned: `{state.aligned_apk}`",
        f"- APK signed: `{state.signed_apk}`",
        "",
        "## Manifest / alvos",
        "",
        f"- Application class: `{app_cls or 'não encontrada/declarada'}`",
        f"- Launcher Activity: `{launcher or 'não encontrada'}`",
        "",
        "## Frida",
        "",
        f"- Frida Gadget version: `{state.frida_version}`",
        f"- ABIs detectadas: `{', '.join(state.detected_abis) if state.detected_abis else 'nenhuma'}`",
        f"- ABIs selecionadas: `{', '.join(state.selected_abis) if state.selected_abis else 'nenhuma'}`",
        "",
        "## Patches aplicados",
        "",
    ]

    if state.patch_log:
        lines.extend([f"- {item}" for item in state.patch_log])
    else:
        lines.append("- Nenhum patch registrado.")

    lines.extend([
        "",
        "## Notas úteis",
        "",
        "Conectando no Gadget em modo listen, normalmente você pode usar algo como:",
        "",
        "```bash",
        "frida -U Gadget -l outputs/frida-scripts/config.js -l outputs/frida-scripts/android-certificate-unpinning.js",
        "```",
        "",
        "Ou carregar o bundle único:",
        "",
        "```bash",
        "frida -U Gadget -l outputs/frida-scripts/ssl-unpinning-bundle.js",
        "```",
        "",
    ])

    if state.notes:
        lines.extend([f"- {item}" for item in state.notes])
        lines.append("")

    lines.extend([
        "## Estado JSON",
        "",
        "```json",
        json.dumps(state.as_dict(), indent=2, ensure_ascii=False),
        "```",
        "",
    ])

    state.report_path.write_text("\n".join(lines), encoding="utf-8")
    print_ok(f"Relatório gerado: {state.report_path}")
    return state.report_path
