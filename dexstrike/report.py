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
        "## Proteções de licença / anti-tamper",
        "",
        f"- Detectadas: `{', '.join(state.detected_protections) if state.detected_protections else 'nenhuma'}`",
        "",
        "## Splits / install-multiple",
        "",
    ]

    if state.signed_split_apks:
        lines.append("Conjunto assinado com a mesma keystore (instale com `adb install-multiple`):")
        lines.append("")
        lines.extend([f"- `{apk}`" for apk in state.signed_split_apks])
        lines.append("")
        lines.append("```bash")
        lines.append("adb install-multiple -r " + " ".join(str(apk) for apk in state.signed_split_apks))
        lines.append("```")
    else:
        lines.append("- Nenhum conjunto de splits assinado nesta sessão.")
    lines.extend([
        "",
        "## Patches aplicados",
        "",
    ])

    if state.patch_log:
        lines.extend([f"- {item}" for item in state.patch_log])
    else:
        lines.append("- Nenhum patch registrado.")

    lines.extend([
        "",
        "## Notas úteis",
        "",
        "Gadget em modo listen na porta 27042. Forma confiável (funciona em "
        "emulador adb-TCP e em USB) — forward + `-H`:",
        "",
        "```bash",
        "adb forward tcp:27042 tcp:27042",
        "frida -H 127.0.0.1:27042 Gadget -l outputs/frida-scripts/config.js -l outputs/frida-scripts/android-certificate-unpinning.js",
        "```",
        "",
        "Ou o bundle único:",
        "",
        "```bash",
        "frida -H 127.0.0.1:27042 Gadget -l outputs/frida-scripts/ssl-unpinning-bundle.js",
        "```",
        "",
        "Em dispositivo USB físico, `frida -U Gadget -l ...` também funciona. "
        "Em emulador conectado via `adb connect`, prefira o `-H` acima — o `-U` "
        "não enxerga o device. A versão do Frida CLI precisa bater com a do Gadget "
        f"(`{state.frida_version}`): `pip install --user 'frida=={state.frida_version}'`.",
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
