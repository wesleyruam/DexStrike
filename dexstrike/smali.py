from __future__ import annotations

import re
from pathlib import Path

from dexstrike.manifest import find_application_class, find_launcher_activity
from dexstrike.state import AppState
from dexstrike.utils import ToolError, print_info, print_ok, print_warn


LOAD_LIBRARY_CODE = [
    '    const-string v0, "frida-gadget"',
    '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V',
    '',
]


def class_to_smali_rel(class_name: str) -> Path:
    return Path(*class_name.split(".")).with_suffix(".smali")


def find_smali_file(decoded_dir: Path, class_name: str) -> Path | None:
    rel = class_to_smali_rel(class_name)
    for smali_root in sorted(decoded_dir.glob("smali*")):
        if not smali_root.is_dir():
            continue
        candidate = smali_root / rel
        if candidate.exists():
            return candidate
    return None


def _get_super_descriptor(lines: list[str]) -> str:
    for line in lines:
        if line.startswith(".super "):
            return line.split(None, 1)[1].strip()
    return "Ljava/lang/Object;"


def _find_method_bounds(lines: list[str], method_name: str, descriptor: str) -> tuple[int, int] | None:
    method_re = re.compile(rf"^\.method\s+.*\b{re.escape(method_name)}\({re.escape(descriptor)}\)V\s*$")
    start = None
    for i, line in enumerate(lines):
        if method_re.match(line):
            start = i
            break
    if start is None:
        return None
    for j in range(start + 1, len(lines)):
        if lines[j].strip() == ".end method":
            return start, j
    raise ToolError(f"Método {method_name} encontrado, mas sem .end method")


def _ensure_register_capacity(lines: list[str], start: int, end: int, *, min_locals: int, min_registers: int) -> int:
    for i in range(start + 1, end):
        stripped = lines[i].strip()
        if stripped.startswith(".locals "):
            current = int(stripped.split()[1])
            if current < min_locals:
                indent = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
                lines[i] = f"{indent}.locals {min_locals}"
            return i
        if stripped.startswith(".registers "):
            current = int(stripped.split()[1])
            if current < min_registers:
                indent = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
                lines[i] = f"{indent}.registers {min_registers}"
            return i
    raise ToolError("Não encontrei .locals nem .registers no método alvo.")


def _method_contains_load(lines: list[str], start: int, end: int) -> bool:
    body = "\n".join(lines[start:end])
    return '"frida-gadget"' in body and "System;->loadLibrary" in body


def _patch_existing_method(lines: list[str], start: int, end: int, *, kind: str) -> bool:
    if _method_contains_load(lines, start, end):
        return False

    if kind == "application":
        reg_line = _ensure_register_capacity(lines, start, end, min_locals=1, min_registers=2)
    else:
        reg_line = _ensure_register_capacity(lines, start, end, min_locals=1, min_registers=3)

    insert_at = reg_line + 1
    lines[insert_at:insert_at] = LOAD_LIBRARY_CODE[:]
    return True


def _create_on_create(lines: list[str], *, kind: str) -> None:
    super_desc = _get_super_descriptor(lines)
    if kind == "application":
        method = [
            "",
            ".method public onCreate()V",
            "    .locals 1",
            "",
            *LOAD_LIBRARY_CODE,
            f"    invoke-super {{p0}}, {super_desc}->onCreate()V",
            "",
            "    return-void",
            ".end method",
            "",
        ]
    else:
        method = [
            "",
            ".method protected onCreate(Landroid/os/Bundle;)V",
            "    .locals 1",
            "",
            *LOAD_LIBRARY_CODE,
            f"    invoke-super {{p0, p1}}, {super_desc}->onCreate(Landroid/os/Bundle;)V",
            "",
            "    return-void",
            ".end method",
            "",
        ]

    try:
        end_class = max(i for i, line in enumerate(lines) if line.strip() == ".end class")
        lines[end_class:end_class] = method
    except ValueError:
        lines.extend(method)


def patch_smali_file(smali_file: Path, *, kind: str) -> bool:
    text = smali_file.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()

    if kind == "application":
        bounds = _find_method_bounds(lines, "onCreate", "")
    else:
        bounds = _find_method_bounds(lines, "onCreate", "Landroid/os/Bundle;")

    changed = False
    if bounds:
        changed = _patch_existing_method(lines, bounds[0], bounds[1], kind=kind)
    else:
        _create_on_create(lines, kind=kind)
        changed = True

    if changed:
        smali_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return changed


def inject_frida_load_library(state: AppState) -> Path:
    if not state.decoded_dir:
        raise ToolError("decoded_dir não configurado.")

    candidates: list[tuple[str, str]] = []
    app_cls = find_application_class(state.decoded_dir)
    launcher_cls = find_launcher_activity(state.decoded_dir)

    if app_cls:
        candidates.append(("application", app_cls))
    if launcher_cls:
        candidates.append(("activity", launcher_cls))

    if not candidates:
        raise ToolError("Não encontrei Application nem LAUNCHER Activity no Manifest.")

    attempted: list[str] = []
    for kind, cls in candidates:
        attempted.append(f"{kind}:{cls}")
        smali_file = find_smali_file(state.decoded_dir, cls)
        if not smali_file:
            print_warn(f"Classe declarada no Manifest, mas smali não encontrado: {cls}")
            continue
        changed = patch_smali_file(smali_file, kind=kind)
        state.log_patch(
            f"Frida loadLibrary {'injetado' if changed else 'já existia'} em `{smali_file}` ({kind}: {cls})"
        )
        print_ok(f"System.loadLibrary('frida-gadget') aplicado em {smali_file}")
        return smali_file

    raise ToolError("Não consegui localizar arquivo smali alvo. Tentativas: " + ", ".join(attempted))


def show_injection_targets(state: AppState) -> None:
    if not state.decoded_dir:
        print_warn("Descompile o APK primeiro.")
        return
    app_cls = find_application_class(state.decoded_dir)
    launcher_cls = find_launcher_activity(state.decoded_dir)
    print_info(f"Application class: {app_cls or 'não declarada'}")
    print_info(f"Launcher activity: {launcher_cls or 'não encontrada'}")
