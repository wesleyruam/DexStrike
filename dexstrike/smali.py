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


_VOID_METHOD_RE = re.compile(r"^\.method\s+.*?\b([A-Za-z_$][\w$]*)\([^)]*\)V\s*$")


def _void_method_name(line: str) -> str | None:
    match = _VOID_METHOD_RE.match(line.strip())
    return match.group(1) if match else None


def _method_end(lines: list[str], start: int) -> int:
    for j in range(start + 1, len(lines)):
        if lines[j].strip() == ".end method":
            return j
    raise ToolError("Método sem .end method correspondente.")


def _body_insertion_index(lines: list[str], start: int, end: int) -> int | None:
    """Índice da primeira instrução executável, pulando diretivas de cabeçalho.

    Pula ``.locals``/``.registers``, blocos ``.annotation``/``.param`` e
    ``.prologue``/linhas em branco, de modo que um ``return-void`` inserido fique
    válido (depois dos metadados do método e antes do código).
    """
    seen_regs = False
    i = start + 1
    while i < end:
        stripped = lines[i].strip()
        if stripped.startswith(".locals") or stripped.startswith(".registers"):
            seen_regs = True
            i += 1
        elif stripped.startswith(".annotation"):
            while i < end and lines[i].strip() != ".end annotation":
                i += 1
            i += 1
        elif stripped.startswith(".param"):
            # Forma em bloco termina com `.end param`; one-liner não.
            j = i + 1
            is_block = False
            while j < end:
                sj = lines[j].strip()
                if sj == ".end param":
                    is_block = True
                    break
                if sj and not sj.startswith(".annotation") and not sj.startswith(".end annotation"):
                    break
                j += 1
            i = j + 1 if is_block else i + 1
        elif stripped == "" or stripped.startswith(".prologue"):
            i += 1
        else:
            break
    if not seen_regs:
        return None
    return i


def neuter_void_method(lines: list[str], start: int, end: int) -> bool:
    """Insere ``return-void`` no início do corpo do método (no-op). Idempotente."""
    insert_at = _body_insertion_index(lines, start, end)
    if insert_at is None:
        return False
    if lines[insert_at].strip() == "return-void":
        return False
    lines[insert_at:insert_at] = ["    return-void"]
    return True


def neuter_methods(smali_file: Path, name_regex: str) -> list[str]:
    """Transforma em no-op todos os métodos ``void`` cujo nome casa ``name_regex``.

    Retorna os nomes efetivamente neutralizados (vazio se nada mudou).
    """
    text = smali_file.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    pattern = re.compile(name_regex)

    neutered: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].lstrip().startswith(".method"):
            end = _method_end(lines, i)
            name = _void_method_name(lines[i])
            if name and pattern.match(name) and neuter_void_method(lines, i, end):
                neutered.append(name)
                end = _method_end(lines, i)  # recalcula após inserir a linha
            i = end + 1
        else:
            i += 1

    if neutered:
        smali_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return neutered


def show_injection_targets(state: AppState) -> None:
    if not state.decoded_dir:
        print_warn("Descompile o APK primeiro.")
        return
    app_cls = find_application_class(state.decoded_dir)
    launcher_cls = find_launcher_activity(state.decoded_dir)
    print_info(f"Application class: {app_cls or 'não declarada'}")
    print_info(f"Launcher activity: {launcher_cls or 'não encontrada'}")
