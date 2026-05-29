from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Sequence


class ToolError(RuntimeError):
    pass


def print_header(title: str) -> None:
    bar = "=" * max(60, len(title) + 8)
    print(f"\n{bar}\n  {title}\n{bar}")


def print_ok(msg: str) -> None:
    print(f"[+] {msg}")


def print_warn(msg: str) -> None:
    print(f"[!] {msg}")


def print_info(msg: str) -> None:
    print(f"[*] {msg}")


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def require_cmd(cmd: str) -> str:
    found = which(cmd)
    if not found:
        raise ToolError(f"Comando obrigatório não encontrado no PATH: {cmd}")
    return found


def run_cmd(
    cmd: Sequence[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd_str = [str(c) for c in cmd]
    print_info("Executando: " + " ".join(cmd_str))
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        result = subprocess.run(
            cmd_str,
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=merged_env,
        )
    except FileNotFoundError as exc:
        raise ToolError(f"Comando não encontrado no PATH: {cmd_str[0]}") from exc
    if result.stdout and result.stdout.strip():
        print(result.stdout)
    if check and result.returncode != 0:
        raise ToolError(f"Comando falhou com código {result.returncode}: {' '.join(cmd_str)}")
    return result


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value if value else (default or "")


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    hint = "S/n" if default else "s/N"
    value = input(f"{prompt} [{hint}]: ").strip().lower()
    if not value:
        return default
    return value in {"s", "sim", "y", "yes", "1", "true"}


def copy_file(src: Path, dst: Path) -> None:
    ensure_dir(dst.parent)
    shutil.copy2(src, dst)


def relative_to_cwd(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path.resolve())


def dedupe_keep_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
