from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from dexstrike.detector import _scan_names
from dexstrike.smali import neuter_methods
from dexstrike.state import AppState
from dexstrike.utils import ToolError, print_info, print_ok, print_warn


@dataclass(frozen=True)
class Protection:
    name: str
    markers: tuple[str, ...]
    bypass_key: str | None  # chave do bypass automático, ou None
    note: str


# Proteções de licença / anti-tamper reconhecidas. As `markers` são trechos de
# caminho (em minúsculas) procurados na árvore descompilada (smali/lib/assets).
PROTECTIONS: tuple[Protection, ...] = (
    Protection(
        name="PairIP License Check (Google Play)",
        markers=("com/pairip/licensecheck", "com/pairip/licensecheck3"),
        bypass_key="pairip_licensecheck",
        note="Quando o APK é re-assinado, redireciona para a Play Store (paywall) "
        "ou mostra um dialog de erro e encerra o app. Bypass: neutraliza os "
        "métodos start*Activity de LicenseClient no smali.",
    ),
    Protection(
        name="PairIP VM Protection (nativa)",
        markers=("com/pairip/vmrunner", "libpairipcore.so"),
        bypass_key=None,
        note="Proteção nativa via libpairipcore.so / VMRunner. Pode cifrar o "
        "bytecode em runtime; não há bypass confiável via smali.",
    ),
    Protection(
        name="Google Play Licensing (LVL)",
        markers=("com/google/android/vending/licensing",),
        bypass_key=None,
        note="LVL clássico. O bypass depende de como o app trata o Policy/callback.",
    ),
)


def detect_license_protections(decoded_dir: Path) -> list[Protection]:
    haystack = "\n".join(_scan_names(decoded_dir)).lower()
    return [p for p in PROTECTIONS if any(m in haystack for m in p.markers)]


def report_license_protections(state: AppState) -> list[Protection]:
    if not state.decoded_dir or not state.decoded_dir.exists():
        print_warn("Descompile o APK antes de detectar proteções.")
        return []

    found = detect_license_protections(state.decoded_dir)
    if not found:
        print_info("Nenhuma proteção de licença/anti-tamper conhecida detectada.")
    else:
        for p in found:
            tag = "bypass automático disponível" if p.bypass_key else "sem bypass automático"
            print_warn(f"Proteção detectada: {p.name} ({tag})")
            print_info("  " + p.note)

    state.detected_protections = [p.name for p in found]
    state.log_patch("Detecção de proteções de licença: " + (", ".join(state.detected_protections) or "nenhuma"))
    return found


def _find_license_client_files(decoded_dir: Path) -> list[Path]:
    files: list[Path] = []
    for smali_root in sorted(decoded_dir.glob("smali*")):
        for sub in ("com/pairip/licensecheck", "com/pairip/licensecheck3"):
            client_dir = smali_root / sub
            if client_dir.is_dir():
                files.extend(sorted(client_dir.glob("LicenseClient*.smali")))
    return files


def bypass_pairip_licensecheck(decoded_dir: Path) -> tuple[list[Path], list[str]]:
    """Neutraliza o PairIP License Check.

    Transforma em no-op os métodos ``start*Activity`` de ``LicenseClient`` (ex.:
    ``startPaywallActivity`` e ``startErrorDialogActivity``), que são as únicas
    saídas que disparam o paywall/erro e o shutdown. Não toca na validação de
    assinatura do payload. Retorna (arquivos alterados, nomes de métodos).
    """
    targets = _find_license_client_files(decoded_dir)
    if not targets:
        raise ToolError("LicenseClient*.smali do PairIP não encontrado. O APK usa PairIP License Check?")

    patched: list[Path] = []
    methods: list[str] = []
    for smali_file in targets:
        neutered = neuter_methods(smali_file, r"^start.*Activity$")
        if neutered:
            patched.append(smali_file)
            methods.extend(neutered)
    return patched, methods


def apply_license_bypass(state: AppState) -> None:
    if not state.decoded_dir or not state.decoded_dir.exists():
        raise ToolError("Descompile o APK primeiro.")

    found = detect_license_protections(state.decoded_dir)
    state.detected_protections = [p.name for p in found]

    auto = [p for p in found if p.bypass_key]
    manual = [p for p in found if not p.bypass_key]

    if not found:
        print_info("Nenhuma proteção de licença detectada — nada a fazer.")
        return

    for protection in auto:
        if protection.bypass_key == "pairip_licensecheck":
            patched, methods = bypass_pairip_licensecheck(state.decoded_dir)
            if patched:
                for f in patched:
                    state.log_patch(
                        f"PairIP License Check neutralizado em `{f}` (métodos: {', '.join(methods)} -> return-void)"
                    )
                print_ok(
                    f"Bypass do PairIP aplicado: {', '.join(sorted(set(methods)))} -> no-op "
                    f"em {len(patched)} arquivo(s)."
                )
            else:
                print_warn("Métodos de bloqueio do PairIP não encontrados (ou já neutralizados).")

    for protection in manual:
        print_warn(f"{protection.name}: sem bypass automático.")
        print_info("  " + protection.note)
