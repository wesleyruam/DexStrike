from __future__ import annotations

import traceback
from pathlib import Path

from dexstrike.apktool import build_apk, decompile_apk
from dexstrike.detector import KNOWN_ABIS, run_detection
from dexstrike.device import adb_install
from dexstrike.frida import choose_abis_interactive, copy_frida_scripts, inject_frida_gadget
from dexstrike.license_check import apply_license_bypass, report_license_protections
from dexstrike.manifest import (
    ensure_network_security_config,
    set_cleartext_traffic,
    set_debuggable,
    set_extract_native_libs,
)
from dexstrike.pull import list_third_party_packages, pull_package
from dexstrike.report import generate_report
from dexstrike.signer import sign_apk, zipalign_apk
from dexstrike.smali import inject_frida_load_library, show_injection_targets
from dexstrike.splits import (
    find_split_apks,
    install_split_set,
    sign_split_set,
    verify_set_signature,
)
from dexstrike.state import PROJECT_FILENAME, AppState
from dexstrike.utils import ToolError, ask, ask_yes_no, ensure_dir, print_header, print_info, print_ok, print_warn


class MenuApp:
    def __init__(self) -> None:
        self.state = AppState()
        self._autoload_project()
        self.state.refresh_paths()

    def _autoload_project(self) -> None:
        """Carrega um ``dexstrike.json`` do diretório atual, se existir."""
        candidate = Path.cwd() / PROJECT_FILENAME
        if candidate.exists() and self.state.load_project(candidate):
            print_ok(f"Projeto carregado de {candidate}")

    def _save_project(self) -> None:
        saved = self.state.save_project()
        if saved:
            print_info(f"Projeto salvo em {saved}")

    def run(self) -> None:
        print_header("DexStrike — APK Rev Eng Toolkit")
        print("Ferramenta para pesquisa autorizada em APKs: patch de Manifest, Frida Gadget, rebuild e assinatura.")

        while True:
            self._show_status()
            self._show_menu()
            choice = input("Escolha: ").strip()
            try:
                if choice == "1":
                    self.configure_project()
                elif choice == "2":
                    self.decompile()
                elif choice == "3":
                    self.patch_manifest_basic()
                elif choice == "4":
                    self.detect()
                elif choice == "5":
                    self.inject_frida_gadget_menu()
                elif choice == "6":
                    self.inject_load_library()
                elif choice == "7":
                    self.copy_scripts()
                elif choice == "8":
                    self.build()
                elif choice == "9":
                    self.sign()
                elif choice == "10":
                    self.full_pipeline()
                elif choice == "11":
                    self.install()
                elif choice == "12":
                    self.report()
                elif choice == "13":
                    show_injection_targets(self.state)
                elif choice == "14":
                    self.detect_protections()
                elif choice == "15":
                    self.bypass_license_check()
                elif choice == "16":
                    self.split_sign_install()
                elif choice == "17":
                    self.pull_from_device()
                elif choice == "0":
                    print_ok("Saindo.")
                    return
                else:
                    print_warn("Opção inválida.")
            except KeyboardInterrupt:
                print_warn("Operação cancelada pelo usuário.")
            except ToolError as exc:
                print_warn(str(exc))
            except Exception as exc:  # noqa: BLE001
                print_warn(f"Erro inesperado: {exc}")
                if ask_yes_no("Mostrar traceback?", default=False):
                    traceback.print_exc()

    def _show_status(self) -> None:
        print("\n--- Status ---")
        print(f"APK: {self.state.apk_path or 'não configurado'}")
        print(f"Decoded: {self.state.decoded_dir or 'não configurado'}")
        print(f"Frida: {self.state.frida_version}")
        print(f"Keystore: {self.state.keystore_path} | alias: {self.state.key_alias} | senha: {'*' * len(self.state.keystore_password)}")
        print(f"Signed APK: {self.state.signed_apk or 'não gerado'}")

    def _show_menu(self) -> None:
        print("\n--- Menu ---")
        print(" 1) Configurar APK/keystore/versão do Frida")
        print(" 2) Descompilar APK")
        print(" 3) Aplicar patches básicos no Manifest")
        print("    - networkSecurityConfig")
        print("    - extractNativeLibs=true")
        print("    - usesCleartextTraffic=true opcional")
        print("    - debuggable=true opcional")
        print(" 4) Detectar ABIs/frameworks/libs/components")
        print(" 5) Baixar e injetar Frida Gadget")
        print(" 6) Injetar System.loadLibrary('frida-gadget') no smali")
        print(" 7) Copiar scripts Frida SSL/unpinning")
        print(" 8) Rebuild com apktool")
        print(" 9) Zipalign + assinar APK")
        print("10) Rodar pipeline completo recomendado")
        print("11) Instalar APK assinado via adb")
        print("12) Gerar relatório")
        print("13) Mostrar alvos de injeção detectados")
        print("14) Detectar proteções de licença/anti-tamper (PairIP/LVL)")
        print("15) Bypass de License Check (PairIP) no smali")
        print("16) Verificar assinatura + assinar splits + install-multiple")
        print("17) Baixar APK base + splits do device (adb pull)")
        print(" 0) Sair")

    def configure_project(self) -> None:
        apk_default = str(self.state.apk_path) if self.state.apk_path else ""
        apk_raw = ask("Caminho do APK", apk_default if apk_default else None)
        if apk_raw:
            apk = Path(apk_raw).expanduser()
            if not apk.exists():
                raise ToolError(f"APK não encontrado: {apk}")
            self.state.apk_path = apk
            self.state.refresh_paths()

        ks_default = str(self.state.keystore_path)
        ks_raw = ask("Caminho da keystore", ks_default)
        if ks_raw:
            self.state.keystore_path = Path(ks_raw).expanduser()

        self.state.keystore_password = ask("Senha da keystore", self.state.keystore_password)
        self.state.key_alias = ask("Alias da key", self.state.key_alias)
        self.state.frida_version = ask("Versão do Frida Gadget", self.state.frida_version)
        self.state.workdir = Path(ask("Diretório de trabalho", str(self.state.workdir))).expanduser()
        self.state.output_dir = Path(ask("Diretório de saída", str(self.state.output_dir))).expanduser()
        self.state.downloads_dir = Path(ask("Diretório de downloads/cache", str(self.state.downloads_dir))).expanduser()
        self.state.refresh_paths()
        self._save_project()
        print_ok("Configuração atualizada.")

    def _ensure_apk(self) -> None:
        if not self.state.apk_path:
            raw = ask("Caminho do APK")
            apk = Path(raw).expanduser()
            if not apk.exists():
                raise ToolError(f"APK não encontrado: {apk}")
            self.state.apk_path = apk
            self.state.refresh_paths()

    def _ensure_decoded(self) -> None:
        if not self.state.decoded_dir or not self.state.decoded_dir.exists():
            raise ToolError("Descompile o APK primeiro.")

    def decompile(self) -> None:
        self._ensure_apk()
        force = ask_yes_no("Se já existir pasta descompilada, apagar e recriar?", default=True)
        decompile_apk(self.state, force=force)

    def patch_manifest_basic(self) -> None:
        self._ensure_decoded()
        ensure_network_security_config(self.state, force_attr=True)
        set_extract_native_libs(self.state, True)
        if ask_yes_no("Também definir android:usesCleartextTraffic=true?", default=True):
            set_cleartext_traffic(self.state, True)
        if ask_yes_no("Também definir android:debuggable=true?", default=False):
            set_debuggable(self.state, True)

    def detect(self) -> None:
        self._ensure_decoded()
        run_detection(self.state)
        report_license_protections(self.state)

    def detect_protections(self) -> None:
        self._ensure_decoded()
        report_license_protections(self.state)

    def bypass_license_check(self) -> None:
        self._ensure_decoded()
        apply_license_bypass(self.state)
        print_info("Lembre de rebuildar (8), assinar (9) e reinstalar para valer o bypass.")

    def split_sign_install(self) -> None:
        self._ensure_apk()
        splits = find_split_apks(self.state.apk_path)
        if splits:
            print_info(f"{len(splits)} split(s) encontrado(s) ao lado do base: " + ", ".join(s.name for s in splits))
            verify_set_signature([self.state.apk_path, *splits], title="Assinatura do conjunto ORIGINAL:")
        else:
            print_warn("Nenhum split encontrado ao lado do base.")

        use_original_base = self._decide_base_source()
        if use_original_base is None:
            return

        signed = sign_split_set(self.state, use_original_base=use_original_base)
        uniform = verify_set_signature(signed, title="Assinatura do conjunto RE-ASSINADO:")
        if not uniform:
            print_warn("Conjunto não uniforme; corrija a keystore/alias antes de instalar.")
            return
        if ask_yes_no("Instalar agora via adb install-multiple?", default=True):
            uninstall = ask_yes_no("Desinstalar versão existente antes (apaga dados)?", default=True)
            install_split_set(self.state, uninstall_first=uninstall)

    def _decide_base_source(self) -> bool | None:
        """Decide qual base usar no conjunto. Retorna True p/ base ORIGINAL,
        False p/ base PATCHEADO, ou None para cancelar."""
        patched_ready = bool(self.state.signed_apk and self.state.signed_apk.exists())
        if patched_ready:
            if ask_yes_no(
                "Base PATCHEADO já assinado encontrado. Usar ele? (n = re-assinar o base ORIGINAL)",
                default=True,
            ):
                return False
            return True

        # Sem base patcheado assinado ainda.
        decoded_ready = bool(self.state.decoded_dir and self.state.decoded_dir.exists())
        if decoded_ready and ask_yes_no(
            "Há uma pasta descompilada mas o base patcheado não foi assinado. "
            "Rodar build + zipalign + sign agora?",
            default=True,
        ):
            build_apk(self.state)
            zipalign_apk(self.state)
            sign_apk(self.state)
            return False

        if not ask_yes_no(
            "Re-assinar o base ORIGINAL (sem patch) + splits com a sua keystore?",
            default=True,
        ):
            return None
        return True

    def pull_from_device(self) -> None:
        print_header("Baixar APK base + splits do device")
        packages = list_third_party_packages()
        if not packages:
            print_warn("Nenhum pacote de terceiros encontrado no device.")
            return

        filtro = ask("Filtrar pacotes por texto (enter = listar todos)", "")
        if filtro:
            packages = [p for p in packages if filtro.lower() in p.lower()]
        if not packages:
            print_warn("Nenhum pacote bate com o filtro.")
            return

        for i, pkg in enumerate(packages, 1):
            print(f" {i:3}) {pkg}")
        raw = ask("Número do pacote (ou digite o nome completo)")
        if not raw:
            return
        if raw.isdigit() and 1 <= int(raw) <= len(packages):
            package = packages[int(raw) - 1]
        else:
            package = raw.strip()

        dest_default = str((self.state.base_dir() / package))
        dest = Path(ask("Pasta de destino do projeto", dest_default)).expanduser()
        pull_package(self.state, package, dest)
        self._save_project()
        print_ok("Projeto pronto. Use a opção 16 para assinar o conjunto e instalar.")

    def inject_frida_gadget_menu(self) -> None:
        self._ensure_decoded()
        if not self.state.detected_abis:
            run_detection(self.state)
        abis = choose_abis_interactive(self.state.detected_abis)
        self.state.selected_abis = abis
        inject_frida_gadget(self.state, abis=abis, write_config=True)

    def inject_load_library(self) -> None:
        self._ensure_decoded()
        inject_frida_load_library(self.state)

    def copy_scripts(self) -> None:
        self._ensure_decoded()
        copy_frida_scripts(self.state)

    def build(self) -> None:
        self._ensure_decoded()
        build_apk(self.state)

    def sign(self) -> None:
        if not self.state.unsigned_apk or not self.state.unsigned_apk.exists():
            raise ToolError("Faça o rebuild primeiro.")
        zipalign_apk(self.state)
        sign_apk(self.state)

    def install(self) -> None:
        adb_install(self.state, replace=True)

    def report(self) -> None:
        generate_report(self.state)

    def full_pipeline(self) -> None:
        self._ensure_apk()
        print_header("Pipeline completo recomendado")
        print_info("Etapas: decompile -> Manifest -> detect -> Frida Gadget -> smali -> scripts -> build -> zipalign/sign -> report")

        force = ask_yes_no("Apagar pasta descompilada existente se houver?", default=True)
        decompile_apk(self.state, force=force)

        ensure_network_security_config(self.state, force_attr=True)
        set_extract_native_libs(self.state, True)

        if ask_yes_no("Ativar usesCleartextTraffic=true?", default=True):
            set_cleartext_traffic(self.state, True)
        if ask_yes_no("Ativar debuggable=true?", default=False):
            set_debuggable(self.state, True)

        run_detection(self.state)
        abis = self.state.detected_abis
        if not abis:
            print_warn("Nenhuma ABI detectada em lib/. Se o APK não tiver libs nativas, escolha a ABI do dispositivo manualmente.")
            abis = choose_abis_interactive([])
        self.state.selected_abis = abis

        protections = report_license_protections(self.state)
        if any(p.bypass_key for p in protections) and ask_yes_no(
            "Aplicar bypass automático de License Check detectado?", default=True
        ):
            apply_license_bypass(self.state)

        inject_frida_gadget(self.state, abis=abis, write_config=True)
        inject_frida_load_library(self.state)
        copy_frida_scripts(self.state)
        build_apk(self.state)
        zipalign_apk(self.state)
        sign_apk(self.state)

        splits = find_split_apks(self.state.apk_path)
        if splits:
            print_info(f"{len(splits)} split(s) detectado(s) ao lado do base.")
            if ask_yes_no("Assinar splits com a mesma chave e preparar install-multiple?", default=True):
                signed = sign_split_set(self.state)
                if verify_set_signature(signed, title="Assinatura do conjunto RE-ASSINADO:") and ask_yes_no(
                    "Instalar agora via adb install-multiple?", default=False
                ):
                    uninstall = ask_yes_no("Desinstalar versão existente antes (apaga dados)?", default=True)
                    install_split_set(self.state, uninstall_first=uninstall)

        generate_report(self.state)

        print_header("Concluído")
        print_ok(f"APK final: {self.state.signed_apk}")
        print_ok(f"Relatório: {self.state.report_path}")
