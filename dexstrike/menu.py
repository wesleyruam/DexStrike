from __future__ import annotations

import traceback
from pathlib import Path

from dexstrike.apktool import build_apk, decompile_apk
from dexstrike.detector import KNOWN_ABIS, run_detection
from dexstrike.device import adb_install
from dexstrike.frida import choose_abis_interactive, copy_frida_scripts, inject_frida_gadget
from dexstrike.manifest import (
    ensure_network_security_config,
    set_cleartext_traffic,
    set_debuggable,
    set_extract_native_libs,
)
from dexstrike.report import generate_report
from dexstrike.signer import sign_apk, zipalign_apk
from dexstrike.smali import inject_frida_load_library, show_injection_targets
from dexstrike.state import AppState
from dexstrike.utils import ToolError, ask, ask_yes_no, ensure_dir, print_header, print_info, print_ok, print_warn


class MenuApp:
    def __init__(self) -> None:
        self.state = AppState()
        self.state.refresh_paths()

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

        inject_frida_gadget(self.state, abis=abis, write_config=True)
        inject_frida_load_library(self.state)
        copy_frida_scripts(self.state)
        build_apk(self.state)
        zipalign_apk(self.state)
        sign_apk(self.state)
        generate_report(self.state)

        print_header("Concluído")
        print_ok(f"APK final: {self.state.signed_apk}")
        print_ok(f"Relatório: {self.state.report_path}")
