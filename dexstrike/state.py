from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Diretórios resolvidos a partir da instalação da ferramenta (não do CWD), para
# que recursos empacotados como a keystore sejam encontrados de qualquer pasta.
PACKAGE_DIR = Path(__file__).resolve().parent
TOOL_ROOT = PACKAGE_DIR.parent
BUNDLED_KEYSTORE = TOOL_ROOT / "resources" / "key.jks"

# Arquivo de projeto gravado na pasta do APK; guarda a configuração entre runs.
PROJECT_FILENAME = "dexstrike.json"


@dataclass
class AppState:
    apk_path: Path | None = None
    project_dir: Path | None = None
    workdir: Path = Path("workspace")
    output_dir: Path = Path("outputs")
    downloads_dir: Path = Path("downloads")
    decoded_dir: Path | None = None
    unsigned_apk: Path | None = None
    aligned_apk: Path | None = None
    signed_apk: Path | None = None
    signed_dir: Path | None = None
    report_path: Path | None = None

    frida_version: str = "17.9.10"
    keystore_path: Path = BUNDLED_KEYSTORE
    keystore_password: str = "123456"
    key_alias: str = "key"

    detected_abis: list[str] = field(default_factory=list)
    selected_abis: list[str] = field(default_factory=list)
    detected_protections: list[str] = field(default_factory=list)
    signed_split_apks: list[Path] = field(default_factory=list)
    patch_log: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def apk_stem(self) -> str:
        if self.apk_path:
            return self.apk_path.stem
        return "app"

    def base_dir(self) -> Path:
        """Raiz do projeto: a pasta do APK (ou o CWD enquanto não há APK)."""
        if self.project_dir:
            return self.project_dir
        if self.apk_path:
            return self.apk_path.parent
        return Path.cwd()

    def _under_base(self, rel: Path) -> Path:
        return rel if rel.is_absolute() else self.base_dir() / rel

    def refresh_paths(self) -> None:
        if self.project_dir is None and self.apk_path is not None:
            self.project_dir = self.apk_path.parent
        stem = self.apk_stem()
        work = self._under_base(self.workdir)
        out = self._under_base(self.output_dir)
        self.decoded_dir = work / f"{stem}_decoded"
        self.unsigned_apk = out / f"{stem}-patched-unsigned.apk"
        self.aligned_apk = out / f"{stem}-patched-aligned.apk"
        self.signed_apk = out / f"{stem}-patched-signed.apk"
        self.signed_dir = out / "signed"
        self.report_path = out / f"{stem}-patch-report.md"

    # ------------------------------------------------------------------
    # Persistência do projeto (dexstrike.json na pasta do APK)
    # ------------------------------------------------------------------
    def project_file(self) -> Path:
        return self.base_dir() / PROJECT_FILENAME

    def save_project(self) -> Path | None:
        """Grava a configuração na pasta do projeto. Requer um APK definido."""
        if not self.apk_path:
            return None
        data = {
            "apk_path": str(self.apk_path),
            "frida_version": self.frida_version,
            "keystore_path": str(self.keystore_path),
            "keystore_password": self.keystore_password,
            "key_alias": self.key_alias,
            "detected_abis": self.detected_abis,
            "selected_abis": self.selected_abis,
        }
        path = self.project_file()
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def load_project(self, path: Path) -> bool:
        """Carrega configuração de um ``dexstrike.json``. Retorna sucesso."""
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        apk = data.get("apk_path")
        if apk:
            self.apk_path = Path(apk).expanduser()
            self.project_dir = self.apk_path.parent
        self.frida_version = data.get("frida_version", self.frida_version)
        if data.get("keystore_path"):
            self.keystore_path = Path(data["keystore_path"]).expanduser()
        self.keystore_password = data.get("keystore_password", self.keystore_password)
        self.key_alias = data.get("key_alias", self.key_alias)
        self.detected_abis = data.get("detected_abis", self.detected_abis)
        self.selected_abis = data.get("selected_abis", self.selected_abis)
        self.refresh_paths()
        return True

    def log_patch(self, message: str) -> None:
        self.patch_log.append(message)

    def note(self, message: str) -> None:
        self.notes.append(message)

    def as_dict(self) -> dict[str, Any]:
        return {
            "apk_path": str(self.apk_path) if self.apk_path else None,
            "decoded_dir": str(self.decoded_dir) if self.decoded_dir else None,
            "unsigned_apk": str(self.unsigned_apk) if self.unsigned_apk else None,
            "aligned_apk": str(self.aligned_apk) if self.aligned_apk else None,
            "signed_apk": str(self.signed_apk) if self.signed_apk else None,
            "signed_dir": str(self.signed_dir) if self.signed_dir else None,
            "frida_version": self.frida_version,
            "keystore_path": str(self.keystore_path),
            "key_alias": self.key_alias,
            "detected_abis": self.detected_abis,
            "selected_abis": self.selected_abis,
            "detected_protections": self.detected_protections,
            "signed_split_apks": [str(p) for p in self.signed_split_apks],
            "patch_log": self.patch_log,
            "notes": self.notes,
        }
