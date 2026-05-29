from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AppState:
    apk_path: Path | None = None
    workdir: Path = Path("workspace")
    output_dir: Path = Path("outputs")
    downloads_dir: Path = Path("downloads")
    decoded_dir: Path | None = None
    unsigned_apk: Path | None = None
    aligned_apk: Path | None = None
    signed_apk: Path | None = None
    report_path: Path | None = None

    frida_version: str = "17.9.10"
    keystore_path: Path = Path("resources/key.jks")
    keystore_password: str = "123456"
    key_alias: str = "key"

    detected_abis: list[str] = field(default_factory=list)
    selected_abis: list[str] = field(default_factory=list)
    patch_log: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def apk_stem(self) -> str:
        if self.apk_path:
            return self.apk_path.stem
        return "app"

    def refresh_paths(self) -> None:
        stem = self.apk_stem()
        self.decoded_dir = self.workdir / f"{stem}_decoded"
        self.unsigned_apk = self.output_dir / f"{stem}-patched-unsigned.apk"
        self.aligned_apk = self.output_dir / f"{stem}-patched-aligned.apk"
        self.signed_apk = self.output_dir / f"{stem}-patched-signed.apk"
        self.report_path = self.output_dir / f"{stem}-patch-report.md"

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
            "frida_version": self.frida_version,
            "keystore_path": str(self.keystore_path),
            "key_alias": self.key_alias,
            "detected_abis": self.detected_abis,
            "selected_abis": self.selected_abis,
            "patch_log": self.patch_log,
            "notes": self.notes,
        }
