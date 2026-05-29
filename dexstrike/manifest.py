from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from dexstrike.state import AppState
from dexstrike.utils import ToolError, ensure_dir, print_ok, print_warn

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ET.register_namespace("android", ANDROID_NS)

_XMLNS_RE = re.compile(r'xmlns:([A-Za-z0-9_.\-]+)\s*=\s*"([^"]+)"')


def a(name: str) -> str:
    return f"{{{ANDROID_NS}}}{name}"


def manifest_path(decoded_dir: Path) -> Path:
    path = decoded_dir / "AndroidManifest.xml"
    if not path.exists():
        raise ToolError(f"AndroidManifest.xml não encontrado em {decoded_dir}")
    return path


def _register_manifest_namespaces(path: Path) -> None:
    """Registra todos os prefixos xmlns do manifesto.

    O ElementTree só preserva o prefixo de um namespace se ele estiver
    registrado globalmente; caso contrário ele reescreve como ``ns0:``,
    ``ns1:`` etc. e o apktool falha ao recompilar. Por isso registramos
    cada ``xmlns:prefixo`` declarado no manifesto antes de fazer o parse.
    """
    text = path.read_text(encoding="utf-8", errors="ignore")
    for prefix, uri in _XMLNS_RE.findall(text):
        ET.register_namespace(prefix, uri)


def parse_manifest(decoded_dir: Path) -> tuple[ET.ElementTree, ET.Element, ET.Element, Path]:
    path = manifest_path(decoded_dir)
    _register_manifest_namespaces(path)
    tree = ET.parse(path)
    root = tree.getroot()
    app = root.find("application")
    if app is None:
        raise ToolError("Tag <application> não encontrada no AndroidManifest.xml")
    return tree, root, app, path


def save_manifest(tree: ET.ElementTree, path: Path) -> None:
    try:
        ET.indent(tree, space="    ")
    except Exception:
        pass
    tree.write(path, encoding="utf-8", xml_declaration=True)


def ensure_network_security_config(state: AppState, *, force_attr: bool = False) -> None:
    if not state.decoded_dir:
        raise ToolError("decoded_dir não configurado.")

    tree, _root, app, path = parse_manifest(state.decoded_dir)
    current = app.get(a("networkSecurityConfig"))
    if current and current != "@xml/network_security_config" and not force_attr:
        print_warn(
            f"Manifest já possui android:networkSecurityConfig={current!r}. "
            "Mantendo valor existente."
        )
    else:
        app.set(a("networkSecurityConfig"), "@xml/network_security_config")
        save_manifest(tree, path)
        state.log_patch("Adicionado/ajustado `android:networkSecurityConfig=\"@xml/network_security_config\"`")

    xml_dir = ensure_dir(state.decoded_dir / "res" / "xml")
    config_path = xml_dir / "network_security_config.xml"
    config_content = """<?xml version=\"1.0\" encoding=\"utf-8\"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src=\"system\" />
            <certificates src=\"user\" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""
    config_path.write_text(config_content, encoding="utf-8")
    state.log_patch("Criado `res/xml/network_security_config.xml` confiando em certificados system + user")
    print_ok("network_security_config aplicado.")


def set_extract_native_libs(state: AppState, value: bool = True) -> None:
    if not state.decoded_dir:
        raise ToolError("decoded_dir não configurado.")
    tree, _root, app, path = parse_manifest(state.decoded_dir)
    app.set(a("extractNativeLibs"), "true" if value else "false")
    save_manifest(tree, path)
    state.log_patch(f"Definido `android:extractNativeLibs=\"{'true' if value else 'false'}\"`")
    print_ok(f"extractNativeLibs definido como {value}.")


def set_debuggable(state: AppState, value: bool = True) -> None:
    if not state.decoded_dir:
        raise ToolError("decoded_dir não configurado.")
    tree, _root, app, path = parse_manifest(state.decoded_dir)
    app.set(a("debuggable"), "true" if value else "false")
    save_manifest(tree, path)
    state.log_patch(f"Definido `android:debuggable=\"{'true' if value else 'false'}\"`")
    print_ok(f"debuggable definido como {value}.")


def set_cleartext_traffic(state: AppState, value: bool = True) -> None:
    if not state.decoded_dir:
        raise ToolError("decoded_dir não configurado.")
    tree, _root, app, path = parse_manifest(state.decoded_dir)
    app.set(a("usesCleartextTraffic"), "true" if value else "false")
    save_manifest(tree, path)
    state.log_patch(f"Definido `android:usesCleartextTraffic=\"{'true' if value else 'false'}\"`")
    print_ok(f"usesCleartextTraffic definido como {value}.")


def get_package_name(decoded_dir: Path) -> str:
    tree, root, _app, _path = parse_manifest(decoded_dir)
    _ = tree
    package = root.get("package")
    if not package:
        raise ToolError("Atributo package não encontrado no AndroidManifest.xml")
    return package


def normalize_class_name(package: str, class_name: str) -> str:
    class_name = class_name.strip()
    if class_name.startswith("."):
        return package + class_name
    if "." not in class_name:
        return package + "." + class_name
    return class_name


def find_application_class(decoded_dir: Path) -> str | None:
    _tree, root, app, _path = parse_manifest(decoded_dir)
    package = root.get("package") or ""
    name = app.get(a("name"))
    if not name:
        return None
    return normalize_class_name(package, name)


def find_launcher_activity(decoded_dir: Path) -> str | None:
    _tree, root, app, _path = parse_manifest(decoded_dir)
    package = root.get("package") or ""

    activity_tags = []
    for tag_name in ("activity", "activity-alias"):
        activity_tags.extend(app.findall(tag_name))

    for activity in activity_tags:
        for intent_filter in activity.findall("intent-filter"):
            has_main = False
            has_launcher = False
            for action in intent_filter.findall("action"):
                if action.get(a("name")) == "android.intent.action.MAIN":
                    has_main = True
            for category in intent_filter.findall("category"):
                if category.get(a("name")) == "android.intent.category.LAUNCHER":
                    has_launcher = True
            if has_main and has_launcher:
                target = activity.get(a("targetActivity")) or activity.get(a("name"))
                if target:
                    return normalize_class_name(package, target)
    return None
