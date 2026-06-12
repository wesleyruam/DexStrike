from __future__ import annotations

import base64
import json
from pathlib import Path

from dexstrike.frida import (
    SCRIPT_LIB_NAME,
    build_unpinning_bundle,
    load_ca_pem,
    write_gadget_config,
)

SAMPLE_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "TUlJQmtUQ0NBVGVnQXdJQkFnSVVEdW1teQ==\n"
    "-----END CERTIFICATE-----"
)


def test_write_gadget_config_script_mode(tmp_path: Path) -> None:
    cfg = write_gadget_config(tmp_path, mode="script")
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["interaction"]["type"] == "script"
    assert data["interaction"]["path"] == SCRIPT_LIB_NAME
    assert data["interaction"]["on_change"] == "reload"


def test_write_gadget_config_listen_mode(tmp_path: Path) -> None:
    cfg = write_gadget_config(tmp_path, mode="listen")
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["interaction"]["type"] == "listen"
    assert data["interaction"]["port"] == 27042


def test_bundle_substitutes_ca_and_proxy() -> None:
    bundle = build_unpinning_bundle(
        ca_pem=SAMPLE_PEM, proxy_host="10.0.2.2", proxy_port=9999, debug=True
    )
    assert "const PROXY_HOST = '10.0.2.2';" in bundle
    assert "const PROXY_PORT = 9999;" in bundle
    assert "const DEBUG_MODE = true;" in bundle
    assert SAMPLE_PEM in bundle
    # precisa conter os DOIS scripts (config + unpinning)
    assert "CERT_PEM" in bundle
    assert "android-certificate-unpinning.js" in bundle


def test_load_ca_pem_from_pem(tmp_path: Path) -> None:
    p = tmp_path / "burp.pem"
    p.write_text("lixo antes\n" + SAMPLE_PEM + "\nlixo depois", encoding="utf-8")
    out = load_ca_pem(p)
    assert out.startswith("-----BEGIN CERTIFICATE-----")
    assert out.endswith("-----END CERTIFICATE-----")
    assert "lixo" not in out


def test_load_ca_pem_from_der(tmp_path: Path) -> None:
    der = bytes(range(60))  # bytes binários quaisquer (não-PEM)
    p = tmp_path / "cacert.der"
    p.write_bytes(der)
    out = load_ca_pem(p)
    assert out.startswith("-----BEGIN CERTIFICATE-----")
    body = out.split("\n", 1)[1].rsplit("\n", 1)[0]
    assert base64.b64decode(body) == der
