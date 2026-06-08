from __future__ import annotations

from pathlib import Path

from dexstrike.license_check import (
    apply_license_bypass,
    bypass_pairip_licensecheck,
    detect_license_protections,
)
from dexstrike.smali import neuter_methods
from dexstrike.state import AppState

# LicenseClient reduzido do PairIP: startPaywallActivity (com annotation de
# MethodParameters, recebe argumento) e startErrorDialogActivity (sem args),
# além de um método benigno que NÃO deve ser tocado.
LICENSE_CLIENT_SMALI = """.class public Lcom/pairip/licensecheck/LicenseClient;
.super Ljava/lang/Object;


.method private startErrorDialogActivity()V
    .locals 3

    .line 546
    invoke-direct {p0}, Lcom/pairip/licensecheck/LicenseClient;->scheduleAppShutdown()V

    iget-object v1, p0, Lcom/pairip/licensecheck/LicenseClient;->context:Landroid/content/Context;

    invoke-virtual {v1, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    return-void
.end method

.method private startPaywallActivity(Landroid/app/PendingIntent;)V
    .locals 2
    .annotation system Ldalvik/annotation/MethodParameters;
        accessFlags = {
            0x0
        }
        names = {
            "paywallIntent"
        }
    .end annotation

    .line 538
    invoke-direct {p0}, Lcom/pairip/licensecheck/LicenseClient;->scheduleAppShutdown()V

    iget-object p1, p0, Lcom/pairip/licensecheck/LicenseClient;->context:Landroid/content/Context;

    invoke-virtual {p1, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V

    return-void
.end method

.method public initializeLicenseCheck()V
    .locals 1

    .line 175
    invoke-direct {p0}, Lcom/pairip/licensecheck/LicenseClient;->connectToLicensingService()V

    return-void
.end method
.end class
"""


def _make_pairip(decoded_dir: Path) -> Path:
    target = decoded_dir / "smali" / "com" / "pairip" / "licensecheck"
    target.mkdir(parents=True)
    smali = target / "LicenseClient.smali"
    smali.write_text(LICENSE_CLIENT_SMALI, encoding="utf-8")
    return smali


def test_detects_pairip_licensecheck(decoded_dir: Path) -> None:
    _make_pairip(decoded_dir)
    found = detect_license_protections(decoded_dir)
    names = [p.name for p in found]
    assert any("PairIP License Check" in n for n in names)


def test_bypass_neuters_blocking_methods(decoded_dir: Path) -> None:
    smali = _make_pairip(decoded_dir)
    patched, methods = bypass_pairip_licensecheck(decoded_dir)

    assert smali in patched
    assert set(methods) == {"startPaywallActivity", "startErrorDialogActivity"}

    body = smali.read_text(encoding="utf-8")
    # startActivity nunca mais é alcançado: return-void inserido antes do corpo.
    assert body.count("return-void") == 5  # 2 inseridos + 3 originais
    # método benigno preservado (sem return-void extra logo após .locals).
    assert "connectToLicensingService" in body


def test_bypass_is_idempotent(decoded_dir: Path) -> None:
    smali = _make_pairip(decoded_dir)
    assert bypass_pairip_licensecheck(decoded_dir)[1]  # primeira passada altera
    second = bypass_pairip_licensecheck(decoded_dir)[1]
    assert second == []  # nada a fazer na segunda
    assert smali.read_text(encoding="utf-8").count("return-void") == 5


def test_paywall_returns_before_start_activity(decoded_dir: Path) -> None:
    smali = _make_pairip(decoded_dir)
    bypass_pairip_licensecheck(decoded_dir)
    lines = smali.read_text(encoding="utf-8").splitlines()
    start = next(i for i, ln in enumerate(lines) if "startPaywallActivity" in ln and ".method" in ln)
    ret = next(i for i in range(start, len(lines)) if lines[i].strip() == "return-void")
    act = next(i for i in range(start, len(lines)) if "startActivity" in lines[i])
    assert ret < act  # o return-void vem antes do startActivity (no-op efetivo)


def test_neuter_methods_only_matches_regex(decoded_dir: Path) -> None:
    smali = _make_pairip(decoded_dir)
    neutered = neuter_methods(smali, r"^startPaywallActivity$")
    assert neutered == ["startPaywallActivity"]
    # o método de erro continua intacto (1 return-void original, nenhum inserido)


def test_apply_bypass_updates_state(decoded_dir: Path) -> None:
    _make_pairip(decoded_dir)
    st = AppState()
    st.decoded_dir = decoded_dir
    apply_license_bypass(st)
    assert any("PairIP License Check" in p for p in st.detected_protections)
    assert any("PairIP License Check neutralizado" in entry for entry in st.patch_log)
