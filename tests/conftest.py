from __future__ import annotations

from pathlib import Path

import pytest

MANIFEST = """<?xml version='1.0' encoding='utf-8'?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools"
    package="com.example.app"
    platformBuildVersionCode="34">
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:name=".MyApp" android:label="Example" tools:ignore="GoogleAppIndexingWarning">
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name=".SyncService" />
    </application>
</manifest>
"""

APP_SMALI = """.class public Lcom/example/app/MyApp;
.super Landroid/app/Application;


.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Application;-><init>()V
    return-void
.end method
.end class
"""

ACTIVITY_SMALI = """.class public Lcom/example/app/MainActivity;
.super Landroidx/appcompat/app/AppCompatActivity;


.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1

    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V

    return-void
.end method
.end class
"""


@pytest.fixture
def decoded_dir(tmp_path: Path) -> Path:
    """Cria uma árvore decodificada mínima, parecida com a saída do apktool."""
    root = tmp_path / "app_decoded"
    (root).mkdir()
    (root / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")

    app = root / "smali" / "com" / "example" / "app"
    app.mkdir(parents=True)
    (app / "MyApp.smali").write_text(APP_SMALI, encoding="utf-8")
    (app / "MainActivity.smali").write_text(ACTIVITY_SMALI, encoding="utf-8")

    # libs nativas em duas ABIs
    for abi in ("arm64-v8a", "armeabi-v7a"):
        (root / "lib" / abi).mkdir(parents=True)
        (root / "lib" / abi / "libapp.so").write_bytes(b"\x7fELF")

    # hint de framework em smali_classes3 (multidex) para testar o scan completo
    flutter = root / "smali_classes3" / "io" / "flutter"
    flutter.mkdir(parents=True)
    (flutter / "FlutterMain.smali").write_text(".class public Lio/flutter/FlutterMain;\n", encoding="utf-8")

    return root
