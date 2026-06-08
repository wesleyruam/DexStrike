from __future__ import annotations

from pathlib import Path

from dexstrike.splits import find_split_apks, verify_uniform_signature


def _touch(path: Path) -> Path:
    path.write_bytes(b"PK\x03\x04")
    return path


def test_find_split_apks_picks_siblings(tmp_path: Path) -> None:
    base = _touch(tmp_path / "base.apk")
    _touch(tmp_path / "split_config.arm64_v8a.apk")
    _touch(tmp_path / "split_config.pt.apk")
    _touch(tmp_path / "config.xxhdpi.apk")
    _touch(tmp_path / "outro.apk")  # não é split, deve ser ignorado

    splits = find_split_apks(base)
    names = sorted(p.name for p in splits)
    assert names == ["config.xxhdpi.apk", "split_config.arm64_v8a.apk", "split_config.pt.apk"]
    assert base not in splits


def test_find_split_apks_empty_when_alone(tmp_path: Path) -> None:
    base = _touch(tmp_path / "base.apk")
    assert find_split_apks(base) == []


def test_verify_uniform_signature(monkeypatch) -> None:
    import dexstrike.splits as splits_mod

    digests = {
        Path("base.apk"): "aa",
        Path("split_a.apk"): "aa",
        Path("split_b.apk"): "aa",
    }
    monkeypatch.setattr(splits_mod, "cert_sha256", lambda apk: digests[apk])
    uniform, table = verify_uniform_signature(list(digests))
    assert uniform is True
    assert set(table.values()) == {"aa"}


def test_verify_detects_divergent_signature(monkeypatch) -> None:
    import dexstrike.splits as splits_mod

    digests = {Path("base.apk"): "aa", Path("split_a.apk"): "bb"}
    monkeypatch.setattr(splits_mod, "cert_sha256", lambda apk: digests[apk])
    uniform, _ = verify_uniform_signature(list(digests))
    assert uniform is False


def test_verify_detects_missing_signature(monkeypatch) -> None:
    import dexstrike.splits as splits_mod

    digests = {Path("base.apk"): "aa", Path("split_a.apk"): None}
    monkeypatch.setattr(splits_mod, "cert_sha256", lambda apk: digests[apk])
    uniform, _ = verify_uniform_signature(list(digests))
    assert uniform is False
