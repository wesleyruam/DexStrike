#!/usr/bin/env python3
"""Gera os assets visuais do projeto (banner, pipeline e demo do terminal).

Estilo cyberpunk/neon. Produz SVGs em ``assets/img/``; converta para PNG com
``rsvg-convert`` (veja ``scripts/build_images.sh``).

Uso:
    python3 scripts/generate_assets.py
"""
from __future__ import annotations

import html
import random
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "assets" / "img"

# Paleta neon
BG0 = "#05070d"
BG1 = "#0a0f1c"
PANEL = "#070a12"
TXT = "#d7e0ea"
MUTED = "#62748c"
PINK = "#ff2e97"
CYAN = "#00eaff"
GREEN = "#39ff14"
PURPLE = "#b14bff"
YELLOW = "#ffd400"
ORANGE = "#ff7a18"
BORDER = "#1b2740"

MONO = "'DejaVu Sans Mono','Noto Sans Mono',monospace"
SANS = "'DejaVu Sans','Noto Sans',sans-serif"


def esc(text: str) -> str:
    return html.escape(text, quote=True)


def _defs() -> str:
    return f"""
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{BG1}"/>
      <stop offset="0.5" stop-color="{BG0}"/>
      <stop offset="1" stop-color="#0b0716"/>
    </linearGradient>
    <linearGradient id="neon" x1="0" y1="0" x2="1" y2="0.4">
      <stop offset="0" stop-color="{PINK}"/>
      <stop offset="0.45" stop-color="{PURPLE}"/>
      <stop offset="0.75" stop-color="{CYAN}"/>
      <stop offset="1" stop-color="{GREEN}"/>
    </linearGradient>
    <linearGradient id="bolt" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="{CYAN}"/>
      <stop offset="1" stop-color="{PINK}"/>
    </linearGradient>
    <radialGradient id="halo" cx="0.3" cy="0.4" r="0.8">
      <stop offset="0" stop-color="{PURPLE}" stop-opacity="0.30"/>
      <stop offset="0.5" stop-color="{PINK}" stop-opacity="0.10"/>
      <stop offset="1" stop-color="{BG0}" stop-opacity="0"/>
    </radialGradient>
    <filter id="glow" x="-60%" y="-60%" width="220%" height="220%">
      <feGaussianBlur stdDeviation="7" result="b"/>
      <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="glowSoft" x="-60%" y="-60%" width="220%" height="220%">
      <feGaussianBlur stdDeviation="3.2" result="b"/>
      <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>"""


def _matrix(w: int, h: int, *, seed: int = 1337, step: int = 24, opacity: float = 0.16) -> str:
    """Chuva de caracteres binários/hex ao fundo (estilo Matrix)."""
    rnd = random.Random(seed)
    glyphs = "01010110ABCDEF<>{}[]/\\$#x:;.+"
    cols = []
    for x in range(10, w, step):
        start = rnd.randint(-10, 6)
        length = rnd.randint(6, 22)
        col_op = opacity * rnd.uniform(0.4, 1.0)
        chars = []
        for k in range(length):
            y = (start + k) * 22
            if y < -10 or y > h + 10:
                continue
            ch = rnd.choice(glyphs)
            # cabeça do rastro mais clara/verde
            if k == length - 1:
                fill, op = "#adffce", min(1.0, col_op * 3)
            else:
                fill, op = GREEN, col_op * (0.25 + 0.75 * k / length)
            chars.append(
                f'<text x="{x}" y="{y}" fill="{fill}" fill-opacity="{op:.2f}" '
                f'font-family="{MONO}" font-size="15">{esc(ch)}</text>'
            )
        cols.append("".join(chars))
    return f'<g>{"".join(cols)}</g>'


def _scanlines(w: int, h: int, *, opacity: float = 0.05) -> str:
    lines = "".join(
        f'<rect x="0" y="{y}" width="{w}" height="1" fill="#ffffff" fill-opacity="{opacity}"/>'
        for y in range(0, h, 4)
    )
    return f"<g>{lines}</g>"


def _bolt(x: float, y: float, scale: float = 1.0) -> str:
    """Raio neon (o 'Strike')."""
    pts = "32,0 8,40 26,40 4,86 56,30 34,30 50,0"
    return (
        f'<g transform="translate({x},{y}) scale({scale})" filter="url(#glow)">'
        f'<polygon points="{pts}" fill="url(#bolt)" stroke="{CYAN}" stroke-width="1.5"/></g>'
    )


# --------------------------------------------------------------------------- #
# Banner
# --------------------------------------------------------------------------- #
def banner() -> str:
    w, h = 1280, 640

    badges = ["Python 3.10+", "apktool", "Frida Gadget", "apksigner", "MIT"]
    colors = [CYAN, PURPLE, PINK, GREEN, YELLOW]
    bx = 80
    badge_svg = []
    for label, col in zip(badges, colors):
        bw = 26 + len(label) * 10
        badge_svg.append(
            f'<g transform="translate({bx},532)">'
            f'<rect width="{bw}" height="40" rx="20" fill="#0b1020" stroke="{col}" '
            f'stroke-opacity="0.8" filter="url(#glowSoft)"/>'
            f'<text x="{bw / 2}" y="26" fill="{col}" font-family="{MONO}" '
            f'font-size="15" text-anchor="middle">{esc(label)}</text></g>'
        )
        bx += bw + 16

    features = [("decompile", GREEN), ("patch Manifest", CYAN),
                ("Frida Gadget", PURPLE), ("rebuild + sign", PINK)]
    fx = 80
    feat_svg = []
    for label, color in features:
        feat_svg.append(
            f'<g transform="translate({fx},470)">'
            f'<circle cx="6" cy="-5" r="6" fill="{color}" filter="url(#glowSoft)"/>'
            f'<text x="22" y="0" fill="{TXT}" font-family="{SANS}" font-size="20">{esc(label)}</text></g>'
        )
        fx += 40 + len(label) * 11

    term_lines = [
        ("$ python3 main.py", GREEN),
        ("[*] alvo: base.apk", CYAN),
        ("[+] APK descompilado", TXT),
        ("[+] Manifest patchado", TXT),
        ("[*] ABIs: arm64-v8a", CYAN),
        ("[+] Frida Gadget injetado", TXT),
        ("[+] loadLibrary no smali", TXT),
        ("[+] APK assinado ✔", GREEN),
    ]
    tl = "".join(
        f'<text x="22" y="{34 + i * 27}" fill="{c}" font-family="{MONO}" '
        f'font-size="16">{esc(t)}</text>'
        for i, (t, c) in enumerate(term_lines)
    )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
{_defs()}
  <rect width="{w}" height="{h}" fill="url(#bg)"/>
  {_matrix(w, h)}
  <rect width="{w}" height="{h}" fill="url(#halo)"/>
  {_scanlines(w, h)}
  <rect x="6" y="6" width="{w - 12}" height="{h - 12}" rx="14" fill="none"
        stroke="{PURPLE}" stroke-opacity="0.35" filter="url(#glowSoft)"/>

  <text x="80" y="120" fill="{CYAN}" font-family="{MONO}" font-size="20"
        filter="url(#glowSoft)">&gt;_ authorized android reverse engineering</text>

  {_bolt(78, 150, 1.15)}
  <text x="150" y="262" fill="url(#neon)" font-family="{SANS}" font-size="118"
        font-weight="800" filter="url(#glow)" letter-spacing="-2">DexStrike</text>

  <text x="82" y="328" fill="{TXT}" font-family="{SANS}" font-size="25">Engenharia reversa autorizada de APKs Android.</text>
  <text x="82" y="362" fill="{MUTED}" font-family="{SANS}" font-size="25">Decompile · Manifest · Frida Gadget · rebuild · sign.</text>

  {"".join(feat_svg)}
  {"".join(badge_svg)}

  <g transform="translate(812,142)">
    <rect width="404" height="284" rx="12" fill="{PANEL}" stroke="{CYAN}"
          stroke-opacity="0.55" filter="url(#glowSoft)"/>
    <rect width="404" height="34" rx="12" fill="#0c1322"/>
    <rect y="22" width="404" height="12" fill="#0c1322"/>
    <circle cx="22" cy="17" r="6" fill="#ff5f56"/>
    <circle cx="44" cy="17" r="6" fill="#ffbd2e"/>
    <circle cx="66" cy="17" r="6" fill="#27c93f"/>
    <text x="202" y="22" fill="{MUTED}" font-family="{MONO}" font-size="13" text-anchor="middle">dexstrike — bash</text>
    <g transform="translate(0,46)">{tl}</g>
  </g>
</svg>
"""


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
def pipeline() -> str:
    w, h = 1280, 720
    steps = [
        ("1", "Descompilar", "apktool d", GREEN),
        ("2", "Patch Manifest", "NSC · extractNativeLibs\nusesCleartextTraffic", CYAN),
        ("3", "Detectar", "ABIs · frameworks\nlibs · components", CYAN),
        ("4", "Frida Gadget", "download .so\nlib/<abi>/", PURPLE),
        ("5", "Injetar smali", "System.loadLibrary\nApplication/Activity", PURPLE),
        ("6", "Scripts Frida", "SSL unpinning\nbundle único", PINK),
        ("7", "Rebuild", "apktool b", YELLOW),
        ("8", "Zipalign + Sign", "apksigner\nverify", GREEN),
        ("9", "Relatório", "Markdown\n+ estado JSON", CYAN),
    ]
    cols, cw, ch, gx, gy = 3, 348, 152, 38, 54
    x0, y0 = 60, 156
    cards = []
    for i, (num, title, sub, color) in enumerate(steps):
        r, c = divmod(i, cols)
        x = x0 + c * (cw + gx)
        y = y0 + r * (ch + gy)
        sub_svg = "".join(
            f'<text x="78" y="{98 + j * 25}" fill="{MUTED}" font-family="{MONO}" font-size="17">{esc(s)}</text>'
            for j, s in enumerate(sub.split("\n"))
        )
        cards.append(
            f'<g transform="translate({x},{y})">'
            f'<rect width="{cw}" height="{ch}" rx="14" fill="{PANEL}" stroke="{color}" '
            f'stroke-opacity="0.55" filter="url(#glowSoft)"/>'
            f'<rect width="7" height="{ch}" rx="3.5" fill="{color}" filter="url(#glowSoft)"/>'
            f'<circle cx="46" cy="46" r="23" fill="none" stroke="{color}" stroke-width="2" filter="url(#glowSoft)"/>'
            f'<text x="46" y="54" fill="{color}" font-family="{SANS}" font-size="24" '
            f'font-weight="700" text-anchor="middle">{num}</text>'
            f'<text x="78" y="52" fill="{TXT}" font-family="{SANS}" font-size="24" font-weight="600">{esc(title)}</text>'
            f"{sub_svg}</g>"
        )
        if c < cols - 1 and i < len(steps) - 1:
            ax, ay = x + cw + 3, y + ch / 2
            cards.append(
                f'<path d="M{ax} {ay} l{gx - 10} 0" stroke="{color}" stroke-opacity="0.7" '
                f'stroke-width="3" marker-end="url(#arr)" filter="url(#glowSoft)"/>'
            )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
{_defs()}
  <marker id="arr" markerWidth="10" markerHeight="10" refX="6" refY="3" orient="auto">
    <path d="M0 0 L6 3 L0 6 z" fill="{CYAN}"/>
  </marker>
  <rect width="{w}" height="{h}" fill="url(#bg)"/>
  {_matrix(w, h, seed=7, opacity=0.10)}
  {_scanlines(w, h)}
  {_bolt(56, 30, 0.62)}
  <text x="108" y="74" fill="url(#neon)" font-family="{SANS}" font-size="40" font-weight="800"
        filter="url(#glowSoft)">DexStrike — pipeline completo</text>
  <text x="108" y="108" fill="{MUTED}" font-family="{SANS}" font-size="21">Opção 10 do menu: do APK original ao APK patchado e assinado, com relatório.</text>
  {"".join(cards)}
</svg>
"""


# --------------------------------------------------------------------------- #
# Terminal demo
# --------------------------------------------------------------------------- #
def terminal() -> str:
    lines = [
        ("$ python3 main.py", GREEN),
        ("", TXT),
        ("============================================================", PURPLE),
        ("  DexStrike — APK reverse engineering toolkit", CYAN),
        ("============================================================", PURPLE),
        ("Escolha: 10", TXT),
        ("", TXT),
        ("[*] decompile -> Manifest -> detect -> Frida -> smali -> build -> sign", CYAN),
        ("[*] Executando: apktool d -f base.apk -o workspace/base_decoded", CYAN),
        ("[+] APK descompilado: workspace/base_decoded", GREEN),
        ("[+] network_security_config aplicado.", GREEN),
        ("[+] extractNativeLibs definido como True.", GREEN),
        ("[*] ABIs detectadas: arm64-v8a, armeabi-v7a", CYAN),
        ("[*] Frameworks: Flutter", CYAN),
        ("[*] Baixando: frida-gadget-17.9.10-android-arm64.so.xz", CYAN),
        ("[+] Frida Gadget injetado em: arm64-v8a, armeabi-v7a", GREEN),
        ("[+] System.loadLibrary('frida-gadget') aplicado no smali", GREEN),
        ("[+] Scripts Frida copiados e bundle gerado.", GREEN),
        ("[*] Executando: apktool b -o outputs/base-patched-unsigned.apk", CYAN),
        ("[+] APK recompilado: outputs/base-patched-unsigned.apk", GREEN),
        ("[+] APK alinhado: outputs/base-patched-aligned.apk", GREEN),
        ("[+] APK assinado: outputs/base-patched-signed.apk", GREEN),
        ("[+] Relatório gerado: outputs/base-patch-report.md", GREEN),
        ("", TXT),
        ("[✔] Concluído — outputs/base-patched-signed.apk", PINK),
    ]
    pad_x, top, lh = 28, 64, 25.5
    w = 1000
    h = int(top + len(lines) * lh + 28)
    rows = "".join(
        f'<text x="{pad_x}" y="{top + i * lh}" fill="{c}" font-family="{MONO}" '
        f'font-size="16.5" xml:space="preserve">{esc(t)}</text>'
        for i, (t, c) in enumerate(lines)
    )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
{_defs()}
  <rect width="{w}" height="{h}" rx="12" fill="{PANEL}" stroke="{CYAN}" stroke-opacity="0.5" filter="url(#glowSoft)"/>
  <rect width="{w}" height="40" rx="12" fill="#0c1322"/>
  <rect y="28" width="{w}" height="12" fill="#0c1322"/>
  <circle cx="26" cy="20" r="7" fill="#ff5f56"/>
  <circle cx="50" cy="20" r="7" fill="#ffbd2e"/>
  <circle cx="74" cy="20" r="7" fill="#27c93f"/>
  <text x="{w / 2}" y="25" fill="{MUTED}" font-family="{MONO}" font-size="14" text-anchor="middle">dexstrike — pipeline completo</text>
  {rows}
</svg>
"""


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, content in {
        "banner.svg": banner(),
        "pipeline.svg": pipeline(),
        "terminal.svg": terminal(),
    }.items():
        (OUT / name).write_text(content, encoding="utf-8")
        print(f"gerado: assets/img/{name}")


if __name__ == "__main__":
    main()
