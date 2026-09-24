#!/usr/bin/env python3
"""
Regenerate the whitepaper figures as SVG.

    python docs/figures/make_figures.py

Standard library only. The issuance chart is computed block by block from the
consensus code in kairos/params.py, so it always matches the implementation.
Every figure has a white background so it stays readable in dark mode.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))

from kairos.params import MAINNET, COIN, subsidy  # noqa: E402

FONT = "Helvetica, Arial, sans-serif"
INK = "#1a1a1a"
GREY = "#8a8a8a"
SHADE = "#e8eef6"
ACCENT = "#1f4e79"


def svg(w, h, body):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
            f'viewBox="0 0 {w} {h}" font-family="{FONT}" fill="{INK}">\n'
            f'<rect width="{w}" height="{h}" fill="#ffffff"/>\n'
            '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
            'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
            f'<path d="M0,0 L10,5 L0,10 z" fill="{INK}"/></marker></defs>\n'
            + "\n".join(body) + "\n</svg>\n")


def box(x, y, w, h, fill="#ffffff", stroke=INK, sw=1.2):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>'


def text(x, y, s, size=13, anchor="middle", weight="normal", style="normal", fill=INK):
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (f'<text x="{x}" y="{y}" font-size="{size}" text-anchor="{anchor}" '
            f'font-weight="{weight}" font-style="{style}" fill="{fill}">{s}</text>')


def line(x1, y1, x2, y2, arrow=False, dash=None, color=INK, sw=1.2):
    extra = ' marker-end="url(#arrow)"' if arrow else ""
    if dash:
        extra += f' stroke-dasharray="{dash}"'
    return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{sw}"{extra}/>'


# --------------------------------------------------------------- Figure 1
def figure_address():
    b = []
    b += [box(40, 30, 220, 50), text(150, 52, "Schnorr public key", weight="bold"),
          text(150, 70, "32 bytes, BIP340", size=11, style="italic")]
    b += [box(380, 30, 220, 50), text(490, 52, "Lamport public key", weight="bold"),
          text(490, 70, "16 KiB, hash-based", size=11, style="italic")]
    b += [box(380, 120, 220, 36), text(490, 143, "pq_root = H(Lamport key)")]
    b += [line(490, 80, 490, 119, arrow=True)]
    b += [box(200, 200, 240, 50, fill=SHADE, sw=1.6),
          text(320, 222, "address", weight="bold"),
          text(320, 240, "H(Schnorr key || pq_root)", size=11, style="italic")]
    b += [line(150, 80, 150, 225), line(150, 225, 199, 225, arrow=True)]
    b += [line(490, 156, 490, 225), line(490, 225, 441, 225, arrow=True)]
    b += [text(320, 285, "today: spend with a 64-byte Schnorr signature", size=12, style="italic"),
          text(320, 304, "quantum emergency: spend with a Lamport signature (section 10)",
               size=12, style="italic")]
    return svg(640, 320, b)


# --------------------------------------------------------------- Figure 2
HEADER_ROWS = [  # field order exactly as serialised by BlockHeader.serialize()
    ("version 4  ·  height 4", False),
    ("prev 32", False),
    ("tx_root 32", False),
    ("utxo_root 32", True),
    ("time 8  ·  bits 4", False),
    ("fee 8", True),
    ("nonce 8", False),
]


def figure_header():
    b = []
    bw, rh, gap, x0, y0 = 196, 24, 58, 20, 44
    titles = ["Block n-1", "Block n", "Block n+1"]
    for i, title in enumerate(titles):
        x = x0 + i * (bw + gap)
        h = 30 + rh * len(HEADER_ROWS) + 10
        b.append(box(x, y0, bw, h, sw=1.4))
        b.append(text(x + bw / 2, y0 + 20, title, weight="bold"))
        for j, (label, committed) in enumerate(HEADER_ROWS):
            ry = y0 + 30 + j * rh
            b.append(box(x + 10, ry, bw - 20, rh - 4, fill=SHADE if committed else "#ffffff", sw=0.9))
            b.append(text(x + bw / 2, ry + 15, label, size=12))
        if i > 0:  # prev hash points back to the parent
            ay = y0 + 30 + 1 * rh + 10
            b.append(line(x + 10, ay, x - gap + 2, ay, arrow=True, sw=1.3))
    total_w = x0 * 2 + 3 * bw + 2 * gap
    b.append(text(total_w / 2, 28, "Each header: 132 bytes, fields in serialisation order (sizes in bytes)",
                  size=12, style="italic"))
    ly = y0 + 30 + rh * len(HEADER_ROWS) + 34
    b.append(box(total_w / 2 - 150, ly - 11, 14, 14, fill=SHADE, sw=0.9))
    b.append(text(total_w / 2 - 128, ly, "state committed by proof-of-work: UTXO set and next base fee",
                  size=12, anchor="start"))
    return svg(total_w, ly + 18, b)


# --------------------------------------------------------------- Figure 3
YEAR = 365.25 * 86400


def issuance(years=40, step_years=0.1):
    """(year, kairos_supply, kairos_per_day, btc_supply, btc_per_day) samples."""
    out = []
    g, n, next_sample = 0, 0, 0.0
    kairos_blocks_per_year = YEAR / MAINNET.target_spacing
    while True:
        y = n / kairos_blocks_per_year
        if y >= next_sample - 1e-9:
            btc_blocks = int(y * YEAR // 600)
            era = btc_blocks // 210000
            btc_reward = (50 * 10 ** 8) >> era
            btc_total, r, left = 0, 50 * 10 ** 8, btc_blocks
            while left > 0 and r > 0:
                take = min(left, 210000)
                btc_total += take * r
                left -= take
                r //= 2
            out.append((y, g / COIN, subsidy(MAINNET, g) / COIN * 720,
                        btc_total / 1e8, btc_reward / 1e8 * 144))
            next_sample += step_years
            if y >= years:
                return out
        g += subsidy(MAINNET, g)
        n += 1


def figure_issuance():
    import math
    data = issuance()
    W, H = 760, 330
    b = []
    panels = [
        (70, "Cumulative supply (millions)", lambda v: v / 1e6, (0, 24), [0, 5, 10, 15, 20], False, 1, 3),
        (455, "New coins per day (log scale)", lambda v: v, (5, 10000), [10, 100, 1000, 10000], True, 2, 4),
    ]
    pw, ph, top = 270, 220, 40
    for px, title, f, (lo, hi), ticks, log, ki, bi in panels:
        def X(yr):
            return px + yr / 40 * pw

        def Y(v):
            v = f(v)
            if log:
                v = max(v, lo)
                return top + ph - (math.log10(v) - math.log10(lo)) / (math.log10(hi) - math.log10(lo)) * ph
            return top + ph - (v - lo) / (hi - lo) * ph
        b.append(text(px + pw / 2, 24, title, size=13, weight="bold"))
        b.append(line(px, top + ph, px + pw, top + ph))
        b.append(line(px, top, px, top + ph))
        for yr in range(0, 41, 10):
            b.append(line(X(yr), top + ph, X(yr), top + ph + 5))
            b.append(text(X(yr), top + ph + 19, str(yr), size=11))
        b.append(text(px + pw / 2, top + ph + 38, "years after genesis", size=11))
        for t in ticks:
            ty = Y(t * 1e6 if not log else t)
            b.append(line(px - 5, ty, px, ty))
            b.append(line(px, ty, px + pw, ty, color="#e6e6e6", sw=0.8))
            label = f"{t:,}"
            b.append(text(px - 8, ty + 4, label, size=11, anchor="end"))
        kpts = " ".join(f"{X(r[0]):.1f},{Y(r[ki]):.1f}" for r in data)
        if log:   # Bitcoin's reward is a step function
            steps, prev = [], None
            for r in data:
                yv = Y(r[bi])
                if prev is not None and abs(prev - yv) > 0.01:
                    steps.append(f"{X(r[0]):.1f},{prev:.1f}")
                steps.append(f"{X(r[0]):.1f},{yv:.1f}")
                prev = yv
            bpts = " ".join(steps)
        else:
            bpts = " ".join(f"{X(r[0]):.1f},{Y(r[bi]):.1f}" for r in data)
        b.append(f'<polyline points="{bpts}" fill="none" stroke="{GREY}" stroke-width="1.8" stroke-dasharray="6 4"/>')
        b.append(f'<polyline points="{kpts}" fill="none" stroke="{ACCENT}" stroke-width="2.2"/>')
    tail = MAINNET.tail_reward / COIN * 720
    ty = top + ph - (math.log10(tail) - math.log10(5)) / (math.log10(10000) - math.log10(5)) * ph
    b.append(text(455 + pw - 4, ty - 8, f"Kairos tail: {tail:,.0f} per day", size=11, anchor="end", fill=ACCENT))
    lx, ly = 90, H - 22
    b.append(line(lx, ly, lx + 30, ly, color=ACCENT, sw=2.2))
    b.append(text(lx + 38, ly + 4, "Kairos (2-minute blocks, smooth decay, permanent tail)", size=11, anchor="start"))
    b.append(f'<line x1="{lx + 390}" y1="{ly}" x2="{lx + 420}" y2="{ly}" stroke="{GREY}" stroke-width="1.8" stroke-dasharray="6 4"/>')
    b.append(text(lx + 428, ly + 4, "Bitcoin (halving every 210,000 blocks)", size=11, anchor="start"))
    return svg(W, H, b)


def main():
    figures = {
        "fig1-address.svg": figure_address(),
        "fig2-header-chain.svg": figure_header(),
        "fig3-issuance.svg": figure_issuance(),
    }
    for name, content in figures.items():
        with open(os.path.join(HERE, name), "w", newline="\n") as f:
            f.write(content)
        print("wrote", os.path.join("docs", "figures", name))


if __name__ == "__main__":
    main()
