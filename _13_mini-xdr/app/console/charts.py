"""콘솔 그래프 — 서버에서 SVG 문자열을 만든다(자바스크립트 0줄, CSP 를 풀지 않는다).

막대에 마우스를 올리면 브라우저 기본 툴팁(<title>)으로 숫자가 보인다. 계정명·엔티티 같은 로그 값은
공격자가 넣을 수 있는 문자열이라 모두 escape 한다. 색은 dataviz 검증기를 통과한 것만 쓴다:
계층 5색 = 기본 범주 팔레트 어두운 단계(패널 #161d26 기준 대비 3:1 이상·색약 인접 ΔE 8.4 이상).
"""
from __future__ import annotations

import math

from markupsafe import Markup, escape

LAYER_COLORS = {"app": "#3987e5", "host": "#d95926", "network": "#199e70", "data": "#c98500", "behavior": "#d55181"}
PRIORITY_COLORS = {"P1": "#c0392b", "P2": "#e67e22", "P3": "#f1c40f", "P4": "#6b7a8c", "미정": "#4a5868"}  # 목록 배지와 같은 색
BAR_COLOR = "#3987e5"
EMPTY = Markup('<p class="muted viz-empty">이 기간에 데이터가 없습니다.</p>')
GAP = 2       # 누적 조각·이웃 막대 사이 틈(px)
RADIUS = 4    # 막대 끝 둥글기(px)


def compact(n: int) -> str:
    """축·막대 끝 숫자 — 1,000 부터 1K·1.3K·13K·1.5M."""
    for size, unit in ((1_000_000, "M"), (1_000, "K")):
        if n >= size:
            v = n / size  # 반올림은 사사오입(파이썬 round 의 짝수 반올림이면 1,250 이 1.2K 가 된다)
            if v < 10:
                return f"{math.floor(v * 10 + 0.5) / 10:g}{unit}"
            return f"{math.floor(v + 0.5)}{unit}"
    return str(n)


def nice_scale(peak: int) -> tuple[int, int]:
    """y 축 (꼭대기, 간격) — 1·2·5×10ⁿ 간격 중 칸이 5개 이하인 가장 촘촘한 것."""
    if peak <= 0:
        return 4, 1
    mag = 10 ** max(0, int(math.log10(peak)) - 1)
    while True:
        for m in (1, 2, 5):
            step = m * mag
            if math.ceil(peak / step) <= 5:
                return math.ceil(peak / step) * step, step
        mag *= 10


def _top_rounded(x: float, y: float, w: float, h: float, r: float = RADIUS) -> str:
    """위 두 모서리만 둥근 세로 막대(아래는 기준선에 붙는다)."""
    r = min(r, w / 2, h)
    return (f"M{x:.1f},{y + h:.1f}V{y + r:.1f}Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f}"
            f"H{x + w - r:.1f}Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}V{y + h:.1f}Z")


def _right_rounded(x: float, y: float, w: float, h: float, r: float = RADIUS) -> str:
    """오른쪽 두 모서리만 둥근 가로 막대(왼쪽은 기준선에 붙는다)."""
    r = min(r, h / 2, w)
    return (f"M{x:.1f},{y:.1f}H{x + w - r:.1f}Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}"
            f"V{y + h - r:.1f}Q{x + w:.1f},{y + h:.1f} {x + w - r:.1f},{y + h:.1f}H{x:.1f}Z")


def stacked_columns(categories: list[str], series: list[tuple[str, str]], values: dict[tuple[str, str], int],
                    *, colors: dict[str, str], unit: str = "건", width: int = 760, height: int = 240) -> Markup:
    """날짜별 누적 세로 막대. series=[(키, 이름)] 아래에서 위로 쌓는 순서, values[(날짜, 키)]=건수."""
    totals = [sum(values.get((c, k), 0) for k, _ in series) for c in categories]
    if not categories or not any(totals):
        return EMPTY
    top, step = nice_scale(max(totals))
    left, right, head, foot = 44, 8, 10, 24
    plot_w, plot_h = width - left - right, height - head - foot
    slot = plot_w / len(categories)
    bar_w = max(3.0, min(36.0, slot - GAP * 2))
    label_every = max(1, math.ceil(len(categories) / 8))
    y_of = lambda v: head + plot_h - plot_h * v / top  # noqa: E731
    out = [f'<svg class="viz" viewBox="0 0 {width} {height}" role="img" '
           f'aria-label="{escape(f"날짜별 누적 막대 — 최대 {max(totals):,}{unit}")}" preserveAspectRatio="xMidYMid meet">']
    for v in range(0, top + 1, step):  # 가로 눈금선(옅게)과 y 축 숫자
        y = y_of(v)
        out.append(f'<line class="grid" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}"/>'
                   f'<text class="y" x="{left - 6}" y="{y + 4:.1f}">{compact(v)}</text>')
    for i, (cat, total) in enumerate(zip(categories, totals)):
        x = left + slot * i + (slot - bar_w) / 2
        parts = [f"{escape(name)} {values.get((cat, key), 0):,}" for key, name in series if values.get((cat, key))]
        tip = f"{escape(cat)} · 합계 {total:,}{unit}" + (" — " + " · ".join(parts) if parts else "")
        out.append(f'<g class="col"><title>{tip}</title>'
                   f'<rect class="hit" x="{left + slot * i:.1f}" y="{head}" width="{slot:.1f}" height="{plot_h}"/>')
        drawn = [(key, values.get((cat, key), 0)) for key, _ in series if values.get((cat, key), 0) > 0]
        base = 0
        for j, (key, n) in enumerate(drawn):
            y_top, y_bottom = y_of(base + n), y_of(base)
            h = y_bottom - y_top - (GAP if j > 0 else 0)  # 아래 조각과 사이에 2px 틈
            if h > 0.3:
                fill = colors.get(key, BAR_COLOR)
                if j == len(drawn) - 1:
                    out.append(f'<path class="mark" fill="{fill}" d="{_top_rounded(x, y_top, bar_w, h)}"/>')
                else:
                    out.append(f'<rect class="mark" fill="{fill}" x="{x:.1f}" y="{y_top:.1f}" '
                               f'width="{bar_w:.1f}" height="{h:.1f}"/>')
            base += n
        out.append("</g>")
        if i % label_every == 0 and i < len(categories) - label_every // 2 or i == len(categories) - 1:
            out.append(f'<text class="x" x="{x + bar_w / 2:.1f}" y="{height - 6}">{escape(cat)}</text>')
    out.append(f'<line class="axis" x1="{left}" x2="{width - right}" y1="{y_of(0):.1f}" y2="{y_of(0):.1f}"/></svg>')
    return Markup("".join(out))


def hbars(rows: list[tuple[str, int, str]], *, unit: str = "건", width: int = 760, bar_h: int = 18,
          label_w: int = 230) -> Markup:
    """가로 막대 — rows=[(이름, 값, 색)] 위에서 아래로 그린다. 값은 막대 끝에 쓴다."""
    if not rows or not any(v for _, v, _ in rows):
        return EMPTY
    peak = max(v for _, v, _ in rows)
    row_h = bar_h + 8
    height = row_h * len(rows) + 4
    plot_w = width - label_w - 56
    out = [f'<svg class="viz" viewBox="0 0 {width} {height}" role="img" '
           f'aria-label="{escape(f"가로 막대 {len(rows)}개 — 최대 {peak:,}{unit}")}" preserveAspectRatio="xMidYMid meet">']
    for i, (label, value, color) in enumerate(rows):
        y = 2 + row_h * i
        w = max(2.0, plot_w * value / peak) if value else 0
        name = str(label) if len(str(label)) <= 32 else str(label)[:31] + "…"
        out.append(f'<g class="bar"><title>{escape(label)} · {value:,}{unit}</title>'
                   f'<rect class="hit" x="0" y="{y - 3}" width="{width}" height="{row_h}"/>'
                   f'<text class="label" x="{label_w - 8}" y="{y + bar_h - 4}">{escape(name)}</text>')
        if w:
            out.append(f'<path class="mark" fill="{color}" d="{_right_rounded(label_w, y, w, bar_h)}"/>')
        out.append(f'<text class="value" x="{label_w + w + 6:.1f}" y="{y + bar_h - 4}">{compact(value)}</text></g>')
    out.append("</svg>")
    return Markup("".join(out))
