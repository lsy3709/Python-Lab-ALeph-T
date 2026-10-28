"""콘솔 그래프 — 서버가 만드는 SVG(자바스크립트 없음, CSP 그대로). 축 눈금·누적·이스케이프·빈 데이터를 확인한다."""
import re

from app.console.charts import LAYER_COLORS, compact, hbars, nice_scale, stacked_columns

XSS = "<script>alert(1)</script>"


def test_compact_numbers():
    assert [compact(n) for n in (0, 999, 1000, 1250, 12500, 1_500_000)] == ["0", "999", "1K", "1.3K", "13K", "1.5M"]


def test_nice_scale_rounds_up_to_clean_steps():
    assert nice_scale(0) == (4, 1)          # 데이터가 0 이어도 축은 그린다
    assert nice_scale(7) == (8, 2)
    assert nice_scale(216) == (250, 50)     # 1·2·5 눈금 중 칸이 5개 이하인 가장 촘촘한 것
    top, step = nice_scale(1536)
    assert top >= 1536 and top % step == 0 and top / step <= 5


def test_stacked_columns_one_group_per_day_with_tooltip_breakdown():
    days = ["10-26", "10-27"]
    series = [("app", "app"), ("host", "host")]
    values = {("10-26", "app"): 3, ("10-27", "app"): 5, ("10-27", "host"): 2}
    svg = str(stacked_columns(days, series, values, colors=LAYER_COLORS))
    assert svg.startswith("<svg") and "<script" not in svg
    assert svg.count('class="col"') == 2
    assert "<title>10-27 · 합계 7건 — app 5 · host 2</title>" in svg
    assert LAYER_COLORS["app"] in svg and LAYER_COLORS["host"] in svg
    assert 'role="img"' in svg and "aria-label" in svg


def test_stacked_columns_zero_segments_are_not_drawn():
    svg = str(stacked_columns(["10-26"], [("app", "app"), ("host", "host")], {("10-26", "app"): 4},
                              colors=LAYER_COLORS))
    assert LAYER_COLORS["host"] not in svg


def test_stacked_columns_thins_out_x_labels_for_long_ranges():
    days = [f"10-{d:02d}" for d in range(1, 31)]
    svg = str(stacked_columns(days, [("app", "app")], {(d, "app"): 1 for d in days}, colors=LAYER_COLORS))
    shown = re.findall(r'class="x"[^>]*>(10-\d\d)<', svg)
    assert 5 <= len(shown) <= 10 and shown[-1] == "10-30"   # 마지막 날(오늘)은 항상 보인다


def test_empty_data_says_so_instead_of_an_empty_axis():
    assert "데이터가 없습니다" in str(stacked_columns(["10-26"], [("app", "app")], {}, colors=LAYER_COLORS))
    assert "데이터가 없습니다" in str(hbars([]))


def test_hbars_label_value_and_escape():
    svg = str(hbars([(XSS, 1200, "#3987e5"), ("ip:203.0.113.9", 40, "#3987e5")]))
    assert "<script>" not in svg and "&lt;script&gt;" in svg
    assert ">1.2K<" in svg and ">40<" in svg
    assert svg.count('class="bar"') == 2
