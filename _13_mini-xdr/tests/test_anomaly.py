"""행위 이상탐지 순수 로직 — 버킷·특징·robust/원형 기준선·2단 선택·채점·behavior 이벤트."""
from datetime import datetime, timedelta, timezone

import pytest

from app.anomaly import (POPULATION, band, build_baselines, bucketize, circular, hour_distance, robust,
                         anomaly_events, score_bucket)
from app.correlator import EventRow

T0 = datetime(2026, 10, 26, 5, 0, 0, tzinfo=timezone.utc)  # KST 14:00


def ev(i, minutes, event_type="web-scan", *, ip="203.0.113.9", user=None, layer="app", source="board",
       rule_id=None):
    return EventRow(id=i, ts=T0 + timedelta(minutes=minutes), layer=layer, source=source, event_type=event_type,
                    src_ip=ip, user_name=user, rule_id=rule_id)


def test_bucketize_by_hour_for_ip_and_user_entities():
    aggs = bucketize([
        ev(1, 1, "login-bruteforce", user="zz_a"), ev(2, 2, "login-bruteforce", user="zz_a"),
        ev(3, 3, "login-success", user="zz_a"), ev(4, 10, "wazuh-alert", layer="app", source="wazuh", rule_id="100230"),
        ev(5, 70, "web-scan"),                                   # 다음 버킷
        ev(6, 5, "x", ip=None, user="(unknown)"),                # 자리표시 계정은 엔티티 아님
        ev(7, 6, "anomaly-events-z5", layer="behavior", source="anomaly"),  # behavior 는 다시 세지 않음
    ])
    ip0 = aggs[("ip", "203.0.113.9", T0)]
    assert ip0.features() == {"events": 4, "signals": 3, "login_fail": 2, "ratio_404": 0.25}
    assert aggs[("ip", "203.0.113.9", T0 + timedelta(hours=1))].features() == {"events": 1, "signals": 1,
                                                                             "ratio_404": 1.0}
    user = aggs[("user", "zz_a", T0)]
    assert user.features()["login_fail"] == 2 and user.login_hours == [pytest.approx(14.05)]
    assert user.top_ip() == "203.0.113.9" and ip0.last_ts == T0 + timedelta(minutes=10)
    assert not any(k[0] == "user" and k[1] == "(unknown)" for k in aggs)


def test_robust_ignores_outliers_and_applies_floor():
    center, scale, n = robust([10, 12, 11, 13, 10, 12, 5000], floor=1.0)
    assert center == 12 and 1.0 <= scale < 5 and n == 7       # 폭주 하나가 중심을 끌어가지 않음
    assert robust([1, 1, 1, 1], floor=1.0) == (1, 1.0, 4)       # MAD 0 → 하한


def test_circular_hours_wrap_around_midnight():
    center, scale, n = circular([23.0, 1.0, 0.0, 23.5, 0.5], floor=1.0)
    assert hour_distance(center, 0.0) < 0.3 and scale < 2 and n == 5   # 평균이 12시가 아니라 자정 부근
    assert hour_distance(23.0, 1.0) == 2.0 and hour_distance(3, 15) == 12


def train_aggs():
    """IP 40개가 각자 한 시간에 10~14건(정상) — 집단 기준선 표본 40, 개인 기준선은 각 1개."""
    events, i = [], 0
    for k in range(40):
        for _ in range(10 + k % 5):
            i += 1
            events.append(ev(i, 1, ip=f"198.51.100.{k}"))
    return list(bucketize(events).values())


def test_two_level_baseline_individual_then_population():
    aggs = train_aggs()
    # 한 IP 만 32시간 동안 매시간 2건 → 개인 기준선 가능
    regular = [ev(1000 + h * 2 + j, h * 60 + 1, ip="192.0.2.1") for h in range(32) for j in range(2)]
    aggs += list(bucketize(regular).values())
    bl = build_baselines(aggs)
    assert bl[("ip", POPULATION, "events")].n == 72
    assert bl[("ip", "192.0.2.1", "events")].n == 32 and bl[("ip", "192.0.2.1", "events")].kind == "individual"
    target = bucketize([ev(9000 + j, 60 * 40 + j % 50, ip="192.0.2.1") for j in range(12)])
    s = score_bucket(next(iter(target.values())), bl, min_samples=30, threshold=3.0)
    assert s.z["events"].kind == "individual" and s.z["events"].z == pytest.approx(10.0)  # (12-2)/1
    new_ip = bucketize([ev(9100 + j, 60 * 40, ip="203.0.113.77") for j in range(12)])
    s2 = score_bucket(next(iter(new_ip.values())), bl, min_samples=30, threshold=3.0)
    assert s2.z["events"].kind == "population" and s2.z["events"].z < 3 and s2.anomalies == []


def test_score_flags_only_upper_side_and_insufficient_is_skipped():
    bl = build_baselines(train_aggs())
    burst = bucketize([ev(i, 1, ip="203.0.113.50") for i in range(200)])
    s = score_bucket(next(iter(burst.values())), bl, min_samples=30, threshold=3.0)
    assert "events" in s.anomalies and s.max_z > 50
    quiet = bucketize([ev(1, 1, ip="203.0.113.51")])
    assert score_bucket(next(iter(quiet.values())), bl, min_samples=30, threshold=3.0).anomalies == []
    assert "login_fail" not in s.z  # 로그인 이벤트가 없는 버킷은 그 특징 자체가 없다


def test_login_hour_anomaly_for_user():
    events = [ev(i, 0, "login-success", user=f"zz_u{i % 7}") for i in range(40)]  # 모두 KST 14시
    bl = build_baselines(list(bucketize(events).values()))
    night = EventRow(id=999, ts=datetime(2026, 10, 26, 18, 10, tzinfo=timezone.utc), layer="app", source="board",
                     event_type="login-success", src_ip="203.0.113.9", user_name="zz_u1")  # KST 03:10
    s = score_bucket(bucketize([night])[("user", "zz_u1", datetime(2026, 10, 26, 18, tzinfo=timezone.utc))], bl,
                     min_samples=30, threshold=3.0)
    assert "login_hour" in s.anomalies and s.z["login_hour"].kind == "population"


def test_band_and_behavior_events_are_deterministic():
    assert [band(z) for z in (3.1, 5.0, 9.9)] == ["z3", "z5", "z8"]
    bl = build_baselines(train_aggs())
    agg = next(iter(bucketize([ev(i, 1, ip="203.0.113.50") for i in range(200)]).values()))
    s = score_bucket(agg, bl, min_samples=30, threshold=3.0)
    evs = anomaly_events(s)
    e = next(x for x in evs if x.event_type.startswith("anomaly-events-"))
    assert (e.layer, e.source, e.src_ip, e.level) == ("behavior", "anomaly", "203.0.113.50", None)
    assert e.event_type == "anomaly-events-z8" and e.ts == agg.last_ts
    assert e.raw_ref.startswith("anom:") and len(e.raw_ref) <= 64
    assert [x.raw_ref for x in anomaly_events(s)] == [x.raw_ref for x in evs]  # 다시 채점해도 같은 raw_ref


def test_user_anomaly_event_carries_users_main_ip():
    events = [ev(i, 0, "login-success", user=f"zz_u{i % 7}") for i in range(40)]
    bl = build_baselines(list(bucketize(events).values()))
    night = EventRow(id=999, ts=datetime(2026, 10, 26, 18, 10, tzinfo=timezone.utc), layer="app", source="board",
                     event_type="login-success", src_ip="203.0.113.9", user_name="zz_u1")
    agg = bucketize([night])[("user", "zz_u1", datetime(2026, 10, 26, 18, tzinfo=timezone.utc))]
    e = anomaly_events(score_bucket(agg, bl, min_samples=30, threshold=3.0))[0]
    assert e.user_name == "zz_u1" and e.src_ip == "203.0.113.9"  # → 그 IP 의 인시던트에 붙는다
