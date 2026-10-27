"""신호 사전 — 룰 번호·신호 이름 → 설명. LLM 고정 앞부분(프롬프트 캐시)에 들어간다.

Wazuh 룰 설명은 랩 Graylog 의 wazuh_rule_description 에서 모은다(python -m app.rule_dictionary --build).
이 랩은 매니저를 바꿔 가며 실습해 같은 번호가 다른 뜻으로 쓰인 적이 있다(100230 = 404 / 저속 브루트포스)
→ 가장 많이 쓰인 뜻(desc)과 다른 뜻(alt)을 함께 둔다. 설명 속 이메일·IP 는 지운다(공개 저장소·외부 LLM).
"""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.normalizer import _as_list

DATA_PATH = Path(__file__).resolve().parent / "data" / "rule_dictionary.json"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

# 게시판·네트워크 센서가 GELF rule 로 보내는 신호(랩 신호 지도 — _local/152 케이스 공통편 기준)
GELF = {
    "admin-auth-fail": "게시판 관리자 API 키 인증 실패(401)",
    "blocked-retry": "차단된 IP 가 다시 요청(403) — 차단 우회 시도",
    "cf-waf": "Cloudflare WAF 차단(엣지)",
    "gold-access": "게시판 골드 등급 민감자료 열람",
    "ids-alert": "Suricata IDS 경보",
    "login-bruteforce": "게시판 로그인 실패(1회당 1건)",
    "login-success": "게시판 로그인 성공",
    "pfsense-block": "pfSense 방화벽 차단",
    "priv-unauthorized-admin": "게시판 권한 위반(과잉 권한 admin 접근)",
    "snort-portscan": "Snort 포트스캔 탐지",
    "web-scan": "게시판 404 — 없는 경로 탐색(스캐너 정황)",
}
FEATURES = {"events": "시간당 이벤트 급증", "signals": "한 시간에 시도한 신호 종류 급증", "login_fail": "로그인 실패 급증",
            "ratio_404": "404 비율 높음", "login_hour": "평소와 다른 로그인 시각"}
BEHAVIOR = {"anomaly-<특징>-<구간>": "행위 이상(통계, LLM 아님) — 특징: " + ", ".join(f"{k}={v}" for k, v in FEATURES.items())
            + " / 구간: z3=평소보다 3~5배 척도, z5=5~8, z8=8 이상"}


def sanitize(text: str | None, size: int = 70) -> str:
    if not text:
        return ""
    out = IPV4_RE.sub("[IP]", EMAIL_RE.sub("[이메일]", text))
    out = re.sub(r"\[이메일\][^)\s]*", "[이메일]", out)  # 이메일 뒤에 붙은 세션 식별자(…/chromoting_ftl_…)도 지움
    return " ".join(out.split())[:size]


def build_entries(samples: dict[str, Counter], levels: dict[str, int | None]) -> dict:
    """samples: 룰 번호 → Counter((설명, MITRE 튜플) → 건수)."""
    entries = {}
    for rid, counter in samples.items():
        by_desc: Counter = Counter()
        mitre: dict[str, set] = {}
        for (desc, tags), n in counter.items():
            d = sanitize(desc)
            by_desc[d] += n
            mitre.setdefault(d, set()).update(tags)
        main = by_desc.most_common(1)[0][0]
        entries[rid] = {"desc": main, "alt": [d for d, _ in by_desc.most_common() if d != main][:2],
                        "mitre": sorted(mitre[main]), "level": levels.get(rid)}
    return entries


def build_from_graylog(client, levels: dict[str, int | None], now: datetime, days: int = 31,
                       per_rule: int = 1500) -> dict:
    samples: dict[str, Counter] = {}
    start = now - timedelta(days=days)
    for rid in levels:
        counter: Counter = Counter()
        for d in range(days):  # 하루씩 훑어 기간마다 다른 뜻을 놓치지 않는다
            frm, to = start + timedelta(days=d), start + timedelta(days=d + 1)
            msgs = client.search_absolute(f"wazuh_rule_id:{rid}", frm, to, limit=500,
                                          fields=["wazuh_rule_description", "wazuh_rule_mitre_id"])
            for m in msgs:
                counter[(m.get("wazuh_rule_description") or "", tuple(_as_list(m.get("wazuh_rule_mitre_id"))))] += 1
            if sum(counter.values()) >= per_rule:
                break
        if counter:
            samples[rid] = counter
    return {"rules": build_entries(samples, levels)}


_cache: dict | None = None


def load() -> dict:
    global _cache
    if _cache is None:
        data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
        _cache = {"rules": data["rules"], "gelf": GELF, "behavior": BEHAVIOR}
    return _cache


def describe(layer: str, source: str, rule_id: str | None, event_type: str) -> str:
    if layer == "behavior":
        parts = event_type.split("-")  # anomaly-<특징>-<구간>
        feature = "-".join(parts[1:-1]) if len(parts) >= 3 else event_type
        return f"행위 이상: {FEATURES.get(feature, feature)}({parts[-1]})"
    if rule_id:
        e = load()["rules"].get(rule_id)
        if not e:
            return ""
        return e["desc"] + (f" (다른 뜻: {e['alt'][0]})" if e["alt"] else "")
    return GELF.get(event_type, "")


def main() -> int:
    import pymysql

    from app.config import Settings
    from app.graylog import GraylogClient

    s = Settings()
    db = pymysql.connect(host=s.mysql_host, port=s.mysql_port, user=s.mysql_user,
                         password=s.mysql_password.get_secret_value() if s.mysql_password else "", database=s.mysql_db)
    with db.cursor() as cur:
        cur.execute("SELECT rule_id, MAX(level) FROM events_norm WHERE source = 'wazuh' AND rule_id IS NOT NULL "
                    "GROUP BY rule_id ORDER BY rule_id")
        levels = {rid: lvl for rid, lvl in cur.fetchall()}
    db.close()
    token, user, password = s.graylog_credentials()
    client = GraylogClient(s.graylog_url, token=token, user=user, password=password)
    try:
        data = build_from_graylog(client, levels, datetime.now(timezone.utc))
    finally:
        client.close()
    DATA_PATH.parent.mkdir(exist_ok=True)
    DATA_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"신호 사전 저장: 룰 {len(data['rules'])}개 → {DATA_PATH}")
    return 0


if __name__ == "__main__":
    import sys

    if "--build" not in sys.argv:
        raise SystemExit("사용법: python -m app.rule_dictionary --build")
    raise SystemExit(main())
