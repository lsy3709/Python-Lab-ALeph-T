# report_maker.py — 경보 리포트 생성 + n8n 웹훅 전송
import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path

import requests  # pip install requests

# ── 설정 ─────────────────────────────────────────────
# 각자 본인 n8n 웹훅 주소를 넣으세요.
# 환경변수 N8N_WEBHOOK_URL 이 설정돼 있으면 그 값을 우선 사용합니다.
# WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "")   # ← 여기 또는 환경변수에
WEBHOOK_URL = "http://localhost:5678/webhook/30370b2c-96d2-4409-a301-e98849fb17fb"

BASE_DIR = Path(__file__).resolve().parent       # 스크립트가 있는 폴더 기준
REPORT_PATH = BASE_DIR / "report.md"
LOG_PATH = BASE_DIR / "report_maker.log"
TIMEOUT = 10        # 초
RETRY = 3           # 재시도 횟수

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    encoding="utf-8",
)

alerts = [
    {"level": 12, "ip": "1.1.1.1", "severity": "High"},
    {"level": 9,  "ip": "2.2.2.2", "severity": "Medium"},
]


def build_report(rows):
    """마크다운 표 문자열 생성"""
    lines = [
        "# 경보 리포트",
        "",
        f"생성 시각: {datetime.now():%Y-%m-%d %H:%M:%S}",
        "",
        "| IP | 레벨 | 심각도 |",
        "|---|---|---|",
    ]
    for a in rows:
        lines.append(f'| {a["ip"]} | {a["level"]} | {a["severity"]} |')
    return "\n".join(lines) + "\n"


def send_to_n8n(url, markdown, rows):
    """n8n 웹훅으로 전송. 성공 시 True"""
    payload = {
        "source": "report_maker",
        "generated_at": datetime.now().isoformat(),
        "count": len(rows),
        "text": markdown,   # n8n에서 그대로 슬랙 text 로 쓸 수 있음
        "alerts": rows,     # 구조화 데이터가 필요할 때
    }
    for attempt in range(1, RETRY + 1):
        try:
            res = requests.post(url, json=payload, timeout=TIMEOUT)
            res.raise_for_status()
            logging.info("전송 성공 (%s) %s", res.status_code, res.text[:200])
            return True
        except requests.RequestException as e:
            logging.warning("전송 실패 %d/%d: %s", attempt, RETRY, e)
            if attempt < RETRY:
                time.sleep(2 ** attempt)   # 2s → 4s 백오프
    return False


def main():
    markdown = build_report(alerts)
    REPORT_PATH.write_text(markdown, encoding="utf-8")
    logging.info("리포트 생성 완료: %s", REPORT_PATH)
    print(f"리포트 생성 완료: {REPORT_PATH}")

    if not WEBHOOK_URL:
        msg = "WEBHOOK_URL 이 비어 있습니다. 환경변수 N8N_WEBHOOK_URL 을 설정하세요."
        logging.error(msg)
        print(msg, file=sys.stderr)
        return 2   # 설정 누락

    if send_to_n8n(WEBHOOK_URL, markdown, alerts):
        print("n8n 전송 완료")
        return 0   # 정상
    print("n8n 전송 실패 (로그 확인)", file=sys.stderr)
    return 1       # 전송 실패


if __name__ == "__main__":
    sys.exit(main())