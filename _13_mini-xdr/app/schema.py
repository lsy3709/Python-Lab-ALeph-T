"""mini_xdr 스키마 위치와 테이블 목록 — 테스트와 P1 저장소 시작 점검이 함께 쓴다."""
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "sql" / "001_schema.sql"

TABLES = (
    "events_norm",
    "incidents",
    "incident_events",
    "baselines",
    "anomaly_scores",
    "triage_results",
    "verdict_cache",
    "llm_calls",
    "checkpoints",
    "actions",
    "app_settings",
)
