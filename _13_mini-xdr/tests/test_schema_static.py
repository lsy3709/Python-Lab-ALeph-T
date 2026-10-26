"""스키마 파일 정적 검사 — 도커 없이 빠르게 돈다."""
import re

from app.schema import SCHEMA_PATH, TABLES


def _sql() -> str:
    return SCHEMA_PATH.read_text(encoding="utf-8")


def test_schema_defines_exactly_the_listed_tables():
    found = set(re.findall(r"CREATE TABLE IF NOT EXISTS\s+(\w+)", _sql()))
    assert found == set(TABLES) and len(TABLES) == 11


def test_app_settings_marks_secret_values():
    block = _sql().split("CREATE TABLE IF NOT EXISTS app_settings", 1)[1].split(") ENGINE", 1)[0]
    assert "is_secret" in block and "updated_at" in block


def test_every_create_is_idempotent():
    assert re.findall(r"CREATE\s+(?:TABLE|DATABASE)\s+(?!IF\s+NOT\s+EXISTS)", _sql()) == []


def test_schema_uses_dedicated_database():
    sql = _sql()
    assert "CREATE DATABASE IF NOT EXISTS mini_xdr" in sql
    assert "USE mini_xdr;" in sql
