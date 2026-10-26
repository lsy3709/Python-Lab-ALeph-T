"""스키마를 일회용 MySQL 컨테이너에 실제로 적용해 본다(도커 필요).

실행: python -m pytest -m integration -v
이미지 바꾸기: MINI_XDR_TEST_MYSQL_IMAGE=mysql:latest python -m pytest -m integration
"""
import pytest

from app.schema import TABLES
from tests._mysql import run_mysql

pytestmark = pytest.mark.integration


def test_all_tables_exist(schema_applied):
    r = run_mysql(schema_applied["name"], "-N", "-e", "SHOW TABLES FROM mini_xdr")
    assert set(r.stdout.split()) == set(TABLES)


def test_raw_ref_unique_blocks_duplicate_ingest(schema_applied):
    ins = ("INSERT INTO mini_xdr.events_norm (ts, layer, source, event_type, raw_ref) "
           "VALUES (NOW(3), 'app', 'board', 'web-scan', 'gl-dup-1');")
    assert run_mysql(schema_applied["name"], "-e", ins).returncode == 0
    dup = run_mysql(schema_applied["name"], "-e", ins)
    assert dup.returncode != 0 and "Duplicate entry" in dup.stderr


def test_incident_delete_cascades_to_links(schema_applied):
    sql = (
        "USE mini_xdr;"
        "INSERT INTO events_norm (ts, layer, source, event_type, raw_ref) VALUES (NOW(3),'host','wazuh','rule','gl-casc-1');"
        "INSERT INTO incidents (entity_key, opened_at, last_event_at, layers) VALUES ('ip:test', NOW(3), NOW(3), JSON_ARRAY('host'));"
        "INSERT INTO incident_events VALUES (LAST_INSERT_ID(), (SELECT id FROM events_norm WHERE raw_ref='gl-casc-1'));"
        "DELETE FROM incidents WHERE entity_key='ip:test';"
        "SELECT COUNT(*) FROM incident_events;"
    )
    r = run_mysql(schema_applied["name"], "-N", "-e", sql)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split()[-1] == "0"
