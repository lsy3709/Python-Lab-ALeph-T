"""스키마를 일회용 MySQL 8.0 컨테이너에 실제로 적용해 본다(도커 필요).

실행: python -m pytest -m integration -v
"""
import shutil
import subprocess
import time
import uuid

import pytest

from app.schema import SCHEMA_PATH, TABLES

pytestmark = pytest.mark.integration

ROOT_PW = "xdr_throwaway_test_pw"  # 테스트가 끝나면 삭제되는 일회용 컨테이너 전용


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def _mysql(name: str, *args: str, input_sql: str | None = None) -> subprocess.CompletedProcess:
    # -h 127.0.0.1 TCP 접속: 초기화용 임시 서버(소켓 전용)가 아닌 최종 서버에만 붙는다.
    cmd = ["docker", "exec", "-i", name, "mysql", "-h", "127.0.0.1", "--protocol=TCP",
           "-uroot", f"-p{ROOT_PW}", *args]
    return subprocess.run(cmd, input=input_sql, capture_output=True, text=True, encoding="utf-8")


@pytest.fixture(scope="module")
def mysql_container():
    if not _docker_ready():
        pytest.skip("docker 를 쓸 수 없음")
    name = f"mini-xdr-schema-test-{uuid.uuid4().hex[:8]}"
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name,
                    "-e", f"MYSQL_ROOT_PASSWORD={ROOT_PW}", "mysql:8.0"],
                   check=True, capture_output=True)
    try:
        deadline = time.time() + 180
        while _mysql(name, "-e", "SELECT 1").returncode != 0:
            if time.time() > deadline:
                pytest.fail("MySQL 준비 시간 초과")
            time.sleep(2)
        yield name
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.fixture(scope="module")
def schema_applied(mysql_container):
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    for attempt in (1, 2):  # 두 번 적용해도 오류가 없어야 한다(멱등)
        r = _mysql(mysql_container, input_sql=sql)
        assert r.returncode == 0, f"{attempt}회차 적용 실패: {r.stderr}"
    return mysql_container


def test_all_tables_exist(schema_applied):
    r = _mysql(schema_applied, "-N", "-e", "SHOW TABLES FROM mini_xdr")
    assert set(r.stdout.split()) == set(TABLES)


def test_raw_ref_unique_blocks_duplicate_ingest(schema_applied):
    ins = ("INSERT INTO mini_xdr.events_norm (ts, layer, source, event_type, raw_ref) "
           "VALUES (NOW(3), 'app', 'board', 'web-scan', 'gl-dup-1');")
    assert _mysql(schema_applied, "-e", ins).returncode == 0
    dup = _mysql(schema_applied, "-e", ins)
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
    r = _mysql(schema_applied, "-N", "-e", sql)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split()[-1] == "0"
