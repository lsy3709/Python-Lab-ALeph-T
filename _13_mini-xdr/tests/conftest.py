"""공용 픽스처 — 일회용 MySQL 컨테이너 하나를 통합 테스트 전체가 함께 쓴다."""
import subprocess
import time
import uuid

import pytest

from app.schema import SCHEMA_PATH
from tests._mysql import IMAGE, ROOT_PW, docker_ready, run_mysql


@pytest.fixture(scope="session")
def mysql_container():
    if not docker_ready():
        pytest.skip("docker 를 쓸 수 없음")
    name = f"mini-xdr-test-{uuid.uuid4().hex[:8]}"
    # 호스트 포트는 무작위(127.0.0.1 만) — PyMySQL 저장소 테스트가 접속한다.
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::3306",
                    "-e", f"MYSQL_ROOT_PASSWORD={ROOT_PW}", IMAGE], check=True, capture_output=True)
    try:
        deadline = time.time() + 180
        while run_mysql(name, "-e", "SELECT 1").returncode != 0:
            if time.time() > deadline:
                pytest.fail("MySQL 준비 시간 초과")
            time.sleep(2)
        mapping = subprocess.run(["docker", "port", name, "3306/tcp"], capture_output=True,
                                 text=True, check=True).stdout.strip().splitlines()[0]
        yield {"name": name, "port": int(mapping.rsplit(":", 1)[1])}
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.fixture(scope="session")
def schema_applied(mysql_container):
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    for attempt in (1, 2):  # 두 번 적용해도 오류가 없어야 한다(멱등)
        r = run_mysql(mysql_container["name"], input_sql=sql)
        assert r.returncode == 0, f"{attempt}회차 적용 실패: {r.stderr}"
    return mysql_container


@pytest.fixture
def fresh_db(schema_applied):
    """같은 스키마를 새 이름의 DB 에 적용해 돌려준다 — 테스트끼리 인시던트·진행 위치가 섞이지 않게."""
    name = f"mxt_{uuid.uuid4().hex[:10]}"
    sql = SCHEMA_PATH.read_text(encoding="utf-8").replace("mini_xdr", name)
    r = run_mysql(schema_applied["name"], input_sql=sql)
    assert r.returncode == 0, r.stderr
    return {"name": name, "port": schema_applied["port"]}
