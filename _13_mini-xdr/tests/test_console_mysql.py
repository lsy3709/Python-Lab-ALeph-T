"""콘솔 조회 — 실제 스키마에서 목록·상세를 읽고, 읽기 전용 세션이 쓰기를 거부하는지 확인한다."""
import pymysql
import pytest

from app.console.queries import ConsoleQueries, connect_readonly
from app.correlator import correlate_once
from app.store import MySQLStore
from tests._mysql import ROOT_PW
from tests.test_store_correlation_mysql import FAR, W, seed

pytestmark = pytest.mark.integration


@pytest.fixture
def queries(fresh_db):
    kw = dict(host="127.0.0.1", port=fresh_db["port"], user="root", password=ROOT_PW, database=fresh_db["name"])
    store = MySQLStore(**kw)
    seed(store)  # IP A(app+network)·IP A 30분 뒤·IP B·asset:board-host(level 12)
    correlate_once(store, W, FAR)
    store.close()
    conn = connect_readonly(**kw)
    yield ConsoleQueries(conn)
    conn.close()


def test_list_orders_by_priority_and_filters(queries):
    rows, total = queries.list_incidents()
    assert total == 4 and rows[0]["current_priority"] == "P1" and rows[0]["entity_key"] == "asset:board-host"
    rows, total = queries.list_incidents(multi=True)
    assert total == 1 and rows[0]["layers"] == ["app", "network"]
    assert queries.list_incidents(priority="P1")[1] == 1
    assert queries.list_incidents(status="open")[1] == 0


def test_detail_queries(queries):
    iid = queries.list_incidents(multi=True)[0][0]["id"]
    inc = queries.get_incident(iid)
    assert inc["event_count"] == 2 and inc["layers"] == ["app", "network"]
    assert [s["sig"] for s in queries.signal_summary(iid)] == ["web-scan", "ids-alert"]
    assert [e.event_type for e in queries.incident_events(iid)] == ["web-scan", "ids-alert"]
    assert queries.users(iid) == []
    assert queries.get_incident(99999) is None
    s = queries.stats()
    assert (s["events"], s["incidents"], s["multi_layer"], s["backlog"]) == (5, 4, 1, 0)


def test_readonly_session_rejects_writes(queries):
    with pytest.raises(pymysql.err.MySQLError) as exc:
        with queries._conn.cursor() as cur:
            cur.execute("DELETE FROM incidents")
    assert exc.value.args[0] == 1792  # Cannot execute statement in a READ ONLY transaction
