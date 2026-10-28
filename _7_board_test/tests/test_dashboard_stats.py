"""대시보드 그래프용 집계 API(/api/security/stats) 테스트.

그래프는 화면 JS(Chart.js)가 그리고, 서버는 숫자만 준다. 조회 전용이라 키 없이 열린다
(`/api/security/events/summary` 와 같은 수준). 날짜는 created_at(이 PC 의 KST) 기준으로 묶는다.
"""
from datetime import datetime, timedelta

import pytest

from app import create_app
from extensions import db
from models import SecurityEvent

SEC = {'X-API-Key': 'test-security-key'}


@pytest.fixture
def app_client(tmp_path):
  class TestConfig:
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'test-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    SECURITY_API_KEY = 'test-security-key'
    ADMIN_API_KEY = 'test-admin-key'
    ADMIN_ALLOWLIST = []
    AUTO_POST_ON_DENY = False
    PUBLIC_API_KEY = None
    PUBLIC_API_URL = 'http://example.invalid/'

  application = create_app(TestConfig)
  yield application, application.test_client()
  with application.app_context():
    db.session.remove()
    db.engine.dispose()


def post(client, *, student='lab', severity='High', source='ip-guard', ip='203.0.113.7'):
  res = client.post('/api/security/events', headers=SEC, json={
      'student': student, 'src_ip': ip, 'decision': 'deny', 'severity': severity,
      'reason': 'stats seed', 'source': source})
  assert res.status_code == 201


def age(app, days):
  """가장 최근 이벤트의 저장 시각을 days 일 전으로 옮긴다."""
  with app.app_context():
    ev = SecurityEvent.query.order_by(SecurityEvent.id.desc()).first()
    ev.created_at = datetime.now() - timedelta(days=days)
    db.session.commit()


def test_stats_without_api_key_counts_by_day_severity_and_source(app_client):
  app, client = app_client
  post(client, severity='High', source='ip-guard')
  post(client, severity='High', source='wazuh')
  post(client, severity='Low', source='wazuh')
  post(client, severity='Critical', source='login_guard')
  age(app, 3)                                   # 마지막 1건은 3일 전으로

  res = client.get('/api/security/stats')       # 키 없이
  assert res.status_code == 200
  d = res.get_json()
  assert d['days'] == 30 and len(d['labels']) == 30
  assert d['labels'][-1] == datetime.now().strftime('%m-%d')
  assert set(d['daily']) == {'Low', 'Medium', 'High', 'Critical'}
  assert all(len(v) == 30 for v in d['daily'].values())
  assert d['daily']['High'][-1] == 2 and d['daily']['Low'][-1] == 1
  assert d['daily']['Critical'][-4] == 1        # 3일 전 칸
  assert d['by_severity'] == {'Low': 1, 'Medium': 0, 'High': 2, 'Critical': 1}
  assert d['by_source'] == [{'source': 'wazuh', 'n': 2}, {'source': 'ip-guard', 'n': 1},
                            {'source': 'login_guard', 'n': 1}]
  assert d['total'] == 4


def test_stats_period_is_whitelisted_and_excludes_older_events(app_client):
  app, client = app_client
  post(client)
  age(app, 10)
  assert client.get('/api/security/stats?days=7').get_json()['total'] == 0     # 10일 전은 7일 밖
  d = client.get('/api/security/stats?days=14').get_json()
  assert d['total'] == 1 and len(d['labels']) == 14
  assert len(client.get('/api/security/stats?days=999').get_json()['labels']) == 30   # 허용 밖 → 기본 30


def test_stats_follows_student_filter(app_client):
  _, client = app_client
  post(client, student='lab')
  post(client, student='lab')
  post(client, student='other')
  assert client.get('/api/security/stats?student=lab').get_json()['total'] == 2
  assert client.get('/api/security/stats?student=nobody').get_json()['total'] == 0


def test_stats_normalizes_severity_case_and_keeps_unknown_apart(app_client):
  _, client = app_client
  post(client, severity='high')
  post(client, severity='Severe')
  d = client.get('/api/security/stats').get_json()
  assert d['by_severity']['High'] == 1 and d['by_severity']['Other'] == 1   # 모르는 등급을 아무 데나 섞지 않는다


def test_dashboard_page_loads_pinned_chart_library_and_chart_slots(app_client):
  _, client = app_client
  html = client.get('/dashboard').get_data(as_text=True)
  assert 'cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js' in html
  for slot in ('chart-trend', 'chart-severity', 'chart-source', 'chart-top-ips'):
    assert f'id="{slot}"' in html, slot
  assert '/api/security/stats' in html and '표로 보기' in html
