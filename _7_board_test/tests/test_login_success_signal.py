"""로그인 성공 신호 테스트 — 새 탐지 시나리오의 토대.

`write_seclog` 는 `login_failed | login_success | login_locked` 를 지원한다고
문서화돼 있었지만 실제로는 **실패만** 기록하고 있었다(2026-09-25 확인).
성공 로그인이 없으면 "심야 접속", "계정 탈취 후 정상 로그인", "한 계정 다중 IP"
같은 시나리오를 만들 수 없다. 성공도 남기도록 하고 그것을 테스트로 고정한다.

개인정보 주의: 남기는 값은 계정명·출발지 IP 뿐이며 비밀번호·토큰은 절대 남기지 않는다.
"""
from datetime import timedelta

import pytest

from app import create_app
from extensions import db

SEC = {'X-API-Key': 'test-security-key'}


@pytest.fixture
def client(tmp_path):
  logf = tmp_path / 'security.log'

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
    SECURITY_LOG_PATH = str(logf)

  application = create_app(TestConfig)
  c = application.test_client()
  c._logf = logf
  yield c
  with application.app_context():
    db.session.remove()
    db.engine.dispose()


def signup(client, name='zz_ok', pw='Aa!23456789'):
  assert client.post('/api/auth/register', json={'username': name, 'password': pw}).status_code == 201


def read_log(client):
  return client._logf.read_text(encoding='utf-8') if client._logf.exists() else ''


def test_successful_login_is_recorded(client):
  """★ 성공 로그인도 security.log 에 남아야 한다."""
  signup(client)
  res = client.post('/api/auth/login', json={'username': 'zz_ok', 'password': 'Aa!23456789'})
  assert res.status_code == 200, res.get_json()
  log = read_log(client)
  assert 'login_success' in log, log
  assert 'user=zz_ok' in log


def test_failed_login_still_recorded(client):
  """기존 동작 유지 — 실패도 계속 남는다."""
  signup(client)
  assert client.post('/api/auth/login', json={'username': 'zz_ok', 'password': 'nope'}).status_code == 401
  assert 'login_failed' in read_log(client)


def test_log_line_has_millisecond_timestamp(client):
  """Wazuh 디코더가 붙으려면 밀리초 타임스탬프여야 한다(windows-date-format 선점 회피)."""
  import re
  signup(client)
  client.post('/api/auth/login', json={'username': 'zz_ok', 'password': 'Aa!23456789'})
  line = [l for l in read_log(client).splitlines() if 'login_success' in l][0]
  assert re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} login_success ', line), line


def test_no_secret_in_log(client):
  """비밀번호·토큰이 로그에 새지 않는다."""
  signup(client)
  client.post('/api/auth/login', json={'username': 'zz_ok', 'password': 'Aa!23456789'})
  log = read_log(client)
  assert 'Aa!23456789' not in log
  assert 'eyJ' not in log          # JWT 접두사
