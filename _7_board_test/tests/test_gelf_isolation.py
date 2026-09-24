"""테스트가 실습용 SIEM 을 오염시키지 않는지 확인한다.

이 파일이 지키는 것은 기능이 아니라 **실습 환경**이다.
`send_gelf` 는 실패해도 조용히 넘어가도록 만들어져 있어서(그래야 SIEM 이 꺼져도
로그인이 동작한다), 테스트가 실제로 UDP 를 쏘고 있어도 아무도 눈치채지 못한다.
그 사이 Graylog 에는 가짜 로그인이 쌓이고 탐지 룰이 헛발동한다.

conftest.py 의 `gelf_outbox` 픽스처가 전송을 가로채는지 여기서 못박는다.
"""
from datetime import timedelta

import pytest

from app import create_app
from extensions import db

PW = 'pw12345'


@pytest.fixture
def client(tmp_path):
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
  yield application.test_client()
  with application.app_context():
    db.session.remove()
    db.engine.dispose()


def test_login_gelf_is_captured_not_sent(client, gelf_outbox):
  """로그인 성공 신호가 스텁에 잡히면, 실제 UDP 로는 나가지 않았다는 뜻이다."""
  client.post('/api/auth/register', json={'username': 'zz_iso', 'password': PW})
  assert client.post('/api/auth/login',
                     json={'username': 'zz_iso', 'password': PW}).status_code == 200

  assert gelf_outbox, 'GELF 가 가로채이지 않았다 = 실습 SIEM 으로 실제 전송되고 있다'
  _payload, addr = gelf_outbox[-1]
  assert addr[1] == 12201          # 보내려던 곳은 맞다(설정은 살아 있다)


def test_failed_login_gelf_is_captured(client, gelf_outbox):
  """실패 신호도 마찬가지로 밖으로 나가지 않는다."""
  client.post('/api/auth/register', json={'username': 'zz_iso2', 'password': PW})
  gelf_outbox.clear()

  client.post('/api/auth/login', json={'username': 'zz_iso2', 'password': 'wrong'})
  assert gelf_outbox, '로그인 실패 신호가 가로채이지 않았다'
