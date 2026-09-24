"""테스트 공통 설정 — 테스트가 실제 SIEM 으로 GELF 를 쏘지 않게 막는다.

`send_gelf` 는 UDP 12201 로 fire-and-forget 전송한다. 그래서 pytest 를 한 번
돌릴 때마다 실습용 Graylog 에 **가짜 로그인 기록이 실제로 쌓인다.**
그 로그는 탐지 룰에 그대로 걸려서, 아무도 공격하지 않았는데 인시던트 티켓이
줄줄이 생긴다(실측: 테스트 1회 실행 → 심야 로그인 탐지 티켓 다수 생성).

그래서 `controllers.gelf` 모듈이 쓰는 socket 만 조용한 대체품으로 바꾼다.
표준 socket 모듈 자체는 건드리지 않으므로 다른 코드에는 영향이 없다.

보낸 내용은 `gelf_outbox` 픽스처로 확인할 수 있다.
"""
import pytest


class _RecordingSocket:
  """보내는 대신 기록만 한다."""

  def __init__(self, box):
    self._box = box

  def sendto(self, payload, addr):
    self._box.append((payload, addr))

  def close(self):
    pass


class _StubSocketModule:
  """`controllers.gelf` 가 기대하는 최소한의 socket 모듈 흉내."""

  AF_INET = 2
  SOCK_DGRAM = 2

  def __init__(self):
    self.sent = []

  def socket(self, *args, **kwargs):
    return _RecordingSocket(self.sent)


@pytest.fixture(autouse=True)
def gelf_outbox(monkeypatch):
  """모든 테스트에서 GELF 전송을 가로챈다. 반환값은 (payload, 주소) 목록."""
  import controllers.gelf as gelf_mod

  stub = _StubSocketModule()
  monkeypatch.setattr(gelf_mod, 'socket', stub)
  return stub.sent
