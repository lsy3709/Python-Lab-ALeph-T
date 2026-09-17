"""보안 로그 파일 기록 — Wazuh 에이전트가 읽어 가는 호스트 로그.

GELF(gelf.py)는 앱이 Graylog 로 '직접' 보내는 길이고,
이 파일은 호스트에 설치된 Wazuh 에이전트가 '읽어 가는' 길이다(센서가 하나 더 붙는다).

형식(한 줄 = 사건 1건):
  2026-09-17 14:03:21.457 login_failed user=victim src_ip=203.0.113.50

주의 두 가지
  ① 타임스탬프에 밀리초(.mmm)가 있어야 한다. 없으면 Wazuh 내장 프리디코더
     (windows-date-format)가 먼저 잡아가서 커스텀 디코더에 도달하지 못한다(미탐).
  ② 사용자 입력(username)을 그대로 쓰면 '로그 인젝션'이 된다. 아이디에 줄바꿈을 넣어
     가짜 로그 줄을 만들 수 있으므로 공백·개행 문자를 '_' 로 바꾸고 길이를 자른다.
"""
import os
import re
from datetime import datetime

from flask import current_app

_UNSAFE = re.compile(r'[\s\x00-\x1f\x7f]+')   # 공백·개행·제어문자


def _clean(value, limit=64):
  text = _UNSAFE.sub('_', str(value or '-'))
  return text[:limit] or '-'


def write_seclog(event, user, src_ip):
  """event: login_failed | login_success | login_locked"""
  path = current_app.config.get('SECURITY_LOG_PATH')
  if not path:
    return
  first_hop = str(src_ip or '').split(',')[0].strip()      # X-Forwarded-For 첫 홉만
  now = datetime.now()
  stamp = now.strftime('%Y-%m-%d %H:%M:%S.') + f'{now.microsecond // 1000:03d}'
  line = f'{stamp} {event} user={_clean(user)} src_ip={_clean(first_hop, 45)}\n'
  try:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a', encoding='utf-8') as f:
      f.write(line)
  except OSError:
    pass   # 로그 파일 문제로 로그인이 멈추면 안 된다(가용성 우선)
