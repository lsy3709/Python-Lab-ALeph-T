#!/bin/sh
# 사이드카 Wazuh 에이전트 진입점:
#   stale lock 제거 → 매니저 주소 설정 → localfile 직접 주입 → (최초)등록 → 데몬 시작 → 로그 tail.
#   ※ 그룹 공유설정(merged.mg) sync 를 기다리지 않도록 localfile 을 ossec.conf 에 직접 넣는다.
set -e
MGR="${WAZUH_MANAGER:-wazuh-manager2}"
NAME="${WAZUH_AGENT_NAME:-ha-board-container}"

# ★ 재시작 시 남는 start-script-lock 교착 방지(lock 은 디렉터리라 -rf)
rm -rf /var/ossec/var/start-script-lock* 2>/dev/null || true

# 매니저 주소 교체(첫 <address>)
sed -i "0,/<address>.*<\/address>/s||<address>${MGR}</address>|" /var/ossec/etc/ossec.conf

# 게시판 보안로그 localfile 을 ossec.conf 에 직접 추가(중복 방지)
if ! grep -q "/app/logs/security.log" /var/ossec/etc/ossec.conf; then
  sed -i "s#</ossec_config>#  <localfile>\n    <location>/app/logs/security.log</location>\n    <log_format>syslog</log_format>\n  </localfile>\n</ossec_config>#" /var/ossec/etc/ossec.conf
fi

# 등록키 없으면 등록
if [ ! -s /var/ossec/etc/client.keys ]; then
  echo "[entrypoint] 등록: manager=${MGR} name=${NAME}"
  /var/ossec/bin/agent-auth -m "$MGR" -A "$NAME" || echo "[entrypoint] agent-auth 경고(계속)"
fi

/var/ossec/bin/wazuh-control start
exec tail -F /var/ossec/logs/ossec.log 2>/dev/null
