# [178 실습] 다른 PC 이식 가이드 — 변경해야 하는 파일 정리

> **전제**: 다른 PC에 이미 **Flask 게시판 원본·Graylog2·n8n·Wazuh·Zabbix** 가 떠 있다.
> ha-lab 은 **자기 것(board·mysql·keepalived)을 새로 빌드/기동**하고, 기존 SOAR/감시 스택에는 **"연결(네트워크·설정)만"** 한다. 그래서 바꿀 건 대부분 **① 경로 ② 이름/주소 ③ 자격증명 ④ 네트워크 연결** 네 가지.

---

## 0. 큰 그림 — 무엇이 "내 것"이고 무엇이 "기존 것"인가
```
 [ha-lab 가 새로 만드는 것 — ha-net 172.16.0.0/24]        [기존 스택 — 그 PC에 이미 있음]
   board-main/sub · mysql-main/sub · keepalived(VIP)  ──▶  Wazuh 매니저 ─▶ Graylog ─▶ n8n
   wazuh-agent(사이드카)                                      Zabbix(가용성 감시)
```
- 핵심 이식 작업 = **기존 스택 컨테이너를 ha-net 에 연결**(또는 반대로) + **설정 파일의 이름/주소/경로/자격증명 맞추기**.

---

## 1. 파일별 변경표 (★=거의 반드시, ○=환경 다르면)

| 파일 | 바꿀 위치 | 무엇으로 | 이유 |
|---|---|---|---|
| ★ `ha_prepare.ps1` | `param($BoardSrc='E:\0-Aleph-Python-Test\...\_7_board_test')` | **그 PC의 Flask 게시판 원본 경로** | ha-board 이미지 빌드 소스. 또는 실행 시 `-BoardSrc <경로>` |
| ★ `ha-compose.yml` | `wazuh-agent` → `WAZUH_MANAGER: wazuh-manager2` | **그 PC의 Wazuh 매니저 컨테이너명** | 에이전트가 이 이름으로 매니저에 등록·전송 |
| ○ `ha-compose.yml` | `networks: ha-net: subnet: 172.16.0.0/24` | 기존 네트워크와 겹치면 **다른 대역**(예 172.20.0.0/24) | 서브넷 충돌 방지 |
| ○ `ha-compose.yml` | `WAZUH_AGENT_GROUP: ha-container` | 그 PC 매니저에 만들 **그룹명과 일치** | agent.conf(localfile) 그룹 공유설정 |
| ★ `zbx_ha_config_safe.py` | `API="http://127.0.0.1:8081/..."` · `USER,PW="Admin","zabbix"` | **그 PC Zabbix 웹 URL·포트·계정** | Zabbix API 로그인 |
| ○ `zbx_ha_config_safe.py` | `TARGETS`(172.16.0.100/.11/.12/.21/.22) | ha-net 대역을 바꿨다면 **그 IP로** | 감시 대상(VIP·노드·DB) |
| ★ `graylog_eventdef_129_soar.json` | `streams`(6aab8a72…) · `notifications`(6aab8baf…) | **그 PC Graylog의 Wazuh 스트림 ID · n8n 알림 ID** | 스트림/알림은 Graylog 인스턴스마다 ID 다름 |
| ○ `graylog_eventdef_129_soar.json` | `query`(wazuh_rule_id:100211 OR …100265) | 그 PC 매니저에 **해당 룰이 있어야**(없으면 추가) | 탐지 룰 ID 매칭 |
| ★ `n8n_wazuhAlertBot001_129.json` | board 차단 타깃 IP(= **VIP 172.16.0.100**) · `X-API-Key: ha-lab-key` · 외부알림 토큰/웹훅 | n8n이 ha-net VIP에 **도달 가능**해야(§2 연결) · 키·토큰 그 PC 값 | n8n→게시판 차단·알림 |
| ○ `keepalived-main/sub.conf` | `172.16.0.11/.12/.100`, `unicast_*` | ha-net 대역 바꿨다면 **그 IP로** | VRRP/VIP |

> `ha_up.ps1`·`ha_failover_B.ps1`·`wazuh-agent-entrypoint.sh`·`Dockerfile.*` 는 **대개 그대로** 써도 된다(경로는 `$PSScriptRoot`·상대경로라 폴더만 맞으면 됨).

---

## 2. ★가장 중요 — 네트워크 연결 (기존 스택 ↔ ha-net)

ha-lab 은 전용 네트워크 `ha-lab_ha-net`(172.16.0.0/24)에 뜬다. 기존 스택은 **다른 네트워크**에 있으므로, 연동되는 컨테이너를 ha-net 에 **붙여야** 서로 이름/IP로 닿는다. ha-lab 기동(`ha_up.ps1`) 후:

```powershell
# (1) Wazuh 매니저 → 에이전트의 이벤트 수신 + Graylog 전송 경로
docker network connect ha-lab_ha-net <wazuh-매니저-컨테이너>
# (2) n8n → 게시판(VIP) 차단 호출이 닿도록
docker network connect ha-lab_ha-net <n8n-컨테이너>
# (3) Zabbix 서버 → ha-net IP(VIP·노드·DB) 가용성 체크가 닿도록
docker network connect ha-lab_ha-net <zabbix-서버-컨테이너>
# (Graylog 는 매니저가 syslog_output 으로 밀어주므로, 매니저가 Graylog 네트워크에 닿으면 됨)
```
- 확인: `docker exec <wazuh-매니저> ping -c1 172.16.0.60`(agent) / `docker exec <n8n> curl -s -o /dev/null -w '%{http_code}' http://172.16.0.100:5000/`(VIP 200).
- (대안) ha-net 대신 **기존 SOAR 네트워크에 ha-lab 을 올리기**: ha-compose.yml 의 networks 를 `external: true` 로 기존 네트워크를 참조. 이땐 IP 충돌만 주의.

---

## 3. SOAR 연동 4요소 — 그 PC에 "있는지" 확인 후 맞추기

1. **Wazuh 매니저 로컬 룰**: `graylog_eventdef` 쿼리의 룰(100211 브루트포스·100231 404폭주·100233 심야로그인·100241/242/243 suricata·100265 snort)이 매니저 `local_rules.xml` 에 있어야. 같은 SOAR 랩이면 이미 있음 — 없으면 [129]/[173] 자산으로 추가.
2. **매니저 → Graylog 전송**: 매니저 `ossec.conf` 의 `syslog_output` 서버가 **그 PC Graylog 컨테이너명:5140** 인지 확인(기본 `gl-graylog:5140`).
3. **매니저 그룹 agent.conf**: 그룹 `ha-container` 에 `/app/logs/security.log`(필요 시 suricata_alert.log·snort_alert.log) localfile 이 있어야 사이드카가 보낸 로그를 수집. (사이드카 entrypoint 가 security.log 는 자동 주입, IDS 로그는 [178 케이스6]/[179] 방식으로 추가.)
4. **Graylog 이벤트 → n8n**: `graylog_eventdef` 의 notification 이 **그 PC n8n webhook URL** 을 가리키는 알림이어야. 스트림/알림 ID 가 다르므로, 가져오기보다 **그 PC Graylog에서 이벤트정의를 새로 만들고**(쿼리·창 60s/30s·반복형 `A OR B`) n8n 웹훅 알림을 연결하는 편이 깔끔.

> ★ 함정: `wazuh_rule_id:(A OR B)` 괄호형은 집계 이벤트에서 발동 안 함 → 반드시 **반복형**(`wazuh_rule_id:A OR wazuh_rule_id:B …`). (이 JSON은 이미 반복형.)

---

## 4. 자격증명·값 (그 PC 기준으로)
| 값 | 이 랩 기본 | 그 PC에서 |
|---|---|---|
| Zabbix | `http://127.0.0.1:8081`, Admin/zabbix | 그 PC URL·포트·계정 |
| Graylog | admin/admin | 그 PC 계정 |
| Wazuh 매니저명 | `wazuh-manager2` | 그 PC 컨테이너명 |
| Graylog 컨테이너명:포트 | `gl-graylog:5140` | 그 PC 값 |
| n8n | admin@admin.com / 12345678A! | 그 PC 계정 |
| 게시판 API 키 | `ha-lab-key` | (그대로 쓰되 n8n·compose 양쪽 동일하게) |
| ha-lab DB 비번 | ha_root_pw/board_pw/replpw | 랩 전용 throwaway(운영 전 변경) |

---

## 5. 이식 체크리스트 (순서)
1. [ ] `ha_prepare.ps1 -BoardSrc <그 PC 게시판 경로>` → 이미지 3종 빌드.
2. [ ] (SOAR 쓰면) `docker build -t ha-wazuh-agent:latest -f .\Dockerfile.wazuh-agent .`
3. [ ] `ha-compose.yml` 의 `WAZUH_MANAGER`·(겹치면)subnet 수정.
4. [ ] `.\ha_up.ps1` → VIP `http://172.16.0.100:5000/` 200 확인.
5. [ ] `docker network connect ha-lab_ha-net` 로 **매니저·n8n·Zabbix** 연결(§2).
6. [ ] 매니저 룰·syslog_output·그룹 agent.conf 확인(§3).
7. [ ] 그 PC Graylog에 이벤트정의(반복형 쿼리)+n8n 웹훅 알림 구성(§3-4).
8. [ ] `n8n_…json` 가져오고 board 차단 타깃=VIP·키·알림 토큰 맞춤.
9. [ ] `python zbx_ha_config_safe.py`(URL·계정 수정 후) → ha-cluster 감시 등록.
10. [ ] `.\ha_failover_B.ps1` → failover + (공격 시) SOAR 티켓까지 확인.

> 참고: 파일별 상세 주석은 같은 `주석/` 폴더의 각 파일·`README.md`. 본편 절차는 노션 [178] 통합판.
