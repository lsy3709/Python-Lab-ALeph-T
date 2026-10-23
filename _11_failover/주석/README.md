# [178 실습] use 폴더 — 파일 지도 · 실행 순서 · 주석 안내

> 이 `주석/` 폴더는 `use/` 의 각 파일을 **입문자용으로 더 자세히 설명**한 사본 모음이다(실행은 `use/` 의 원본으로).
> 랩 성격: **게시판+MySQL 이중화(Active-Standby, keepalived VIP)** 를 로컬 도커로 띄우고, 장애를 줘서 VIP 가 넘어가는지(failover) + SOAR 탐지까지 보는 실습([178]).

## 0. 한 줄 그림
```
                        VIP 172.16.0.100  (살아있는 쪽이 보유)
   [attacker .50] ──HTTP/nmap──▶   ├─ board-main .11 (+keepalived MASTER) ─ mysql-main .21
                                   └─ board-sub  .12 (+keepalived BACKUP) ─ mysql-sub  .22 (복제)
   board 보안로그(security.log) ─공유볼륨─▶ wazuh-agent .60 ─▶ wazuh-manager2 ─▶ Graylog/n8n(SOAR)
```
- 네트워크: `172.16.0.0/24`(ha-net, 운영 스택과 분리). 학생은 항상 **VIP `172.16.0.100:5000`** 로 접속.

## 1. 실행 순서 (PowerShell, 이 폴더에서)
| 순서 | 명령 | 하는 일 |
|---|---|---|
| ① 빌드 | `powershell -NoProfile -ExecutionPolicy Bypass -File .\ha_prepare.ps1 -ResetLab` | Docker 점검 + 이미지 3종(ha-board·ha-keepalived·ha-attacker) 빌드 |
| ② 기동 | `.\ha_up.ps1` | MySQL 복제 구성 → board → keepalived/VIP 순차 기동, VIP 200 확인 |
| ③ failover | `.\ha_failover_B.ps1` | main 다운 → VIP 가 sub 로 인계되는지 측정 |
| (SOAR) | wazuh-agent 컨테이너 + `graylog_eventdef_129_soar.json` + `n8n_wazuhAlertBot001_129.json` | 보안로그→Wazuh→Graylog 이벤트→n8n 티켓 |
| (감시) | `python zbx_ha_config_safe.py` | Zabbix 로 VIP·노드·DB 가용성 감시 |

- ★ `ha_prepare.ps1` 는 게시판 원본(`-BoardSrc`)이 필요: 기본 `E:\0-Aleph-Python-Test\Python-Lab-ALeph-T\_7_board_test`. 경로가 다르면 `-BoardSrc <경로>` 로 지정.
- ★ `.ps1` 은 **UTF-8 BOM** 으로 저장해야 Windows PowerShell 5.1 에서 한글이 안 깨진다.

## 2. 파일 14개 — 무엇이며 언제 쓰나
| 파일 | 분류 | 역할 |
|---|---|---|
| `ha_prepare.ps1` | 빌드 | 환경 점검 + 이미지 3종 빌드(①) |
| `ha_up.ps1` | 기동 | MySQL 복제→board→keepalived 순차 기동(②) |
| `ha_failover_B.ps1` | 테스트 | main 다운→VIP 인계 측정(③) |
| `ha-compose.yml` | 구성 | 모든 컨테이너·네트워크·볼륨 정의(②가 이걸로 up) |
| `Dockerfile.board` | 빌드 | 게시판 이미지(`ha-board:latest`) |
| `Dockerfile.keepalived` | 빌드 | VRRP/VIP 이미지(`ha-keepalived:latest`) |
| `Dockerfile.attacker` | 빌드 | 공격/점검 박스(`ha-attacker:latest`, nmap·curl) |
| `Dockerfile.wazuh-agent` | 빌드 | 보안로그 전송 사이드카(`ha-wazuh-agent:latest`) |
| `wazuh-agent-entrypoint.sh` | 빌드 | wazuh-agent 기동 스크립트(매니저 등록·시작) |
| `keepalived-main.conf` | 구성 | MASTER(priority 150, VIP 평소 보유) |
| `keepalived-sub.conf` | 구성 | BACKUP(priority 100, 인계 대기) |
| `zbx_ha_config_safe.py` | 감시 | Zabbix 에 ha-cluster 호스트·항목·트리거 생성 |
| `graylog_eventdef_129_soar.json` | SOAR | Graylog 이벤트 정의(룰 발동→n8n 호출) |
| `n8n_wazuhAlertBot001_129.json` | SOAR | n8n 워크플로(판정→IP 차단·티켓·알림) |

## 3. 빌드 → 기동 의존 흐름
```
ha_prepare.ps1 ─ docker build ─▶ ha-board:latest     (Dockerfile.board + 게시판 원본)
                               ─▶ ha-keepalived:latest(Dockerfile.keepalived)
                               ─▶ ha-attacker:latest  (Dockerfile.attacker)
  (wazuh-agent 는 compose 가 ha-wazuh-agent:latest 를 쓰므로, SOAR 쓸 땐 Dockerfile.wazuh-agent 도 빌드)
ha_up.ps1 ─ docker compose up ─▶ mysql-main/sub → board-main → (복제확인) → board-sub·keepalived·attacker
                                  keepalived-main.conf / keepalived-sub.conf 를 각 keepalived 가 마운트
```

## 4. JSON 2개 설명 (JSON 은 주석 불가 → 여기서)
- **`graylog_eventdef_129_soar.json`**: Graylog **이벤트 정의** 백업/가져오기용. `wazuh_rule_id:A OR wazuh_rule_id:B …`(반복형) 쿼리로 공격 룰을 묶어, 창 60초/주기 30초로 집계되면 **알림(n8n 웹훅) 호출**. ★괄호형 `(A OR B)` 는 집계 이벤트 프로세서에서 발동 안 함 — 반드시 반복형.
- **`n8n_wazuhAlertBot001_129.json`**: n8n **워크플로** 내보내기. 웹훅 수신 → 룰ID로 공격 종류·심각도·ATT&CK 판정(MAP) → IF 차단 대상이면 게시판 API(`X-API-Key: ha-lab-key`)로 **IP 차단** + 보안이벤트/인시던트 기록 + 외부 채널 알림. 가져오기: n8n UI Import 또는 `docker exec n8n n8n import:workflow --input=...`.

## 5. 네트워크·자격증명 (랩 전용 — 운영 전 반드시 변경)
| 대상 | IP | 비고 |
|---|---|---|
| board-main / sub | 172.16.0.11 / .12 | keepalived netns 공유 |
| mysql-main / sub | 172.16.0.21 / .22 | master-replica 복제 |
| VIP | 172.16.0.100 | 접속 대상 |
| attacker | 172.16.0.50 | 상주(sleep infinity) |
| wazuh-agent | 172.16.0.60 | hostname=ha-board-container |
- 비밀번호 `ha_root_pw`/`board_pw`/`replpw`, API 키 `ha-lab-key` 는 **격리 랩 전용 throwaway**. 운영 전환 시 전부 교체.
