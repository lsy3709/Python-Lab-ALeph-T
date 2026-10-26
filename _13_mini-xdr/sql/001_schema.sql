-- mini-xdr 저장소 스키마 (P0) — MySQL 8.0
-- 적용(PowerShell): Get-Content -Raw sql\001_schema.sql | docker exec -i <MySQL컨테이너> mysql -uroot -p<루트비번>
-- 여러 번 적용해도 안전하다(IF NOT EXISTS). 게시판 DB 의 incidents(SOAR 티켓)와 섞이지 않도록 전용 DB 를 쓴다.

CREATE DATABASE IF NOT EXISTS mini_xdr CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE mini_xdr;

-- 1) 정규화 이벤트 — 출처가 달라도 같은 모양으로
CREATE TABLE IF NOT EXISTS events_norm (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ts          DATETIME(3)      NOT NULL,
  layer       ENUM('app','host','network','data','behavior') NOT NULL,
  source      VARCHAR(32)      NOT NULL,            -- board, wazuh, pfsense, mysql_audit, anomaly
  src_ip      VARCHAR(45)      NULL,                -- IPv6 대비 45자
  user_name   VARCHAR(128)     NULL,
  asset       VARCHAR(128)     NULL,
  event_type  VARCHAR(64)      NOT NULL,            -- login-bruteforce, web-scan, rule ...
  rule_id     VARCHAR(16)      NULL,
  level       TINYINT UNSIGNED NULL,                -- Wazuh level 0~15
  mitre       VARCHAR(64)      NULL,                -- T1110 등(여러 개면 쉼표)
  raw_ref     VARCHAR(64)      NOT NULL,            -- Graylog 메시지 ID(원본 참조)
  ingested_at DATETIME(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_events_raw_ref (raw_ref),           -- 같은 원본 중복 적재 방지
  KEY ix_events_ip_ts (src_ip, ts),
  KEY ix_events_user_ts (user_name, ts)
) ENGINE=InnoDB;

-- 2) 인시던트 — 관련 이벤트 묶음
CREATE TABLE IF NOT EXISTS incidents (
  id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  entity_key       VARCHAR(160) NOT NULL,           -- ip:203.0.113.7 또는 user:alice
  status           ENUM('open','closed') NOT NULL DEFAULT 'open',
  opened_at        DATETIME(3)  NOT NULL,
  last_event_at    DATETIME(3)  NOT NULL,
  layers           JSON         NOT NULL,           -- ["app","host"]
  event_count      INT UNSIGNED NOT NULL DEFAULT 0,
  max_level        TINYINT UNSIGNED NULL,
  fingerprint      CHAR(64)     NULL,               -- SHA-256 hex (호출 깔때기 G3)
  rule_floor       ENUM('P1','P2','P3','P4') NULL,  -- AI 가 이보다 낮출 수 없는 하한
  current_priority ENUM('P1','P2','P3','P4') NULL,
  last_triaged_at  DATETIME(3)  NULL,
  material_state   JSON         NULL,               -- 디바운스(G4) 비교용: 마지막 판정 시점 상태
  KEY ix_incidents_entity_status (entity_key, status),
  KEY ix_incidents_fingerprint (fingerprint),
  KEY ix_incidents_priority (status, current_priority)
) ENGINE=InnoDB;

-- 3) 인시던트와 이벤트 연결
CREATE TABLE IF NOT EXISTS incident_events (
  incident_id BIGINT UNSIGNED NOT NULL,
  event_id    BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (incident_id, event_id),
  KEY ix_ie_event (event_id),
  CONSTRAINT fk_ie_incident FOREIGN KEY (incident_id) REFERENCES incidents(id)   ON DELETE CASCADE,
  CONSTRAINT fk_ie_event    FOREIGN KEY (event_id)    REFERENCES events_norm(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 4) 행위 기준선 — 엔티티별 특징의 평균·표준편차
CREATE TABLE IF NOT EXISTS baselines (
  entity_type ENUM('user','ip') NOT NULL,
  entity      VARCHAR(128) NOT NULL,
  feature     VARCHAR(32)  NOT NULL,               -- login_hour, req_per_min, ratio_404, fail_ratio, path_diversity
  mean        DOUBLE       NOT NULL,
  std         DOUBLE       NOT NULL,
  n           INT UNSIGNED NOT NULL,               -- 표본 수(30 미만이면 기준선 부족)
  updated_at  DATETIME(3)  NOT NULL,
  PRIMARY KEY (entity_type, entity, feature)
) ENGINE=InnoDB;

-- 5) 이상 점수 이력
CREATE TABLE IF NOT EXISTS anomaly_scores (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  entity_type ENUM('user','ip') NOT NULL,
  entity      VARCHAR(128) NOT NULL,
  ts          DATETIME(3)  NOT NULL,
  score       DOUBLE       NOT NULL,               -- 특징별 |z| 의 최댓값
  features    JSON         NOT NULL,               -- 특징별 z 값
  KEY ix_anomaly_entity_ts (entity_type, entity, ts)
) ENGINE=InnoDB;

-- 6) 판정 이력 — 누가(LLM·캐시·규칙) 어떤 관문에서 판정했는가
CREATE TABLE IF NOT EXISTS triage_results (
  id                        BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  incident_id               BIGINT UNSIGNED NOT NULL,
  source                    ENUM('llm','cache','rule','refusal') NOT NULL,
  gate                      VARCHAR(16)  NOT NULL,   -- G1, G2, G3, G5, LLM (호출률·절감 측정용)
  model                     VARCHAR(64)  NULL,
  priority                  ENUM('P1','P2','P3','P4') NOT NULL,
  verdict                   ENUM('true_positive','benign','needs_review') NOT NULL,
  false_positive_likelihood DECIMAL(4,3) NULL,
  reasoning_ko              VARCHAR(600) NULL,
  recommended_playbook      ENUM('block_ip','lock_account','monitor','none') NOT NULL DEFAULT 'none',
  confidence                DECIMAL(4,3) NULL,
  created_at                DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY ix_triage_incident (incident_id, created_at),
  CONSTRAINT fk_triage_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 7) 지문 판정 캐시 (호출 깔때기 G3)
CREATE TABLE IF NOT EXISTS verdict_cache (
  fingerprint CHAR(64)     PRIMARY KEY,
  verdict     JSON         NOT NULL,               -- 판정 스키마 그대로
  model       VARCHAR(64)  NOT NULL,
  hits        INT UNSIGNED NOT NULL DEFAULT 0,
  created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  expires_at  DATETIME(3)  NOT NULL,
  KEY ix_cache_expires (expires_at)
) ENGINE=InnoDB;

-- 8) LLM 호출 기록 — 토큰·캐시·비용·지연
CREATE TABLE IF NOT EXISTS llm_calls (
  id                 BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ts                 DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  provider           ENUM('claude','gemini') NOT NULL,
  model              VARCHAR(64)   NOT NULL,
  incidents_in_batch TINYINT UNSIGNED NOT NULL DEFAULT 1,
  input_tokens       INT UNSIGNED  NOT NULL DEFAULT 0,
  output_tokens      INT UNSIGNED  NOT NULL DEFAULT 0,
  cache_read_tokens  INT UNSIGNED  NOT NULL DEFAULT 0,
  cache_write_tokens INT UNSIGNED  NOT NULL DEFAULT 0,
  cost_usd_est       DECIMAL(10,6) NOT NULL DEFAULT 0,
  latency_ms         INT UNSIGNED  NULL,
  status             ENUM('ok','refusal','invalid','error','max_tokens') NOT NULL,
  gate_reason        VARCHAR(64)   NOT NULL,       -- 호출 사유(gray_zone, escalate_low_confidence ...)
  KEY ix_llm_ts (ts)
) ENGINE=InnoDB;

-- 9) 수집 체크포인트 — 중복·누락 없이 이어 받기
CREATE TABLE IF NOT EXISTS checkpoints (
  source     VARCHAR(32) PRIMARY KEY,              -- graylog:wazuh, graylog:board ...
  last_ts    DATETIME(3) NOT NULL,
  last_id    VARCHAR(64) NULL,
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB;

-- 10) 대응 요청·승인·결과
CREATE TABLE IF NOT EXISTS actions (
  id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  incident_id      BIGINT UNSIGNED NOT NULL,
  playbook         ENUM('block_ip','lock_account','monitor') NOT NULL,
  requested_at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  n8n_execution_id VARCHAR(64)  NULL,
  decision         ENUM('pending','approved','rejected','timeout') NOT NULL DEFAULT 'pending',
  decided_by       VARCHAR(128) NULL,
  decided_at       DATETIME(3)  NULL,
  executed_at      DATETIME(3)  NULL,
  changed          BOOLEAN      NULL,              -- 게시판 API 응답의 changed(멱등 200 함정 대비)
  result_note      VARCHAR(255) NULL,
  KEY ix_actions_incident (incident_id),
  CONSTRAINT fk_actions_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 11) 앱 설정 — 웹 콘솔(/settings)에서 바꾸는 값. .env 보다 우선한다.
--     AI 키는 Fernet 암호문(enc:v1:…)으로만 저장하고, 복호화 열쇠(SETTINGS_SECRET_KEY)는 .env 에만 둔다.
CREATE TABLE IF NOT EXISTS app_settings (
  name       VARCHAR(64)  PRIMARY KEY,            -- llm_provider, gemini_model, gemini_api_key ...
  value      TEXT         NOT NULL,
  is_secret  BOOLEAN      NOT NULL DEFAULT FALSE,  -- TRUE 면 value 는 암호문
  updated_at DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB;
