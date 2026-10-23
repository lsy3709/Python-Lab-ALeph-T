# ===========================================================================
# ha_prepare.ps1 — HA 랩 환경 검사 + 이미지 3종 빌드 (Windows PowerShell 전용)
# ---------------------------------------------------------------------------
# 역할 : Docker/Compose 점검 → (선택)기존 ha-lab 정리 → ha-board/ha-keepalived/
#        ha-attacker 이미지 빌드.
# 사용 : powershell -NoProfile -ExecutionPolicy Bypass -File .\ha_prepare.ps1 [-BoardSrc <경로>] [-ResetLab]
#   -BoardSrc : Flask 게시판 원본 폴더(app.py 등이 있는 곳). 기본값은 아래 경로.
#   -ResetLab : 기존 ha-lab 컨테이너/네트워크를 내리고(down) 처음부터 재빌드(초기 구축용).
# 주의 : 이 파일은 반드시 'UTF-8 BOM' 으로 저장해야 Windows PowerShell 5.1 에서
#        한글이 깨지지 않는다(BOM 없으면 cp949 로 오독 → 파싱 에러).
# ===========================================================================
param(
    [string]$BoardSrc = 'E:\0-Aleph-Python-Test\Python-Lab-ALeph-T\_7_board_test',
    [switch]$ResetLab
)
$ErrorActionPreference = 'Stop'       # cmdlet 오류는 즉시 중단
Set-Location $PSScriptRoot            # 이 .ps1 이 있는 폴더(=176_files\ha-lab)로 이동
$CF = '.\ha-compose.yml'

# --- 네이티브(docker) 실행 헬퍼 -------------------------------------------
# Windows PowerShell 5.1 은 docker 가 진행상황을 stderr 로 쓰면, $ErrorActionPreference='Stop'
# + '2>&1' 조합에서 그것을 '종료 에러'로 오인해 스크립트를 멈춘다. 그래서 docker 호출 동안만
# ErrorActionPreference 를 완화하고, 성공/실패는 종료코드($LASTEXITCODE)로만 판정한다.
function Invoke-Native([scriptblock]$Script, [string]$ErrMsg) {
    # docker 를 리다이렉트 없이 그대로 실행한다. ErrorActionPreference='Continue' 에서는
    # 네이티브 stderr(진행 메시지)가 일반 텍스트로 콘솔에 나가고 스크립트를 멈추지 않는다.
    # (2>&1 로 파이프에 합치면 Windows PowerShell 이 그 줄을 '종료 에러'로 오인하므로 쓰지 않는다.)
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Script }
    finally { $ErrorActionPreference = $old }
    if ($LASTEXITCODE -ne 0) { throw "$ErrMsg (exit=$LASTEXITCODE)" }
}

Write-Host '[1] Docker 환경 확인(OSType=linux 이어야 함)' -ForegroundColor Cyan
Invoke-Native { docker info --format '{{.OSType}}' } 'docker info 실패 — Docker Desktop 실행/Linux 컨테이너 모드 확인'

Write-Host '[2] Compose 구문 검사' -ForegroundColor Cyan
Invoke-Native { docker compose -p ha-lab -f $CF config -q } 'compose config 실패 — ha-compose.yml 확인'

if ($ResetLab) {
    Write-Host '[3] 기존 ha-lab 정리(down) — 초기 구축' -ForegroundColor Yellow
    # down 은 ha-lab 컨테이너/네트워크만 제거한다(다른 프로젝트 컨테이너는 건드리지 않음).
    Invoke-Native { docker compose -p ha-lab -f $CF down } 'ha-lab down 실패'
}

Write-Host '[4] ha-board 이미지 빌드(게시판 원본을 빌드 컨텍스트로 사용)' -ForegroundColor Cyan
# Dockerfile.board 는 app.py/controllers/... 를 COPY 하므로 빌드 컨텍스트가 게시판 원본이어야 한다.
if (-not (Test-Path (Join-Path $BoardSrc 'app.py'))) {
    throw "게시판 원본을 찾을 수 없습니다: $BoardSrc (app.py 없음). -BoardSrc 로 실제 경로를 지정하세요."
}
Invoke-Native { docker build -t ha-board:latest -f .\Dockerfile.board $BoardSrc } 'ha-board 빌드 실패'

Write-Host '[5] ha-keepalived 이미지 빌드(entrypoint 에 stale PID 정리 포함)' -ForegroundColor Cyan
Invoke-Native { docker build -t ha-keepalived:latest -f .\Dockerfile.keepalived . } 'ha-keepalived 빌드 실패'

Write-Host '[6] ha-attacker 이미지 빌드(curl/nmap 테스트용)' -ForegroundColor Cyan
Invoke-Native { docker build -t ha-attacker:latest -f .\Dockerfile.attacker . } 'ha-attacker 빌드 실패'

Write-Host '[7] 빌드된 이미지 확인' -ForegroundColor Cyan
docker images | Select-String 'ha-board|ha-keepalived|ha-attacker'
Write-Host '준비 완료. 다음 단계: .\ha_up.ps1' -ForegroundColor Green
