# ha_up.ps1 — 빈(초기) ha-lab DB 기준 순차 기동: MySQL main/replica → board → keepalived/VIP
#   ※ 이 스크립트는 "처음 구축(빈 DB)" 전용입니다. 이미 복제가 구성된 상태에서 재실행하면 안 됩니다
#      (재기동/복구는 문서의 '재기동·복구' 절 — resync 절차 참고).
# 사용: powershell -NoProfile -ExecutionPolicy Bypass -File .\ha_up.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$CF = '.\ha-compose.yml'
$RP = 'ha_root_pw'   # 격리 랩 전용 throwaway 비밀번호(ha-compose.yml 와 동일)

function Assert-Docker([string]$Message) { if ($LASTEXITCODE -ne 0) { throw "$Message (Docker exit=$LASTEXITCODE)" } }

# Windows PowerShell 5.1 은 리다이렉트된 네이티브 stderr 를 에러 레코드로 취급한다.
# mysql CLI 는 -p 사용 시 항상 무해한 암호 경고를 stderr 로 출력하므로,
# 로컬에서 ErrorActionPreference 를 완화해 경고는 걸러내고 종료코드/실제 오류만 보고한다.
# ★ SHOW REPLICA STATUS 는 -N -B 를 쓰면 필드명이 사라져 상태 판정이 깨지므로 제외한다.
function Invoke-DbMysql([string]$Container, [string]$Sql) {
    $oldPref = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($Sql -like 'SHOW REPLICA STATUS*') {
            $raw = & docker exec $Container mysql -uroot "-p$RP" -e $Sql 2>&1
        } else {
            $raw = & docker exec $Container mysql -uroot "-p$RP" -N -B -e $Sql 2>&1
        }
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $oldPref }
    $lines = @(
        $raw | ForEach-Object { [string]$_ } |
            Where-Object { $_ -notmatch 'Using a password on the command line interface can be insecure' }
    )
    return [pscustomobject]@{ ExitCode = $code; Output = ($lines -join "`n").Trim() }
}
function DbQuery([string]$Container, [string]$Sql) {
    $r = Invoke-DbMysql $Container $Sql
    if ($r.ExitCode -ne 0) { throw "MySQL 명령 실패: $Container ; exit=$($r.ExitCode); 오류=$($r.Output); SQL=$Sql" }
    return $r.Output
}
function DbReady([string]$Container) {
    $r = Invoke-DbMysql $Container 'SELECT 1'
    return ($r.ExitCode -eq 0 -and $r.Output -eq '1')
}

Write-Host '[1] MySQL 2개 컨테이너 시작' -ForegroundColor Cyan
docker compose -p ha-lab -f $CF up -d mysql-main mysql-sub; Assert-Docker 'MySQL 시작 실패'
$ready = $false
for ($i=0; $i -lt 40; $i++) {
    if ((DbReady 'ha-mysql-main') -and (DbReady 'ha-mysql-sub')) { $ready = $true; break }
    Start-Sleep -Seconds 3
}
if (-not $ready) { throw 'MySQL 준비 실패: docker logs ha-mysql-main / ha-mysql-sub 확인' }
Write-Host '  main/sub SELECT 1 성공' -ForegroundColor Green

# 빈 DB 전제 확인(초기 구축 전용). 이미 데이터가 있으면 중단.
$beforeM = [int](DbQuery 'ha-mysql-main' "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='my_new_board_db';")
$beforeS = [int](DbQuery 'ha-mysql-sub'  "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='my_new_board_db';")
if ($beforeM -ne 0 -or $beforeS -ne 0) {
    throw "빈 DB 초기 상태가 아닙니다(main=$beforeM, sub=$beforeS). 이미 구성된 랩이면 이 스크립트를 재실행하지 말고 '재기동·복구' 절차를 따르세요."
}
# 기존 복제 설정이 남아 있으면 중단(테이블이 없어도 복제 메타데이터는 있을 수 있음)
$existing = DbQuery 'ha-mysql-sub' 'SHOW REPLICA STATUS\G'
if ($existing -match '(?m)^\s*Source_Host:\s*\S+') {
    throw "기존 Replica 설정이 발견되었습니다. 초기 구축 스크립트를 중단합니다. '재기동·복구' 절차(resync)를 따르세요."
}

Write-Host '[2] 복제 계정 + binlog 위치 조회' -ForegroundColor Cyan
DbQuery 'ha-mysql-main' "CREATE USER IF NOT EXISTS 'repl'@'%' IDENTIFIED WITH mysql_native_password BY 'replpw'; GRANT REPLICATION SLAVE ON *.* TO 'repl'@'%'; FLUSH PRIVILEGES;" | Out-Null
$raw = DbQuery 'ha-mysql-main' 'SHOW MASTER STATUS;'
$first = @($raw -split "`r?`n")[0]
if ($first -notmatch '^(\S+)\s+(\d+)') { throw "SHOW MASTER STATUS 파싱 실패: $raw" }
$binFile = $Matches[1]; $binPos = [int64]$Matches[2]
Write-Host "  Master file=$binFile / pos=$binPos"

Write-Host '[3] MySQL Replica 구성' -ForegroundColor Cyan
DbQuery 'ha-mysql-sub' 'STOP REPLICA; RESET REPLICA ALL;' | Out-Null
$sql = "CHANGE REPLICATION SOURCE TO SOURCE_HOST='mysql-main', SOURCE_PORT=3306, SOURCE_USER='repl', SOURCE_PASSWORD='replpw', SOURCE_LOG_FILE='$binFile', SOURCE_LOG_POS=$binPos, GET_SOURCE_PUBLIC_KEY=1; START REPLICA;"
DbQuery 'ha-mysql-sub' $sql | Out-Null
$replOk = $false
for ($i=0; $i -lt 20; $i++) {
    $status = DbQuery 'ha-mysql-sub' 'SHOW REPLICA STATUS\G'
    if ($status -match '(?m)^\s*Replica_IO_Running:\s*Yes\s*$' -and $status -match '(?m)^\s*Replica_SQL_Running:\s*Yes\s*$') { $replOk = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $replOk) { Write-Host $status; throw 'Replica_IO_Running/Replica_SQL_Running = Yes 확인 실패' }
Write-Host '  Replica_IO_Running=Yes, Replica_SQL_Running=Yes' -ForegroundColor Green

Write-Host '[4] board-main 기동(Flask create_all → 스키마 생성·복제 전파)' -ForegroundColor Cyan
docker compose -p ha-lab -f $CF up -d board-main; Assert-Docker 'board-main 기동 실패'
$schemaOk = $false
for ($i=0; $i -lt 40; $i++) {
    $mc = [int](DbQuery 'ha-mysql-main' "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='my_new_board_db';")
    $sc = [int](DbQuery 'ha-mysql-sub'  "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='my_new_board_db';")
    if ($mc -ge 3 -and $sc -eq $mc) { $schemaOk = $true; break }
    Start-Sleep -Seconds 3
}
if (-not $schemaOk) { docker logs --tail 40 ha-board-main; throw "테이블 복제 확인 실패: main=$mc, sub=$sc" }
Write-Host "  main 테이블=$mc / sub 테이블=$sc (복제 전파 확인)" -ForegroundColor Green

Write-Host '[5] board-sub / keepalived-main / keepalived-sub / attacker 기동' -ForegroundColor Cyan
docker compose -p ha-lab -f $CF up -d board-sub keepalived-main keepalived-sub attacker; Assert-Docker 'HA 부속 컨테이너 시작 실패'
$vipOk = $false
for ($i=0; $i -lt 20; $i++) {
    $oldPref = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $code = & docker exec ha-attacker curl -s -o /dev/null -w '%{http_code}' -m 3 http://172.16.0.100:5000/ 2>$null; $curlExit = $LASTEXITCODE }
    finally { $ErrorActionPreference = $oldPref }
    if ($curlExit -eq 0 -and (($code | Out-String).Trim() -eq '200')) { $vipOk = $true; break }
    Start-Sleep -Seconds 2
}
Write-Host '[6] HA 컨테이너 상태' -ForegroundColor Cyan
docker ps --filter 'name=ha-' --format 'table {{.Names}}\t{{.Status}}'
Write-Host '[7] VIP 소유 확인(keepalived 컨테이너에서 — board 이미지엔 ip 명령 없음)' -ForegroundColor Cyan
Write-Host '--- MAIN (172.16.0.11 + VIP 172.16.0.100 이어야) ---'
docker exec ha-keepalived-main ip -4 addr show eth0 | Select-String 'inet '
Write-Host '--- SUB (172.16.0.12 만, VIP 없어야) ---'
docker exec ha-keepalived-sub ip -4 addr show eth0 | Select-String 'inet '
if (-not $vipOk) { throw 'VIP HTTP 200 확인 실패. docker logs ha-keepalived-main / ha-board-main 확인' }
Write-Host 'VIP HTTP 200 확인. 다음: .\ha_failover_B.ps1 (failover 테스트)' -ForegroundColor Green
