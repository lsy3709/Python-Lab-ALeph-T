# ===========================================================================
# ha_failover_B.ps1 — 시나리오 B: board-main 강제 다운 → VIP 서브 인계(failover) 실측
# ---------------------------------------------------------------------------
# VIP 에 0.3초 간격 150회 프로브(attacker 내부) 중 board-main 을 중지 → 공백·성공률 측정 → 복구.
# 사용 : powershell -NoProfile -ExecutionPolicy Bypass -File .\ha_failover_B.ps1
# 핵심 : PowerShell 은 'docker exec sh -c "긴 셸 문자열"' 의 내부 따옴표를 뭉개므로,
#        프로브 셸 스크립트를 '파일로 만들어 docker cp' 한 뒤 컨테이너 안에서 실행한다.
# 주의 : UTF-8 BOM 으로 저장(한글 깨짐 방지).
# ===========================================================================
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$CF = '.\ha-compose.yml'

# VIP HTTP 코드를 attacker 컨테이너에서 조회(네이티브 stderr 는 무시, 종료코드로 판정)
function Get-Vip {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $c = & docker exec ha-attacker curl -s -o /dev/null -w '%{http_code}' -m 3 http://172.16.0.100:5000/ 2>$null }
    finally { $ErrorActionPreference = $old }
    return ($c | Out-String).Trim()
}

Write-Host '[1] 정상 VIP 확인' -ForegroundColor Cyan
$c0 = Get-Vip; Write-Host "  VIP=$c0"
if ($c0 -ne '200') { throw "VIP 가 200 이 아닙니다($c0). 먼저 .\ha_up.ps1 로 스택을 정상화하세요." }

Write-Host '[2] VIP 프로브 150회 준비(파일 생성 → docker cp → 컨테이너 내부 실행)' -ForegroundColor Cyan
# 프로브 셸 스크립트(LF 줄바꿈). $i·$(...) 는 컨테이너 sh 가 해석한다.
$probe = @'
i=0
while [ $i -lt 150 ]; do
  printf "%s %s\n" "$(date +%s)" "$(curl -s -o /dev/null -w %{http_code} -m 1 http://172.16.0.100:5000/)" >> /tmp/probe.log
  i=$((i+1))
  sleep 0.3
done
'@
$tmp = Join-Path $env:TEMP 'ha_probe.sh'
[System.IO.File]::WriteAllText($tmp, ($probe -replace "`r`n", "`n"))   # 반드시 LF
docker cp $tmp ha-attacker:/tmp/probe.sh | Out-Null
docker exec ha-attacker sh -c 'rm -f /tmp/probe.log' | Out-Null
docker exec -d ha-attacker sh /tmp/probe.sh                            # 백그라운드 프로브 시작

Start-Sleep -Seconds 10
Write-Host '[3] board-main 강제 중지(노드 다운 모사)' -ForegroundColor Yellow
docker stop ha-board-main | Out-Null
Start-Sleep -Seconds 18

Write-Host '[4] board-main 복구(+ keepalived-main 재생성)' -ForegroundColor Cyan
docker start ha-board-main | Out-Null
# keepalived-main 은 board-main 의 netns 를 공유하므로, board 재시작 후 재생성해야 VIP 로직이 깨끗이 복구된다.
$old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
docker compose -p ha-lab -f $CF up -d --force-recreate --no-deps keepalived-main 2>&1 | Out-Null
$ErrorActionPreference = $old
Start-Sleep -Seconds 18

Write-Host '[5] 프로브 분석(VIP 가용성)' -ForegroundColor Cyan
$log = & docker exec ha-attacker cat /tmp/probe.log 2>$null
$codes = @($log | ForEach-Object { ($_ -split '\s+') | Select-Object -Last 1 } | Where-Object { $_ -match '^\d+$' })
$n = $codes.Count
$ok = @($codes | Where-Object { $_ -eq '200' }).Count
$fail = $n - $ok
$max = 0; $cur = 0
foreach ($cc in $codes) { if ($cc -eq '200') { $cur = 0 } else { $cur++; if ($cur -gt $max) { $max = $cur } } }
$rate = if ($n) { [math]::Round(100 * $ok / $n, 1) } else { 0 }
Write-Host ("  총 {0} | 200 {1} | 실패 {2} | 성공률 {3}%" -f $n, $ok, $fail, $rate)
Write-Host ("  최대 연속 실패 {0}회 (~{1}초) = VIP 인계 공백" -f $max, [math]::Round($max * 0.3, 1))

Write-Host '[6] keepalived 전이 로그(sub 에 Entering MASTER STATE 가 보이면 failover 성공)' -ForegroundColor Cyan
$old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
docker logs ha-keepalived-sub 2>&1 | Select-String 'MASTER|BACKUP' | Select-Object -Last 4 | ForEach-Object { Write-Host "  $_" }
$ErrorActionPreference = $old

Write-Host "[7] 현재 VIP: $(Get-Vip)" -ForegroundColor Green
Write-Host '===== failover 테스트 끝 =====' -ForegroundColor Green
