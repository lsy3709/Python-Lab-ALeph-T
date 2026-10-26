#!/usr/bin/env bash
# 시나리오 2 — 컨테이너 강제 크래시(PID1 SIGKILL) → kubelet 자동 재시작(self-healing)
# 프레시 파드로 리셋해 back-off 영향을 배제하고 깨끗하게 측정
cd "$(dirname "$0")"
KCTL="kubectl --context kind-ha-k8s -n ha"
P=probe_live.log; rm -f "$P"
echo "[$(date +%T)] 프레시 파드로 리셋(이전 back-off 제거)"
$KCTL rollout restart deploy/board >/dev/null
$KCTL rollout status deploy/board --timeout=150s
VICTIM=$($KCTL get pods -l app=board -o jsonpath='{.items[0].metadata.name}')
R0=$($KCTL get pod "$VICTIM" -o jsonpath='{.status.containerStatuses[0].restartCount}')
echo "[$(date +%T)] 대상 $VICTIM (RESTARTS=$R0)"
# 외부 가용성 프로브: 0.25초×120 (~30초)
( i=0; while [ $i -lt 120 ]; do printf "%s %s\n" "$(date +%s.%N)" "$(curl -s -o /dev/null -w %{http_code} -m 1 http://localhost:30080/)" >> "$P"; i=$((i+1)); sleep 0.25; done ) &
PROBE=$!
sleep 5
T0=$(date +%s)
echo "[$(date +%T)] $VICTIM 크래시(SIGKILL: PID1+서버 자식)"
MSYS_NO_PATHCONV=1 $KCTL exec "$VICTIM" -- sh -c 'kill -9 1 11 2>/dev/null; true' >/dev/null 2>&1 &
# RESTARTS 증가(=kubelet 재시작)까지 측정
REC=""; R1="$R0"
for i in $(seq 40); do
  R1=$($KCTL get pod "$VICTIM" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null)
  [ -n "$R1" ] && [ "$R1" != "$R0" ] && REC=$(( $(date +%s) - T0 )) && break
  sleep 1
done
wait $PROBE
echo "[$(date +%T)] RESTARTS $R0 -> ${R1} (크래시→재시작 ~${REC:-측정중}s)"
$KCTL get pods -l app=board -o wide
echo "=== 외부 가용성(크래시 중 — 다른 복제본이 계속 서비스) ==="
awk '{n++; if($2==200){ok++;run=0} else {fail++;run++; if(run>maxrun)maxrun=run}} END{printf "총 %d | 200 %d | 실패 %d | 성공률 %.1f%% | 최대연속실패 %d(~%.2f초)\n", n, ok+0, fail+0, 100*ok/n, maxrun+0, (maxrun+0)*0.25}' "$P"
