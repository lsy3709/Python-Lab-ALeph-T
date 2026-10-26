#!/usr/bin/env bash
# 시나리오 1 — 파드 강제 삭제 → ReplicaSet 자동 재생성(재스케줄)
cd "$(dirname "$0")"
KCTL="kubectl --context kind-ha-k8s -n ha"
P=probe_pod.log; rm -f "$P"
echo "[$(date +%H:%M:%S)] 삭제 전 파드"; $KCTL get pods -l app=board -o wide
# 프로브: 0.2초×150 (~30초), host NodePort 30080
( i=0; while [ $i -lt 150 ]; do printf "%s %s\n" "$(date +%s.%N)" "$(curl -s -o /dev/null -w %{http_code} -m 1 http://localhost:30080/)" >> "$P"; i=$((i+1)); sleep 0.2; done ) &
PROBE=$!
sleep 6
VICTIM=$($KCTL get pods -l app=board -o jsonpath='{.items[0].metadata.name}')
echo "[$(date +%H:%M:%S)] delete pod $VICTIM (--force)"
$KCTL delete pod "$VICTIM" --grace-period=0 --force 2>/dev/null
wait $PROBE
echo "[$(date +%H:%M:%S)] 삭제 후 파드(재생성 확인)"; $KCTL get pods -l app=board -o wide
echo "=== 프로브 분석(파드 삭제 구간) ==="
awk '{n++; if($2==200){ok++; run=0} else {fail++; run++; if(run>maxrun)maxrun=run}} END{printf "총 %d | 200 %d | 실패 %d | 성공률 %.1f%% | 최대연속실패 %d(~%.1f초)\n", n, ok+0, fail+0, 100*ok/n, maxrun+0, (maxrun+0)*0.2}' "$P"
