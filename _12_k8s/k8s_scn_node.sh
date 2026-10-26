#!/usr/bin/env bash
# 시나리오 3 — 워커 노드 다운(drain) → 파드 타 노드 자동 재배치(reschedule)
cd "$(dirname "$0")"
CTX="--context kind-ha-k8s"
KCTL="kubectl $CTX -n ha"
P=probe_node.log; rm -f "$P"
echo "[$(date +%H:%M:%S)] 교란 전 배치"; $KCTL get pods -l app=board -o wide
# mysql 가 없는 워커(board 가 올라간) 노드를 고른다 → drain 해도 DB 는 유지
MYSQLNODE=$($KCTL get pod mysql-0 -o jsonpath='{.spec.nodeName}')
NODE=$($KCTL get pods -l app=board -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | grep -v "^${MYSQLNODE}$" | head -1)
[ -z "$NODE" ] && NODE=$($KCTL get pods -l app=board -o jsonpath='{.items[0].spec.nodeName}')
echo "[$(date +%H:%M:%S)] mysql 노드=$MYSQLNODE / drain 대상=$NODE"
( i=0; while [ $i -lt 200 ]; do printf "%s %s\n" "$(date +%s.%N)" "$(curl -s -o /dev/null -w %{http_code} -m 1 http://localhost:30080/)" >> "$P"; i=$((i+1)); sleep 0.2; done ) &
PROBE=$!
sleep 6
echo "[$(date +%H:%M:%S)] drain $NODE (노드 다운 모사: cordon + 파드 축출)"
kubectl $CTX drain "$NODE" --ignore-daemonsets --delete-emptydir-data --force --timeout=90s 2>&1 | tail -4
echo "[$(date +%H:%M:%S)] 축출 후 재배치"; $KCTL get pods -l app=board -o wide
$KCTL rollout status deploy/board --timeout=90s
wait $PROBE
echo "[$(date +%H:%M:%S)] uncordon $NODE (노드 복구)"; kubectl $CTX uncordon "$NODE" >/dev/null
echo "=== 프로브 분석(노드 다운→재배치 구간) ==="
awk '{n++; if($2==200){ok++; run=0} else {fail++; run++; if(run>maxrun)maxrun=run}} END{printf "총 %d | 200 %d | 실패 %d | 성공률 %.1f%% | 최대연속실패 %d(~%.1f초)\n", n, ok+0, fail+0, 100*ok/n, maxrun+0, (maxrun+0)*0.2}' "$P"
