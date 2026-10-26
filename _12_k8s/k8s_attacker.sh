#!/usr/bin/env bash
# Kali 공격 파드 — (A) HTTP 폭주 중 가용성 유지 확인, (B) 기본 SA 로 파드 삭제 시도→RBAC 거부 증명
cd "$(dirname "$0")"
CTX="--context kind-ha-k8s"
KCTL="kubectl $CTX -n ha"
P=probe_attack.log; rm -f "$P"

echo "=== 공격 파드 기동 ==="
$KCTL apply -f k8s_attacker.yaml >/dev/null
$KCTL wait --for=condition=Ready pod/kali-attacker --timeout=120s
echo

echo "=== (A) HTTP 폭주(클러스터 내부 board Service) 중 외부 가용성 측정 ==="
# 외부(host NodePort) 프로브 0.2초×120 (~24초)
( i=0; while [ $i -lt 120 ]; do printf "%s %s\n" "$(date +%s.%N)" "$(curl -s -o /dev/null -w %{http_code} -m 1 http://localhost:30080/)" >> "$P"; i=$((i+1)); sleep 0.2; done ) &
PROBE=$!
sleep 4
echo "[$(date +%H:%M:%S)] kali → board.ha.svc 로 20스레드 폭주(~15초)"
MSYS_NO_PATHCONV=1 $KCTL exec kali-attacker -- python -c '
import urllib.request as u, threading, time
cnt=[0]
def f():
    end=time.time()+15
    while time.time()<end:
        try: u.urlopen("http://board.ha.svc/",timeout=1).read(); cnt[0]+=1
        except: pass
ts=[threading.Thread(target=f) for _ in range(20)]
[t.start() for t in ts]; [t.join() for t in ts]
print("폭주 요청수:",cnt[0])
'
wait $PROBE
echo "--- 외부 가용성(폭주 중) ---"
awk '{n++; if($2==200){ok++; run=0} else {fail++; run++; if(run>maxrun)maxrun=run}} END{printf "총 %d | 200 %d | 실패 %d | 성공률 %.1f%% | 최대연속실패 %d\n", n, ok+0, fail+0, 100*ok/n, maxrun+0}' "$P"
echo

echo "=== (B) 기본 ServiceAccount 로 board 파드 삭제 시도 → RBAC 거부(403) 증명 ==="
VICTIM=$($KCTL get pods -l app=board -o jsonpath='{.items[0].metadata.name}')
echo "삭제 시도 대상: $VICTIM"
MSYS_NO_PATHCONV=1 $KCTL exec kali-attacker -- python -c "
import ssl, urllib.request, urllib.error
tok=open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
ns=open('/var/run/secrets/kubernetes.io/serviceaccount/namespace').read().strip()
url='https://kubernetes.default.svc/api/v1/namespaces/%s/pods/$VICTIM'%ns
req=urllib.request.Request(url, method='DELETE'); req.add_header('Authorization','Bearer '+tok)
ctx=ssl.create_default_context(cafile='/var/run/secrets/kubernetes.io/serviceaccount/ca.crt')
try:
    r=urllib.request.urlopen(req,context=ctx,timeout=10); print('결과: HTTP',r.status,'(삭제됨 — 권한 있음!)')
except urllib.error.HTTPError as e:
    print('결과: HTTP',e.code, '→', ('Forbidden(거부 — 공격자 권한 없음)' if e.code==403 else e.reason))
"
echo "--- 삭제 시도 후 파드(그대로 살아있음) ---"
$KCTL get pods -l app=board
echo "===== 끝 ====="
