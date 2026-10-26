#!/usr/bin/env bash
# HA 3단계 — 클러스터에 게시판+MySQL 적재·배포·준비대기
# ★ 반드시 Git Bash("C:\Program Files\Git\bin\bash.exe")로 실행 — WSL bash(System32\bash.exe)는
#   kubectl/kubeconfig 가 분리돼 'context "kind-ha-k8s" does not exist' 가 난다.
#   (또는 그냥 PowerShell §2 블록을 쓰면 된다.)
set -e
cd "$(dirname "$0")"
KIND=kind        # winget 설치본(PATH). 구버전은 ./kind.exe 였음 — 더는 로컬 파일에 의존하지 않음
KCTL="kubectl --context kind-ha-k8s"
# 컨텍스트가 없으면(노드는 떠 있는데 kubeconfig 에만 없음) 복원
kind export kubeconfig --name ha-k8s >/dev/null 2>&1 || true

echo "=== 1) board 로컬 이미지를 아카이브로 적재(mysql 은 노드가 Hub 에서 풀) ==="
[ -f hab.tar ] || docker save ha-board:latest -o hab.tar
$KIND load image-archive hab.tar --name ha-k8s

echo "=== 2) 매니페스트 적용 ==="
$KCTL apply -f k8s-ha-all.yaml

echo "=== 3) MySQL(StatefulSet) 준비 대기 ==="
$KCTL -n ha rollout status statefulset/mysql --timeout=240s

echo "=== 4) board(Deployment) 준비 대기 ==="
$KCTL -n ha rollout status deploy/board --timeout=240s

echo "=== 5) 배치 결과(노드 분산 확인) ==="
$KCTL -n ha get pods -o wide
echo "=== NodePort 외부 도달 확인(host:30080) ==="
for i in 1 2 3; do printf "try%s: %s\n" "$i" "$(curl -s -o /dev/null -w '%{http_code}' -m 3 http://localhost:30080/)"; sleep 1; done
