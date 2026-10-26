"""통합 테스트용 일회용 MySQL 도우미 — 테스트 파일이 직접 import 한다(픽스처는 conftest.py)."""
import os
import shutil
import subprocess

ROOT_PW = "xdr_throwaway_test_pw"  # 테스트가 끝나면 삭제되는 일회용 컨테이너 전용
IMAGE = os.environ.get("MINI_XDR_TEST_MYSQL_IMAGE", "mysql:8.0")


def docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def run_mysql(name: str, *args: str, input_sql: str | None = None) -> subprocess.CompletedProcess:
    # -h 127.0.0.1 TCP 접속: 초기화용 임시 서버(소켓 전용)가 아닌 최종 서버에만 붙는다.
    cmd = ["docker", "exec", "-i", name, "mysql", "-h", "127.0.0.1", "--protocol=TCP",
           "-uroot", f"-p{ROOT_PW}", *args]
    return subprocess.run(cmd, input=input_sql, capture_output=True, text=True, encoding="utf-8")
