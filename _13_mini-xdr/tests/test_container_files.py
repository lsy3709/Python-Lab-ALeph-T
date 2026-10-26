"""컨테이너 파일 정적 점검 — 비밀값이 이미지에 들어가지 않고, 콘솔은 이 PC 에만 공개되며,
기존 SOAR 컨테이너의 네트워크를 건드리지 않는지 확인한다."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def test_dockerignore_keeps_secrets_and_venv_out_of_image():
    lines = {line.strip() for line in read(".dockerignore").splitlines()}
    assert {".env", ".env.*", ".venv/", ".git/"} <= lines


def test_dockerfile_runs_as_non_root_and_copies_only_code():
    text = read("Dockerfile")
    assert "USER xdr" in text
    assert "COPY . " not in text and "COPY ./ " not in text  # 통째 복사 금지(.env 실수 방지 이중 장치)
    assert "COPY app/ app/" in text and "COPY sql/ sql/" in text


def test_compose_publishes_console_on_localhost_only():
    text = read("docker-compose.yml")
    assert '"127.0.0.1:8099:8099"' in text
    assert "0.0.0.0:8099" not in text


def test_compose_does_not_join_existing_stack_networks():
    text = read("docker-compose.yml")
    assert "external:" not in text and "graylog_default" not in text and "network_mode" not in text
    assert "host.docker.internal" in text


def test_compose_takes_secrets_only_from_env_file():
    text = read("docker-compose.yml")
    assert "env_file: .env" in text
    for secret in ("MYSQL_PASSWORD", "GRAYLOG_TOKEN", "GRAYLOG_PASSWORD", "ANTHROPIC_API_KEY"):
        assert secret not in text
