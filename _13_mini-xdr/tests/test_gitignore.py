"""공개 저장소 보호: 비밀 .env 류는 git 이 무시하고 .env.example 만 추적되는지 실제로 확인한다."""
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git 없음")


def _ignored(rel: str) -> bool:
    r = subprocess.run(["git", "check-ignore", "-q", rel], cwd=PROJECT, capture_output=True)
    if r.returncode not in (0, 1):  # 128 = git 저장소가 아님(zip 으로 받은 경우 등)
        pytest.skip("git 저장소가 아님")
    return r.returncode == 0  # 0 = 무시됨, 1 = 추적 대상


@pytest.mark.parametrize("name", [".env", ".env.local", ".env.prod"])
def test_secret_env_files_are_ignored(name):
    assert _ignored(name)


def test_env_example_is_tracked():
    assert not _ignored(".env.example")
