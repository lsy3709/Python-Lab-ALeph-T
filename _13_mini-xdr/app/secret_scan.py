"""공개 저장소에 비밀(API 키·토큰·개인키)이 섞여 들어가지 않았는지 검사한다.

사용: python -m app.secret_scan [경로]   → 발견 시 종료 코드 1 (값은 출력하지 않음)
"""
from __future__ import annotations

import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

# 실제 키 형식만 잡도록 길이 하한을 둔다. 자리표시자(<YOUR_API_KEY>)는 통과.
PATTERNS: dict[str, re.Pattern[str]] = {
    "anthropic_api_key": re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "notion_token": re.compile(r"(?:secret|ntn)_[A-Za-z0-9]{40,}"),
}

SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", "node_modules"}
TEXT_SUFFIXES = {
    "", ".py", ".md", ".txt", ".sql", ".ini", ".toml", ".cfg",
    ".yml", ".yaml", ".json", ".example", ".sh", ".ps1",
}


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    kind: str


def scan_text(text: str) -> list[tuple[int, str]]:
    """문자열에서 (줄 번호, 종류) 목록을 돌려준다."""
    hits: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in PATTERNS.items():
            if pattern.search(line):
                hits.append((lineno, kind))
    return hits


def _is_secret_env_file(name: str) -> bool:
    """.gitignore 로 커밋에서 빠지는 실제 비밀 파일(.env, .env.local …)은 검사 대상이 아니다."""
    return name == ".env" or (name.startswith(".env.") and name != ".env.example")


def iter_files(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if _is_secret_env_file(path.name) or path.suffix not in TEXT_SUFFIXES:
            continue
        yield path


def scan_path(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        findings.extend(Finding(path, lineno, kind) for lineno, kind in scan_text(text))
    return findings


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    root = Path(args[0]) if args else Path(__file__).resolve().parent.parent
    findings = scan_path(root)
    for f in findings:
        print(f"[비밀 의심] {f.path}:{f.line} ({f.kind})")
    if not findings:
        print(f"비밀 스캔 통과: {root}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
