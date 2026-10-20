import json
from pathlib import Path

SOURCE = Path("soar_dashboard.json")
OUTPUT = Path("soar_dashboard_fixed.json")

OLD_NAME = "/wazuh-manager2"
NEW_NAME = "/wazuh-manager"

# 기존 JSON 읽기
data = json.loads(
    SOURCE.read_text(encoding="utf-8-sig")
)

count = 0

# 대시보드 참조 정보 수정
for ref in data["references"].values():

    if ref.get("host") != "docker-engine":
        continue

    if ref.get("kind") not in ("item", "itemprototype"):
        continue

    old_key = ref.get("key", "")

    new_key = old_key.replace(
        f'"{OLD_NAME}"',
        f'"{NEW_NAME}"'
    )

    if old_key != new_key:
        ref["key"] = new_key

        print("변경 전:", old_key)
        print("변경 후:", new_key)
        print()

        count += 1

if count == 0:
    raise SystemExit("변경할 Wazuh Item 참조가 없습니다.")

# 수정된 JSON 저장
OUTPUT.write_text(
    json.dumps(
        data,
        ensure_ascii=False,
        indent=2
    ),
    encoding="utf-8"
)

print("=" * 50)
print("수정된 Item 참조:", count)
print("저장 파일:", OUTPUT)
print("=" * 50)