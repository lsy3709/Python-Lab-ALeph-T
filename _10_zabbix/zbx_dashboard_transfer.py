#!/usr/bin/env python3
"""Portable Zabbix 7.0 user dashboard export/import (standard library only).

Export creates a JSON manifest containing dashboard pages/widgets and human-readable
identities for referenced host groups, hosts, items, item prototypes, graphs and graph
prototypes. Import remaps references on a different, separately installed Zabbix server.

The tool intentionally fails on unhandled ID-bearing widget fields rather than
importing a dashboard with broken or unsafe references.
"""

import argparse
import datetime
import getpass
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request

FORMAT = "zbx7-dashboard-portable-v1"
FIELD_KINDS = {2: "hostgroup", 3: "host", 4: "item", 5: "itemprototype",
               6: "graph", 7: "graphprototype"}


class MigrationError(RuntimeError):
    pass


class Zabbix:
    def __init__(self, url, username):
        self.url = url
        self.username = username
        self.token = None
        self.seq = 0

    def call(self, method, params=None):
        self.seq += 1
        payload = {"jsonrpc": "2.0", "method": method,
                   "params": params if params is not None else {}, "id": self.seq}
        headers = {"Content-Type": "application/json-rpc"}
        if self.token is not None:
            headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.url,
                                     data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=25) as res:
                answer = json.loads(res.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            raise MigrationError(f"API 접속 실패 ({method}, {self.url}): {exc}") from exc
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise MigrationError(f"API 응답이 JSON이 아닙니다 ({method}): {exc}") from exc
        if "error" in answer:
            raise MigrationError(f"API {method} 오류: {answer['error']}")
        if "result" not in answer:
            raise MigrationError(f"API {method} 응답에 result가 없습니다: {answer}")
        return answer["result"]

    def __enter__(self):
        version = str(self.call("apiinfo.version"))
        if not version.startswith("7.0."):
            raise MigrationError(f"Zabbix 7.0.x 전용 스크립트입니다. 현재 버전: {version}")
        secret = os.environ.get("ZBX_PASSWORD") or getpass.getpass(
            f"{self.username}@{self.url} 비밀번호: ")
        self.token = self.call("user.login", {"username": self.username, "password": secret})
        print(f"API 로그인 성공 (Zabbix {version})")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.token:
            try:
                self.call("user.logout", [])
            except MigrationError:
                pass
        self.token = None


def exactly_one(rows, description):
    if len(rows) != 1:
        raise MigrationError(f"{description}: 검색 결과 {len(rows)}개 (반드시 1개여야 함)")
    return rows[0]


def get_source_host_name(api, hostid):
    obj = exactly_one(api.call("host.get", {"hostids": [hostid],
                                            "output": ["host", "hostid"]}),
                      f"원본 호스트 ID={hostid}")
    return obj["host"]  # technical host name, not visible name


def get_source_graph_hosts(api, graph, what):
    hosts = sorted({h["host"] for h in graph.get("hosts", [])})
    if not hosts:
        raise MigrationError(f"{what}: 호스트를 확인할 수 없어 이전을 중단합니다")
    return hosts


def describe(api, typ, oldid):
    """Convert a server-local widget ID to a portable identity."""
    kind = FIELD_KINDS.get(typ)
    if kind is None:
        raise MigrationError(f"필드 유형 {typ}은 자동 ID 변환을 지원하지 않습니다")
    if typ == 2:
        o = exactly_one(api.call("hostgroup.get", {
            "groupids": [oldid], "output": ["groupid", "name"]}),
            f"원본 호스트 그룹 ID={oldid}")
        return {"kind": kind, "name": o["name"]}
    if typ == 3:
        return {"kind": kind, "host": get_source_host_name(api, oldid)}
    if typ in (4, 5):
        method = "item.get" if typ == 4 else "itemprototype.get"
        o = exactly_one(api.call(method, {
            "itemids": [oldid], "output": ["itemid", "key_", "hostid"]}),
            f"원본 {kind} ID={oldid}")
        return {"kind": kind,
                "host": get_source_host_name(api, o["hostid"]), "key": o["key_"]}
    if typ in (6, 7):
        method = "graph.get" if typ == 6 else "graphprototype.get"
        o = exactly_one(api.call(method, {
            "graphids": [oldid], "output": ["graphid", "name"],
            "selectHosts": ["host"]}), f"원본 {kind} ID={oldid}")
        return {"kind": kind, "name": o["name"],
                "hosts": get_source_graph_hosts(api, o, kind)}
    raise MigrationError(f"알 수 없는 필드 유형 {typ}")


def all_widget_fields(dashboard):
    for pindex, page in enumerate(dashboard.get("pages", []), 1):
        for windex, widget in enumerate(page.get("widgets", []), 1):
            for field in widget.get("fields", []):
                yield pindex, windex, widget, field


def export_dashboard(api, dashboard_name, output):
    matches = api.call("dashboard.get", {"output": "extend",
                                         "selectPages": "extend",
                                         "filter": {"name": [dashboard_name]}})
    dashboard = exactly_one(matches, f"대시보드 이름={dashboard_name!r}")
    refs = {}
    counts = {}
    for p, w, widget, field in all_widget_fields(dashboard):
        typ = int(field["type"])
        if typ in (0, 1):
            continue  # ordinary int/string fields; cross-widget reference strings stay as-is
        key = f"{typ}:{field['value']}"
        if key not in refs:
            try:
                refs[key] = describe(api, typ, field["value"])
            except MigrationError as exc:
                raise MigrationError(
                    f"페이지 {p}, 위젯 {w} ({widget['type']}), 필드 {field['name']}: {exc}"
                ) from exc
        counts[typ] = counts.get(typ, 0) + 1
    manifest = {
        "format": FORMAT,
        "exported_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dashboard": dashboard,
        "references": refs,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise MigrationError(f"기존 파일을 덮어쓰지 않습니다: {output}")
    with output.open("x", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"내보내기 완료: {output}")
    print(f"페이지 {len(dashboard['pages'])}개 / 위젯 "
          f"{sum(len(p.get('widgets', [])) for p in dashboard['pages'])}개 / "
          f"매핑 참조 {len(refs)}개")


class Resolver:
    def __init__(self, api):
        self.api = api
        self.cache = {}

    def resolve(self, desc):
        memo = json.dumps(desc, sort_keys=True, ensure_ascii=False)
        if memo in self.cache:
            return self.cache[memo]
        kind = desc["kind"]
        if kind == "hostgroup":
            o = exactly_one(self.api.call("hostgroup.get", {
                "filter": {"name": [desc["name"]]}, "output": ["groupid", "name"]}),
                f"대상 호스트 그룹 {desc['name']!r}")
            ident = o["groupid"]
        elif kind == "host":
            o = exactly_one(self.api.call("host.get", {
                "filter": {"host": [desc["host"]]}, "output": ["hostid", "host"]}),
                f"대상 호스트 {desc['host']!r}")
            ident = o["hostid"]
        elif kind in ("item", "itemprototype"):
            hostid = self.resolve({"kind": "host", "host": desc["host"]})
            method = "item.get" if kind == "item" else "itemprototype.get"
            o = exactly_one(self.api.call(method, {
                "hostids": [hostid], "filter": {"key_": [desc["key"]]},
                "output": ["itemid", "key_"]}),
                f"대상 {kind}: {desc['host']} / {desc['key']}")
            ident = o["itemid"]
        elif kind in ("graph", "graphprototype"):
            if not desc.get("hosts"):
                raise MigrationError(f"그래프의 호스트 정보가 없습니다: {desc}")
            hostids = [self.resolve({"kind": "host", "host": host})
                       for host in desc["hosts"]]
            method = "graph.get" if kind == "graph" else "graphprototype.get"
            rows = self.api.call(method, {
                "hostids": hostids, "filter": {"name": [desc["name"]]},
                "output": ["graphid", "name"], "selectHosts": ["host"]})
            # Same name on multiple hosts can be ambiguous: compare host sets.
            wanted = set(desc["hosts"])
            matches = [g for g in rows
                       if {h["host"] for h in g.get("hosts", [])} == wanted]
            o = exactly_one(matches, f"대상 {kind}: {desc['name']} / {desc['hosts']}")
            ident = o["graphid"]
        else:
            raise MigrationError(f"지원하지 않는 참조 유형: {kind}")
        self.cache[memo] = ident
        return ident


def import_dashboard(api, infile, rename=None, check_only=False):
    with infile.open("r", encoding="utf-8") as f:
        manifest = json.load(f)
    if manifest.get("format") != FORMAT:
        raise MigrationError(f"지원하지 않는 JSON 형식: {manifest.get('format')!r}")
    dashboard = manifest["dashboard"]
    new_name = rename or dashboard["name"]
    exists = api.call("dashboard.get", {"output": ["dashboardid", "name"],
                                        "filter": {"name": [new_name]}})
    if exists:
        raise MigrationError(
            f"대상에 이미 {new_name!r} 대시보드가 있습니다. "
            f"덮어쓰지 않습니다. --rename 으로 새 이름을 정하세요.")
    refs = manifest["references"]
    resolver = Resolver(api)
    # Construct a new create payload: do not carry server-local read-only IDs,
    # owner, user permissions, or sharing rules into another Zabbix database.
    pages = []
    substitutions = []
    for pidx, page in enumerate(dashboard.get("pages", []), 1):
        widgets = []
        for widx, widget in enumerate(page.get("widgets", []), 1):
            fields = []
            for field in widget.get("fields", []):
                typ = int(field["type"])
                value = field["value"]
                if typ not in (0, 1):
                    key = f"{typ}:{value}"
                    desc = refs.get(key)
                    if desc is None:
                        raise MigrationError(
                            f"매핑 정보 누락: 페이지 {pidx}, 위젯 {widx}, "
                            f"필드 {field['name']} ({key})")
                    try:
                        newvalue = resolver.resolve(desc)
                    except MigrationError as exc:
                        raise MigrationError(
                            f"페이지 {pidx}, 위젯 {widx} ({widget['type']}), "
                            f"필드 {field['name']}: {exc}") from exc
                    substitutions.append((key, str(newvalue)))
                    value = newvalue
                fields.append({"type": typ, "name": field["name"], "value": value})
            new_widget = {k: widget[k] for k in
                          ("type", "name", "x", "y", "width", "height", "view_mode")
                          if k in widget}
            new_widget["fields"] = fields
            widgets.append(new_widget)
        pages.append({"name": page.get("name", ""),
                      "display_period": page.get("display_period", 0),
                      "widgets": widgets})
    if not pages:
        raise MigrationError("가져올 대시보드 페이지가 없습니다")
    print(f"참조 매핑 확인: {len(substitutions)}개 필드, "
          f"{len(pages)}개 페이지, {sum(len(p['widgets']) for p in pages)}개 위젯")
    if check_only:
        print("검증 성공! (--check-only: 대시보드를 생성하지 않았습니다)")
        return
    payload = {"name": new_name, "private": 1,  # import privately, not shared
               "display_period": dashboard.get("display_period", 30),
               "auto_start": dashboard.get("auto_start", 1), "pages": pages}
    result = api.call("dashboard.create", payload)
    print(f"가져오기 완료: {new_name} / dashboardid={result['dashboardids'][0]}")
    print("대시보드가 비공개로 생성되었습니다. 공유 권한은 필요하면 웹 UI에서 설정하세요.")


def main():
    parser = argparse.ArgumentParser(
        description="Zabbix 7.0 일반 대시보드 이식: 내보내기/가져오기")
    sub = parser.add_subparsers(dest="mode", required=True)
    pexport = sub.add_parser("export", help="기존 서버에서 JSON 내보내기")
    pexport.add_argument("--dashboard", required=True, help="내보낼 대시보드의 정확한 이름")
    pimport = sub.add_parser("import", help="대상 서버에 JSON 가져오기")
    pimport.add_argument("--rename", help="중복 방지를 위한 새 대시보드 이름")
    pimport.add_argument("--check-only", action="store_true", help="매핑 검증만 수행")
    for p in (pexport, pimport):
        p.add_argument("--api", default="http://127.0.0.1:8081/api_jsonrpc.php",
                       help="대상 PC의 Zabbix API URL (기본: 127.0.0.1:8081)")
        p.add_argument("--user", default="Admin", help="Zabbix 로그인 ID (기본 Admin)")
        p.add_argument("--file", default="soar_dashboard.json", help="JSON 파일 경로")
    args = parser.parse_args()
    try:
        with Zabbix(args.api, args.user) as api:
            if args.mode == "export":
                export_dashboard(api, args.dashboard, Path(args.file))
            else:
                import_dashboard(api, Path(args.file), args.rename, args.check_only)
    except (MigrationError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
