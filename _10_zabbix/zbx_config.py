# zbx_config.py — Zabbix 7.0 API 로 기존 스택 가용성 감시 구성
# 호스트 1개 + Simple check 5개(net.tcp.service[tcp,host.docker.internal,PORT]) + DOWN 트리거 5개
import json, urllib.request, sys

API = "http://127.0.0.1:8081/api_jsonrpc.php"
USER, PW = "Admin", "zabbix"   # Zabbix 기본 관리자

TARGETS = [
    ("board-5000",   5000, "게시판"),
    ("graylog-9000", 9000, "Graylog"),
    ("wazuhdash-443", 443, "Wazuh 대시보드"),
    ("mysql-3306",   3306, "MySQL"),
    ("n8n-5678",     5678, "n8n"),
]

def call(method, params, token=None, as_login=False):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(API, data=data, headers={"Content-Type": "application/json-rpc"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=15) as r:
        res = json.loads(r.read())
    if "error" in res:
        raise RuntimeError("%s -> %s" % (method, res["error"]))
    return res["result"]

def main():
    token = call("user.login", {"username": USER, "password": PW})
    print("login OK")

    # 호스트그룹
    g = call("hostgroup.get", {"filter": {"name": ["HA-lab-targets"]}}, token)
    gid = g[0]["groupid"] if g else call("hostgroup.create", {"name": "HA-lab-targets"}, token)["groupids"][0]

    # 기존 호스트 있으면 삭제(멱등 재실행)
    ex = call("host.get", {"filter": {"host": ["existing-stack"]}}, token)
    if ex:
        call("host.delete", [ex[0]["hostid"]], token)
        print("기존 호스트 삭제(재구성)")

    hid = call("host.create", {
        "host": "existing-stack",
        "name": "기존 SOAR 스택(가용성)",
        "groups": [{"groupid": gid}],
        "interfaces": [{"type": 1, "main": 1, "useip": 1, "ip": "127.0.0.1", "dns": "", "port": "10050"}],
    }, token)["hostids"][0]
    print("host 생성:", hid)

    for key_name, port, label in TARGETS:
        key = "net.tcp.service[tcp,host.docker.internal,%d]" % port
        iid = call("item.create", {
            "hostid": hid, "name": "%s(%d) 가용성" % (label, port),
            "key_": key, "type": 3, "value_type": 3, "delay": "30s",
        }, token)["itemids"][0]
        call("trigger.create", {
            "description": "%s(%d) DOWN" % (label, port),
            "expression": "last(/existing-stack/%s)=0" % key,
            "priority": 4,
        }, token)
        print("  item+trigger:", label, port, "->", iid)

    print("DONE")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("ERROR:", e); sys.exit(1)
