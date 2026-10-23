# zbx_ha_config_safe.py — Zabbix 에 HA 클러스터(VIP·노드) 가용성 감시 추가 (비파괴 버전)
#   기존 zbx_ha_config.py 와 달리 이미 있는 ha-cluster 호스트/항목을 "삭제하지 않고 재사용"한다.
#   사용: python .\zbx_ha_config_safe.py   (Zabbix 웹 http://127.0.0.1:8081, Admin/zabbix)
import json, urllib.request, sys
API = "http://127.0.0.1:8081/api_jsonrpc.php"
USER, PW = "Admin", "zabbix"
TARGETS = [
    ("VIP(가상IP) 가용성",     "172.16.0.100", 5000),
    ("board-main(앱) 가용성",  "172.16.0.11",  5000),
    ("board-sub(앱) 가용성",   "172.16.0.12",  5000),
    ("mysql-main 가용성",      "172.16.0.21",  3306),
    ("mysql-sub 가용성",       "172.16.0.22",  3306),
]
def call(m, p, t=None):
    req = urllib.request.Request(API, data=json.dumps({"jsonrpc":"2.0","method":m,"params":p,"id":1}).encode(),
                                 headers={"Content-Type":"application/json-rpc"})
    if t: req.add_header("Authorization", "Bearer "+t)
    r = json.loads(urllib.request.urlopen(req, timeout=15).read())
    if "error" in r: raise RuntimeError("%s -> %s" % (m, r["error"]))
    return r["result"]
def main():
    tok = call("user.login", {"username":USER, "password":PW}); print("Zabbix API 로그인 성공")
    g = call("hostgroup.get", {"filter":{"name":["HA-lab-targets"]}}, tok)
    gid = g[0]["groupid"] if g else call("hostgroup.create", {"name":"HA-lab-targets"}, tok)["groupids"][0]
    ex = call("host.get", {"filter":{"host":["ha-cluster"]}}, tok)
    if ex:
        hid = ex[0]["hostid"]; print("기존 ha-cluster 재사용(hostid=%s)" % hid)
    else:
        hid = call("host.create", {"host":"ha-cluster","name":"HA 클러스터(이중화 데모)","groups":[{"groupid":gid}],
            "interfaces":[{"type":1,"main":1,"useip":1,"ip":"127.0.0.1","dns":"","port":"10050"}]}, tok)["hostids"][0]
        print("호스트 생성: ha-cluster (hostid=%s)" % hid)
    for name, ip, port in TARGETS:
        # Simple check(에이전트리스): TCP 연결 성공=1 / 실패=0, 15초 주기(type 3=Simple check, value_type 3=정수)
        key = "net.tcp.service[tcp,%s,%d]" % (ip, port)
        if call("item.get", {"hostids":hid, "filter":{"key_":key}}, tok):
            print("  = 이미 존재:", name); continue   # ★비파괴: 이미 있으면 건너뜀(중복 생성 방지)
        call("item.create", {"hostid":hid, "name":name, "key_":key, "type":3, "value_type":3, "delay":"15s"}, tok)
        prio = 5 if "VIP" in name else 3   # VIP down=Disaster(5), 노드 down=Average(3)
        # 값이 0(=포트 죽음)이면 트리거 발동. 이미 있으면 무시(멱등)
        try:
            call("trigger.create", {"description":"%s DOWN" % name,
                "expression":"last(/ha-cluster/%s)=0" % key, "priority":prio}, tok)
        except RuntimeError as e:
            if "already exists" not in str(e): raise
        print("  + 생성:", name, ip, port)
    print("DONE")
if __name__ == "__main__":
    try: main()
    except Exception as e: print("ERROR:", e); sys.exit(1)
