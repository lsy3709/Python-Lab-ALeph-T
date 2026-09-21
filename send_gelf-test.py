# send_gelf.py — tcpdump→GELF 또는 방화벽 로그가 보낼 법한 GELF 를 직접 전송
import json, socket, sys, time
def send(rule, src_ip, msg, **extra):
    d={'version':'1.1','host':'netsensor','short_message':msg,'level':4,'_rule':rule,'_src_ip':src_ip}
    for k,v in extra.items(): d['_'+k]=v
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.sendto(json.dumps(d).encode(), ('localhost',12201))
    finally: s.close()
if __name__=='__main__':
    if len(sys.argv) < 2:
        print('사용법: python send_gelf-test.py <출발지IP> [보낼 개수=3]')
        print('  예)  python send_gelf-test.py 203.0.113.50 5')
        sys.exit(2)
    ip=sys.argv[1]; n=int(sys.argv[2] if len(sys.argv)>2 else 3)
    for i in range(n): send('portscan', ip, f'SYN scan burst from {ip} (#{i+1})', dpt=5000); time.sleep(0.2)
    print(f'sent {n} portscan GELF for {ip}')