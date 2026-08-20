#!/usr/bin/env python3
import socket,sys
host=sys.argv[1] if len(sys.argv)>1 else '127.0.0.1'; port=int(sys.argv[2]) if len(sys.argv)>2 else 5514
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(6): s.sendto(f'<134> Failed login for demo-user from 203.0.113.5 attempt={i+1}'.encode(),(host,port))
print(f'Sent 6 syslog auth failures to {host}:{port}')
