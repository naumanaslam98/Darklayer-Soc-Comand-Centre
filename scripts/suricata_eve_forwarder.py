#!/usr/bin/env python3
"""Tail Suricata eve.json and forward events to the SOC API."""
import json, os, time, urllib.request, socket, sys
PATH=os.getenv('EVE_PATH','/var/log/suricata/eve.json')
URL=os.getenv('SOC_URL','http://127.0.0.1:8000').rstrip('/')+'/api/events'
TOKEN=os.getenv('SOC_TOKEN','')
if not TOKEN: print('Set SOC_TOKEN first.',file=sys.stderr); raise SystemExit(2)
def send(x):
    alert=x.get('alert') or {}; flow=x.get('flow') or {}
    body={'source':'suricata','event_type':x.get('event_type','network_event'),'severity':'info','asset':socket.gethostname(),
      'src_ip':x.get('src_ip'),'dst_ip':x.get('dest_ip'),'dst_port':x.get('dest_port'),
      'message':alert.get('signature') or x.get('event_type','Suricata event'),'raw':x}
    if alert:
        sev=alert.get('severity'); body['severity']='high' if sev==1 else 'medium' if sev==2 else 'low'
    req=urllib.request.Request(URL,data=json.dumps(body).encode(),method='POST',headers={'Content-Type':'application/json','Authorization':f'Bearer {TOKEN}'})
    with urllib.request.urlopen(req,timeout=5) as r:r.read()
with open(PATH,'r',errors='replace') as f:
    f.seek(0,2)
    while True:
        line=f.readline()
        if not line: time.sleep(.25); continue
        try: send(json.loads(line))
        except Exception as e: print('forward error:',e,file=sys.stderr)
