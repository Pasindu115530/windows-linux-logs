#!/usr/bin/env python3
"""Linux collector for two authorized test Linux hosts.
Runs as root to read journal and account inventories. Requires only Python stdlib.
"""
import os, re, json, pwd, grp, subprocess, urllib.request, pathlib
from datetime import datetime, timezone, timedelta

BASE=os.environ['API_BASE'].rstrip('/')
MACHINE=os.environ['MACHINE_ID']
KEY=os.environ['AGENT_KEY']
STATE=pathlib.Path('/var/lib/access-review/journal_cursor')
if MACHINE not in ('linux01','linux02'):
    raise SystemExit('MACHINE_ID must be linux01 or linux02')

def post(path, data):
    req=urllib.request.Request(BASE+path,
        data=json.dumps(data).encode(),
        headers={'Content-Type':'application/json','X-Agent-Key':KEY},method='POST')
    with urllib.request.urlopen(req,timeout=30) as r:
        if r.status not in (200,201):
            raise RuntimeError(f'API returned {r.status}')

def snapshot():
    try:
        sudo_members=set(grp.getgrnam('sudo').gr_mem)
    except KeyError:
        sudo_members=set()
    accounts=[]
    for u in pwd.getpwall():
        if u.pw_uid < 1000 or u.pw_uid >= 65534:
            continue # Exclude service/system accounts from this first MVP
        if u.pw_shell.endswith(('nologin','false')):
            continue
        # Linux sudoers may grant access outside of the sudo group.
        accounts.append({'username':u.pw_name,'enabled':True,
                         'is_admin':u.pw_name in sudo_members,
                         'last_login_at':None})
    post('/api/ingest/snapshot',{'machine_id':MACHINE,
         'collected_at':datetime.now(timezone.utc).isoformat(),'accounts':accounts})

def parse_event(item):
    message=item.get('MESSAGE','')
    if not isinstance(message,str):
        return None
    source=item.get('SYSLOG_IDENTIFIER','')
    username=None
    kind=None
    if 'sshd' in str(source) or 'sshd[' in message:
        match=re.search(r'Accepted \S+ for (\S+) from ',message)
        if match:
            username=match.group(1); kind='login_success'
        else:
            match=re.search(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from ',message)
            if match:
                username=match.group(1); kind='login_failure'
    elif str(source)=='sudo':
        match=re.search(r'^(\S+)\s*:\s*TTY=',message)
        if match:
            username=match.group(1); kind='sudo_used'
    if not kind:
        return None
    stamp=int(item.get('__REALTIME_TIMESTAMP','0')) / 1_000_000
    return {'event_uid':item['__CURSOR'],'username':username,'event_type':kind,
            'occurred_at':datetime.fromtimestamp(stamp,tz=timezone.utc).isoformat(),
            'details':{'source':str(source)}}

def journal_events():
    cursor=STATE.read_text().strip() if STATE.exists() else ''
    command=['journalctl','--no-pager','--output=json']
    if cursor:
        command += ['--after-cursor='+cursor]
    else:
        command += ['--since=-1 hour']
    proc=subprocess.run(command,capture_output=True,text=True)
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or 'journalctl failed')
    batch=[]
    last_cursor=cursor
    for line in proc.stdout.splitlines():
        try:
            item=json.loads(line)
        except json.JSONDecodeError:
            continue
        last_cursor=item.get('__CURSOR',last_cursor)
        ev=parse_event(item)
        if ev:
            batch.append(ev)
            if len(batch)==100:
                post('/api/ingest/events',{'machine_id':MACHINE,'events':batch})
                batch=[]
    if batch:
        post('/api/ingest/events',{'machine_id':MACHINE,'events':batch})
    if last_cursor and last_cursor!=cursor:
        STATE.parent.mkdir(parents=True,exist_ok=True)
        STATE.write_text(last_cursor)
    print('Linux events synchronized')

if __name__=='__main__':
    snapshot()
    journal_events()
