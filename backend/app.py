import os
import secrets
from datetime import datetime, timezone
from typing import Literal
from pathlib import Path
from contextlib import asynccontextmanager

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from fastapi import FastAPI, Depends, HTTPException, Header, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

DATABASE_URL = os.environ['DATABASE_URL']
KEYS = {k: os.environ[f'{k.upper()}_KEY'] for k in ('win01','win02','linux01','linux02')}
OS_TYPES = {'win01':'windows','win02':'windows','linux01':'linux','linux02':'linux'}
security = HTTPBasic()

@asynccontextmanager
async def lifespan(app: FastAPI):
    schema_path = Path(__file__).parent / 'schema.sql'
    if schema_path.exists():
        with psycopg.connect(DATABASE_URL) as conn:
            conn.execute(schema_path.read_text(encoding='utf-8'))
    yield

app = FastAPI(title='Access Review MVP', docs_url=None, redoc_url=None, lifespan=lifespan)

@app.get('/', include_in_schema=False)
def root():
    return RedirectResponse(url='/dashboard')

class Event(BaseModel):
    event_uid: str = Field(min_length=1, max_length=240)
    username: str | None = Field(default=None, max_length=255)
    event_type: Literal['login_success','login_failure','sudo_used','account_change']
    occurred_at: datetime
    details: dict = Field(default_factory=dict)

class EventBatch(BaseModel):
    machine_id: Literal['win01','win02','linux01','linux02']
    events: list[Event] = Field(min_length=1,max_length=200)

class AccountSnapshot(BaseModel):
    username: str = Field(min_length=1,max_length=255)
    enabled: bool = True
    is_admin: bool = False
    last_login_at: datetime | None = None

class Snapshot(BaseModel):
    machine_id: Literal['win01','win02','linux01','linux02']
    collected_at: datetime
    accounts: list[AccountSnapshot] = Field(max_length=1000)

class ReviewDecision(BaseModel):
    reviewer: str = Field(min_length=2,max_length=128)
    decision: Literal['retain','revoke_requested']
    explanation: str = Field(min_length=5,max_length=1000)


def require_agent(machine_id: str, supplied: str | None):
    expected = KEYS.get(machine_id)
    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        raise HTTPException(status_code=401, detail='Invalid machine credential')


def require_admin(creds: HTTPBasicCredentials = Depends(security)):
    u = secrets.compare_digest(creds.username.encode(), os.environ['ADMIN_USER'].encode())
    p = secrets.compare_digest(creds.password.encode(), os.environ['ADMIN_PASSWORD'].encode())
    if not (u and p):
        raise HTTPException(401, 'Invalid credentials', headers={'WWW-Authenticate':'Basic'})
    return creds.username


def upsert_machine(conn, machine_id):
    conn.execute('''INSERT INTO machines(machine_id,os_type) VALUES (%s,%s)
      ON CONFLICT(machine_id) DO UPDATE SET last_seen=now()''', (machine_id,OS_TYPES[machine_id]))

@app.get('/api/health')
def health():
    return {'status':'running'}

@app.post('/api/ingest/events')
def ingest_events(batch: EventBatch, x_agent_key: str | None=Header(default=None)):
    require_agent(batch.machine_id,x_agent_key)
    with psycopg.connect(DATABASE_URL) as conn:
        upsert_machine(conn,batch.machine_id)
        for ev in batch.events:
            conn.execute('''INSERT INTO security_events
                (machine_id,event_uid,username,event_type,occurred_at,details)
                VALUES (%s,%s,%s,%s,%s,%s)
                ON CONFLICT(machine_id,event_uid) DO NOTHING''',
                (batch.machine_id,ev.event_uid,ev.username,ev.event_type,ev.occurred_at,Jsonb(ev.details)))
            if ev.event_type == 'login_success' and ev.username and (batch.machine_id.startswith('linux') or ev.details.get('local_account', False)):
                conn.execute('''UPDATE accounts SET last_login_at = GREATEST(
                    COALESCE(last_login_at,%s),%s)
                    WHERE machine_id=%s AND lower(username)=lower(%s)''',
                    (ev.occurred_at,ev.occurred_at,batch.machine_id,ev.username))
    return {'accepted':len(batch.events)}

@app.post('/api/ingest/snapshot')
def ingest_snapshot(s: Snapshot, x_agent_key: str | None=Header(default=None)):
    require_agent(s.machine_id,x_agent_key)
    with psycopg.connect(DATABASE_URL) as conn:
        upsert_machine(conn,s.machine_id)
        for acc in s.accounts:
            conn.execute('''INSERT INTO accounts
                (machine_id,username,enabled,is_admin,last_login_at,last_snapshot_at)
                VALUES (%s,%s,%s,%s,%s,%s)
                ON CONFLICT(machine_id,username)
                DO UPDATE SET enabled=EXCLUDED.enabled,is_admin=EXCLUDED.is_admin,
                last_snapshot_at=EXCLUDED.last_snapshot_at,
                last_login_at=GREATEST(accounts.last_login_at,EXCLUDED.last_login_at)''',
                (s.machine_id,acc.username,acc.enabled,acc.is_admin,acc.last_login_at,s.collected_at))
    return {'accounts_seen':len(s.accounts)}


def risk(acc):
    score=0
    reasons=[]
    if not acc['enabled']:
        return 0, ['Disabled account (no active-access remediation suggested)']
    if acc['employee_id'] is None:
        score+=30
        reasons.append('Account has no verified employee mapping — investigate potential orphan')
    elif acc['employment_status'].lower()!='active':
        score+=60
        reasons.append('Enabled account belongs to a non-active employee')
    if acc['is_admin'] and not acc['approved_admin']:
        score+=35
        reasons.append('Admin privilege not approved in employee baseline')
    if acc['last_login_at']:
        days=(datetime.now(timezone.utc)-acc['last_login_at']).days
        if days>=90:
            score+=20
            reasons.append(f'Last observed login was {days} days ago (verify log coverage)')
    return min(100,score), reasons


def all_accounts():
    with psycopg.connect(DATABASE_URL,row_factory=dict_row) as conn:
        rows=conn.execute('''SELECT a.*, im.employee_id, e.full_name, e.department,
                 e.employment_status, COALESCE(e.approved_admin,false) AS approved_admin
                 FROM accounts a
                 LEFT JOIN identity_map im ON (lower(im.machine_id)=lower(a.machine_id)
                       AND lower(im.username)=lower(a.username))
                 LEFT JOIN employees e ON e.employee_id=im.employee_id
                 ORDER BY a.machine_id,a.username''').fetchall()
    for a in rows:
        a['risk_score'],a['reasons']=risk(a)
    return rows

@app.get('/api/dashboard/accounts')
def accounts(admin=Depends(require_admin)):
    return all_accounts()

@app.get('/api/dashboard/stats')
def stats(admin=Depends(require_admin)):
    data=all_accounts()
    with psycopg.connect(DATABASE_URL,row_factory=dict_row) as conn:
        machine_rows=conn.execute('SELECT * FROM machines ORDER BY machine_id').fetchall()
        n_events=conn.execute('SELECT COUNT(*) AS n FROM security_events').fetchone()['n']
        n_reviews=conn.execute('SELECT COUNT(*) AS n FROM access_reviews').fetchone()['n']
    return {'machines':machine_rows,'account_count':len(data),'event_count':n_events,
            'risk_count':sum(a['risk_score']>=30 for a in data),'review_count':n_reviews,
            'connected_count':sum((datetime.now(timezone.utc)-m['last_seen']).total_seconds()<900 for m in machine_rows)}

@app.get('/api/dashboard/events')
def events(admin=Depends(require_admin)):
    with psycopg.connect(DATABASE_URL,row_factory=dict_row) as conn:
        return conn.execute('''SELECT machine_id,username,event_type,occurred_at
              FROM security_events ORDER BY occurred_at DESC LIMIT 30''').fetchall()

@app.get('/api/dashboard/reviews')
def reviews(admin=Depends(require_admin)):
    with psycopg.connect(DATABASE_URL,row_factory=dict_row) as conn:
        return conn.execute('''SELECT r.*,a.machine_id,a.username FROM access_reviews r
              JOIN accounts a ON a.id=r.account_id ORDER BY decided_at DESC LIMIT 100''').fetchall()

@app.post('/api/dashboard/accounts/{account_id}/review')
def save_review(account_id:int, decision:ReviewDecision, admin=Depends(require_admin)):
    with psycopg.connect(DATABASE_URL) as conn:
        rec=conn.execute('SELECT id FROM accounts WHERE id=%s',(account_id,)).fetchone()
        if not rec:
            raise HTTPException(404,'Account not found')
        conn.execute('''INSERT INTO access_reviews(account_id,reviewer,decision,explanation)
                        VALUES (%s,%s,%s,%s)''',
                     (account_id,decision.reviewer,decision.decision,decision.explanation))
    return {'status':'recorded','note':'Approval only: no operating-system access was changed'}

@app.get('/api/dashboard/audit.csv')
def audit_csv(admin=Depends(require_admin)):
    import csv, io
    from fastapi.responses import Response
    rows=all_accounts()
    output=io.StringIO()
    writer=csv.writer(output)
    writer.writerow(['machine_id','username','employee_id','full_name','enabled','is_admin','risk_score','reasons'])
    for a in rows:
        writer.writerow([a['machine_id'],a['username'],a['employee_id'],a['full_name'],a['enabled'],a['is_admin'],a['risk_score'],'; '.join(a['reasons'])])
    return Response(output.getvalue(),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=access_review_audit.csv','Cache-Control':'no-store'})

@app.get('/dashboard',response_class=HTMLResponse)
def dashboard(admin=Depends(require_admin)):
    return Path('/app/dashboard.html').read_text(encoding='utf-8')
