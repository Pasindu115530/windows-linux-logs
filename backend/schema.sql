CREATE TABLE IF NOT EXISTS machines (
  machine_id text PRIMARY KEY,
  os_type text NOT NULL,
  last_seen timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS accounts (
  id bigserial PRIMARY KEY,
  machine_id text NOT NULL REFERENCES machines(machine_id),
  username text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  is_admin boolean NOT NULL DEFAULT false,
  last_login_at timestamptz,
  last_snapshot_at timestamptz,
  UNIQUE(machine_id, username)
);
CREATE TABLE IF NOT EXISTS security_events (
  id bigserial PRIMARY KEY,
  machine_id text NOT NULL REFERENCES machines(machine_id),
  event_uid text NOT NULL,
  username text,
  event_type text NOT NULL,
  occurred_at timestamptz NOT NULL,
  details jsonb NOT NULL DEFAULT '{}',
  received_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(machine_id, event_uid)
);
CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(occurred_at DESC);
CREATE TABLE IF NOT EXISTS employees (
  employee_id text PRIMARY KEY,
  full_name text NOT NULL,
  department text NOT NULL,
  employment_status text NOT NULL,
  approved_admin boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS identity_map (
  machine_id text NOT NULL,
  username text NOT NULL,
  employee_id text NOT NULL REFERENCES employees(employee_id),
  PRIMARY KEY(machine_id,username)
);
CREATE TABLE IF NOT EXISTS access_reviews (
  id bigserial PRIMARY KEY,
  account_id bigint NOT NULL REFERENCES accounts(id),
  reviewer text NOT NULL,
  decision text NOT NULL CHECK(decision IN ('retain','revoke_requested')),
  explanation text NOT NULL,
  decided_at timestamptz NOT NULL DEFAULT now()
);
