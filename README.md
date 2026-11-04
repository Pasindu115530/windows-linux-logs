# Access Review MVP — 2 Windows + 2 Linux + Ubuntu VPS

**For an authorized university lab demonstration, not a production employee-monitoring platform.**

This starter includes a functional FastAPI collector API, PostgreSQL database, Caddy HTTPS reverse proxy, simple browser dashboard, secure per-host agent keys, Linux and Windows collectors, identity import, basic review recording, and CSV audit export. This starter **does not** execute real access revocation. It is not a replacement for IAM/IGA software, and needs privacy/legal review, professional authentication, durable log buffering and improved data sources before any real-world employee deployment.

## Architecture

```
Windows win01  ----\
Windows win02  -----\
Linux linux01  ------> HTTPS access.example.com -> Caddy -> FastAPI -> PostgreSQL
Linux linux02  -----/                                  |
                                                    Dashboard + reviews
```

The collector endpoint validates an individual secret for each machine. Dashboard endpoints require administrator HTTP Basic authentication (over HTTPS). Database and API container ports are **not** published to the public internet. Only Caddy's ports 80 and 443 are published. **Caution**: Docker-published ports can bypass UFW; never publish ports 5432 or 8000.

## 0. Prerequisites

- Ubuntu 22.04/24.04 VPS with SSH access and 8GB RAM. Avoid installing over an existing stack listening on ports 80/443.
- A domain or subdomain such as `access.example.com`. Create a DNS `A` record pointing to your VPS public IPv4. Do not leave a conflicting `AAAA` record unless IPv6 works. If using a proxy service, prefer DNS-only while validating HTTPS issuance.
- VPS provider firewall: allow HTTPS TCP 443, HTTP TCP 80; allow SSH TCP 22 **only from trusted admin IPs** when possible.
- Four **authorized test** endpoints. Keep system time synchronized.

## 1. Install Docker on Ubuntu VPS

Log in as a sudo user. Keep the SSH session open while changing firewall rules.

```bash
sudo apt update
sudo apt install -y ca-certificates curl python3 unzip ufw
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF2
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF2
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker compose version
```

UFW rules (if you use SSH on a nonstandard port, **allow that port instead of 22 first**):

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw status verbose
# Only if you have confirmed that your SSH connection will remain accessible:
sudo ufw enable
```

## 2. Transfer and deploy files

Unzip this project on the VPS, then go into the directory.

```bash
unzip access-review-vps-starter.zip
cd access-review-vps-starter
python3 scripts/init_env.py access.example.com   # CHANGE this to your domain
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs caddy --tail=50
curl -fsS https://access.example.com/api/health   # CHANGE domain
```

> If you are already working from the unzipped folder, skip the unzip command. Do not commit the `.env` file to Git.

Caddy obtains and renews the TLS certificate automatically when DNS points at the VPS and ports 80/443 are reachable. HTTPS may need a short moment to become ready after initial boot. Use `sudo docker compose logs caddy --tail=100` for diagnostics.

Check basic authentication by opening `https://access.example.com/dashboard` in a browser. Use `ADMIN_USER` and `ADMIN_PASSWORD` from the `.env` file. If possible, restrict dashboard access with a private VPN or an identity-aware proxy; HTTP Basic is for this prototype only.

**Security note**: Treat `.env` as confidential, use strict filesystem permissions, and avoid sharing usernames / event exports with unauthorized people.

## 3. First API test (from your VPS)

The command below intentionally reads the secret from `.env` without writing it to shell history. Read the complete command before running it.

```bash
set -a; source .env; set +a
curl -fsS -X POST "https://${DOMAIN}/api/ingest/events" \
  -H "X-Agent-Key: ${LINUX01_KEY}" \
  -H 'Content-Type: application/json' \
  -d '{"machine_id":"linux01","events":[{"event_uid":"demo:manual:001","username":"developer01","event_type":"login_success","occurred_at":"2026-11-04T09:00:00Z","details":{"source":"demo"}}]}'
```

This creates a **synthetic event** for connectivity testing, clearly labeled demo. Remove or exclude demo events when measuring real detections.

## 4. Configure Linux 01 and Linux 02

Copy `collectors/linux_collector.py` and the two files in `configs/` to each Linux machine. Example from the machine itself after extracting the ZIP:

```bash
sudo install -d -m 755 /opt/access-review
sudo install -d -m 700 /etc/access-review
sudo install -m 755 collectors/linux_collector.py /opt/access-review/linux_collector.py
sudo install -m 644 configs/access-review.service /etc/systemd/system/access-review.service
sudo install -m 644 configs/access-review.timer /etc/systemd/system/access-review.timer
sudo nano /etc/access-review/agent.env
```

`/etc/access-review/agent.env` on **Linux 01**:

```ini
API_BASE=https://access.example.com
MACHINE_ID=linux01
AGENT_KEY=PASTE_LINUX01_KEY_FROM_VPS_ENV
```

On Linux 02 use `MACHINE_ID=linux02` and `LINUX02_KEY`. Then:

```bash
sudo chmod 600 /etc/access-review/agent.env
sudo systemctl daemon-reload
sudo systemctl enable --now access-review.timer
sudo systemctl start access-review.service
sudo journalctl -u access-review.service -n 30 --no-pager
sudo systemctl list-timers access-review.timer
```

The collector reads local interactive accounts and sudo-group membership. Some sudoers grants, SSSD/LDAP accounts, password-lock states and other privileges require additional connectors. It reads journal security events and stores a journal cursor at `/var/lib/access-review/journal_cursor` so subsequent runs do not replay the complete journal. Runs as root to read security records; limit this collector to authorized test systems. No raw commands or passwords are uploaded.

If no events are arriving, test an SSH login to the Linux test machine and see whether `journalctl -t sshd -t sudo --since '10 minutes ago'` shows the event. Source formats vary by distro and configuration, so you may need to adapt the parser.

## 5. Configure Windows 01 and Windows 02

Open **64-bit Windows PowerShell as Administrator**. Extract the ZIP and copy `windows_collector.ps1` to `C:\ProgramData\AccessReview\`:

```powershell
New-Item -ItemType Directory -Path 'C:\ProgramData\AccessReview' -Force | Out-Null
Copy-Item '.\collectors\windows_collector.ps1' 'C:\ProgramData\AccessReview\windows_collector.ps1'
auditpol /get /subcategory:'Logon'
auditpol /set /subcategory:'Logon' /success:enable /failure:enable
Set-Content 'C:\ProgramData\AccessReview\agent.key' 'PASTE_WIN01_KEY_FROM_VPS_ENV'
icacls 'C:\ProgramData\AccessReview\agent.key' /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F'
```

On Windows 02, use its distinct `WIN02_KEY` and replace `win01` with `win02` in the commands below.

Run once to verify:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\ProgramData\AccessReview\windows_collector.ps1' -MachineId win01 -ApiBase 'https://access.example.com'
```

Then schedule it every 5 minutes as SYSTEM:

```powershell
$script = 'C:\ProgramData\AccessReview\windows_collector.ps1'
$arg = '-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -MachineId win01 -ApiBase "https://access.example.com"'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName 'AccessReviewCollector' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force
Get-ScheduledTask -TaskName 'AccessReviewCollector'
```

By default, the Windows collector captures local user inventory and selected local interactive/remote-interactive logon events, and uses event record IDs to reduce resends. It does **not** enumerate Active Directory, GitHub, third-party applications, nested domain groups or all effective privileges. If the security event log is cleared and record IDs reset, the local state file may need to be reset after investigation. If >5000 login events accrue in one day, enlarge or redesign its bounded event query to avoid loss.

## 6. Import employee roster and map accounts

Edit the CSV at `sample/employees.example.csv` to replace synthetic employees with **authorized pseudonymous test employee data**. The same employee can be represented on different machines by separate rows.

```bash
# VPS, in project directory:
sudo docker compose cp sample/employees.example.csv api:/tmp/employees.csv
sudo docker compose exec -T api python import_employees.py /tmp/employees.csv
```

Without an employee roster you can identify *unmapped accounts*, but **cannot reliably confirm orphaned or departed employee accounts**.

## 7. Dashboard and test scenario

Go to: `https://access.example.com/dashboard` (your actual domain).

Demonstrate:
1. Confirm **4 distinct machines** have fresh `last_seen` values.
2. Show events from Windows and Linux.
3. Create a known test admin group assignment or a deliberately unmapped test account.
4. Update the employee CSV to mark one synthetic employee as terminated, re-import it, and see high risk for the enabled account.
5. Click **Review**, choose `retain` or `revoke_requested`, record the evidence.
6. Export the audit CSV from `/api/dashboard/audit.csv`.

**Do not revoke real permissions automatically for this MVP.** Review actions only create a record.

## 8. Diagnostic and maintenance commands (VPS)

```bash
sudo docker compose ps
sudo docker compose logs -f --tail=100 api
sudo docker compose logs -f --tail=100 caddy
sudo docker compose exec -T db psql -U accessreview -d accessreview -c 'SELECT machine_id,os_type,last_seen FROM machines ORDER BY machine_id;'
sudo docker compose exec -T db psql -U accessreview -d accessreview -c 'SELECT machine_id,username,event_type,occurred_at FROM security_events ORDER BY occurred_at DESC LIMIT 15;'
sudo docker compose exec -T db psql -U accessreview -d accessreview -c 'SELECT machine_id,username,enabled,is_admin FROM accounts ORDER BY machine_id,username;'
```

Back up the database (handle exported log data as confidential):

```bash
sudo docker compose exec -T db pg_dump -U accessreview accessreview > accessreview-backup.sql
chmod 600 accessreview-backup.sql
```

A scheduled encrypted/off-VPS backup, retention, dashboards with RBAC, reliable delivery queues, CSRF protection, device certificates, and integrity monitoring should be added before production.

## 9. One-week development responsibilities

- Member 1: Docker + Caddy HTTPS, FastAPI, database, backups; end-to-end ingestion.
- Member 2: configure Windows/Linux collectors, refine parsers and permission snapshots, validate risk rules.
- Member 3: customize dashboard, add review assignment, filters, reports, testing, demo.

**Known limitations**: HTTP Basic dashboard login is only prototype-grade; the custom agents have no persistent offline queue; Windows local accounts and Linux local accounts do not cover AD/Entra/SSO; a seven-day collection window cannot prove 90 days of inactivity. Risk scores are explainable heuristics, **not trained AI**. Mark unknown usage as unknown.
