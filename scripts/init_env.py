#!/usr/bin/env python3
"""One-time .env creator; never prints any secret."""
import secrets, pathlib, sys
if len(sys.argv) != 2 or '.' not in sys.argv[1] or '/' in sys.argv[1]:
    raise SystemExit('Usage: python3 scripts/init_env.py access.example.com')
target=pathlib.Path('.env')
if target.exists():
    raise SystemExit('.env already exists; not overwriting existing credentials')
domain=sys.argv[1].lower().strip()
values={'DOMAIN':domain,'DB_PASSWORD':secrets.token_urlsafe(36),
        'ADMIN_USER':'admin','ADMIN_PASSWORD':secrets.token_urlsafe(36)}
for m in ('WIN01','WIN02','LINUX01','LINUX02'):
    values[m+'_KEY']=secrets.token_hex(32)
target.write_text(''.join(f'{k}={v}\n' for k,v in values.items()),encoding='utf-8')
target.chmod(0o600)
print('Created .env with unique random secrets for four collectors. Keep it private.')
