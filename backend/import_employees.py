import os,csv,sys
import psycopg
if len(sys.argv)!=2:
    raise SystemExit('Usage: python import_employees.py /path/to/employees.csv')
with psycopg.connect(os.environ['DATABASE_URL']) as conn,open(sys.argv[1],newline='',encoding='utf-8') as f:
    for row in csv.DictReader(f):
        conn.execute('''INSERT INTO employees(employee_id,full_name,department,employment_status,approved_admin)
             VALUES(%s,%s,%s,%s,%s)
             ON CONFLICT(employee_id) DO UPDATE SET full_name=EXCLUDED.full_name,
             department=EXCLUDED.department,employment_status=EXCLUDED.employment_status,
             approved_admin=EXCLUDED.approved_admin''',
             (row['employee_id'],row['full_name'],row['department'],row['employment_status'],row['approved_admin'].lower() in ('true','1','yes')))
        conn.execute('''INSERT INTO identity_map(machine_id,username,employee_id)
             VALUES(%s,%s,%s)
             ON CONFLICT(machine_id,username) DO UPDATE SET employee_id=EXCLUDED.employee_id''',
             (row['machine_id'].lower(),row['username'],row['employee_id']))
print('Employee and identity mappings imported')
