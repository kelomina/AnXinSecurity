import sqlite3, json

conn = sqlite3.connect(r'e:\Project\HTML\AnXinSecurity\vm-automation\output\batch-1-behavior.db')
cur = conn.cursor()

# 1. process_lifecycle entries whose process_path or command_line references C:\Samples
rows = cur.execute(
    "SELECT pid, process_path, command_line, create_time, exit_time, duration_ms, parent_pid, "
    "file_hash, signature_status, exit_status, subsystem_type, details "
    "FROM process_lifecycle "
    "WHERE process_path LIKE '%C:\\Samples%' OR command_line LIKE '%C:\\Samples%' "
    "ORDER BY create_time"
).fetchall()
cols = ['pid','process_path','command_line','create_time','exit_time','duration_ms','parent_pid','file_hash','signature_status','exit_status','subsystem_type','details']
print('=== process_lifecycle referencing C:\\Samples ===')
for r in rows:
    d = dict(zip(cols, r))
    d['process_path'] = (d.get('process_path') or '')[:120]
    d['command_line'] = (d.get('command_line') or '')[:150]
    print(json.dumps(d, ensure_ascii=False))

# 2. For each such pid, list its events grouped by operation/path (dedupe), up to 12 each
print()
print('=== events per launched sample pid ===')
for r in rows:
    pid = r[0]
    evs = cur.execute(
        "SELECT operation, path, COUNT(*) c FROM events WHERE pid=? "
        "AND path NOT LIKE '%C:\\Samples%' GROUP BY operation, path ORDER BY c DESC LIMIT 12",
        (pid,)
    ).fetchall()
    print(f'--- pid={pid} ---')
    for e in evs:
        print(f'  {e[0]}  x{e[2]}  {str(e[1])[:110]}')

# 3. quarantine_items
print()
print('=== quarantine_items count ===')
print(cur.execute('SELECT COUNT(*) FROM quarantine_items').fetchone()[0])

conn.close()