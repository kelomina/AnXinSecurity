#!/usr/bin/env python3
"""antagonist-analyze-db.py - Post-batch behavior DB analysis.

Reads the batch result CSV and the behavior DB, cross-references sample PIDs
against events/process_lifecycle tables, and produces a verdict update:
  - WEAK-DETECT:    behavior DB contains events for this sample's PID
  - PROC-MON-OK:    process_lifecycle has the PID (ProcMon driver captured it)
  - NOT-DETECTED:   no trace in behavior DB

Usage:
  python antagonist-analyze-db.py batch-<N>-result.csv batch-<N>-behavior.db
"""
import csv, json, sqlite3, sys, os

def analyze(batch_csv, behavior_db):
    if not os.path.exists(behavior_db):
        print(f"SKIP: behavior DB not found: {behavior_db}")
        return

    conn = sqlite3.connect(behavior_db)
    cur = conn.cursor()

    # discover tables
    tables = set()
    for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        tables.add(row[0])
    has_events = 'events' in tables
    has_lifecycle = 'process_lifecycle' in tables

    # read batch results
    with open(batch_csv, encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    updates = []
    for row in rows:
        seq = row['Seq']
        verdict = row['Verdict']
        pids_str = row.get('Pids', '').strip()
        # skip COPY-FAIL / LAUNCH-FAIL
        if verdict in ('COPY-FAIL', 'LAUNCH-FAIL'):
            continue

        if verdict == 'STRONG-INTERCEPT':
            # already intercepted, no need to check behavior DB
            continue

        pids = []
        if pids_str:
            for s in pids_str.split(';'):
                s = s.strip()
                if s:
                    try:
                        pids.append(int(s))
                    except ValueError:
                        pass

        weak_detect = False
        procmon_ok = False
        db_events = []

        for pid in pids:
            if has_events:
                cur.execute("SELECT COUNT(*) FROM events WHERE pid=?", (pid,))
                cnt = cur.fetchone()[0]
                if cnt > 0:
                    weak_detect = True
                    db_events.append(f"pid={pid} events={cnt}")
                    # fetch first event details
                    cur.execute("SELECT operation, path, timestamp FROM events WHERE pid=? LIMIT 3", (pid,))
                    for evt in cur.fetchall():
                        db_events.append(f"  op={evt[0]} path={evt[1]} ts={evt[2]}")

            if has_lifecycle:
                cur.execute("SELECT COUNT(*) FROM process_lifecycle WHERE pid=?", (pid,))
                cnt = cur.fetchone()[0]
                if cnt > 0:
                    procmon_ok = True
                    if not weak_detect:
                        db_events.append(f"pid={pid} lifecycle={cnt}")

        if weak_detect:
            new_verdict = 'WEAK-DETECT'
        else:
            new_verdict = 'NOT-DETECTED'

        if procmon_ok:
            new_verdict += '+PROCMON'
        elif weak_detect:
            pass  # WEAK-DETECT is the main verdict

        updates.append((seq, new_verdict, '; '.join(db_events)))

    conn.close()

    # output as JSON for merging
    result = []
    for seq, new_verdict, db_ev in updates:
        result.append({"seq": seq, "verdict": new_verdict, "db_events": db_ev})
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python antagonist-analyze-db.py <batch-result.csv> <behavior.db>", file=sys.stderr)
        sys.exit(1)
    analyze(sys.argv[1], sys.argv[2])