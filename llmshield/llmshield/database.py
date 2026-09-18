"""SQLite audit storage: each operation owns its connection and transaction."""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = '''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS runs (
 id TEXT PRIMARY KEY, group_id TEXT NOT NULL, mode TEXT NOT NULL, provider TEXT NOT NULL,
 suite_hash TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT,
 status TEXT NOT NULL, total INTEGER NOT NULL, metrics_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS test_cases (
 suite_hash TEXT NOT NULL, test_id TEXT NOT NULL, snapshot_json TEXT NOT NULL,
 PRIMARY KEY(suite_hash, test_id));
CREATE TABLE IF NOT EXISTS results (
 id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), test_id TEXT NOT NULL,
 category TEXT NOT NULL, severity TEXT NOT NULL, kind TEXT NOT NULL, verdict TEXT NOT NULL,
 evidence_json TEXT NOT NULL, response_json TEXT NOT NULL, duration_ms REAL NOT NULL,
 UNIQUE(run_id, test_id));
CREATE TABLE IF NOT EXISTS tool_attempts (
 id INTEGER PRIMARY KEY, result_id TEXT NOT NULL REFERENCES results(id), details_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS guardrail_decisions (
 id INTEGER PRIMARY KEY, result_id TEXT NOT NULL REFERENCES results(id), details_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (
 id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), result_id TEXT NOT NULL REFERENCES results(id),
 details_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_results_run ON results(run_id);
CREATE INDEX IF NOT EXISTS idx_runs_group ON runs(group_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
'''


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def start(self, run, cases):
        with self.connect() as db:
            db.execute('INSERT INTO runs(id,group_id,mode,provider,suite_hash,started_at,status,total) VALUES(?,?,?,?,?,?,?,?)',
                       tuple(run[k] for k in ['id','group_id','mode','provider','suite_hash','started_at','status','total']))
            for case in cases:
                db.execute('INSERT OR IGNORE INTO test_cases VALUES(?,?,?)',
                           (run['suite_hash'], case.id, case.model_dump_json()))

    def save_result(self, run_id, result, finding=None):
        with self.connect() as db:
            db.execute('INSERT INTO results VALUES(?,?,?,?,?,?,?,?,?,?)',
                       (result['id'],run_id,result['test_id'],result['category'],result['severity'],result['kind'],result['verdict'],
                        json.dumps(result['evidence']),json.dumps(result['response']),result['duration_ms']))
            for attempt in result['response']['attempts']:
                db.execute('INSERT INTO tool_attempts(result_id,details_json) VALUES(?,?)',(result['id'],json.dumps(attempt)))
            for decision in result['response']['decisions']:
                db.execute('INSERT INTO guardrail_decisions(result_id,details_json) VALUES(?,?)',(result['id'],json.dumps(decision)))
            if finding:
                db.execute('INSERT INTO findings VALUES(?,?,?,?)',(finding['id'],run_id,result['id'],json.dumps(finding)))

    def finish(self, run_id, finished, metrics, status='completed'):
        with self.connect() as db:
            db.execute('UPDATE runs SET finished_at=?,metrics_json=?,status=? WHERE id=?',
                       (finished,json.dumps(metrics),status,run_id))

    def recover(self):
        with self.connect() as db:
            db.execute("UPDATE runs SET status='interrupted' WHERE status='running'")

    @staticmethod
    def decode_run(row):
        result = dict(row)
        result['metrics'] = json.loads(result.pop('metrics_json'))
        return result

    def list_runs(self, limit=100):
        with self.connect() as db:
            return [self.decode_run(r) for r in db.execute('SELECT * FROM runs ORDER BY started_at DESC LIMIT ?', (limit,))]

    def get_run(self, run_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM runs WHERE id=?',(run_id,)).fetchone()
            if row is None:
                return None
            run = self.decode_run(row)
            results = []
            for row in db.execute('SELECT * FROM results WHERE run_id=? ORDER BY rowid',(run_id,)):
                r = dict(row)
                r['evidence'] = json.loads(r.pop('evidence_json'))
                r['response'] = json.loads(r.pop('response_json'))
                case = db.execute('SELECT snapshot_json FROM test_cases WHERE suite_hash=? AND test_id=?',
                                  (run['suite_hash'],r['test_id'])).fetchone()
                r['case'] = json.loads(case[0])
                results.append(r)
            run['results'] = results
            run['findings'] = [json.loads(r[0]) for r in db.execute('SELECT details_json FROM findings WHERE run_id=?',(run_id,))]
            return run

    def group(self, group_id):
        with self.connect() as db:
            ids = [r[0] for r in db.execute('SELECT id FROM runs WHERE group_id=? ORDER BY started_at',(group_id,))]
        return [self.get_run(id) for id in ids]

    def update_finding(self, finding):
        with self.connect() as db:
            db.execute('UPDATE findings SET details_json=? WHERE id=?',(json.dumps(finding),finding['id']))
