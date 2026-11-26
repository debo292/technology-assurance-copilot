import sqlite3, json, uuid
from datetime import datetime,timezone
from core.config import DB_PATH
def connect():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True); return sqlite3.connect(DB_PATH)
def init_db():
    with connect() as con: con.execute("CREATE TABLE IF NOT EXISTS assessments (assessment_id TEXT PRIMARY KEY, created_at TEXT, module TEXT, population INTEGER, exception_count INTEGER, payload TEXT)")
def save_assessment(result):
    init_db(); aid=str(uuid.uuid4())[:8]
    with connect() as con: con.execute("INSERT INTO assessments VALUES (?,?,?,?,?,?)",(aid,datetime.now(timezone.utc).isoformat(),result.get("module"),result.get("population"),result.get("exception_count"),json.dumps(result)))
    return aid
def list_assessments():
    init_db()
    with connect() as con: rows=con.execute("SELECT assessment_id,created_at,module,population,exception_count FROM assessments ORDER BY created_at DESC").fetchall()
    return [dict(zip(["assessment_id","created_at","module","population","exception_count"],r)) for r in rows]
