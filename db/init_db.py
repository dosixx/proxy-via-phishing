# db/init_db.py
import sqlite3
from pathlib import Path

URLS_COLUMNS = {
    "source": "TEXT NOT NULL",
    "proxy_type": "TEXT",
    "task_url": "TEXT NOT NULL",
    "page_url": "TEXT",
    "second_page_url": "TEXT",
    "final_redirect_url": "TEXT",
    "script_redirect_url": "TEXT",
    "redirect_snippet": "TEXT",
    "base_domain": "TEXT",
    "verdict": "TEXT",
    "score": "REAL",
    "malicious": "BOOLEAN",
    "country": "TEXT",
    "ip": "TEXT",
    "http_requests": "INTEGER",
    "unique_ips": "INTEGER",
    "urlscan_timestamp": "TEXT",
    "collected_at": "TEXT",
    "status_checked": "BOOLEAN DEFAULT 0",
    "last_status_code": "INTEGER",
    "notes": "TEXT",
}

def _table_exists(cur, name: str) -> bool:
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", (name,))
    return cur.fetchone() is not None

def _column_exists(cur, table: str, column: str) -> bool:
    cur.execute(f"PRAGMA table_info({table});")
    return column in [row[1] for row in cur.fetchall()]

def ensure_urls_table(conn: sqlite3.Connection):
    cur = conn.cursor()
    if not _table_exists(cur, "urls"):
        cur.execute("""
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            proxy_type TEXT,
            task_url TEXT NOT NULL,
            page_url TEXT,
            second_page_url TEXT,
            final_redirect_url TEXT,
            script_redirect_url TEXT,
            redirect_snippet TEXT,
            base_domain TEXT,
            verdict TEXT,
            score REAL,
            malicious BOOLEAN,
            country TEXT,
            ip TEXT,
            http_requests INTEGER,
            unique_ips INTEGER,
            urlscan_timestamp TEXT,
            collected_at TEXT,
            status_checked BOOLEAN DEFAULT 0,
            last_status_code INTEGER,
            notes TEXT
        );
        """)
        return

    # 있으면 부족한 컬럼 추가
    for col, coltype in URLS_COLUMNS.items():
        if not _column_exists(cur, "urls", col):
            cur.execute(f"ALTER TABLE urls ADD COLUMN {col} {coltype};")

def ensure_virustotal_table(conn: sqlite3.Connection):
    """virustotal 테이블 생성 (없으면)"""
    cur = conn.cursor()
    if not _table_exists(cur, "virustotal"):
        cur.execute("""
        CREATE TABLE virustotal (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url_id INTEGER,
            ioc TEXT NOT NULL,
            type TEXT NOT NULL,
            detection_count INTEGER,
            detection_breakdown TEXT,
            historical_whois TEXT,
            referrer_files TEXT,
            referrer_file_insights TEXT,
            whois_analysis TEXT,
            whois_date_range_oldest TEXT,
            whois_date_range_newest TEXT,
            created_at TEXT,
            FOREIGN KEY (url_id) REFERENCES urls(id)
        );
        """)
        # 인덱스 추가
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vt_url_id ON virustotal(url_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vt_ioc ON virustotal(ioc);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vt_type ON virustotal(type);")

def init_db(db_path: str):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        ensure_urls_table(conn)
        ensure_virustotal_table(conn)
        conn.commit()
    finally:
        conn.close()
    print(f"[init_db] Initialized {db_path}")
