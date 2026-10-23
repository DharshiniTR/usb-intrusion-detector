import sys
import os
import time
import sqlite3
import threading
from pathlib import Path
from dotenv import load_dotenv

# Set UTF-8 encoding for stdout if supported
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def _safe_print(*args, **kwargs):
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        text = " ".join(str(a) for a in args)
        safe_text = text.encode("ascii", errors="replace").decode("ascii")
        print(safe_text, **kwargs)

# ─── Load Environment ────────────────────────────────────────────────────────
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

DATABASE_URL = os.getenv("DATABASE_URL")

# Check if psycopg2 is installed
try:
    import psycopg2
    import psycopg2.extras
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

_thread_local = threading.local()
_db_engine = None  # 'postgres' or 'sqlite'
_db_lock = threading.Lock()
_sqlite_path = Path(__file__).resolve().parent / "usb_detection.db"


# ─── Cache System ─────────────────────────────────────────────────────────────
_cache = {}
_cache_ttl = 3  # seconds

def _cached(key, fetch_fn):
    now = time.time()
    if key in _cache and (now - _cache[key]["time"]) < _cache_ttl:
        return _cache[key]["data"]
    data = fetch_fn()
    _cache[key] = {"data": data, "time": now}
    return data

def invalidate_cache():
    _cache.clear()


# ─── Connection Management ─────────────────────────────────────────────────────
def _create_postgres_conn():
    if not DATABASE_URL or not PSYCOPG2_AVAILABLE:
        return None
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = True
        return conn
    except Exception as e:
        _safe_print(f"⚠️ Neon PostgreSQL connection attempt failed: {e}")
        return None


def _get_conn():
    global _db_engine
    if _db_engine == 'postgres':
        conn = getattr(_thread_local, 'pg_conn', None)
        if conn is not None:
            try:
                if not conn.closed:
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1")
                    return conn, 'postgres'
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                _thread_local.pg_conn = None

        new_conn = _create_postgres_conn()
        if new_conn:
            _thread_local.pg_conn = new_conn
            return new_conn, 'postgres'
        else:
            _safe_print("⚠️ PostgreSQL connection lost. Falling back to local SQLite database.")
            _db_engine = 'sqlite'

    # SQLite fallback
    conn = getattr(_thread_local, 'sqlite_conn', None)
    if conn is None:
        conn = sqlite3.connect(str(_sqlite_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.isolation_level = None  # Autocommit
        _thread_local.sqlite_conn = conn
    return conn, 'sqlite'


# ─── Init & Schema Setup ──────────────────────────────────────────────────────
def initialize_database():
    """Connect and ensure the required table exists in PostgreSQL or SQLite."""
    global _db_engine
    with _db_lock:
        if DATABASE_URL and PSYCOPG2_AVAILABLE:
            conn = _create_postgres_conn()
            if conn:
                _db_engine = 'postgres'
                _thread_local.pg_conn = conn
                _safe_print("✅ Connected to Neon PostgreSQL")
            else:
                _safe_print("⚠️ Could not connect to PostgreSQL. Using local SQLite database.")
                _db_engine = 'sqlite'
        else:
            if not DATABASE_URL:
                _safe_print("ℹ️ DATABASE_URL not set in .env. Using local SQLite database.")
            elif not PSYCOPG2_AVAILABLE:
                _safe_print("⚠️ psycopg2 not installed. Using local SQLite database.")
            _db_engine = 'sqlite'

        conn, engine = _get_conn()
        if engine == 'postgres':
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS device_details (
                        id SERIAL PRIMARY KEY,
                        usb_vid VARCHAR(50),
                        usb_pid VARCHAR(50),
                        usb_serial TEXT,
                        device_type VARCHAR(50) DEFAULT 'unknown',
                        threat_level VARCHAR(50) DEFAULT 'unknown',
                        last_seen REAL
                    );
                """)
            _safe_print("✅ Neon PostgreSQL schema verified")
        else:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS device_details (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        usb_vid TEXT,
                        usb_pid TEXT,
                        usb_serial TEXT,
                        device_type TEXT DEFAULT 'unknown',
                        threat_level TEXT DEFAULT 'unknown',
                        last_seen REAL
                    );
                """)
            _safe_print("✅ Local SQLite database schema verified")


# ─── Query Execution Helper ───────────────────────────────────────────────────
def _execute_query(sql, params=(), fetchone=False, fetchall=False, return_id=False):
    """Executes a SQL query against PostgreSQL or SQLite with automatic retry."""
    conn, engine = _get_conn()

    for attempt in range(2):
        try:
            if engine == 'postgres':
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(sql, params)
                    if return_id:
                        row = cur.fetchone()
                        if row:
                            return row['id'] if isinstance(row, dict) else row[0]
                        return None
                    if fetchone:
                        row = cur.fetchone()
                        return dict(row) if row else None
                    if fetchall:
                        rows = cur.fetchall()
                        return [dict(r) for r in rows]
                    return cur.rowcount
            else:
                sqlite_sql = sql.replace("%s", "?")
                if "RETURNING id" in sqlite_sql:
                    sqlite_sql = sqlite_sql.replace("RETURNING id", "").strip()

                cur = conn.cursor()
                cur.execute(sqlite_sql, params)
                if return_id:
                    return cur.lastrowid
                if fetchone:
                    row = cur.fetchone()
                    return dict(row) if row else None
                if fetchall:
                    rows = cur.fetchall()
                    return [dict(r) for r in rows]
                return cur.rowcount
        except Exception as e:
            if attempt == 0 and engine == 'postgres':
                _thread_local.pg_conn = None
                conn, engine = _get_conn()
                continue
            raise e


# ─── Get ALL devices ──────────────────────────────────────────────────────────
def get_all_devices_full():
    """Returns everything the dashboard needs, deduplicated by VID:PID."""
    def _fetch():
        rows = _execute_query("""
            SELECT id, usb_vid, usb_pid, usb_serial, device_type,
                   threat_level, last_seen
            FROM device_details
            ORDER BY last_seen DESC
        """, fetchall=True) or []

        grouped = {}
        for d in rows:
            key = f"{d['usb_vid']}:{d['usb_pid']}"
            if key not in grouped:
                grouped[key] = d
                grouped[key]["interface_count"] = 1
                grouped[key]["all_serials"] = d.get("usb_serial", "") or ""
            else:
                grouped[key]["interface_count"] += 1
                existing = grouped[key]["all_serials"]
                serial = d.get("usb_serial", "") or ""
                if serial and serial not in existing.split(","):
                    grouped[key]["all_serials"] = f"{existing},{serial}"

        return list(grouped.values())

    return _cached("all_devices", _fetch)


# ─── Single-row lookups ───────────────────────────────────────────────────────
def get_device_by_id(device_id):
    """Fetch a single device by its integer ID."""
    try:
        dev_id = int(device_id)
    except (ValueError, TypeError):
        return None
    return _execute_query("SELECT * FROM device_details WHERE id = %s", (dev_id,), fetchone=True)


def get_device_by_vid_pid(vid, pid):
    """Fetch the most recently seen device matching VID and PID."""
    return _execute_query("""
        SELECT * FROM device_details
        WHERE usb_vid = %s AND usb_pid = %s
        ORDER BY last_seen DESC
        LIMIT 1
    """, (vid, pid), fetchone=True)


def count_interfaces(vid, pid):
    """Count distinct serials for a given VID+PID."""
    res = _execute_query("""
        SELECT COUNT(DISTINCT usb_serial) as cnt FROM device_details WHERE usb_vid = %s AND usb_pid = %s
    """, (vid, pid), fetchone=True)
    if res and "cnt" in res:
        return res["cnt"]
    elif res:
        return list(res.values())[0]
    return 0


def get_device_types(vid, pid):
    """Return list of device_type values for all records matching VID+PID."""
    rows = _execute_query("""
        SELECT device_type FROM device_details WHERE usb_vid = %s AND usb_pid = %s
    """, (vid, pid), fetchall=True) or []
    return [r["device_type"] for r in rows if "device_type" in r]


# ─── Insert / Update / Delete ─────────────────────────────────────────────────
def insert_device(vid, pid, serial):
    """
    Insert a new device or update last_seen if it already exists (matched by vid+pid+serial).
    Returns the integer row ID.
    """
    now_ts = time.time()
    existing = _execute_query("""
        SELECT id FROM device_details WHERE usb_vid = %s AND usb_pid = %s AND usb_serial = %s
    """, (vid, pid, serial), fetchone=True)

    if existing:
        dev_id = existing["id"]
        _execute_query("UPDATE device_details SET last_seen = %s WHERE id = %s", (now_ts, dev_id))
        invalidate_cache()
        return dev_id
    else:
        new_id = _execute_query("""
            INSERT INTO device_details (usb_vid, usb_pid, usb_serial,
                                        device_type, threat_level, last_seen)
            VALUES (%s, %s, %s, 'unknown', 'unknown', %s)
            RETURNING id
        """, (vid, pid, serial, now_ts), return_id=True)
        invalidate_cache()
        return new_id


def update_device_status(vid, pid, device_type, threat_level):
    """Update device_type and threat_level for all records matching VID+PID."""
    now_ts = time.time()
    count = _execute_query("""
        UPDATE device_details
        SET device_type = %s, threat_level = %s, last_seen = %s
        WHERE usb_vid = %s AND usb_pid = %s
    """, (device_type, threat_level, now_ts, vid, pid))
    invalidate_cache()
    return count


def update_device_serial(device_id, serial_csv):
    """Update the usb_serial field for a specific integer row ID."""
    try:
        dev_id = int(device_id)
    except (ValueError, TypeError):
        return
    now_ts = time.time()
    _execute_query("""
        UPDATE device_details
        SET usb_serial = %s, last_seen = %s
        WHERE id = %s
    """, (serial_csv, now_ts, dev_id))
    invalidate_cache()


def delete_device(vid, pid):
    """Delete all records matching VID+PID. Returns count of deleted rows."""
    count = _execute_query("""
        DELETE FROM device_details WHERE usb_vid = %s AND usb_pid = %s
    """, (vid, pid))
    invalidate_cache()
    return count