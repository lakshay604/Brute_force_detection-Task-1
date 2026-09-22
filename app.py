"""
Brute Force Detection, Visualization & IP Blocking System
-----------------------------------------------------------
A small local Flask app that:
  1. Exposes a test /login endpoint
  2. Logs every login attempt to SQLite
  3. Detects brute-force patterns (too many fails, same IP, short window)
  4. Blocks offending IPs automatically (and lets an admin block/unblock manually)
  5. Serves a dashboard with tables + charts of what's happening

Run with:  python app.py
Dashboard: http://localhost:8000/dashboard
"""

import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, request, jsonify, render_template, g

# --------------------------------------------------------------------------
# 1. CONFIG  (the "knobs" you can turn without touching logic)
# --------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database" / "security.db"

FAILED_THRESHOLD = 5      # how many failed attempts...
TIME_WINDOW_SECONDS = 60  # ...within this many seconds = brute force
BLOCK_DURATION_MINUTES = 15  # how long an automatic block lasts (0 = until manually unblocked)

# A fake "real" account so /login has something to check against.
VALID_USERNAME = "admin"
VALID_PASSWORD = "admin123"

app = Flask(__name__)


# --------------------------------------------------------------------------
# 2. DATABASE HELPERS
# --------------------------------------------------------------------------
def get_db():
    """One SQLite connection per request (Flask's recommended pattern)."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables if they don't already exist. Safe to run every startup."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            username TEXT,
            success INTEGER NOT NULL,           -- 1 = success, 0 = failed
            recent_failures INTEGER DEFAULT 0    -- failures for this IP at time of attempt
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS brute_force_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL,
            status TEXT NOT NULL,      -- e.g. BLOCKED
            reason TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip_address TEXT PRIMARY KEY,
            blocked_at TEXT NOT NULL,
            reason TEXT,
            status TEXT NOT NULL,      -- ACTIVE or UNBLOCKED
            block_type TEXT NOT NULL,  -- AUTO or MANUAL
            expires_at TEXT            -- NULL = no expiry (until manually unblocked)
        )
    """)

    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# 3. CORE SECURITY LOGIC
# --------------------------------------------------------------------------
def get_client_ip():
    """
    Figure out the caller's IP.
    In real life you'd trust request.remote_addr (or a proxy header only if
    you control/trust the proxy). For LOCAL TESTING we also allow a custom
    header so simulate_attack.py can pretend to be many different attacker
    IPs while everything still runs on localhost.
    """
    return request.headers.get("X-Test-IP", request.remote_addr)


def is_ip_blocked(db, ip):
    row = db.execute(
        "SELECT * FROM blocked_ips WHERE ip_address = ? AND status = 'ACTIVE'",
        (ip,),
    ).fetchone()

    if row is None:
        return False

    # Handle expiry for automatic, time-limited blocks
    if row["expires_at"]:
        expires_at = datetime.fromisoformat(row["expires_at"])
        if datetime.now() >= expires_at:
            db.execute(
                "UPDATE blocked_ips SET status = 'UNBLOCKED' WHERE ip_address = ?",
                (ip,),
            )
            db.commit()
            return False

    return True


def count_recent_failures(db, ip):
    """How many failed logins has this IP had in the last TIME_WINDOW_SECONDS?"""
    window_start = (datetime.now() - timedelta(seconds=TIME_WINDOW_SECONDS)).isoformat()
    row = db.execute(
        """SELECT COUNT(*) AS c FROM login_attempts
           WHERE ip_address = ? AND success = 0 AND timestamp >= ?""",
        (ip, window_start),
    ).fetchone()
    return row["c"]


def block_ip(db, ip, reason, block_type="AUTO"):
    now = datetime.now()
    expires_at = None
    if block_type == "AUTO" and BLOCK_DURATION_MINUTES > 0:
        expires_at = (now + timedelta(minutes=BLOCK_DURATION_MINUTES)).isoformat()

    db.execute(
        """INSERT INTO blocked_ips (ip_address, blocked_at, reason, status, block_type, expires_at)
           VALUES (?, ?, ?, 'ACTIVE', ?, ?)
           ON CONFLICT(ip_address) DO UPDATE SET
                blocked_at=excluded.blocked_at,
                reason=excluded.reason,
                status='ACTIVE',
                block_type=excluded.block_type,
                expires_at=excluded.expires_at""",
        (ip, now.isoformat(), reason, block_type, expires_at),
    )
    db.commit()


def log_brute_force_event(db, ip, failed_attempts, reason):
    db.execute(
        """INSERT INTO brute_force_events (ip_address, detected_at, failed_attempts, status, reason)
           VALUES (?, ?, ?, 'BLOCKED', ?)""",
        (ip, datetime.now().isoformat(), failed_attempts, reason),
    )
    db.commit()


# --------------------------------------------------------------------------
# 4. THE TEST LOGIN ENDPOINT  (this is what gets attacked / defended)
# --------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    db = get_db()
    ip = get_client_ip()
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")

    # STEP 1: Is this IP already blocked? Reject immediately, don't even
    # check the password. This is what protects the endpoint.
    if is_ip_blocked(db, ip):
        return jsonify({
            "error": "Forbidden",
            "message": "Your IP has been temporarily blocked."
        }), 403

    # STEP 2: Check the credentials
    success = (username == VALID_USERNAME and password == VALID_PASSWORD)

    # STEP 3: Log the attempt (always, success or fail)
    recent_failures_before = count_recent_failures(db, ip)
    db.execute(
        """INSERT INTO login_attempts (timestamp, ip_address, username, success, recent_failures)
           VALUES (?, ?, ?, ?, ?)""",
        (datetime.now().isoformat(), ip, username, 1 if success else 0, recent_failures_before),
    )
    db.commit()

    if success:
        # A real login resets the "streak" conceptually - we don't need to
        # do anything extra since we only count FAILURES in the window.
        return jsonify({"message": "Login successful"}), 200

    # STEP 4: Re-count failures now that this failed attempt is included
    current_failures = count_recent_failures(db, ip)

    # STEP 5: Brute force detection rule
    if current_failures >= FAILED_THRESHOLD:
        reason = f"Too many failed login attempts ({current_failures} in {TIME_WINDOW_SECONDS}s)"
        block_ip(db, ip, reason, block_type="AUTO")
        log_brute_force_event(db, ip, current_failures, reason)
        return jsonify({
            "error": "Forbidden",
            "message": "Your IP has been temporarily blocked."
        }), 403

    return jsonify({"message": "Invalid username or password"}), 401


# --------------------------------------------------------------------------
# 5. DASHBOARD PAGE
# --------------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/")
def index():
    return render_template("dashboard.html")


# --------------------------------------------------------------------------
# 6. DASHBOARD APIs  (frontend calls these to fill in tables / charts)
# --------------------------------------------------------------------------
@app.route("/api/stats")
def api_stats():
    db = get_db()
    total = db.execute("SELECT COUNT(*) AS c FROM login_attempts").fetchone()["c"]
    success = db.execute("SELECT COUNT(*) AS c FROM login_attempts WHERE success = 1").fetchone()["c"]
    failed = db.execute("SELECT COUNT(*) AS c FROM login_attempts WHERE success = 0").fetchone()["c"]
    events = db.execute("SELECT COUNT(*) AS c FROM brute_force_events").fetchone()["c"]
    blocked_now = db.execute(
        "SELECT COUNT(*) AS c FROM blocked_ips WHERE status = 'ACTIVE'"
    ).fetchone()["c"]

    return jsonify({
        "total_attempts": total,
        "successful_logins": success,
        "failed_logins": failed,
        "brute_force_events": events,
        "currently_blocked": blocked_now,
    })


@app.route("/api/attempts")
def api_attempts():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM login_attempts ORDER BY id DESC LIMIT 50"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/events")
def api_events():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM brute_force_events ORDER BY id DESC LIMIT 50"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/blocked")
def api_blocked():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM blocked_ips ORDER BY blocked_at DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/block", methods=["POST"])
def api_block():
    """Manual block from the dashboard."""
    db = get_db()
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "Manually blocked by administrator").strip()

    if not ip:
        return jsonify({"error": "ip is required"}), 400

    block_ip(db, ip, reason, block_type="MANUAL")
    return jsonify({"message": f"{ip} blocked"}), 200


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    """Manual unblock from the dashboard."""
    db = get_db()
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()

    if not ip:
        return jsonify({"error": "ip is required"}), 400

    db.execute(
        "UPDATE blocked_ips SET status = 'UNBLOCKED' WHERE ip_address = ?", (ip,)
    )
    db.commit()
    return jsonify({"message": f"{ip} unblocked"}), 200


@app.route("/api/chart-data")
def api_chart_data():
    """
    Two datasets for the dashboard charts:
      1. Failed logins over time (bucketed per minute, last 30 minutes)
      2. Top IPs by failed attempts
    """
    db = get_db()

    # --- Failed logins over time (last 30 min, 1-min buckets) ---
    since = (datetime.now() - timedelta(minutes=30)).isoformat()
    rows = db.execute(
        """SELECT timestamp FROM login_attempts
           WHERE success = 0 AND timestamp >= ?""",
        (since,),
    ).fetchall()

    buckets = {}
    for r in rows:
        ts = datetime.fromisoformat(r["timestamp"])
        key = ts.strftime("%H:%M")
        buckets[key] = buckets.get(key, 0) + 1
    timeline = [{"time": k, "count": v} for k, v in sorted(buckets.items())]

    # --- Top IPs by failed attempts (all-time) ---
    top_rows = db.execute(
        """SELECT ip_address, COUNT(*) AS c FROM login_attempts
           WHERE success = 0 GROUP BY ip_address ORDER BY c DESC LIMIT 10"""
    ).fetchall()
    top_ips = [{"ip": r["ip_address"], "count": r["c"]} for r in top_rows]

    return jsonify({"timeline": timeline, "top_ips": top_ips})


@app.route("/api/config")
def api_config():
    """Expose current detection settings so the dashboard can display them."""
    return jsonify({
        "failed_threshold": FAILED_THRESHOLD,
        "time_window_seconds": TIME_WINDOW_SECONDS,
        "block_duration_minutes": BLOCK_DURATION_MINUTES,
    })


# --------------------------------------------------------------------------
# 7. ENTRY POINT
# --------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print(" Brute Force Monitor starting...")
    print(f" Detection rule: {FAILED_THRESHOLD} fails / {TIME_WINDOW_SECONDS}s -> auto block")
    print(" Dashboard: http://localhost:8000/dashboard")
    print("=" * 60)
    app.run(host="0.0.0.0", port=8000, debug=True)
