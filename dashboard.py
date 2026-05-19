from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET_KEY"  # Change in production!

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "idrs.db")


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def login_required(fn):
    def wrapper(*args, **kwargs):
        if "admin" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        admin = db.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
        db.close()
        if admin and check_password_hash(admin["password_hash"], password):
            session["admin"] = username
            return redirect(url_for("index"))
        else:
            error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/api/alerts")
@login_required
def get_alerts():
    db = get_db()
    alerts = db.execute(
        "SELECT timestamp, threat, attacker_ip, victim_ip, details, detection_type, ml_score "
        "FROM alerts ORDER BY id DESC LIMIT 100"
    ).fetchall()
    db.close()
    return jsonify([
        {
            "timestamp": a["timestamp"],
            "threat": a["threat"],
            "attacker": a["attacker_ip"],
            "victim": a["victim_ip"],
            "details": a["details"] or "",
            "detection_type": a["detection_type"] or "rule",
            "ml_score": a["ml_score"] or 0.0
        } for a in alerts
    ])


@app.route("/api/blocked")
@login_required
def get_blocked():
    db = get_db()
    blocked = db.execute("""
        SELECT ip_address as ip, threat_type as threat, blocked_at, 
               expires_at as expires, block_count as count, status, detection_source
        FROM blocked_ips WHERE status = 'active' ORDER BY blocked_at DESC
    """).fetchall()
    db.close()
    return jsonify([
        {
            "ip": b["ip"],
            "threat": b["threat"],
            "blocked_at": b["blocked_at"],
            "expires": b["expires"],
            "count": b["count"],
            "status": b["status"],
            "source": b["detection_source"] or "rule"
        } for b in blocked
    ])


@app.route("/api/unblock", methods=["POST"])
@login_required
def unblock():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"success": False, "error": "No IP provided"}), 400

    try:
        import subprocess
        subprocess.run(f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null; iptables -D FORWARD -s {ip} -j DROP 2>/dev/null",
                       shell=True, capture_output=True)

        db = get_db()
        db.execute("UPDATE blocked_ips SET status = 'manual_unblock' WHERE ip_address = ?", (ip,))
        db.commit()
        db.close()
        return jsonify({"success": True, "ip": ip})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/quick-block", methods=["POST"])
@login_required
def quick_block():
    data = request.get_json()
    ip = data.get("ip")
    threat = data.get("threat", "Manual Block")
    if not ip:
        return jsonify({"success": False, "error": "No IP provided"}), 400

    try:
        import subprocess
        subprocess.run(f"iptables -I INPUT 1 -s {ip} -j DROP", shell=True, check=True, capture_output=True)
        subprocess.run(f"iptables -I FORWARD 1 -s {ip} -j DROP", shell=True, capture_output=True)

        db = get_db()
        blocked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        expires_at = (datetime.now() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")

        try:
            db.execute("""
                INSERT INTO blocked_ips (ip_address, threat_type, blocked_at, expires_at, block_count, status, detection_source)
                VALUES (?, ?, ?, ?, 1, 'active', 'manual')
            """, (ip, threat, blocked_at, expires_at))
        except sqlite3.IntegrityError:
            db.execute("""
                UPDATE blocked_ips SET threat_type=?, blocked_at=?, expires_at=?, 
                block_count=block_count+1, status='active', detection_source='manual'
                WHERE ip_address=?
            """, (threat, blocked_at, expires_at, ip))

        db.commit()
        db.close()
        return jsonify({"success": True, "ip": ip})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/stats")
@login_required
def get_stats():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    critical = db.execute("SELECT COUNT(*) FROM alerts WHERE threat LIKE '%CRITICAL%'").fetchone()[0]
    high = db.execute("SELECT COUNT(*) FROM alerts WHERE threat LIKE '%HIGH%' OR threat LIKE '%SEVERE%'").fetchone()[0]
    blocked = db.execute("SELECT COUNT(*) FROM blocked_ips WHERE status='active'").fetchone()[0]
    ml_count = db.execute("SELECT COUNT(*) FROM alerts WHERE detection_type='ml'").fetchone()[0]
    db.close()
    return jsonify({"total": total, "critical": critical, "high": high, "blocked": blocked, "ml_alerts": ml_count})


if __name__ == "__main__":
    print("[*] Starting IDRS Dashboard...")
    print("[*] Access URLs:")
    print("    Local:    http://127.0.0.1:5000")
    print("    Network:  http://<THIS_VM_IP>:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)