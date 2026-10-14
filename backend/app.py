
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS

from detector import check_url, check_message

app = Flask(__name__)
CORS(app, origins=["http://localhost:5173"])

DB_PATH = Path(__file__).with_name("cyberrakshak.db")


def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                input_text TEXT NOT NULL,
                risk TEXT NOT NULL,
                score INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def save_scan(scan_type, value, result):
    with get_db() as db:
        db.execute("""
            INSERT INTO scans
            (scan_type, input_text, risk, score, reasons, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_type,
            value[:500],
            result["risk"],
            result["score"],
            json.dumps(result["reasons"]),
            datetime.now(timezone.utc).isoformat()
        ))


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "success",
        "message": "CyberRakshak backend is running!"
    })


def run_scan(scan_type):
    data = request.get_json(silent=True) or {}
    field = "url" if scan_type == "url" else "message"
    value = data.get(field, "")

    if not isinstance(value, str):
        return jsonify({"error": f"{field} must be text."}), 400

    value = value.strip()

    if not value:
        return jsonify({"error": f"Please enter a {field}."}), 400

    if len(value) > 5000:
        return jsonify({"error": "Input must be 5000 characters or fewer."}), 400

    result = check_url(value) if scan_type == "url" else check_message(value)
    save_scan(scan_type, value, result)
    return jsonify(result)


@app.route("/api/scan-url", methods=["POST"])
def scan_url():
    return run_scan("url")


@app.route("/api/scan-message", methods=["POST"])
def scan_message():
    return run_scan("message")


@app.route("/api/stats", methods=["GET"])
def stats():
    with get_db() as db:
        totals = db.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN risk = 'High' THEN 1 ELSE 0 END) AS high_risk,
                SUM(CASE WHEN scan_type = 'url' THEN 1 ELSE 0 END) AS url_scans,
                SUM(CASE WHEN scan_type = 'message' THEN 1 ELSE 0 END) AS message_scans
            FROM scans
        """).fetchone()

    return jsonify({
        "total": totals["total"] or 0,
        "high_risk": totals["high_risk"] or 0,
        "url_scans": totals["url_scans"] or 0,
        "message_scans": totals["message_scans"] or 0
    })


@app.route("/api/history", methods=["GET"])
def history():
    with get_db() as db:
        rows = db.execute("""
            SELECT id, scan_type, input_text, risk, score, reasons, created_at
            FROM scans
            ORDER BY id DESC
            LIMIT 10
        """).fetchall()

    return jsonify([
        {
            "id": row["id"],
            "type": row["scan_type"],
            "input": row["input_text"],
            "risk": row["risk"],
            "score": row["score"],
            "reasons": json.loads(row["reasons"]),
            "created_at": row["created_at"]
        }
        for row in rows
    ])


init_db()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
