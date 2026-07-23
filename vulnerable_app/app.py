#!/usr/bin/env python3
"""
secure-ci-pipeline demo target — Flask application (INTENTIONALLY VULNERABLE).

This is the vulnerable version that lives on the ``add-user-feature`` branch. It
contains exactly three planted vulnerabilities, each marked with an
``# INTENTIONALLY VULNERABLE`` comment, plus one outdated dependency pinned in
requirements.txt. Opened as a pull request against ``main``, its pipeline fails
the security gate and the merge is blocked.

    1. SQL injection             -> caught by SAST (Semgrep)
    2. Reflected XSS             -> caught by DAST (OWASP ZAP)
    3. IDOR / broken access ctrl -> typically MISSED by both SAST and DAST

The secure version of this same app lives on ``main``; compare the two to see
the fix for each issue.

WARNING: this application is deliberately insecure. Never deploy it publicly.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)

# A tiny file-backed SQLite database keeps the app self-contained.
DB_PATH = Path(__file__).with_name("bank.db")


def get_db() -> sqlite3.Connection:
    """Open a short-lived SQLite connection with row-by-name access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create and seed the demo database if it does not already exist."""
    conn = get_db()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email    TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id       INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            balance  INTEGER NOT NULL,
            iban     TEXT NOT NULL
        );
        """
    )
    if not cur.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        cur.executemany(
            "INSERT INTO users (id, username, email) VALUES (?, ?, ?)",
            [(1, "alice", "alice@example.com"),
             (2, "bob", "bob@example.com")],
        )
        cur.executemany(
            "INSERT INTO accounts (id, owner_id, balance, iban) VALUES (?, ?, ?, ?)",
            [(1001, 1, 500000, "DE89 3704 0044 0532 0130 00"),
             (1002, 2, 125000, "DE89 3704 0044 0532 0130 11")],
        )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    """Landing page. The links let the ZAP spider discover the routes below."""
    return (
        "<h1>Demo Bank</h1>"
        "<ul>"
        '<li><a href="/user?username=alice">Look up a user</a></li>'
        '<li><a href="/greet?name=World">Greeting</a></li>'
        '<li><a href="/account/1001">View an account</a></li>'
        "</ul>"
    )


@app.route("/health")
def health():
    """Liveness probe used by docker-compose and the CI wait-loop."""
    return jsonify(status="ok")


@app.route("/user")
def get_user():
    """Look up a user by their username."""
    username = request.args.get("username", "")
    conn = get_db()
    cur = conn.cursor()

    # INTENTIONALLY VULNERABLE: SQL injection
    # The username is concatenated straight into the SQL string instead of being
    # passed as a bound parameter, so input such as  alice' OR '1'='1  changes
    # the meaning of the query. Semgrep's formatted-sql-query rule flags this at
    # build time (a static, source-visible pattern).
    query = "SELECT id, username, email FROM users WHERE username = '%s'" % username
    rows = [dict(r) for r in cur.execute(query).fetchall()]

    conn.close()
    return jsonify(results=rows)


@app.route("/greet")
def greet():
    """Return a personalised greeting for the supplied name."""
    name = request.args.get("name", "friend")

    # INTENTIONALLY VULNERABLE: Reflected XSS
    # User input is reflected into the HTML response with no output encoding, so
    # a payload such as  <script>alert(1)</script>  executes in the victim's
    # browser. This is a runtime behaviour, so a DAST scan (OWASP ZAP) exercising
    # the live endpoint is what surfaces it.
    return "<h1>Hello, " + name + "!</h1>"


@app.route("/account/<int:account_id>")
def get_account(account_id: int):
    """Fetch a bank account by its numeric ID."""
    conn = get_db()
    cur = conn.cursor()

    # INTENTIONALLY VULNERABLE: IDOR / broken access control
    # The query itself is safely parameterised, but the account is returned
    # purely on the supplied ID with NO ownership / authorisation check. In a
    # real app the caller would be authenticated and we would verify that the
    # current user actually owns `account_id` before returning it. Because the
    # code looks correct (no injection, valid 200 response), SAST and DAST both
    # typically MISS this — only auth-aware testing or business-logic review
    # catches it. See the "What automated scanners miss" section of the README.
    row = cur.execute(
        "SELECT id, owner_id, balance, iban FROM accounts WHERE id = ?",
        (account_id,),
    ).fetchone()
    conn.close()

    if row is None:
        return jsonify(error="account not found"), 404
    return jsonify(dict(row))


# Seed the database at import time so the app is ready under gunicorn too.
init_db()


if __name__ == "__main__":
    # Local development entrypoint. In the container, gunicorn serves `app`.
    app.run(host="0.0.0.0", port=5000)
