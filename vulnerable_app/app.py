#!/usr/bin/env python3
"""
secure-ci-pipeline demo target — Flask application (SECURE baseline).

This is the clean version that lives on the ``main`` branch. The three classes
of vulnerability that the pipeline is built to catch have been fixed here, so
``main``'s pipeline passes green.

The intentionally-vulnerable version of this same app lives on the
``add-user-feature`` branch, where the pipeline blocks the pull request. Compare
the two to see the exact fix for each issue:

    * /user     — SQL injection      -> fixed with a parameterised query
    * /greet    — Reflected XSS       -> fixed with an autoescaping template
    * /account  — IDOR / broken access-> fixed with an ownership check

WARNING: this app is a scan target for a security demo. Do not expose it
publicly even in this clean state.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

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

    # SECURE: the username is passed as a bound parameter, so it is treated as
    # data and cannot alter the structure of the query (no SQL injection).
    rows = [
        dict(r)
        for r in cur.execute(
            "SELECT id, username, email FROM users WHERE username = ?",
            (username,),
        ).fetchall()
    ]

    conn.close()
    return jsonify(results=rows)


@app.route("/greet")
def greet():
    """Return a personalised greeting for the supplied name."""
    name = request.args.get("name", "friend")

    # SECURE: the value is rendered through Jinja, which autoescapes it. A
    # payload such as <script>alert(1)</script> is HTML-encoded and rendered
    # inert instead of executing (no reflected XSS). Note the template is a
    # constant and the input is passed as a context variable, so there is no
    # server-side template injection either.
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)


@app.route("/account/<int:account_id>")
def get_account(account_id: int):
    """Fetch a bank account by its numeric ID, enforcing ownership."""
    # In a real app the current user id comes from the authenticated session;
    # here we read it from a header that an auth middleware would populate.
    current_user_id = request.headers.get("X-User-Id", type=int)

    conn = get_db()
    cur = conn.cursor()
    row = cur.execute(
        "SELECT id, owner_id, balance, iban FROM accounts WHERE id = ?",
        (account_id,),
    ).fetchone()
    conn.close()

    if row is None:
        return jsonify(error="account not found"), 404

    # SECURE: enforce that the caller actually owns this account before
    # returning it (fixes the IDOR / broken-access-control flaw). Without this
    # check any user could enumerate and read every account.
    if current_user_id is None or row["owner_id"] != current_user_id:
        return jsonify(error="forbidden"), 403

    return jsonify(dict(row))


# Seed the database at import time so the app is ready under gunicorn too.
init_db()


if __name__ == "__main__":
    # Local development entrypoint. In the container, gunicorn serves `app`.
    app.run(host="0.0.0.0", port=5000)
