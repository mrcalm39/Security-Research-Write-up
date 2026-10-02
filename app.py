import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "local-development-secret-change-this"
)

DATABASE = os.environ.get("DATABASE", "lab.db")
LAB_MODE = os.environ.get("LAB_MODE", "fixed").lower()

if LAB_MODE not in ("fixed", "vulnerable"):
    LAB_MODE = "fixed"


# -------------------------------------------------------------------
# Database
# -------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db():
    db = get_db()

    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_owner INTEGER NOT NULL DEFAULT 0,
            session_version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            invited_by INTEGER NOT NULL,
            FOREIGN KEY(invited_by) REFERENCES users(id)
        );
        """
    )

    # Create demonstration owner account.
    owner = db.execute(
        "SELECT id FROM users WHERE email = ?",
        ("owner@example.com",)
    ).fetchone()

    if owner is None:
        db.execute(
            """
            INSERT INTO users
            (email, password_hash, is_owner, session_version, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "owner@example.com",
                generate_password_hash("Password123!"),
                1,
                1,
                datetime.utcnow().isoformat(),
            ),
        )

    db.commit()


# -------------------------------------------------------------------
# Authentication
# -------------------------------------------------------------------

def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        session.clear()
        return None

    # ---------------------------------------------------------------
    # THE FIX
    #
    # Every authenticated session records the user's session_version.
    # When the password is reset, session_version is incremented.
    #
    # In vulnerable mode this check is intentionally skipped so the
    # old session remains authenticated.
    # ---------------------------------------------------------------

    if LAB_MODE == "fixed":

        session_version = session.get("session_version")

        if session_version != user["session_version"]:
            session.clear()
            return None

    return user


@app.context_processor
def inject_user():
    return {
        "current_user": current_user(),
        "lab_mode": LAB_MODE,
    }


def login_required(function):

    @wraps(function)
    def decorated(*args, **kwargs):

        user = current_user()

        if user is None:
            flash("You must log in first.")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return decorated


def owner_required(function):

    @wraps(function)
    def decorated(*args, **kwargs):

        user = current_user()

        if user is None:
            return redirect(url_for("login"))

        if not user["is_owner"]:
            flash("Only the current owner can perform this action.")
            return redirect(url_for("dashboard"))

        return function(*args, **kwargs)

    return decorated


# -------------------------------------------------------------------
# HTML
# -------------------------------------------------------------------

BASE_HTML = """
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Session Security Lab</title>

    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 950px;
            margin: 40px auto;
            padding: 0 20px;
            background: #f5f7fa;
            color: #222;
        }

        nav {
            background: #111827;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 25px;
        }

        nav a {
            color: white;
            margin-right: 18px;
            text-decoration: none;
        }

        .card {
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,.08);
        }

        input {
            width: 100%;
            padding: 10px;
            margin: 8px 0 15px;
            box-sizing: border-box;
        }

        button {
            background: #2563eb;
            color: white;
            border: 0;
            padding: 10px 16px;
            border-radius: 6px;
            cursor: pointer;
        }

        .danger {
            background: #dc2626;
        }

        .success {
            color: #15803d;
        }

        .warning {
            background: #fff7ed;
            border-left: 5px solid #f97316;
            padding: 15px;
        }

        .fixed {
            background: #ecfdf5;
            border-left: 5px solid #16a34a;
            padding: 15px;
        }

        code {
            background: #eee;
            padding: 2px 5px;
            border-radius: 4px;
        }

        a {
            color: #2563eb;
        }
    </style>
</head>

<body>

<nav>
    <a href="{{ url_for('index') }}">Home</a>

    {% if current_user %}
        <a href="{{ url_for('dashboard') }}">Dashboard</a>
        <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
        <a href="{{ url_for('login') }}">Login</a>
        <a href="{{ url_for('forgot_password') }}">Forgot Password</a>
    {% endif %}
</nav>

{% with messages = get_flashed_messages() %}
    {% for message in messages %}
        <div class="card">
            {{ message }}
        </div>
    {% endfor %}
{% endwith %}

{{ content|safe }}

</body>
</html>
"""


def render_page(content, **context):
    return render_template_string(
        BASE_HTML,
        content=render_template_string(content, **context),
        **context,
    )


# -------------------------------------------------------------------
# Home
# -------------------------------------------------------------------

@app.route("/")
def index():

    content = """
    <div class="card">
        <h1>Session Security Lab</h1>

        <p>
            This intentionally vulnerable/fixed application demonstrates
            session invalidation after password reset.
        </p>

        {% if lab_mode == "vulnerable" %}
            <div class="warning">
                <strong>VULNERABLE MODE</strong><br>
                Existing authenticated sessions are NOT invalidated
                after password reset.
            </div>
        {% else %}
            <div class="fixed">
                <strong>FIXED MODE</strong><br>
                Existing authenticated sessions are invalidated
                after password reset.
            </div>
        {% endif %}

        <h2>Demonstration account</h2>

        <p>
            Email:
            <code>owner@example.com</code>
        </p>

        <p>
            Password:
            <code>Password123!</code>
        </p>

        <p>
            This account is provided only for this local lab.
        </p>
    </div>
    """

    return render_page(content)


# -------------------------------------------------------------------
# Login
# -------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["session_version"] = user["session_version"]

            flash("Login successful.")

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    content = """
    <div class="card">

        <h1>Login</h1>

        <form method="post">

            <label>Email</label>
            <input type="email" name="email" required>

            <label>Password</label>
            <input type="password" name="password" required>

            <button type="submit">Login</button>

        </form>

        <p>
            <a href="{{ url_for('forgot_password') }}">
                Forgotten password?
            </a>
        </p>

    </div>
    """

    return render_page(content)


# -------------------------------------------------------------------
# Logout
# -------------------------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.")

    return redirect(url_for("login"))


# -------------------------------------------------------------------
# Dashboard
# -------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    user = current_user()

    content = """
    <div class="card">

        <h1>Dashboard</h1>

        <p>
            You are authenticated as:
            <strong>{{ user["email"] }}</strong>
        </p>

        <p>
            User ID:
            <code>{{ user["id"] }}</code>
        </p>

        <p>
            Session version:
            <code>{{ user["session_version"] }}</code>
        </p>

        {% if user["is_owner"] %}
            <p>
                <strong>Role:</strong> Owner
            </p>

            <hr>

            <h2>Owner functions</h2>

            <p>
                <a href="{{ url_for('invite') }}">
                    Invite a user
                </a>
            </p>

            <p>
                <a href="{{ url_for('transfer_ownership') }}">
                    Transfer ownership
                </a>
            </p>
        {% else %}
            <p>
                <strong>Role:</strong> User
            </p>
        {% endif %}

    </div>

    <div class="card">

        <h2>Password-reset security test</h2>

        <p>
            Open this application in two separate browser sessions.
            Log in on Device A, then reset the password on Device B.
        </p>

        <p>
            Refresh Device A to observe whether the old session remains
            authenticated.
        </p>

    </div>
    """

    return render_page(content, user=user)


# -------------------------------------------------------------------
# Forgot password
# -------------------------------------------------------------------

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if user:

            token = secrets.token_urlsafe(32)

            expires = (
                datetime.utcnow() + timedelta(minutes=30)
            ).isoformat()

            db.execute(
                """
                INSERT INTO password_resets
                (user_id, token, expires_at)
                VALUES (?, ?, ?)
                """,
                (
                    user["id"],
                    token,
                    expires,
                ),
            )

            db.commit()

            reset_url = url_for(
                "reset_password",
                token=token,
                _external=True
            )

            content = """
            <div class="card">

                <h1>Password Reset Link</h1>

                <p>
                    In a real application this link would be sent
                    through an external email service.
                </p>

                <p>
                    For this local security lab, the reset link is
                    displayed directly:
                </p>

                <p>
                    <a href="{{ reset_url }}">
                        {{ reset_url }}
                    </a>
                </p>

            </div>
            """

            return render_page(
                content,
                reset_url=reset_url
            )

        flash(
            "If that account exists, a reset link would be sent."
        )

    content = """
    <div class="card">

        <h1>Forgotten Password</h1>

        <form method="post">

            <label>Email address</label>

            <input
                type="email"
                name="email"
                required
            >

            <button type="submit">
                Request password reset
            </button>

        </form>

    </div>
    """

    return render_page(content)


# -------------------------------------------------------------------
# Password reset
# -------------------------------------------------------------------

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    db = get_db()

    reset = db.execute(
        """
        SELECT *
        FROM password_resets
        WHERE token = ?
        AND used = 0
        """,
        (token,)
    ).fetchone()

    if not reset:
        return render_page(
            "<div class='card'><h1>Invalid reset link</h1></div>"
        )

    if datetime.fromisoformat(
        reset["expires_at"]
    ) < datetime.utcnow():

        return render_page(
            "<div class='card'><h1>Reset link expired</h1></div>"
        )

    if request.method == "POST":

        password = request.form.get("password", "")

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters."
            )

            return redirect(
                url_for(
                    "reset_password",
                    token=token
                )
            )

        db.execute(
            """
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
            """,
            (
                generate_password_hash(password),
                reset["user_id"],
            ),
        )

        # -----------------------------------------------------------
        # THE SECURITY FIX
        #
        # Incrementing this value invalidates every existing session.
        #
        # In vulnerable mode this increment is deliberately omitted.
        # -----------------------------------------------------------

        if LAB_MODE == "fixed":

            db.execute(
                """
                UPDATE users
                SET session_version = session_version + 1
                WHERE id = ?
                """,
                (reset["user_id"],),
            )

        db.execute(
            """
            UPDATE password_resets
            SET used = 1
            WHERE id = ?
            """,
            (reset["id"],)
        )

        db.commit()

        flash(
            "Password changed successfully. "
            "Existing sessions were invalidated."
            if LAB_MODE == "fixed"
            else
            "Password changed successfully. "
            "Existing sessions were NOT invalidated because "
            "the lab is running in vulnerable mode."
        )

        return redirect(url_for("login"))

    content = """
    <div class="card">

        <h1>Create New Password</h1>

        <form method="post">

            <label>New password</label>

            <input
                type="password"
                name="password"
                minlength="8"
                required
            >

            <button type="submit">
                Change password
            </button>

        </form>

    </div>
    """

    return render_page(content)


# -------------------------------------------------------------------
# Invite user
# -------------------------------------------------------------------

@app.route("/invite", methods=["GET", "POST"])
@owner_required
def invite():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        if not email:

            flash("Email address is required.")

            return redirect(url_for("invite"))

        db = get_db()

        existing = db.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing:

            flash("That user already exists.")

            return redirect(url_for("invite"))

        token = secrets.token_urlsafe(32)

        expires = (
            datetime.utcnow() + timedelta(hours=24)
        ).isoformat()

        inviter = current_user()

        db.execute(
            """
            INSERT INTO invitations
            (email, token, expires_at, invited_by)
            VALUES (?, ?, ?, ?)
            """,
            (
                email,
                token,
                expires,
                inviter["id"],
            ),
        )

        db.commit()

        invitation_url = url_for(
            "accept_invitation",
            token=token,
            _external=True
        )

        content = """
        <div class="card">

            <h1>User Invitation</h1>

            <p>
                Invitation created for:
                <strong>{{ email }}</strong>
            </p>

            <p>
                Local lab invitation link:
            </p>

            <p>
                <a href="{{ invitation_url }}">
                    {{ invitation_url }}
                </a>
            </p>

        </div>
        """

        return render_page(
            content,
            email=email,
            invitation_url=invitation_url,
        )

    content = """
    <div class="card">

        <h1>Invite User</h1>

        <form method="post">

            <label>Email address</label>

            <input
                type="email"
                name="email"
                required
            >

            <button type="submit">
                Create invitation
            </button>

        </form>

    </div>
    """

    return render_page(content)


# -------------------------------------------------------------------
# Accept invitation
# -------------------------------------------------------------------

@app.route(
    "/accept-invitation/<token>",
    methods=["GET", "POST"]
)
def accept_invitation(token):

    db = get_db()

    invitation = db.execute(
        """
        SELECT *
        FROM invitations
        WHERE token = ?
        AND used = 0
        """,
        (token,)
    ).fetchone()

    if not invitation:

        return render_page(
            "<div class='card'><h1>Invalid invitation</h1></div>"
        )

    if datetime.fromisoformat(
        invitation["expires_at"]
    ) < datetime.utcnow():

        return render_page(
            "<div class='card'><h1>Invitation expired</h1></div>"
        )

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters."
            )

            return redirect(
                url_for(
                    "accept_invitation",
                    token=token
                )
            )

        existing = db.execute(
            "SELECT id FROM users WHERE email = ?",
            (invitation["email"],)
        ).fetchone()

        if existing:

            flash("User already exists.")

            return redirect(url_for("login"))

        cursor = db.execute(
            """
            INSERT INTO users
            (email, password_hash, is_owner, session_version, created_at)
            VALUES (?, ?, 0, 1, ?)
            """,
            (
                invitation["email"],
                generate_password_hash(password),
                datetime.utcnow().isoformat(),
            ),
        )

        db.execute(
            """
            UPDATE invitations
            SET used = 1
            WHERE id = ?
            """,
            (invitation["id"],)
        )

        db.commit()

        session.clear()

        session["user_id"] = cursor.lastrowid
        session["session_version"] = 1

        flash("Account created successfully.")

        return redirect(url_for("dashboard"))

    content = """
    <div class="card">

        <h1>Accept Invitation</h1>

        <p>
            Create a password for
            <strong>{{ invitation["email"] }}</strong>
        </p>

        <form method="post">

            <label>Password</label>

            <input
                type="password"
                name="password"
                minlength="8"
                required
            >

            <button type="submit">
                Create account
            </button>

        </form>

    </div>
    """

    return render_page(
        content,
        invitation=invitation
    )


# -------------------------------------------------------------------
# Ownership transfer
# -------------------------------------------------------------------

@app.route(
    "/transfer-ownership",
    methods=["GET", "POST"]
)
@owner_required
def transfer_ownership():

    db = get_db()

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        target = db.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        if not target:

            flash(
                "That user does not exist."
            )

            return redirect(
                url_for("transfer_ownership")
            )

        if target["id"] == current_user()["id"]:

            flash(
                "You are already the owner."
            )

            return redirect(
                url_for("transfer_ownership")
            )

        db.execute(
            """
            UPDATE users
            SET is_owner = 0
            WHERE id = ?
            """,
            (current_user()["id"],)
        )

        db.execute(
            """
            UPDATE users
            SET is_owner = 1
            WHERE id = ?
            """,
            (target["id"],)
        )

        db.commit()

        session.clear()

        flash(
            "Ownership transferred successfully. "
            "Your previous owner session has been logged out."
        )

        return redirect(url_for("login"))

    users = db.execute(
        """
        SELECT email
        FROM users
        WHERE id != ?
        """,
        (current_user()["id"],)
    ).fetchall()

    content = """
    <div class="card">

        <h1>Transfer Ownership</h1>

        {% if users %}

            <form method="post">

                <label>New owner</label>

                <select name="email" required>

                    {% for user in users %}

                        <option value="{{ user["email"] }}">
                            {{ user["email"] }}
                        </option>

                    {% endfor %}

                </select>

                <br><br>

                <button
                    class="danger"
                    type="submit"
                >
                    Transfer ownership
                </button>

            </form>

        {% else %}

            <p>
                No other users exist yet.
                Invite another user first.
            </p>

        {% endif %}

    </div>
    """

    return render_page(
        content,
        users=users
    )


# -------------------------------------------------------------------
# Security information
# -------------------------------------------------------------------

@app.route("/security")
def security():

    content = """
    <div class="card">

        <h1>Security Finding</h1>

        <h2>Session Persistence After Password Reset</h2>

        <p>
            The vulnerable implementation allows an already-authenticated
            session to remain valid after the account password is changed
            from another device.
        </p>

        <h2>Expected Secure Behavior</h2>

        <p>
            Changing the password should invalidate previously issued
            authentication sessions.
        </p>

        <h2>Remediation</h2>

        <p>
            This lab uses a server-side
            <code>session_version</code>.
            The value is incremented after a password reset.
            Existing sessions contain the previous value and therefore
            become invalid.
        </p>

        <h2>Verification</h2>

        <ol>
            <li>Log in on Device A.</li>
            <li>Leave Device A authenticated.</li>
            <li>Open Device B.</li>
            <li>Use Forgotten Password.</li>
            <li>Change the password.</li>
            <li>Return to Device A.</li>
            <li>Refresh the dashboard.</li>
        </ol>

        <p>
            In vulnerable mode, Device A remains authenticated.
            In fixed mode, Device A is redirected to login.
        </p>

    </div>
    """

    return render_page(content)


# -------------------------------------------------------------------
# Application startup
# -------------------------------------------------------------------

with app.app_context():
    init_db()


if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "5000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
