import os
import secrets
import sqlite3
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    render_template,
    flash,
    abort,
)


# ============================================================
# Configuration
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "lab.db")

# LAB_MODE:
#   vulnerable -> old PHPSESSID remains valid after password reset
#   fixed      -> old PHPSESSID is invalidated after password reset
MODE = os.getenv("LAB_MODE", "fixed").lower()

SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")


app = Flask(__name__)
app.secret_key = SECRET_KEY

# IMPORTANT:
# The lab intentionally uses PHPSESSID so the session cookie can
# be observed and tested as part of the session-management lab.
app.config.update(
    SESSION_COOKIE_NAME="PHPSESSID",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


# ============================================================
# Database
# ============================================================

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            reset_token TEXT,
            reset_expires TEXT,
            session_version INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            version INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            invited_by INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            accepted INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        """
    )

    # Create initial lab accounts only when the database is empty.
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        add_user(
            conn,
            "alice@example.test",
            "Alice",
            "password123",
            "owner",
        )

        add_user(
            conn,
            "bob@example.test",
            "Bob",
            "password123",
            "member",
        )

    conn.commit()
    conn.close()


# ============================================================
# Password helpers
# ============================================================

def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()


def add_user(conn, email, name, password, role="member"):
    conn.execute(
        """
        INSERT INTO users (
            email,
            name,
            password_hash,
            role
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            email,
            name,
            hash_pw(password),
            role,
        ),
    )


# ============================================================
# Session handling
# ============================================================

def current_user():
    """
    Resolve the currently authenticated user.

    The Flask session contains a random server-side session token.

    PHPSESSID
        |
        v
    Flask session
        |
        v
    session_token
        |
        v
    sessions table
        |
        v
    user account

    Vulnerable mode:
        The session remains valid after a password reset.

    Fixed mode:
        Password reset invalidates the old server-side session.
    """

    token = session.get("session_token")

    if not token:
        return None

    conn = db()

    row = conn.execute(
        """
        SELECT
            u.*,
            s.version AS token_version
        FROM sessions s
        JOIN users u
            ON u.id = s.user_id
        WHERE s.token = ?
        """,
        (token,),
    ).fetchone()

    conn.close()

    if not row:
        # The server-side session no longer exists.
        session.clear()
        return None

    # --------------------------------------------------------
    # FIXED MODE
    # --------------------------------------------------------
    #
    # Each session contains the user's session_version.
    #
    # Password reset increments the user's session_version and
    # removes existing sessions.
    #
    # Therefore an old PHPSESSID can no longer authenticate.
    #
    if MODE == "fixed":
        if row["token_version"] != row["session_version"]:
            session.clear()
            return None

    # --------------------------------------------------------
    # VULNERABLE MODE
    # --------------------------------------------------------
    #
    # Nothing is checked here to invalidate the old session.
    #
    # If the PHPSESSID still maps to a valid session record,
    # the user remains authenticated.
    #
    return row


def login_user(user):
    """
    Create a new authenticated server-side session.

    The browser receives a PHPSESSID cookie containing the
    Flask session data, which references this server-side token.
    """

    token = secrets.token_urlsafe(32)

    conn = db()

    conn.execute(
        """
        INSERT INTO sessions (
            token,
            user_id,
            version,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            token,
            user["id"],
            user["session_version"],
            datetime.utcnow().isoformat(),
        ),
    )

    conn.commit()
    conn.close()

    session.clear()

    session["session_token"] = token


def require_login(fn):
    """
    Authentication decorator.

    Every protected endpoint calls current_user().

    This is important for the lab because the vulnerability
    exists when an old PHPSESSID still resolves to an
    authenticated user.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()

        if not user:
            flash("Please log in.")
            return redirect(url_for("login"))

        return fn(user, *args, **kwargs)

    return wrapper


# ============================================================
# Template globals
# ============================================================

@app.context_processor
def inject_globals():
    return {
        "mode": MODE,
        "user": current_user(),
    }


# ============================================================
# Home
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


# ============================================================
# Login
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()

        conn.close()

        if user and user["password_hash"] == hash_pw(password):

            login_user(user)

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")


# ============================================================
# Logout
# ============================================================

@app.route("/logout", methods=["POST"])
def logout():

    token = session.get("session_token")

    if token:

        conn = db()

        conn.execute(
            """
            DELETE FROM sessions
            WHERE token = ?
            """,
            (token,),
        )

        conn.commit()
        conn.close()

    session.clear()

    flash("Logged out.")

    return redirect(url_for("index"))


# ============================================================
# Dashboard
# ============================================================

@app.route("/dashboard")
@require_login
def dashboard(user):

    conn = db()

    users = conn.execute(
        """
        SELECT
            id,
            name,
            email,
            role
        FROM users
        """
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        users=users,
    )


# ============================================================
# Forgot password
# ============================================================

@app.route("/forgot", methods=["GET", "POST"])
def forgot():

    reset_url = None

    if request.method == "POST":

        email = request.form["email"].strip().lower()

        conn = db()

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()

        if user:

            token = secrets.token_urlsafe(24)

            expires = (
                datetime.utcnow()
                + timedelta(minutes=30)
            ).isoformat()

            conn.execute(
                """
                UPDATE users
                SET
                    reset_token = ?,
                    reset_expires = ?
                WHERE id = ?
                """,
                (
                    token,
                    expires,
                    user["id"],
                ),
            )

            conn.commit()

            reset_url = url_for(
                "reset_password",
                token=token,
                _external=True,
            )

        conn.close()

        flash(
            "If the account exists, a reset link "
            "was generated for this lab."
        )

    return render_template(
        "forgot.html",
        reset_url=reset_url,
    )


# ============================================================
# Password reset
# ============================================================

@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):

    conn = db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE reset_token = ?
        """,
        (token,),
    ).fetchone()

    if (
        not user
        or not user["reset_expires"]
        or datetime.fromisoformat(
            user["reset_expires"]
        ) < datetime.utcnow()
    ):
        conn.close()

        abort(
            400,
            "Invalid or expired reset token.",
        )

    if request.method == "POST":

        password = request.form["password"]

        if len(password) < 8:

            flash(
                "Password must be at least 8 characters."
            )

            conn.close()

            return render_template(
                "reset.html"
            )

        # ====================================================
        # FIXED IMPLEMENTATION
        # ====================================================
        #
        # Password reset invalidates every previously issued
        # authenticated session belonging to this account.
        #
        # This is the security fix.
        #
        if MODE == "fixed":

            # Delete all existing authenticated sessions.
            conn.execute(
                """
                DELETE FROM sessions
                WHERE user_id = ?
                """,
                (user["id"],),
            )

            # Increase the session version.
            #
            # Any session created using the previous version
            # is no longer valid.
            conn.execute(
                """
                UPDATE users
                SET session_version =
                    session_version + 1
                WHERE id = ?
                """,
                (user["id"],),
            )

        # ====================================================
        # VULNERABLE IMPLEMENTATION
        # ====================================================
        #
        # Deliberately DO NOT:
        #
        #   DELETE FROM sessions
        #
        # and DO NOT:
        #
        #   increment session_version
        #
        # Therefore an existing PHPSESSID remains associated
        # with a valid authenticated session.
        #
        # This reproduces the session-persistence vulnerability.
        #

        conn.execute(
            """
            UPDATE users
            SET
                password_hash = ?,
                reset_token = NULL,
                reset_expires = NULL
            WHERE id = ?
            """,
            (
                hash_pw(password),
                user["id"],
            ),
        )

        conn.commit()
        conn.close()

        if MODE == "fixed":

            flash(
                "Password changed. "
                "Existing sessions have been revoked."
            )

        else:

            flash(
                "Password changed. "
                "Existing sessions remain valid "
                "in vulnerable mode."
            )

        return redirect(url_for("login"))

    conn.close()

    return render_template(
        "reset.html"
    )


# ============================================================
# Invite user
# ============================================================

@app.route("/invite", methods=["GET", "POST"])
@require_login
def invite(user):

    if request.method == "POST":

        email = request.form["email"].strip().lower()

        token = secrets.token_urlsafe(20)

        conn = db()

        conn.execute(
            """
            INSERT INTO invites (
                email,
                invited_by,
                token,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                email,
                user["id"],
                token,
                datetime.utcnow().isoformat(),
            ),
        )

        conn.commit()
        conn.close()

        invite_url = url_for(
            "accept_invite",
            token=token,
            _external=True,
        )

        flash(
            f"Lab invite created: {invite_url}"
        )

    return render_template(
        "invite.html"
    )


# ============================================================
# Accept invitation
# ============================================================

@app.route(
    "/invite/<token>",
    methods=["GET", "POST"],
)
def accept_invite(token):

    conn = db()

    inv = conn.execute(
        """
        SELECT *
        FROM invites
        WHERE token = ?
          AND accepted = 0
        """,
        (token,),
    ).fetchone()

    conn.close()

    if not inv:
        abort(404)

    if request.method == "POST":

        email = inv["email"]
        name = request.form["name"]
        password = request.form["password"]

        conn = db()

        try:

            add_user(
                conn,
                email,
                name,
                password,
                "member",
            )

            conn.execute(
                """
                UPDATE invites
                SET accepted = 1
                WHERE id = ?
                """,
                (inv["id"],),
            )

            conn.commit()

            flash(
                "Invitation accepted. "
                "You can now log in."
            )

            return redirect(
                url_for("login")
            )

        except sqlite3.IntegrityError:

            flash(
                "That email already has an account."
            )

        finally:

            conn.close()

    return render_template(
        "accept_invite.html",
        invite=inv,
    )


# ============================================================
# Ownership transfer
# ============================================================

@app.route(
    "/transfer",
    methods=["GET", "POST"],
)
@require_login
def transfer(user):

    # Only the current owner can transfer ownership.
    #
    # In vulnerable mode, the old PHPSESSID still resolves
    # to this user after a password reset, so this check still
    # succeeds.
    if user["role"] != "owner":
        abort(403)

    conn = db()

    members = conn.execute(
        """
        SELECT
            id,
            name,
            email
        FROM users
        WHERE id != ?
        """,
        (user["id"],),
    ).fetchall()

    if request.method == "POST":

        try:
            target_id = int(
                request.form["target_id"]
            )
        except (TypeError, ValueError):

            conn.close()

            abort(400)

        target = conn.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            """,
            (target_id,),
        ).fetchone()

        if target:

            # Remove owner role from current user.
            conn.execute(
                """
                UPDATE users
                SET role = "member"
                WHERE id = ?
                """,
                (user["id"],),
            )

            # Give owner role to selected account.
            conn.execute(
                """
                UPDATE users
                SET role = "owner"
                WHERE id = ?
                """,
                (target_id,),
            )

            conn.commit()

            flash(
                f'Ownership transferred to '
                f'{target["email"]}.'
            )

            conn.close()

            return redirect(
                url_for("dashboard")
            )

    conn.close()

    return render_template(
        "transfer.html",
        members=members,
    )


# ============================================================
# Application startup
# ============================================================

if __name__ == "__main__":

    init_db()

    print(
        f"Running session-reset lab "
        f"in {MODE.upper()} mode"
    )

    print(
        "Session cookie name: PHPSESSID"
    )

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv("PORT", 5000)
        ),
        debug=False,
    )
