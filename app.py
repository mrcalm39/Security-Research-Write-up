import uuid
from flask import Flask, request, make_response, redirect, url_for

app = Flask(__name__)

# Simulated Global Database
USER_DB = {
    "username": "admin",
    "password": "password123"
}

# Vulnerability Core: Active session tracking database mapping tokens to users
# (Even when passwords update, old valid tokens are never pruned from this dictionary)
ACTIVE_SESSIONS = {
    "stale-admin-token-demo-999": "admin"
}

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>JoeSecLab - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f6f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); width: 350px; border-top: 5px solid #007bff; }
        h2 { margin-top: 0; color: #333; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; background: #007bff; color: white; border: none; padding: 12px; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .error { color: #dc3545; font-size: 14px; margin-bottom: 10px; }
        .info { background: #e8f4fd; color: #1d6fa5; padding: 10px; border-radius: 4px; font-size: 13px; line-height: 1.4; }
    </style>
</head>
<body>
    <div class="box">
        <h2>🔒 JoeSecLab Portal</h2>
        <p class="error">{{ error }}</p>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username (Default: admin)" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
        <br>
        <div class="info">
            <strong>Lab Hack Instructions:</strong><br>
            To use an existing session cookie directly without logging in, add a cookie named <code>session_id</code> with value <code>stale-admin-token-demo-999</code> to your browser.
        </div>
    </div>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>JoeSecLab - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f6f9; }
        .container { max-width: 700px; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-top: 5px solid #28a745; }
        .user-card { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; border-left: 4px solid #007bff; }
        .btn { background: #dc3545; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-panel { background: #007bff; }
        .alert-success { background: #d4edda; color: #155724; padding: 15px; border-radius: 4px; margin-top: 15px; border: 1px solid #c3e6cb; }
    </style>
</head>
<body>
    <div class="container">
        <h2>👋 Welcome back, {{ username }}!</h2>
        <div class="user-card">
            <p><strong>Your Active Session Token:</strong> <code>{{ current_cookie }}</code></p>
            <p>Status: Authenticated Session Persistent</p>
        </div>

        <h3>🛠️ Administrative Post-Exploitation Actions</h3>
        <p>If you can access this panel after a password reset on another browser, the vulnerability is verified.</p>
        <form method="POST" action="/execute-action">
            <select name="action_type" style="padding: 8px; width: 250px;">
                <option value="api_key">🔑 Generate Production API Keys</option>
                <option value="invite">👤 Invite External Admin User</option>
                <option value="ownership">⚠️ Transfer Root Ownership</option>
            </select>
            <button type="submit" class="btn btn-panel">Run Action</button>
        </form>

        {% if action_msg %}
            <div class="alert-success">🔥 <strong>EXPLOIT SUCCESSFUL:</strong> {{ action_msg }}</div>
        {% endif %}

        <hr style="margin: 30px 0; border: 0; border-top: 1px solid #ddd;">
        
        <h3>🔑 Account Self-Service Remediation</h3>
        <p>Simulate an account recovery scenario. Change your password here to see if old cookies expire:</p>
        <form method="POST" action="/change-password">
            <input type="text" name="new_password" placeholder="Enter New Password" style="padding:8px; width:235px;" required>
            <button type="submit" class="btn" style="background:#6c757d;">Update Account Password</button>
        </form>
        <br>
        <a href="/logout" class="btn">Log Out Securely</a>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    cookie = request.cookies.get('session_id')
    if cookie in ACTIVE_SESSIONS:
        username = ACTIVE_SESSIONS[cookie]
        action_msg = request.args.get('msg')
        return render_template_string(DASHBOARD_PAGE, username=username, current_cookie=cookie, action_msg=action_msg)
    
    error = request.args.get('error', '')
    return render_template_string(LOGIN_PAGE, error=error)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username == USER_DB["username"] and password == USER_DB["password"]:
        new_token = str(uuid.uuid4())
        ACTIVE_SESSIONS[new_token] = username
        response = make_response(redirect(url_for('index')))
        response.set_cookie('session_id', new_token)
        return response
    
    return redirect(url_for('index', error="Invalid credentials specified."))

@app.route('/change-password', methods=['POST'])
def change_password():
    cookie = request.cookies.get('session_id')
    if cookie not in ACTIVE_SESSIONS:
        return redirect(url_for('index'))
    
    new_pw = request.form.get('new_password')
    USER_DB["password"] = new_pw
    
    # 🚨 CRITICAL VULNERABILITY ARCHITECTURE HAUNT:
    # The application successfully commits the new password to USER_DB, 
    # but it intentionally completely FORGETS to clear out existing tokens from ACTIVE_SESSIONS.
    
    return redirect(url_for('index', msg="Password updated successfully inside the database!"))

@app.route('/execute-action', methods=['POST'])
def execute_action():
    cookie = request.cookies.get('session_id')
    if cookie not in ACTIVE_SESSIONS:
        return redirect(url_for('index', error="Session expired or invalid."))
        
    action_type = request.form.get('action_type')
    messages = {
        "api_key": "Bypassed 2FA and generated high-privilege production API access keys using a stale cookie!",
        "invite": "Bypassed security boundaries to successfully invite an external attacker profile as Admin!",
        "ownership": "Complete critical takeover! Transferred root workspace ownership using a legacy persistent cookie."
    }
    return redirect(url_for('index', msg=messages.get(action_type, "Action executed.")))

@app.route('/logout')
def logout():
    cookie = request.cookies.get('session_id')
    if cookie in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[cookie]
    response = make_response(redirect(url_for('index')))
    response.set_cookie('session_id', '', expires=0)
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
