from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

# Simulated database state
DB = {
    "password": "password123",
    "valid_session_token": "stale_session_cookie_demo_prod"
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Stale Session Vulnerability Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 30px; background: #f4f6f9; display: flex; gap: 20px; }
        .browser { flex: 1; background: white; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-top: 5px solid #333; }
        .device-a { border-top-color: #007bff; }
        .device-b { border-top-color: #28a745; }
        h2 { margin-top: 0; color: #333; }
        .badge { display: inline-block; padding: 4px 8px; background: #e9ecef; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .status-active { background: #d4edda; color: #155724; }
        .status-loggedout { background: #f8d7da; color: #721c24; }
        .btn { background: #007bff; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-danger { background: #dc3545; }
        .alert { background: #fff3cd; color: #856404; padding: 12px; border-radius: 4px; margin: 15px 0; font-size: 14px; border: 1px solid #ffeeba; }
        .success-box { background: #d4edda; color: #155724; padding: 15px; border-radius: 4px; margin-top: 15px; border: 1px solid #c3e6cb; }
        ul { padding-left: 20px; font-size: 14px; }
    </style>
</head>
<body>

    <!-- DEVICE A: ATTACKER / OLD PERSISTENT SESSION -->
    <div class="browser device-a">
        <h2>💻 DEVICE A <span class="badge status-active">Session: Active</span></h2>
        <p><strong>Current Session Cookie:</strong> <code>{{ token }}</code></p>
        <p>This browser represents an older login session left active on a shared computer or intercepted by an attacker.</p>
        
        <div class="alert">
            <strong>Task:</strong> Keep this window open. Go to Device B, log out, trigger a password reset, and see if you can still perform administrative tasks here!
        </div>

        <h3>🛠️ Administrative Console Action Panel</h3>
        <form method="POST" action="/action">
            <input type="hidden" name="token" value="{{ token }}">
            <select name="action_type" style="padding: 6px; margin-right: 10px;">
                <option value="api_key">🔑 Generate Global API Production Keys</option>
                <option value="invite">👤 Invite External User as Organization Admin</option>
                <option value="ownership">⚠️ Transfer Project Full Ownership</option>
            </select>
            <button type="submit" class="btn">Execute Action</button>
        </form>

        {% if action_result %}
            <div class="success-box">
                🔥 <strong>VULNERABILITY CONFIRMED:</strong><br>
                {{ action_result }}
            </div>
        {% endif %}
    </div>

    <!-- DEVICE B: LEGITIMATE USER / RESET SYSTEM -->
    <div class="browser device-b">
        <h2>💻 DEVICE B</h2>
        {% if b_logged_in %}
            <span class="badge status-active">Logged In (New Password)</span>
            <p style="margin-top: 15px;">You have successfully configured and signed in with your new credentials!</p>
            <a href="/logout-b" class="btn btn-danger">Log Out of Device B</a>
        {% else %}
            <span class="badge status-loggedout">Logged Out</span>
            <p>Simulating the "Forgot Password" self-service remediation workflow.</p>
            <form method="POST" action="/reset-password" style="background: #f8f9fa; padding: 15px; border-radius: 4px;">
                <label style="display:block; margin-bottom: 5px; font-size: 14px;"><strong>Enter New Password:</strong></label>
                <input type="text" name="new_password" value="SecurePassword2026!" style="width: 90%; padding: 6px; margin-bottom: 10px;">
                <button type="submit" class="btn" style="background: #28a745;">Complete Password Reset</button>
            </form>
        {% endif %}
    </div>

</body>
</html>
"""

@app.route('/')
def index():
    action_res = request.args.get('res')
    b_state = request.args.get('b_state') == 'true'
    return render_template_string(
        HTML_TEMPLATE, 
        token=DB["valid_session_token"], 
        action_result=action_res,
        b_logged_in=b_state
    )

@app.route('/reset-password', methods=['POST'])
def reset_password():
    new_pw = request.form.get('new_password')
    DB["password"] = new_pw
    # VULNERABILITY MECHANISM:
    # We update the password field, but we FAIL to change or delete DB["valid_session_token"]
    return redirect(url_for('index', b_state='true'))

@app.route('/logout-b')
def logout_b():
    return redirect(url_for('index', b_state='false'))

@app.route('/action', methods=['POST'])
def execute_action():
    submitted_token = request.form.get('token')
    action_type = request.form.get('action_type')
    
    # Check if the submitted token matches the current database token
    if submitted_token == DB["valid_session_token"]:
        if action_type == "api_key":
            return redirect(url_for('index', res="Successfully created high-privilege production API keys using stale cookie data!"))
        elif action_type == "invite":
            return redirect(url_for('index', res="Successfully invited malicious external threat actor as Organization Admin!"))
        elif action_type == "ownership":
            return redirect(url_for('index', res="Successfully transferred total root account ownership away from the victim!"))
    
    return redirect(url_for('index', res="Error: Session Invalidated."))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
