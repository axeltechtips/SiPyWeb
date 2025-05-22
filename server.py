import os
import sys
import platform
import time
import threading
import tkinter as tk
from tkinter import ttk
from io import BytesIO

from flask import (
    Flask, render_template_string, request, redirect, url_for,
    session, jsonify, send_file
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import pyotp
import qrcode
from PIL import Image, ImageTk

# --- SETTINGS AND GLOBALS ---

LOG_FILE = "sipyweb.log"
SETTINGS_FILE = "settings.json"
START_TIME = time.time()

import json

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    # Default settings
    return {
        "password": "admin123",
        "totp_secret": pyotp.random_base32(),
        "port": 8000
    }

def save_settings():
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f)

settings = load_settings()

def log(msg):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

# --- FLASK APP SETUP ---

app = Flask(__name__)
app.secret_key = os.urandom(24)

limiter = Limiter(app, key_func=get_remote_address)

# --- AUTH HELPERS ---

def is_logged_in():
    return session.get("logged_in", False)

def verify_totp(token):
    totp_secret = settings.get("totp_secret")
    if not totp_secret:
        return False
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(token, valid_window=1)

# --- ROUTES ---

@app.route("/")
def index():
    if not is_logged_in():
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        token = request.form.get("token", "")
        if password != settings.get("password"):
            error = "Invalid password"
        elif not verify_totp(token):
            error = "Invalid 2FA code"
        else:
            session["logged_in"] = True
            log("User logged in")
            return redirect(url_for("dashboard"))
    return render_template_string(LOGIN_HTML, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))
    return render_template_string(DASHBOARD_HTML, port=settings.get("port", 8000))

# --- API ENDPOINTS ---

@app.route("/api/settings")
def api_get_settings():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "port": settings.get("port", 8000),
        "totp_secret": settings.get("totp_secret")
    })

@app.route("/api/restart", methods=["POST"])
def api_restart():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    log("Restart requested via dashboard (simulated).")
    return jsonify({"success": True, "message": "Server restart simulated. Please manually restart."})

@app.route("/api/change_password", methods=["POST"])
def api_change_password():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json()
    old_pass = data.get("old_password")
    new_pass = data.get("new_password")
    confirm = data.get("confirm_password")
    if old_pass != settings.get("password"):
        return jsonify({"success": False, "error": "Old password incorrect"})
    if not new_pass or len(new_pass) < 6:
        return jsonify({"success": False, "error": "New password must be at least 6 characters"})
    if new_pass != confirm:
        return jsonify({"success": False, "error": "New password and confirmation do not match"})
    settings["password"] = new_pass
    save_settings()
    log("Password changed via dashboard")
    return jsonify({"success": True})

@app.route("/api/download_logs")
def api_download_logs():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    if not os.path.exists(LOG_FILE):
        return jsonify({"error": "Log file not found"}), 404
    return send_file(LOG_FILE, as_attachment=True)

@app.route("/api/clear_logs", methods=["POST"])
def api_clear_logs():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    open(LOG_FILE, "w").close()
    log("Logs cleared via dashboard")
    return jsonify({"success": True})

@app.route("/api/system_info")
def api_system_info():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    uptime = time.time() - START_TIME
    info = {
        "python_version": sys.version.split("\n")[0],
        "platform": platform.platform(),
        "uptime_seconds": int(uptime),
    }
    return jsonify(info)

@app.route("/api/last_logs")
def api_last_logs():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    if not os.path.exists(LOG_FILE):
        return jsonify({"logs": ""})
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    last_lines = lines[-10:]
    return jsonify({"logs": "".join(last_lines)})

# --- HTML TEMPLATES ---

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>SiPyWeb Login</title>
<style>
  body { background: #121212; color: #eee; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
  .login-container { max-width: 400px; margin: 80px auto; padding: 30px; background: #1E1E1E; border-radius: 12px; box-shadow: 0 0 15px #00aaff99; }
  h2 { color: #00aaff; text-align: center; }
  label { display: block; margin-top: 15px; }
  input { width: 100%; padding: 10px; margin-top: 5px; border-radius: 5px; border: none; background: #222; color: #eee; font-size: 1em; }
  button { width: 100%; margin-top: 20px; padding: 10px; border: none; border-radius: 5px; background: #00aaff; color: white; font-weight: bold; cursor: pointer; }
  button:hover { background: #0088cc; }
  .error { margin-top: 15px; color: #ff5555; text-align: center; }
</style>
</head>
<body>
  <div class="login-container">
    <h2>SiPyWeb Login</h2>
    <form method="POST">
      <label for="password">Password</label>
      <input name="password" id="password" type="password" required autocomplete="current-password" />
      <label for="token">2FA Code</label>
      <input name="token" id="token" type="text" pattern="\\d{6}" maxlength="6" autocomplete="one-time-code" required />
      <button type="submit">Login</button>
    </form>
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
  </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>SiPyWeb Dashboard</title>
<style>
  body { background: #121212; color: #eee; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin:0; padding:0;}
  .container { max-width: 900px; margin: 20px auto; padding: 20px; background: #1E1E1E; border-radius: 10px; box-shadow: 0 0 15px #00aaff99;}
  h1, h2 { color: #00aaff; }
  label { display: block; margin-top: 10px; }
  input, button, textarea { width: 100%; padding: 10px; margin-top: 5px; border-radius: 5px; border: none; font-size: 1em; }
  input, textarea { background: #222; color: #eee; }
  button { background: #00aaff; color: #eee; cursor: pointer; font-weight: bold; }
  button:hover { background: #0088cc; }
  #qr_code { max-width: 180px; margin-top: 10px; border-radius: 10px; background: #111; padding: 10px; }
  #logs { background: #222; height: 200px; overflow-y: scroll; white-space: pre-wrap; font-family: monospace; }
  #system_info { margin-top: 15px; }
  .flex-row { display: flex; gap: 15px; }
  .flex-child { flex: 1; }
  .msg { margin-top: 8px; font-weight: bold; }
  a.logout { float: right; color: #ff5555; font-weight: bold; text-decoration: none; }
  a.logout:hover { text-decoration: underline; }
</style>
</head>
<body>
  <a class="logout" href="/logout">Logout</a>
  <div class="container">
    <h1>SiPyWeb Dashboard</h1>
    <div class="flex-row">
      <div class="flex-child">
        <h2>2FA Authenticator QR Code</h2>
        <div id="qr_code"></div>
        <p>Scan this with your Authenticator app (e.g. Google Authenticator)</p>
      </div>
      <div class="flex-child">
        <h2>Change Password</h2>
        <form id="change_password_form">
          <label for="old_password">Old Password</label>
          <input type="password" id="old_password" required />
          <label for="new_password">New Password</label>
          <input type="password" id="new_password" required minlength="6" />
          <label for="confirm_password">Confirm New Password</label>
          <input type="password" id="confirm_password" required minlength="6" />
          <button type="submit">Change Password</button>
          <div id="password_change_msg" class="msg"></div>
        </form>
      </div>
    </div>

    <h2>Server Logs</h2>
    <pre id="logs"></pre>
    <button id="download_logs">Download Logs</button>
    <button id="clear_logs">Clear Logs</button>

    <h2>System Info</h2>
    <pre id="system_info"></pre>

    <button id="restart_server">Restart Server (Simulated)</button>
    <div id="restart_msg" class="msg"></div>
  </div>

<script>
async function fetchQRCode() {
  const res = await fetch("/api/settings");
  if (!res.ok) return;
  const data = await res.json();
  const secret = data.totp_secret;
  if (!secret) return;

  const otpAuth = `otpauth://totp/SiPyWeb?secret=${secret}&issuer=SiPyWeb`;
  // Use Google Chart API to generate QR code for simplicity:
  const qrUrl = `https://chart.googleapis.com/chart?chs=180x180&chld=M|0&cht=qr&chl=${encodeURIComponent(otpAuth)}`;

  const qrDiv = document.getElementById("qr_code");
  qrDiv.innerHTML = `<img src="${qrUrl}" alt="Authenticator QR Code" />`;
}

async function fetchLogs() {
  const res = await fetch("/api/last_logs");
  if (!res.ok) return;
  const data = await res.json();
  document.getElementById("logs").textContent = data.logs || "";
  // Auto scroll to bottom
  const logsEl = document.getElementById("logs");
  logsEl.scrollTop = logsEl.scrollHeight;
}

async function downloadLogs() {
  const res = await fetch("/api/download_logs");
  if (!res.ok) {
    alert("Failed to download logs");
    return;
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "sipyweb.log";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function clearLogs() {
  if (!confirm("Clear all logs?")) return;
  const res = await fetch("/api/clear_logs", { method: "POST" });
  if (!res.ok) {
    alert("Failed to clear logs");
    return;
  }
  await fetchLogs();
}

async function fetchSystemInfo() {
  const res = await fetch("/api/system_info");
  if (!res.ok) return;
  const data = await res.json();
  const uptime = new Date(data.uptime_seconds * 1000).toISOString().substr(11, 8);
  document.getElementById("system_info").textContent =
    `Platform: ${data.platform}\n` +
    `Python: ${data.python_version}\n` +
    `Uptime: ${uptime}`;
}

document.getElementById("change_password_form").onsubmit = async e => {
  e.preventDefault();
  const old_password = document.getElementById("old_password").value;
  const new_password = document.getElementById("new_password").value;
  const confirm_password = document.getElementById("confirm_password").value;
  const res = await fetch("/api/change_password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ old_password, new_password, confirm_password })
  });
  const data = await res.json();
  const msgElem = document.getElementById("password_change_msg");
  if (data.success) {
    msgElem.style.color = "lightgreen";
    msgElem.textContent = "Password changed successfully.";
    document.getElementById("change_password_form").reset();
  } else {
    msgElem.style.color = "#ff5555";
    msgElem.textContent = data.error || "Failed to change password.";
  }
};

document.getElementById("download_logs").onclick = downloadLogs;
document.getElementById("clear_logs").onclick = clearLogs;

document.getElementById("restart_server").onclick = async () => {
  const res = await fetch("/api/restart", { method: "POST" });
  const data = await res.json();
  const msgElem = document.getElementById("restart_msg");
  if (data.success) {
    msgElem.style.color = "lightgreen";
    msgElem.textContent = data.message;
  } else {
    msgElem.style.color = "#ff5555";
    msgElem.textContent = data.error || "Failed to restart.";
  }
};

async function refreshDashboard() {
  await fetchQRCode();
  await fetchLogs();
  await fetchSystemInfo();
}
refreshDashboard();
setInterval(fetchLogs, 5000);
setInterval(fetchSystemInfo, 60000);
</script>

</body>
</html>
"""

# --- TKINTER GUI ---

class SiPyWebGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SiPyWeb Control Panel")
        self.root.geometry("400x480")
        self.root.configure(bg="#121212")

        self.label = tk.Label(root, text="SiPyWeb - Scan 2FA QR Code to Setup", fg="#00aaff", bg="#121212", font=("Segoe UI", 14, "bold"))
        self.label.pack(pady=10)

        self.qr_label = tk.Label(root, bg="#121212")
        self.qr_label.pack(pady=20)

        self.update_qr_code()

    def update_qr_code(self):
        secret = settings.get("totp_secret")
        if not secret:
            secret = pyotp.random_base32()
            settings["totp_secret"] = secret
            save_settings()
        otp_auth = pyotp.totp.TOTP(secret).provisioning_uri(name="SiPyWeb", issuer_name="SiPyWeb")
        qr = qrcode.make(otp_auth)
        qr = qr.resize((180, 180))
        self.img = ImageTk.PhotoImage(qr)
        self.qr_label.config(image=self.img)

# --- RUN FLASK APP ---

def run_flask():
    port = settings.get("port", 8000)
    log(f"Starting SiPyWeb Flask server on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

# --- MAIN ---

if __name__ == "__main__":
    root = tk.Tk()
    gui = SiPyWebGUI(root)
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    root.mainloop()
