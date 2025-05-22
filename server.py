import threading
import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import io
import qrcode
import pystray
from pystray import MenuItem as item
from flask import Flask, session, request, redirect, url_for, render_template_string, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
import base64
import time
import logging

# ========== Global shared state ==========
totp_secret_for_gui = None  # store TOTP secret globally for GUI access

# ========== Flask App Setup ==========
app = Flask(__name__)
app.secret_key = "supersecretkey"  # Replace with strong secret in prod

limiter = Limiter(app, key_func=get_remote_address)

# Basic in-memory user store (just one user for demo)
USERS = {
    "admin": {
        "password": "admin123",
        "totp_secret": None
    }
}

# ========== Flask Routes ==========

@app.route("/")
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    global totp_secret_for_gui
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = USERS.get(username)
        if not user or user["password"] != password:
            return render_template_string(LOGIN_HTML, error="Invalid username or password")
        # On first login, generate TOTP secret if none
        if not user["totp_secret"]:
            user["totp_secret"] = pyotp.random_base32()
        # Save secret globally for GUI
        totp_secret_for_gui = user["totp_secret"]
        session["username"] = username
        session["logged_in"] = True
        session["totp_secret"] = user["totp_secret"]
        session["totp_verified"] = False
        return redirect(url_for("two_factor"))
    return render_template_string(LOGIN_HTML, error=None)

@app.route("/two_factor", methods=["GET", "POST"])
def two_factor():
    if not session.get("logged_in") or not session.get("totp_secret"):
        return redirect(url_for("login"))
    if request.method == "POST":
        token = request.form.get("token")
        totp = pyotp.TOTP(session["totp_secret"])
        if totp.verify(token):
            session["totp_verified"] = True
            return redirect(url_for("dashboard"))
        else:
            return render_template_string(TWO_FACTOR_HTML, error="Invalid authentication code", qr_code=generate_qr_code(session["totp_secret"]))
    # On GET show QR code and form
    return render_template_string(TWO_FACTOR_HTML, error=None, qr_code=generate_qr_code(session["totp_secret"]))

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in") or not session.get("totp_verified"):
        return redirect(url_for("login"))
    # Modern dark mode dashboard HTML
    return render_template_string(DASHBOARD_HTML, username=session.get("username"))

@app.route("/logout")
def logout():
    global totp_secret_for_gui
    totp_secret_for_gui = None
    session.clear()
    return redirect(url_for("login"))

@app.route("/api/totp_secret")
def get_totp_secret():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"totp_secret": session.get("totp_secret")})

# ========== Helper functions ==========

def generate_qr_code(secret):
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri("SiPyWeb User", issuer_name="SiPyWeb")
    qr = qrcode.make(otp_uri)
    bio = io.BytesIO()
    qr.save(bio, format="PNG")
    bio.seek(0)
    return base64.b64encode(bio.read()).decode()

# ========== HTML Templates ==========

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>SiPyWeb Login</title>
<style>
body { background:#121212; color:#eee; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display:flex; height:100vh; justify-content:center; align-items:center; }
form { background:#1e1e1e; padding:2rem; border-radius:8px; box-shadow:0 0 15px #000; width:300px; }
input { width:100%; margin:10px 0; padding:10px; border:none; border-radius:4px; background:#333; color:#eee; }
button { width:100%; padding:10px; background:#0af; border:none; border-radius:4px; color:#fff; font-weight:bold; cursor:pointer; }
.error { color:#f55; font-weight:bold; }
</style>
</head>
<body>
<form method="POST">
<h2>SiPyWeb Login</h2>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<input type="text" name="username" placeholder="Username" required autofocus />
<input type="password" name="password" placeholder="Password" required />
<button type="submit">Login</button>
</form>
</body>
</html>
"""

TWO_FACTOR_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>SiPyWeb 2FA</title>
<style>
body { background:#121212; color:#eee; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; display:flex; height:100vh; justify-content:center; align-items:center; flex-direction:column; }
form { background:#1e1e1e; padding:2rem; border-radius:8px; box-shadow:0 0 15px #000; width:300px; text-align:center;}
input { width:100%; margin:10px 0; padding:10px; border:none; border-radius:4px; background:#333; color:#eee; }
button { width:100%; padding:10px; background:#0af; border:none; border-radius:4px; color:#fff; font-weight:bold; cursor:pointer; }
.error { color:#f55; font-weight:bold; margin-bottom: 10px; }
img { margin-top: 15px; }
</style>
</head>
<body>
<h2>Two-Factor Authentication</h2>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="POST">
<input type="text" name="token" placeholder="Enter authentication code" autocomplete="off" required autofocus />
<button type="submit">Verify</button>
</form>
{% if qr_code %}
<img src="data:image/png;base64,{{ qr_code }}" alt="Authenticator QR Code" />
{% endif %}
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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap');
body {
    margin: 0;
    font-family: 'Inter', sans-serif;
    background: #121212;
    color: #eee;
}
header {
    background: #1f1f1f;
    padding: 1rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 1px 5px #0009;
}
h1 {
    font-weight: 700;
    font-size: 1.8rem;
}
main {
    padding: 2rem;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.5rem;
}
.card {
    background: #1e1e1e;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px #0008;
    transition: background 0.3s ease;
}
.card:hover {
    background: #272727;
}
.card h2 {
    margin-top: 0;
    font-weight: 700;
    font-size: 1.2rem;
}
.card p {
    margin-bottom: 0;
    color: #bbb;
}
button.logout {
    background: #f33;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    color: #fff;
    font-weight: 700;
    cursor: pointer;
    transition: background 0.3s ease;
}
button.logout:hover {
    background: #d00;
}
footer {
    text-align: center;
    padding: 1rem;
    color: #666;
    font-size: 0.9rem;
    margin-top: 2rem;
}
</style>
</head>
<body>
<header>
    <h1>SiPyWeb Dashboard</h1>
    <form action="{{ url_for('logout') }}" method="get" style="margin:0;">
        <button type="submit" class="logout">Logout</button>
    </form>
</header>
<main>
    <div class="card">
        <h2>Welcome, {{ username }}</h2>
        <p>Secure Web Server Control Panel</p>
    </div>
    <div class="card">
        <h2>Server Status</h2>
        <p>Running smoothly</p>
    </div>
    <div class="card">
        <h2>Features</h2>
        <ul>
            <li>Super fast & optimized</li>
            <li>2FA Authentication</li>
            <li>Rate Limiting</li>
            <li>QR Code for easy phone setup</li>
            <li>Dark mode UI</li>
            <li>Background tray app</li>
        </ul>
    </div>
</main>
<footer>
    &copy; 2025 SiPyWeb — Made Modern & Secure
</footer>
</body>
</html>
"""

# ========== Tkinter GUI with pystray ==========

class SiPyWebGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SiPyWeb Control Panel")
        self.root.geometry("400x500")
        self.root.configure(bg="#121212")

        self.qr_label = tk.Label(self.root, bg="#121212")
        self.qr_label.pack(pady=20)

        self.status_label = tk.Label(self.root, text="Waiting for 2FA setup...", fg="#eee", bg="#121212", font=("Segoe UI", 12))
        self.status_label.pack(pady=10)

        # Start update loop for QR code
        self.update_qr_code()

        # Setup system tray icon
        self.setup_systray()

    def update_qr_code(self):
        global totp_secret_for_gui
        secret = totp_secret_for_gui
        if secret:
            img = self.generate_qr_image(secret)
            self.qr_label.configure(image=img)
            self.qr_label.image = img
            self.status_label.config(text="Scan the QR code with your Authenticator app.")
        else:
            self.qr_label.configure(image="")
            self.status_label.config(text="No TOTP secret available.")

        # Refresh every 60 seconds
        self.root.after(60000, self.update_qr_code)

    def generate_qr_image(self, secret):
        otp_uri = pyotp.totp.TOTP(secret).provisioning_uri("SiPyWeb User", issuer_name="SiPyWeb")
        qr = qrcode.make(otp_uri)
        qr = qr.resize((200, 200))
        img = ImageTk.PhotoImage(qr)
        return img

    def setup_systray(self):
        menu = (
            item('Show', self.show_window),
            item('Exit', self.exit_app)
        )
        self.icon = pystray.Icon("SiPyWeb", icon=self.get_icon_image(), title="SiPyWeb Control", menu=menu)
        threading.Thread(target=self.icon.run, daemon=True).start()

    def get_icon_image(self):
        # Simple blank icon fallback
        img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
        return img

    def show_window(self, _):
        self.root.after(0, self.root.deiconify)

    def exit_app(self, _):
        self.icon.stop()
        self.root.after(0, self.root.destroy)

# ========== Main ==========

def main():
    logging.basicConfig(level=logging.INFO)
    print("[INFO] Starting SiPyWeb Flask server on port 8000")
    threading.Thread(target=lambda: app.run(port=8000, debug=False, use_reloader=False), daemon=True).start()

    root = tk.Tk()
    gui = SiPyWebGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
