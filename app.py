import os
import hashlib
import sqlite3
import datetime
from flask import Flask, request, render_template_string, Response, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
# Rate limit to slow automated spikes (adjust as needed)
limiter = Limiter(app, key_func=get_remote_address, default_limits=["60 per minute"])

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "change_me")

def init_db():
    conn = sqlite3.connect('honeypot_logs.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  password_hash TEXT,
                  ip TEXT,
                  time TEXT)''')
    conn.commit()
    conn.close()

init_db()

login_html = """
<!doctype html>
<title>Secure Portal</title>
<h1>Secure Portal</h1>
<form method="post">
  Username: <input name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
"""

@limiter.limit("30/minute")
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        ip = request.remote_addr or 'unknown'
        time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        # Hash the password before storing (do NOT store plain text)
        pw_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        conn = sqlite3.connect('honeypot_logs.db')
        c = conn.cursor()
        c.execute("INSERT INTO logs (username, password_hash, ip, time) VALUES (?, ?, ?, ?)",
                  (username, pw_hash, ip, time))
        conn.commit()
        conn.close()

        return "Login failed! (recorded for security purposes)"
    return render_template_string(login_html)

def check_auth():
    auth = request.authorization
    return auth and auth.username == ADMIN_USER and auth.password == ADMIN_PASS

@app.route('/view-logs')
def view_logs():
    # Basic HTTP auth protect this page
    if not check_auth():
        return Response('Login required', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

    conn = sqlite3.connect('honeypot_logs.db')
    c = conn.cursor()
    c.execute("SELECT id, username, password_hash, ip, time FROM logs ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()

    # simple HTML table for viewing
    html = "<h2>Honeypot Logs</h2><table border=1 cellpadding=4><tr><th>ID</th><th>User</th><th>Pw hash</th><th>IP</th><th>Time (UTC)</th></tr>"
    for r in rows:
        html += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td style='font-family:monospace'>{r[2]}</td><td>{r[3]}</td><td>{r[4]}</td></tr>"
    html += "</table>"
    return html

if __name__ == "__main__":
    # for local testing only
    app.run(host="0.0.0.0", port=5000, debug=False)
