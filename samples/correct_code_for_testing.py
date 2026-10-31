"""CORRECT / SECURE CODE - FOR TESTING AI-SENTINEL ONLY.
This is the secure counterpart to wrong_code_for_testing.py.
It does the same jobs (login, greet, ping, action, pay) with
secure patterns, so AI-Sentinel should report a clean scan.
"""
from flask import Flask, request, render_template
import sqlite3
import os
import re
import json
import secrets
import hashlib
import hmac
import subprocess

app = Flask(__name__)
SECRET_KEY = os.environ.get('SECRET_KEY')
API_KEY = os.environ.get('API_KEY')
ALLOWED_CALLBACK_PREFIX = 'https://example.com/'

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, password_hash FROM users WHERE username = ?",
        (username,)
    )
    user = cursor.fetchone()
    if user:
        salt = b'stored-per-user-salt'
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', password.encode(), salt, 100000
        )
        if hmac.compare_digest(password_hash, user[1]):
            token = secrets.token_hex(16)
            return render_template('welcome.html', username=username, token=token)
    return "Login failed"

@app.route('/greet')
def greet():
    name = request.args.get('name', 'guest')
    return render_template('greet.html', name=name)

@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    if not re.match(r'^[A-Za-z0-9.-]+$', host):
        return "Invalid host", 400
    result = subprocess.run(
        ['ping', '-c', '1', host],
        capture_output=True, text=True, timeout=5
    )
    if result.returncode == 0:
        return "Done"
    return "Ping failed", 400

@app.route('/action')
def action():
    chosen = request.args.get('action', '')
    if chosen == 'status':
        return "OK"
    return "Action not allowed", 400

@app.route('/pay', methods=['POST'])
def pay():
    card_token = request.form['card_token']
    token_hash = hashlib.sha256(card_token.encode()).hexdigest()
    otp_token = secrets.token_hex(4)
    callback_url = request.form.get('callback_url', '')
    if callback_url and not callback_url.startswith(ALLOWED_CALLBACK_PREFIX):
        return "Callback not allowed", 400
    data = request.form['data']
    obj = json.loads(data)
    if not isinstance(obj, dict):
        return "Invalid data", 400
    return render_template(
        'payment_success.html', token=token_hash, otp_token=otp_token
    )

if __name__ == '__main__':
    app.run(debug=False)
