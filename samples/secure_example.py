from flask import Flask, request, render_template
import sqlite3
import os
import secrets
import hashlib

app = Flask(__name__)
SECRET_KEY = os.environ.get('SECRET_KEY')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    )
    user = cursor.fetchone()
    if user:
        token = secrets.token_hex(16)
        digest = hashlib.sha256(password.encode()).hexdigest()
        return render_template('welcome.html', username=username, token=token)
    return "Login failed"

if __name__ == '__main__':
    app.run(debug=False)
