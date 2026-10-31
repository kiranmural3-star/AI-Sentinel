"""WRONG / VULNERABLE CODE - FOR TESTING AI-SENTINEL ONLY.
Do NOT use this in a real app or deploy it. Every flaw below is
intentional, so AI-Sentinel should flag it.
"""
from flask import Flask, request, render_template_string
import sqlite3
import os
import hashlib
import random
import pickle
import requests

app = Flask(__name__)
ADMIN_PASSWORD = "admin123"
API_KEY = "mysecretkey12345"

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        return f"<h1>Welcome {username}</h1>"
    return "Login failed"

@app.route('/greet')
def greet():
    name = request.args.get('name', 'guest')
    return render_template_string(f"<h1>Hello {name}</h1>")

@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    os.system("ping -c 1 " + host)
    return "Done"

@app.route('/run')
def run():
    cmd = request.args.get('cmd', '')
    eval(cmd)
    return "Done"

@app.route('/pay', methods=['POST'])
def pay():
    card_token = request.form['card_token']
    token_hash = hashlib.md5(card_token.encode()).hexdigest()
    otp = random.randint(1000, 9999)
    url = request.form['callback_url']
    requests.get(url)
    data = request.form['data']
    obj = pickle.loads(data.encode())
    filename = request.args.get('file', 'data.txt')
    f = open(filename)
    content = f.read()
    return "Payment processed"

if __name__ == '__main__':
    app.run(debug=True)
