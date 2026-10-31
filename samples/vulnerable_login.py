from flask import Flask, request
import sqlite3

app = Flask(__name__)
ADMIN_PASSWORD = "admin123"

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

if __name__ == '__main__':
    app.run(debug=True)
