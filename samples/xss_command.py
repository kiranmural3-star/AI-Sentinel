from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

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
