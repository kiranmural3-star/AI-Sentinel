"""AI-Sentinel web app: paste or upload Python code, get a ranked report."""
import os
from flask import Flask, jsonify, render_template, request

from analyzer import analyze_code
from fixer import fix_code

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")
    if not code.strip():
        return jsonify({"error": "No code provided. Paste some Python code first."}), 400
    ui_ctx = {
        "deployment": data.get("deployment", "public_api"),
        "sensitive_data": bool(data.get("sensitive_data", False)),
    }
    result = analyze_code(code, ui_ctx)
    return jsonify(result)


@app.route("/api/fix", methods=["POST"])
def api_fix():
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")
    if not code.strip():
        return jsonify({"error": "No code provided. Paste some Python code first."}), 400
    ui_ctx = {
        "deployment": data.get("deployment", "public_api"),
        "sensitive_data": bool(data.get("sensitive_data", False)),
    }
    fixed, changes = fix_code(code)
    return jsonify({
        "fixed_code": fixed,
        "changes": changes,
        "original": analyze_code(code, ui_ctx),
        "fixed": analyze_code(fixed, ui_ctx),
    })


@app.route("/api/samples")
def api_samples():
    out = {}
    samples_dir = os.path.join(BASE, "samples")
    if os.path.isdir(samples_dir):
        for name in sorted(os.listdir(samples_dir)):
            if name.endswith(".py"):
                with open(os.path.join(samples_dir, name), encoding="utf-8") as f:
                    out[name] = f.read()
    return jsonify(out)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    # 0.0.0.0, not 127.0.0.1, so Render (and other hosts) can reach it
    app.run(host="0.0.0.0", port=port, debug=False)
