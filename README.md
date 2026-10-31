# AI-Sentinel

Context-aware security analysis and risk prioritization of AI-generated software.

Paste Python code (or try the built-in samples) and get a ranked report:
what the flaw is, why it scores that high, what context made it worse,
and how to fix it securely.

## Run it

```
cd ai-sentinel
./run.sh
# open http://127.0.0.1:5000
```

The first run creates a virtual environment (`.venv`) and installs Flask.

## Try these samples first

- **Vulnerable login** — SQL injection + hardcoded secret + debug mode
- **XSS + command injection** — template injection, `os.system`, `eval`
- **Payment SSRF** — SSRF, MD5, insecure random, pickle, exposed key
- **Secure example** — parameterized queries, `secrets`, env secrets,
  template rendering, debug off — should come back clean

Change the Deployment dropdown from Public API to Internal tool on the
same sample and watch the risk scores drop. That is the context-aware
part working.

## Files

- `analyzer.py` — scanners, taint tracking, context engine, risk scorer
- `app.py` — Flask app, `/` page and `/api/analyze` endpoint
- `templates/index.html`, `static/style.css`, `static/app.js` — UI
- `samples/` — 4 labelled Python examples
- `PLAN.md` — full project plan, architecture and 8-week timeline
