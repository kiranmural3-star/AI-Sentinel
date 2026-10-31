# AI-Sentinel — Project Plan

## Title
AI-Sentinel: Context-Aware Security Analysis and Risk Prioritization of AI-Generated Software

## Problem (in one line)
AI tools write code fast, but that code often contains hidden security flaws.
Existing scanners flag everything equally, so developers waste time on low-risk
issues and miss the dangerous ones. AI-Sentinel fixes the ranking, not just
the finding.

## What it does
1. Takes Python code (paste, upload a file, or try a built-in sample).
2. Finds real vulnerabilities with AST parsing + pattern checks.
3. Understands context: is the code reachable from a public route? Does
   user input flow into the dangerous call? Does it handle passwords,
   payments or personal data? Is there any login check?
4. Gives every finding a 0–10 risk score and sorts Critical first, with
   a plain-language reason and a secure fix for each issue.
5. Shows an overall security score (0–100) and grade, plus a summary
   a reviewer can act on in minutes.

## What it does NOT do
- It does not detect whether code was written by AI or by a human.
  It assumes the input is AI-generated and checks it.
- It does not train a new LLM, and it does not replace Bandit/Semgrep.
  In a full version those tools can be plugged in as extra scanners.

## Architecture
```
User code
   ↓
[1] Parser        — Python ast + line text, collects routes, functions,
                    assignments, decorators
   ↓
[2] Scanners      — SQLi, command injection, eval/exec, XSS,
                    hardcoded secrets, weak crypto, insecure random,
                    pickle/YAML deserialization, path traversal, SSRF,
                    debug mode, sensitive route without auth
   ↓
[3] Context engine — taint tracking (source → variable → sink),
                    route detection, auth detection, sensitive-data
                    detection, deployment context from the UI
   ↓
[4] Risk scorer   — Risk = base severity, adjusted by taint (+),
                    public route (+), sensitive data (+),
                    not reachable (−). Clamped to 0–10.
   ↓
[5] Report UI     — sorted findings, score ring, counts, code snippet,
                    why-this-score, secure fix
```

## Risk scoring (example)
Base: Critical 9.0, High 7.5, Medium 5.0, Low 2.5
- +1.5 if user input actually reaches the sink (tainted flow)
- +0.8 if it is on a public route with no login check
- +0.7 if it handles sensitive data
- +0.5 if deployment is a public API
- −1.0 if deployment is an internal tool
- −1.5 if the flaw is not reachable from any route/input

Levels: 9.0+ Critical, 7.0+ High, 4.0+ Medium, otherwise Low.
Same bug, different context, different priority — that is the demo.

## Tech stack
- Backend: Python 3.12, Flask 3 (only dependency)
- Analysis: Python `ast` + `re` only, no paid APIs, works offline
- Frontend: HTML + CSS + vanilla JavaScript, no build step
- Storage: none needed for the MVP (scans are stateless; history
  is kept in the browser only)

## Build order (what was actually built)
1. Analyzer engine (`analyzer.py`) — scanners + context + scoring
2. Flask app (`app.py`) — one page + `/api/analyze` JSON endpoint
3. UI (`templates/index.html`, `static/`) — editor, context controls,
   samples, score ring, sorted findings with fixes
4. Samples — vulnerable login, XSS/command injection, payment SSRF,
   and one fully secure version that should score clean
5. Test — run all samples through the API and check the ranking

## 8-week plan (for a report)
- Weeks 1–2: Literature survey (SAST, taint analysis, CVSS, AI-code
  security studies), scope to Python, collect test snippets
- Weeks 3–4: Parser + scanners + taint tracking
- Weeks 5–6: Context engine + risk scorer + UI
- Week 7: Evaluation — your tool vs a plain scanner on 30–40 labelled
  snippets: false positives, ranking quality, time saved
- Week 8: Report, demo video/screenshots, future work

## Evaluation idea
Build a labelled set (e.g. 20 vulnerable + 20 safe snippets generated
with an AI tool, hand-checked). Report: findings found, false positives,
and how many Critical issues a plain scanner would have buried under
Medium/Low noise. That comparison is the strongest result for this title.

## Future work
- JavaScript/TypeScript support, multi-file project upload
- Plug in Bandit and Semgrep as additional scanners
- Dependency scanning (pip-audit) and secret scanning
- GitHub repo import, CI check, and LLM-generated fix suggestions
  (local Ollama, so code never leaves the machine)

## How to run
```
cd ai-sentinel
./run.sh
# open http://127.0.0.1:5000
```
First run creates a virtual environment and installs Flask automatically.
