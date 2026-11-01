# AI Security Log Analyzer

**Live demo:** https://ai-security-log-backend.onrender.com

> Hosted on Render's free plan, so the first load after a period of inactivity can take 30 to 60 seconds while the server wakes up.

Upload or paste application/server security logs. The tool detects suspicious activity, summarizes incidents and recommends actions.


## What it detects

**Rule-based detection:** repeated login failures (brute force), successful login after many failures (possible account compromise), SQL injection, XSS, path traversal, scanner tools (sqlmap, nikto...), unusual request volume per IP, and endpoint probing (many 404s). Every incident includes the evidence lines, a severity and a recommended action.

**Machine learning:** an Isolation Forest model (scikit-learn) analyzes per-IP behavior (requests, failed logins, error responses, attack-pattern hits) and flags IPs that are unusual compared with the rest, including low-and-slow activity that stays below the rule thresholds. Findings are labeled "Anomalous behavior (ML)" with an anomaly score, and say whether the rules also caught that IP. The model needs at least 10 distinct IPs, so smaller logs skip it.

**AI summary (optional):** if `ANTHROPIC_API_KEY` is set, Claude writes the incident summary. Without a key, a rule-based summary is used, so the app works either way.

**Risk score:** a 0 to 100 score based on the severity of the incidents found.

## Tech stack
Python, Flask, scikit-learn, vanilla JavaScript, deployed on Render.

## Structure
```
backend/    Flask API (app.py, analyzer.py, ai_summary.py)
frontend/   Static UI (index.html, sample.log)
sample_logs/sample.log   Demo data
```

## Run locally
```bash
cd backend
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Optional: set the `ANTHROPIC_API_KEY` environment variable to enable AI-written summaries.

Open http://localhost:5000, click **Analyze sample logs**, or paste/upload your own logs and click **Analyze logs**.

## API
- `GET /api/health`
- `GET /api/analyze-sample` - analyzes the built-in sample log.
- `POST /api/analyze` - JSON body with `logs_b64` (base64-encoded log text) or `logs` (plain text), or a multipart `file`. Returns stats, incidents, top IPs, ML status and summary.

## Deployment note
The frontend base64-encodes log text before sending it. Logs full of attack strings (SQL injection, XSS) can be blocked by firewalls in front of the server with an HTTP 403, and encoding avoids that.

## Tuning
Thresholds (`BRUTE_THRESHOLD`, `RATE_THRESHOLD`, `NOT_FOUND_THRESHOLD`, `MIN_IPS_FOR_ML`, `ML_MIN_SCORE`) and regex rules are at the top of
