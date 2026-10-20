# AI Security Log Analyzer

**Live demo:** https://ai-security-log-backend.onrender.com

> Hosted on Render's free plan, so the first load after a period of inactivity can take 30 to 60 seconds while the server wakes up.

Upload or paste application/server security logs. The tool detects suspicious activity, summarizes incidents and recommends actions.

**Detects:** repeated login failures (brute force), successful login after many failures (possible compromise), SQL injection, XSS, path traversal, scanner tools (sqlmap, nikto...), unusual request volume per IP, and endpoint probing (many 404s).

**AI summary:** if `ANTHROPIC_API_KEY` is set, Claude writes the incident summary. Without a key, a rule-based summary is used, so the app works either way.

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
- `POST /api/analyze` - JSON body with `logs_b64` (base64-encoded log text) or `logs` (plain text), or a multipart `file`. Returns stats, incidents, top IPs and summary.

## Deployment note
The frontend base64-encodes log text before sending it. Logs full of attack strings (SQL injection, XSS) can be blocked by firewalls in front of the server with an HTTP 403, and encoding avoids that.

## Tuning
Thresholds (`BRUTE_THRESHOLD`, `RATE_THRESHOLD`, `NOT_FOUND_THRESHOLD`) and regex rules are at the top of `backend/analyzer.py`.
