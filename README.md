# AI Security Log Analyzer

Upload or paste application/server security logs. The tool detects suspicious activity, summarizes incidents and recommends actions.

**Detects:** repeated login failures (brute force), successful login after many failures (possible compromise), SQL injection, XSS, path traversal, scanner tools (sqlmap, nikto...), unusual request volume per IP, and endpoint probing (many 404s).

**AI summary:** if `ANTHROPIC_API_KEY` is set, Claude writes the incident summary. Without a key, a rule-based summary is used, so the app works either way.

## Structure
```
backend/    Flask API (app.py, analyzer.py, ai_summary.py)
frontend/   Static UI (index.html, sample.log)
sample_logs/sample.log   Demo data
```

## Run
```bash
cd backend
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # optional: add ANTHROPIC_API_KEY
python app.py
```
Open http://localhost:5000, click **Load sample logs**, then **Analyze logs**.

## API
- `GET /api/health`
- `POST /api/analyze` - multipart `file`, or form/JSON field `logs`. Returns stats, incidents, top IPs and summary.

## Tuning
Thresholds (`BRUTE_THRESHOLD`, `RATE_THRESHOLD`, `NOT_FOUND_THRESHOLD`) and regex rules are at the top of `backend/analyzer.py`.
