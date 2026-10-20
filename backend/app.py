import base64
import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

load_dotenv()
from analyzer import analyze
from ai_summary import summarize

BASE = Path(__file__).resolve().parent
FRONTEND = BASE.parent / "frontend"
SAMPLE_CANDIDATES = [
    BASE.parent / "sample_logs" / "sample.log",
    BASE / "sample_logs" / "sample.log",
    FRONTEND / "sample.log",
]

app = Flask(__name__, static_folder=str(FRONTEND), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB
CORS(app)


def run_analysis(text: str):
    result = analyze(text)
    result["summary"] = summarize(result)
    return jsonify(result)


@app.get("/")
def index():
    if (FRONTEND / "index.html").exists():
        return send_from_directory(FRONTEND, "index.html")
    return jsonify(status="ok", service="AI Security Log Analyzer API")


@app.get("/api/health")
def health():
    return jsonify(status="ok", ai_enabled=bool(os.getenv("ANTHROPIC_API_KEY")))


@app.get("/api/analyze-sample")
def analyze_sample():
    for path in SAMPLE_CANDIDATES:
        if path.exists():
            return run_analysis(path.read_text(encoding="utf-8", errors="ignore"))
    return jsonify(error="Sample log file not found on the server."), 404


@app.post("/api/analyze")
def analyze_route():
    if "file" in request.files:
        text = request.files["file"].read().decode("utf-8", errors="ignore")
    elif request.is_json:
        data = request.get_json(silent=True) or {}
        if data.get("logs_b64"):
            try:
                text = base64.b64decode(data["logs_b64"]).decode("utf-8", errors="ignore")
            except Exception:
                return jsonify(error="Invalid encoded log data."), 400
        else:
            text = data.get("logs", "")
    else:
        text = request.form.get("logs", "")

    if not text.strip():
        return jsonify(error="No log data received. Upload a file or paste logs."), 400
    return run_analysis(text)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
