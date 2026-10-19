import os
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

load_dotenv()
from analyzer import analyze
from ai_summary import summarize

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
app = Flask(__name__, static_folder=str(FRONTEND), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB
CORS(app)


@app.get("/")
def index():
    return send_from_directory(FRONTEND, "index.html")


@app.get("/api/health")
def health():
    return jsonify(status="ok", ai_enabled=bool(os.getenv("ANTHROPIC_API_KEY")))


@app.post("/api/analyze")
def analyze_route():
    if "file" in request.files:
        text = request.files["file"].read().decode("utf-8", errors="ignore")
    elif request.is_json:
        text = (request.get_json(silent=True) or {}).get("logs", "")
    else:
        text = request.form.get("logs", "")
    if not text.strip():
        return jsonify(error="No log data received. Upload a file or paste logs."), 400
    result = analyze(text)
    result["summary"] = summarize(result)
    return jsonify(result)


@app.get("/api/analyze-sample")
def analyze_sample():
    sample_path = Path(__file__).resolve().parent / "sample.log"

    if not sample_path.exists():
        return jsonify(error="sample.log not found in backend folder"), 404

    text = sample_path.read_text(encoding="utf-8", errors="ignore")
    result = analyze(text)
    result["summary"] = summarize(result)
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
