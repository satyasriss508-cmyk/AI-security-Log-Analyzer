"""Rule-based detection engine for server/application security logs."""
import re
from collections import Counter, defaultdict
from urllib.parse import unquote_plus

IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
STATUS_RE = re.compile(r'"\s*(\d{3})\s')
FAIL_RE = re.compile(r"failed password|authentication failure|invalid user|login failed|failed login|invalid credentials|unauthorized|\s401\s", re.I)
OK_RE = re.compile(r"accepted password|accepted publickey|login successful|successful login|logged in", re.I)
USER_RE = re.compile(r"(?:for|user|username)[=\s]+(?:invalid user\s+)?([\w.@-]+)", re.I)

SQLI_RE = re.compile(
    r"(union\s+(all\s+)?select|(?:'|\")\s*(or|and)\s+['\"\d]|\bor\s+1\s*=\s*1|;\s*drop\s+table|"
    r"information_schema|sleep\s*\(|benchmark\s*\(|xp_cmdshell|load_file\s*\(|'\s*--)", re.I)
XSS_RE = re.compile(r"<script|onerror\s*=|onload\s*=|javascript:|<img[^>]+src", re.I)
TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|cmd\.exe", re.I)
SCANNER_RE = re.compile(r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|hydra", re.I)

BRUTE_THRESHOLD = 5
RATE_THRESHOLD = 100
NOT_FOUND_THRESHOLD = 15
ML_MIN_SCORE = 0.70  # only report clearly unusual IPs (0.5 is the model's own, much looser, cutoff)
MIN_IPS_FOR_ML = 10  # Isolation Forest needs enough IPs to learn what normal looks like

RECOMMENDATIONS = {
    "Brute-force login attempt": "Block or rate-limit the IP, enforce account lockout and MFA, and reset passwords of targeted accounts.",
    "Possible account compromise": "Treat the account as compromised: force logout, reset credentials, review activity after the successful login.",
    "SQL injection attempt": "Block the IP at the WAF, use parameterized queries, validate input, and check DB logs for data exposure.",
    "Cross-site scripting (XSS) attempt": "Apply output encoding and a Content-Security-Policy; sanitize user input.",
    "Path traversal attempt": "Normalize and validate file paths, run the app with least privilege, and block the source IP.",
    "Scanner / attack tool detected": "Block the IP and user-agent; confirm no sensitive endpoints were exposed.",
    "Unusual request volume": "Apply rate limiting; check for DoS or scraping; consider a CDN/WAF challenge.",
    "Anomalous behavior (ML)": "Review this IP's requests in full. It behaves very differently from the other clients; block or rate-limit it if it is not a known client.",
    "Endpoint probing (many 404s)": "Likely directory enumeration. Block or throttle the IP and remove unused endpoints.",
}
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEV_WEIGHT = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
def ml_anomalies(per_ip, hits):
    """Isolation Forest over per-IP behavior. Returns (top findings, status for the UI)."""
    ips = [ip for ip in per_ip if ip != "unknown"]
    status = {"method": "Isolation Forest", "ips_analyzed": len(ips), "flagged": 0, "state": "ran"}
    if len(ips) < MIN_IPS_FOR_ML:
        status["state"] = f"skipped: needs at least {MIN_IPS_FOR_ML} IPs"
        return [], status
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except ImportError:
        status["state"] = "unavailable: scikit-learn is not installed"
        return [], status

    rows = []
    for ip in ips:
        d = per_ip[ip]
        events = sum(len(by_ip[ip]) for by_ip in hits.values() if ip in by_ip)
        kinds = sum(1 for by_ip in hits.values() if ip in by_ip)
        rows.append([d["requests"], d["fails"], d["404"], d["errors"], events, kinds])

    X = np.log1p(np.array(rows, dtype=float))
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42).fit(X)
    scores = -model.score_samples(X)  # higher = more unusual

    found = []
    for ip, row, sc in zip(ips, rows, scores):
        # Also require real bad behavior (2+ failed logins, 3+ error responses, or any attack pattern),
        # so a busy client, or one with a single harmless 404, is never flagged.
        if sc >= ML_MIN_SCORE and (row[1] >= 2 or row[3] >= 3 or row[4] >= 1):
            found.append((float(sc), ip, row))
    found.sort(reverse=True)
    found = found[:5]
    status["flagged"] = len(found)
    return found, status


def analyze(text: str) -> dict:
    lines = [l for l in text.splitlines() if l.strip()]
    per_ip = defaultdict(lambda: {"requests": 0, "fails": 0, "ok": 0, "404": 0, "errors": 0, "users": Counter()})
    hits = defaultdict(lambda: defaultdict(list))  # attack type -> ip -> evidence lines
    status_counts = Counter()

    for line in lines:
        m = IP_RE.search(line)
        ip = m.group(1) if m else "unknown"
        d = per_ip[ip]
        d["requests"] += 1
        decoded = unquote_plus(line)

        s = STATUS_RE.search(line)
        if s:
            status_counts[s.group(1)] += 1
            if s.group(1) == "404":
                d["404"] += 1
            if int(s.group(1)) >= 400:
                d["errors"] += 1

        if FAIL_RE.search(line):
            d["fails"] += 1
            u = USER_RE.search(line)
            if u:
                d["users"][u.group(1)] += 1
        if OK_RE.search(line):
            d["ok"] += 1
            if d["fails"] >= BRUTE_THRESHOLD:
                hits["Possible account compromise"][ip].append(line)

        for name, rx in (("SQL injection attempt", SQLI_RE), ("Cross-site scripting (XSS) attempt", XSS_RE),
                         ("Path traversal attempt", TRAVERSAL_RE), ("Scanner / attack tool detected", SCANNER_RE)):
            if rx.search(decoded):
                hits[name][ip].append(line)

    incidents = []

    def add(kind, sev, ip, count, evidence):
        incidents.append({"type": kind, "severity": sev, "ip": ip, "count": count,
                          "evidence": [e[:220] for e in evidence[:3]], "recommendation": RECOMMENDATIONS[kind]})

    for ip, d in per_ip.items():
        if d["fails"] >= BRUTE_THRESHOLD:
            users = ", ".join(u for u, _ in d["users"].most_common(5)) or "n/a"
            add("Brute-force login attempt", "High", ip, d["fails"], [f"{d['fails']} failed logins; targeted users: {users}"])
        if d["requests"] >= RATE_THRESHOLD:
            add("Unusual request volume", "Medium", ip, d["requests"], [f"{d['requests']} requests from one IP"])
        if d["404"] >= NOT_FOUND_THRESHOLD:
            add("Endpoint probing (many 404s)", "Medium", ip, d["404"], [f"{d['404']} 'not found' responses"])

    sev = {"Possible account compromise": "Critical", "SQL injection attempt": "High",
           "Path traversal attempt": "High", "Cross-site scripting (XSS) attempt": "Medium",
           "Scanner / attack tool detected": "Medium"}
    for kind, by_ip in hits.items():
        for ip, ev in by_ip.items():
            add(kind, sev[kind], ip, len(ev), ev)

    # Machine learning: find IPs whose behavior is unusual compared with the rest
    rule_ips = {i["ip"] for i in incidents}
    ml_found, ml_status = ml_anomalies(per_ip, hits)
    for sc, ip, (reqs, fails, nf, errors, events, kinds) in ml_found:
        note = "Also flagged by detection rules." if ip in rule_ips else "Not caught by any rule: review manually."
        add("Anomalous behavior (ML)", "Medium", ip, reqs, [
            f"Anomaly score {round(sc * 100)}/100. Requests {reqs}, failed logins {fails}, "
            f"error responses {errors}, attack-pattern events {events}.", note])

    incidents.sort(key=lambda i: (SEVERITY_ORDER[i["severity"]], -i["count"]))
    top_ips = [{"ip": ip, "requests": d["requests"], "failed_logins": d["fails"]}
               for ip, d in sorted(per_ip.items(), key=lambda x: -x[1]["requests"])[:10]]

    return {
        "stats": {"total_lines": len(lines), "unique_ips": len(per_ip), "incidents": len(incidents),
                  "by_severity": dict(Counter(i["severity"] for i in incidents)), "status_codes": dict(status_counts)},
        "incidents": incidents,
        "top_ips": top_ips,
        "ml": ml_status,
    }


def rule_based_summary(result: dict) -> str:
    inc, st = result["incidents"], result["stats"]
    head = f"Analyzed {st['total_lines']} log lines from {st['unique_ips']} unique IPs."
    if not inc:
        return head + " No suspicious activity detected.\nOverall risk level: None."

    levels = {i["severity"] for i in inc}
    risk = next(l for l in ("Critical", "High", "Medium", "Low") if l in levels)

    score, kinds = defaultdict(int), defaultdict(list)
    for i in inc:
        score[i["ip"]] += SEV_WEIGHT[i["severity"]]
        if i["type"] not in kinds[i["ip"]]:
            kinds[i["ip"]].append(i["type"])
    top = sorted(score, key=score.get, reverse=True)[:3]

    actions = []
    for i in inc:
        if i["recommendation"] not in actions:
            actions.append(i["recommendation"])
    actions = actions[:5]

    types = Counter(i["type"] for i in inc)
    lines = [
        f"OVERALL RISK LEVEL: {risk}",
        f"{head} Found {len(inc)} incident(s): " + ", ".join(f"{n}x {t}" for t, n in types.items()) + ".",
        "",
        "Most dangerous IPs:",
        *[f"- {ip}: {', '.join(kinds[ip])}" for ip in top],
        "",
        "Recommended actions, in priority order:",
        *[f"{n}. {a}" for n, a in enumerate(actions, 1)],
    ]
    return "\n".join(lines)
