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

RECOMMENDATIONS = {
    "Brute-force login attempt": "Block or rate-limit the IP, enforce account lockout and MFA, and reset passwords of targeted accounts.",
    "Possible account compromise": "Treat the account as compromised: force logout, reset credentials, review activity after the successful login.",
    "SQL injection attempt": "Block the IP at the WAF, use parameterized queries, validate input, and check DB logs for data exposure.",
    "Cross-site scripting (XSS) attempt": "Apply output encoding and a Content-Security-Policy; sanitize user input.",
    "Path traversal attempt": "Normalize and validate file paths, run the app with least privilege, and block the source IP.",
    "Scanner / attack tool detected": "Block the IP and user-agent; confirm no sensitive endpoints were exposed.",
    "Unusual request volume": "Apply rate limiting; check for DoS or scraping; consider a CDN/WAF challenge.",
    "Endpoint probing (many 404s)": "Likely directory enumeration. Block or throttle the IP and remove unused endpoints.",
}
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def analyze(text: str) -> dict:
    lines = [l for l in text.splitlines() if l.strip()]
    per_ip = defaultdict(lambda: {"requests": 0, "fails": 0, "ok": 0, "404": 0, "users": Counter()})
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

    incidents.sort(key=lambda i: (SEVERITY_ORDER[i["severity"]], -i["count"]))
    top_ips = [{"ip": ip, "requests": d["requests"], "failed_logins": d["fails"]}
               for ip, d in sorted(per_ip.items(), key=lambda x: -x[1]["requests"])[:10]]

    return {
        "stats": {"total_lines": len(lines), "unique_ips": len(per_ip), "incidents": len(incidents),
                  "by_severity": dict(Counter(i["severity"] for i in incidents)), "status_codes": dict(status_counts)},
        "incidents": incidents,
        "top_ips": top_ips,
    }


def rule_based_summary(result: dict) -> str:
    inc, st = result["incidents"], result["stats"]
    if not inc:
        return f"Analyzed {st['total_lines']} log lines from {st['unique_ips']} IPs. No suspicious activity detected."
    types = Counter(i["type"] for i in inc)
    worst = inc[0]
    return (f"Analyzed {st['total_lines']} log lines from {st['unique_ips']} IPs and found {len(inc)} incident(s). "
            "Breakdown: " + ", ".join(f"{n}x {t}" for t, n in types.items()) + ". "
            f"Highest priority: {worst['severity']} - {worst['type']} from {worst['ip']}. {worst['recommendation']}")
