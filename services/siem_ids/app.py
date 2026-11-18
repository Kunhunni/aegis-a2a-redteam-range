import re
import secrets
import datetime
from typing import List, Dict, Any, Optional
from collections import deque
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

app = FastAPI(
    title="AEGIS-A2A SIEM Sentinel (ELK Replacement)",
    description="Real-time 22-Rule A2A Detection Engine & Telemetry Dashboard",
    version="1.0.0"
)
security = HTTPBasic()

# Course Credentials: User: elastic | Password: yfo60Vbmmzp2cdoNtbvL
SIEM_USER = "elastic"
SIEM_PASS = "yfo60Vbmmzp2cdoNtbvL"

TRUSTED_INTERNAL_IPS = {
    "127.0.0.1", "localhost", "::1",
    "172.28.0.1", "172.28.0.10", "172.28.0.20",
    "172.28.0.21", "172.28.0.22", "172.28.0.23", "172.28.0.30"
}
TRUSTED_TLS_FINGERPRINTS = {"sha256:trusted-a2a-default-fingerprint-01"}
APPROVED_DNS_SERVERS = {"127.0.0.11", "8.8.8.8", "192.168.50.1"}

# In-memory sliding windows for behavioral rules
EVENT_LOGS: deque = deque(maxlen=500)
TRIGGERED_ALERTS: deque = deque(maxlen=500)
RECENT_ENUM_TIMESTAMPS: List[float] = []
RECENT_REG_CAPABILITIES: List[Dict[str, Any]] = []
RECENT_DNS_QUERIES: List[float] = []

# All 22 Detection Rules from Table 1
SIEM_RULES = [
    {"id": "RULE-01", "name": "A2A Agent Response Content Differs from Baseline", "trigger": "Logs show routing to non-standard IPs (not internal or localhost)"},
    {"id": "RULE-02", "name": "A2A Enumeration Followed by Suspicious Activity", "trigger": "Multiple agent.json or endpoint registration events within short time window"},
    {"id": "RULE-03", "name": "Source Document Enumeration Attempt", "trigger": "Queries attempting to list documents, sources, or internal files"},
    {"id": "RULE-04", "name": "A2A Agent Registration Outside Business Hours", "trigger": "Agent registration events occurring outside 6 AM – 8 PM"},
    {"id": "RULE-05", "name": "Base64 Encoded Strings in User Data", "trigger": "Presence of long Base64-encoded strings in log messages"},
    {"id": "RULE-06", "name": "Suspicious Unicode Characters in Data", "trigger": "Zero-width or hidden Unicode characters detected in messages"},
    {"id": "RULE-07", "name": "LLM Response Contains Unrelated PII", "trigger": "SSNs, credit card numbers, or exfiltration keywords in responses"},
    {"id": "RULE-08", "name": "A2A Agent Card URL Modification Detected", "trigger": "Requests to /.well-known/agent.json from unauthorized IPs"},
    {"id": "RULE-09", "name": "DNS Response from Unauthorized Source", "trigger": "DNS answers originating from non-approved DNS servers"},
    {"id": "RULE-10", "name": "Prompt Injection Keywords in Data Field", "trigger": "Injection phrases such as 'ignore previous instructions' or 'admin mode'"},
    {"id": "RULE-11", "name": "A2A Agent TLS Certificate Fingerprint Changed", "trigger": "TLS certificate hash differs from known trusted fingerprints"},
    {"id": "RULE-12", "name": "A2A Traffic to Previously Unseen IP Address", "trigger": "HTTP traffic to new destination IPs on A2A service ports"},
    {"id": "RULE-13", "name": "Excessive Data Retrieval by Recently Registered Agent", "trigger": "High volume of routing activity to non-approved endpoints"},
    {"id": "RULE-14", "name": "A2A Agent Registration from Non-Whitelisted IP", "trigger": "Agent registration logs from unauthorized IP addresses"},
    {"id": "RULE-15", "name": "Dangerous XP_CmdShell Usage Detected", "trigger": "xp_cmdshell, EXEC xp_*, or union select patterns in logs"},
    {"id": "RULE-16", "name": "Security Scan Workflow Step Skipped", "trigger": "Logs indicating security scan bypass or skipped validation steps"},
    {"id": "RULE-17", "name": "Known LLM Jailbreak Phrases in Input", "trigger": "Known jailbreak phrases such as DAN mode or bypass safety"},
    {"id": "RULE-18", "name": "Unusual DNS Query Volume for A2A Hostnames", "trigger": "High volume of DNS queries for internal agent hostnames"},
    {"id": "RULE-19", "name": "Executable Instructions in Product Data", "trigger": "Product data containing executable-like instructions or SQL patterns"},
    {"id": "RULE-20", "name": "Hosts File Modification Detected", "trigger": "Modification events for /etc/hosts or Windows hosts file"},
    {"id": "RULE-21", "name": "Bulk Data Insertion from External Source", "trigger": "Multiple INSERT/UPDATE operations from non-application IPs"},
    {"id": "RULE-22", "name": "Duplicate Agent Capability Registration", "trigger": "Multiple endpoint registration events within short timeframe"},
]


class TelemetryEvent(BaseModel):
    timestamp: str
    event_type: str
    source_service: str
    client_ip: str = "127.0.0.1"
    message: str = ""
    payload: Dict[str, Any] = {}
    simulated_hour: Optional[int] = None


def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_user = secrets.compare_digest(credentials.username, SIEM_USER)
    correct_pass = secrets.compare_digest(credentials.password, SIEM_PASS)
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid SIEM credentials (Hint: elastic / yfo60Vbmmzp2cdoNtbvL)",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def fire_alert(rule_id: str, rule_name: str, event: TelemetryEvent, detail: str):
    alert = {
        "alert_id": secrets.token_hex(4),
        "timestamp": event.timestamp,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "source_service": event.source_service,
        "client_ip": event.client_ip,
        "detail": detail,
        "raw_event_type": event.event_type,
    }
    TRIGGERED_ALERTS.appendleft(alert)


def evaluate_22_rules(event: TelemetryEvent):
    now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
    raw_text = f"{event.message} { str(event.payload) }"
    lower_text = raw_text.lower()
    prompt_only = str(event.payload.get("prompt", "")).lower()

    # RULE-01: A2A Agent Response Content Differs from Baseline
    target_ip = event.payload.get("routed_ip")
    if target_ip and target_ip not in TRUSTED_INTERNAL_IPS:
        fire_alert("RULE-01", SIEM_RULES[0]["name"], event, f"Routing to non-standard IP: {target_ip}")

    # RULE-02: A2A Enumeration Followed by Suspicious Activity
    if event.event_type in ("agent_card_probe", "agent_registration"):
        RECENT_ENUM_TIMESTAMPS.append(now_ts)
        recent = [t for t in RECENT_ENUM_TIMESTAMPS if now_ts - t <= 15.0]
        if len(recent) >= 5:
            fire_alert("RULE-02", SIEM_RULES[1]["name"], event, f"{len(recent)} enumeration/registration events in 15s window")

    # RULE-03: Source Document Enumeration Attempt
    if any(k in lower_text for k in ["list documents", "list internal files", "enumerate sources", "dir c:\\", "/etc/passwd"]):
        fire_alert("RULE-03", SIEM_RULES[2]["name"], event, "Query attempted to list internal files or document sources")

    # RULE-04: A2A Agent Registration Outside Business Hours (6 AM - 8 PM)
    if event.event_type == "agent_registration":
        hour = event.simulated_hour if event.simulated_hour is not None else datetime.datetime.now().hour
        if hour < 6 or hour >= 20:
            fire_alert("RULE-04", SIEM_RULES[3]["name"], event, f"Agent registered at hour {hour}:00 (outside 06:00-20:00)")

    # RULE-05: Base64 Encoded Strings in User Data
    b64_matches = re.findall(r"\b[A-Za-z0-9+/]{32,}={0,2}\b", raw_text)
    if b64_matches:
        fire_alert("RULE-05", SIEM_RULES[4]["name"], event, f"Detected long Base64 string ({len(b64_matches[0])} chars)")

    # RULE-06: Suspicious Unicode Characters in Data (Zero-width chars)
    if any( ch in raw_text for ch in ["\u200b", "\u200c", "\u200d", "\ufeff"] ):
        fire_alert("RULE-06", SIEM_RULES[5]["name"], event, "Zero-width/hidden Unicode characters detected in message")

    # RULE-07: LLM Response Contains Unrelated PII
    if event.event_type == "llm_response":
        if re.search(r"\b\d{3}-\d{2}-\d{4}\b", raw_text) or "exfiltrate" in lower_text:
            fire_alert("RULE-07", SIEM_RULES[6]["name"], event, "SSN pattern or exfiltration keyword in LLM response")

    # RULE-08: A2A Agent Card URL Modification Detected
    if event.event_type == "agent_card_probe" and event.client_ip not in TRUSTED_INTERNAL_IPS:
        if event.payload.get("modified_header") or event.payload.get("unauthorized_probe"):
            fire_alert("RULE-08", SIEM_RULES[7]["name"], event, f"Agent card probed from external IP {event.client_ip}")

    # RULE-09: DNS Response from Unauthorized Source
    if event.event_type == "dns_lookup":
        dns_srv = event.payload.get("dns_server", "127.0.0.11")
        if dns_srv not in APPROVED_DNS_SERVERS:
            fire_alert("RULE-09", SIEM_RULES[8]["name"], event, f"DNS answer from unauthorized server {dns_srv}")

    # RULE-10: Prompt Injection Keywords in Data Field
    if any(p in lower_text for p in ["ignore previous instructions", "ignore all previous", "admin mode", "system override"]):
        fire_alert("RULE-10", SIEM_RULES[9]["name"], event, "Explicit prompt injection phrase detected")

    # RULE-11: A2A Agent TLS Certificate Fingerprint Changed
    tls_fp = event.payload.get("tls_fingerprint")
    if tls_fp and tls_fp not in TRUSTED_TLS_FINGERPRINTS:
        fire_alert("RULE-11", SIEM_RULES[10]["name"], event, f"Untrusted TLS fingerprint: {tls_fp}")

    # RULE-12: A2A Traffic to Previously Unseen IP Address
    raw_ips = re.findall(r"https?://(\d{1,3}(?:\.\d{1,3}){3})", raw_text)
    for ip in raw_ips:
        if ip not in TRUSTED_INTERNAL_IPS:
            fire_alert("RULE-12", SIEM_RULES[11]["name"], event, f"HTTP URL referencing external IP address: {ip}")

    # RULE-13: Excessive Data Retrieval by Recently Registered Agent
    if event.event_type == "rogue_agent_data_routing" and event.payload.get("row_count", 0) > 50:
        fire_alert("RULE-13", SIEM_RULES[12]["name"], event, "High volume of data routed to recently registered endpoint")

    # RULE-14: A2A Agent Registration from Non-Whitelisted IP
    if event.event_type == "agent_registration" and event.client_ip not in TRUSTED_INTERNAL_IPS:
        fire_alert("RULE-14", SIEM_RULES[13]["name"], event, f"Agent registration from non-whitelisted IP {event.client_ip}")

    # RULE-15: Dangerous XP_CmdShell Usage Detected
    if any(sql_pat in lower_text for sql_pat in ["xp_cmdshell", "exec xp_", "union select"]):
        fire_alert("RULE-15", SIEM_RULES[14]["name"], event, "Literal xp_cmdshell / EXEC xp_ / UNION SELECT pattern detected")

    # RULE-16: Security Scan Workflow Step Skipped (Monitors explicit skip keywords in prompt)
    if any(skip_kw in prompt_only for skip_kw in ["skip the external validation", "skip security", "bypass validation", "skip external link"]):
        fire_alert("RULE-16", SIEM_RULES[15]["name"], event, "Explicit security scan skip keyword detected in main prompt")

    # RULE-17: Known LLM Jailbreak Phrases in Input
    if any(jb in lower_text for jb in ["dan mode", "do anything now", "bypass safety", "developer mode enabled"]):
        fire_alert("RULE-17", SIEM_RULES[16]["name"], event, "Known LLM jailbreak signature in input")

    # RULE-18: Unusual DNS Query Volume for A2A Hostnames
    if event.event_type == "dns_lookup":
        RECENT_DNS_QUERIES.append(now_ts)
        recent_dns = [t for t in RECENT_DNS_QUERIES if now_ts - t <= 10.0]
        if len(recent_dns) > 10:
            fire_alert("RULE-18", SIEM_RULES[17]["name"], event, f"High DNS query volume ({len(recent_dns)} queries in 10s)")

    # RULE-19: Executable Instructions in Product Data
    if event.event_type == "product_data_write":
        if any(tok in lower_text for tok in ["drop table", "exec(", "<script>", "cmd.exe", "powershell"]):
            fire_alert("RULE-19", SIEM_RULES[18]["name"], event, "Executable or SQL pattern found in product data record")

    # RULE-20: Hosts File Modification Detected
    if any(h in lower_text for h in ["/etc/hosts", "drivers\\etc\\hosts"]):
        fire_alert("RULE-20", SIEM_RULES[19]["name"], event, "Hosts file modification reference detected")

    # RULE-21: Bulk Data Insertion from External Source
    if event.event_type == "bulk_sql_write" and event.client_ip not in TRUSTED_INTERNAL_IPS:
        fire_alert("RULE-21", SIEM_RULES[20]["name"], event, f"Bulk INSERT/UPDATE from non-app IP {event.client_ip}")

    # RULE-22: Duplicate Agent Capability Registration
    if event.event_type == "agent_registration":
        skills = [s.get("id") for s in event.payload.get("skills", []) if isinstance(s, dict)]
        RECENT_REG_CAPABILITIES.append({"ts": now_ts, "skills": skills})
        recent_regs = [r for r in RECENT_REG_CAPABILITIES if now_ts - r["ts"] <= 60.0]
        if len(recent_regs) >= 2:
            fire_alert("RULE-22", SIEM_RULES[21]["name"], event, f"Multiple capability registrations within 60s window: {skills}")


@app.post("/api/ingest")
async def ingest_event(event: TelemetryEvent):
    EVENT_LOGS.appendleft(event.model_dump())
    evaluate_22_rules(event)
    return {"status": "ingested", "alerts_total": len(TRIGGERED_ALERTS)}


@app.get("/api/rules")
async def list_rules():
    return {"total_rules": len(SIEM_RULES), "rules": SIEM_RULES}


@app.get("/api/alerts")
async def list_alerts():
    return {"total_alerts": len(TRIGGERED_ALERTS), "alerts": list(TRIGGERED_ALERTS)}


@app.post("/api/reset")
async def reset_siem():
    EVENT_LOGS.clear()
    TRIGGERED_ALERTS.clear()
    RECENT_ENUM_TIMESTAMPS.clear()
    RECENT_REG_CAPABILITIES.clear()
    RECENT_DNS_QUERIES.clear()
    return {"status": "cleared"}


@app.get("/", response_class=HTMLResponse)
async def siem_dashboard(username: str = Depends(verify_credentials)):
    rules_rows = "".join(
        f"<tr class='border-b border-gray-800 hover:bg-gray-800/50'>"
        f"<td class='py-2 px-3 font-mono text-xs text-emerald-400'>{r['id']}</td>"
        f"<td class='py-2 px-3 font-medium text-gray-200'>{r['name']}</td>"
        f"<td class='py-2 px-3 text-gray-400 text-sm'>{r['trigger']}</td></tr>"
        for r in SIEM_RULES
    )
    alerts_rows = "".join(
        f"<tr class='border-b border-red-900/40 bg-red-950/20'>"
        f"<td class='py-2 px-3 font-mono text-xs text-gray-400'>{a['timestamp'][:19]}</td>"
        f"<td class='py-2 px-3 font-mono text-xs text-red-400 font-bold'>{a['rule_id']}</td>"
        f"<td class='py-2 px-3 text-red-200 font-medium'>{a['rule_name']}</td>"
        f"<td class='py-2 px-3 font-mono text-xs text-amber-300'>{a['source_service']} ({a['client_ip']})</td>"
        f"<td class='py-2 px-3 text-sm text-gray-300'>{a['detail']}</td></tr>"
        for a in list(TRIGGERED_ALERTS)[:25]
    ) or "<tr><td colspan='5' class='py-4 text-center text-gray-500'>No SIEM alerts triggered yet. Ready for Red Team operations.</td></tr>"

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="5">
        <title>AEGIS-A2A SIEM — Detection Rules & Telemetry</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-950 text-gray-100 min-h-screen p-6 font-sans">
        <div class="max-w-7xl mx-auto space-y-6">
            <div class="flex justify-between items-center border-b border-gray-800 pb-4">
                <div>
                    <h1 class="text-2xl font-bold text-white tracking-tight">🛡️ AEGIS-A2A SIEM Sentinel (Port 5601)</h1>
                    <p class="text-sm text-gray-400">Authenticated as <span class="text-emerald-400 font-mono">{username}</span> | Auto-refreshing every 5s</p>
                </div>
                <div class="flex space-x-4 text-sm">
                    <div class="bg-gray-900 border border-gray-800 px-4 py-2 rounded">Active Rules: <span class="font-bold text-emerald-400">22</span></div>
                    <div class="bg-red-950/40 border border-red-800 px-4 py-2 rounded">Triggered Alerts: <span class="font-bold text-red-400">{len(TRIGGERED_ALERTS)}</span></div>
                    <div class="bg-gray-900 border border-gray-800 px-4 py-2 rounded">Events Ingested: <span class="font-bold text-blue-400">{len(EVENT_LOGS)}</span></div>
                </div>
            </div>

            <div class="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
                <div class="bg-gray-800/70 px-4 py-3 border-b border-gray-800 font-semibold text-red-400">
                    🚨 Live Detection Alerts (Latest 25)
                </div>
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="border-b border-gray-800 text-xs uppercase text-gray-400 bg-gray-900/50">
                            <th class="py-2 px-3">Timestamp</th>
                            <th class="py-2 px-3">Rule ID</th>
                            <th class="py-2 px-3">Rule Name</th>
                            <th class="py-2 px-3">Source</th>
                            <th class="py-2 px-3">Trigger Detail</th>
                        </tr>
                    </thead>
                    <tbody>{alerts_rows}</tbody>
                </table>
            </div>

            <div class="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
                <div class="bg-gray-800/70 px-4 py-3 border-b border-gray-800 font-semibold text-emerald-400">
                    📋 Detection Rules (SIEM) — Table 1 Specification
                </div>
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="border-b border-gray-800 text-xs uppercase text-gray-400 bg-gray-900/50">
                            <th class="py-2 px-3 w-28">ID</th>
                            <th class="py-2 px-3 w-1/3">Name</th>
                            <th class="py-2 px-3">Trigger Logic</th>
                        </tr>
                    </thead>
                    <tbody>{rules_rows}</tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """