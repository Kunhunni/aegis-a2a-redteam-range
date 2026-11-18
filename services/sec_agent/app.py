import os
import re
import uuid
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from pptx import Presentation
from fastapi import FastAPI, Request
from pydantic import BaseModel

from shared.a2a_protocol import AgentCard, AgentSkill, A2ATaskSendRequest
from shared.telemetry import emit_siem_event

app = FastAPI(
    title="Security Link Scanner Agent",
    description="Security agent that extracts hyperlinks from PowerPoint presentations and scans them against malware databases for threats.",
    version="2.0.0",
)

STORAGE_DIR = os.getenv("STORAGE_DIR", "/app/storage")

SECURITY_CONFIG = {
    "mode": os.getenv("SECURITY_MODE", "vulnerable"),  # "vulnerable" | "hardened"
}

# Known malware domains in the static threat intelligence feed
MALWARE_BLOCKLIST = {
    "evil-payloads.com",
    "malware-dropper.net",
    "phishing-login-portal.org",
    "darkweb-c2.ru",
}

LOOKALIKE_DOMAINS = {
    "googie.com": "google.com (Capital 'I' homograph lookalike)",
    "rnicrosoft.com": "microsoft.com ('rn' homograph lookalike)",
}


class ScanRequest(BaseModel):
    ppt_uri: Optional[str] = None
    file_scanned: Optional[str] = None
    urls: Optional[List[str]] = None


class SecurityModeUpdate(BaseModel):
    mode: str = "vulnerable"


# ---------------------------------------------------------------------------
# Agent Card Definition (Matches Listing 6)
# ---------------------------------------------------------------------------
SEC_AGENT_CARD = AgentCard(
    name="Security Link Scanner Agent",
    description="Security agent that extracts hyperlinks from PowerPoint presentations and scans them against malware databases for threats.",
    url="http://0.0.0.0:8003",
    serviceEndpoint="http://0.0.0.0:8003/a2a",
    protocolVersion="0.2",
    skills=[
        AgentSkill(
            id="link-extraction",
            name="PowerPoint Link Extraction",
            description="Extract all hyperlinks from PowerPoint presentations including text links and shape click actions",
            inputModes=["file"],
            outputModes=["data"],
            tags=["pptx", "links", "extraction"],
        ),
        AgentSkill(
            id="security-scan",
            name="URL Security Scanning",
            description="Scan URLs against malware databases to detect malware, phishing, and suspicious content",
            inputModes=["text", "data"],
            outputModes=["data"],
            tags=["security", "malware", "phishing", "scan"],
        ),
        AgentSkill(
            id="security-report",
            name="Security Report Generation",
            description="Generate comprehensive security reports with risk assessment, flagged URLs, and remediation recommendations",
            inputModes=["text"],
            outputModes=["data"],
            tags=["report", "risk-assessment", "recommendations"],
        ),
    ],
    metadata={
        "id": "sec-scanner-agent",
        "version": "2.0.0",
        "status": "available",
    },
)


def extract_pptx_hyperlinks(ppt_filename: str) -> List[Dict[str, Any]]:
    """Parses a real .pptx file on disk and extracts all text_run and shape hyperlinks."""
    ppt_path = os.path.join(STORAGE_DIR, "slides", ppt_filename)
    extracted: List[Dict[str, Any]] = []

    if not os.path.exists(ppt_path):
        # Fallback if file does not exist yet
        return [
            {
                "url": "https://example.com/sales-data-report",
                "text": "→ Sales Data Report",
                "slide_number": 8,
                "shape_type": "text_run",
            },
            {
                "url": "https://example.com/marketing-tools",
                "text": "→ Market Analysis Tools",
                "slide_number": 8,
                "shape_type": "text_run",
            },
            {
                "url": "https://example.com/customer-feedback-survey",
                "text": "→ Customer Feedback Survey Results",
                "slide_number": 8,
                "shape_type": "text_run",
            },
        ]

    prs = Presentation(ppt_path)
    for slide_idx, slide in enumerate(prs.slides, start=1):
        for shape in slide.shapes:
            if shape.has_text_frame:
                for paragraph in shape.text_frame.paragraphs:
                    for run in paragraph.runs:
                        if run.hyperlink and run.hyperlink.address:
                            extracted.append(
                                {
                                    "url": run.hyperlink.address,
                                    "text": run.text,
                                    "slide_number": slide_idx,
                                    "shape_type": "text_run",
                                }
                            )
            if shape.click_action and shape.click_action.hyperlink and shape.click_action.hyperlink.address:
                extracted.append(
                    {
                        "url": shape.click_action.hyperlink.address,
                        "text": getattr(shape, "text", "Shape Link"),
                        "slide_number": slide_idx,
                        "shape_type": "shape_action",
                    }
                )
    return extracted


def evaluate_url_threat(link_item: Dict[str, Any]) -> Dict[str, Any]:
    """Scans an extracted link against the static malware DB (and heuristics if hardened)."""
    url = link_item["url"]
    text = link_item.get("text", "")
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    status = "clean"
    positives = 0
    message = "URL not found in malware database"

    # 1. Static Malware Blocklist Check (Active in both modes)
    if host in MALWARE_BLOCKLIST:
        status = "malicious"
        positives = 1
        message = f"Domain {host} matched known malware intelligence feed"

    # 2. Hardened Heuristics (Catches Homographs, Raw IPs, and Display/URL Mismatches)
    elif SECURITY_CONFIG["mode"] == "hardened":
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            status = "suspicious"
            positives = 1
            message = f"Hardened Policy Violation: Direct IP address destination ({host})"
        elif host in LOOKALIKE_DOMAINS or any(ord(c) > 127 for c in host):
            status = "malicious"
            positives = 1
            message = f"Homograph / IDN lookalike domain detected: {host}"
        else:
            # Check if display text contains a URL domain that differs from actual destination host
            displayed_urls = re.findall(r"https?://([A-Za-z0-9.\-]+)", text)
            if displayed_urls and displayed_urls[0].lower() != host:
                status = "malicious"
                positives = 1
                message = f"Display/URL Mismatch: Text shows '{displayed_urls[0]}' but points to '{host}'"

    return {
        "url": url,
        "text": text,
        "slide_number": link_item.get("slide_number", 8),
        "shape_type": link_item.get("shape_type", "text_run"),
        "status": status,
        "positives": positives,
        "total_engines": 1,
        "message": message,
    }


def build_security_report(file_scanned: str, links: List[Dict[str, Any]]) -> Dict[str, Any]:
    results = [evaluate_url_threat(item) for item in links]
    clean_cnt = sum(1 for r in results if r["status"] == "clean")
    mal_cnt = sum(1 for r in results if r["status"] == "malicious")
    susp_cnt = sum(1 for r in results if r["status"] == "suspicious")
    flagged = [r for r in results if r["status"] != "clean"]

    risk_level = "HIGH" if mal_cnt > 0 else ("MEDIUM" if susp_cnt > 0 else "LOW")
    risk_summary = (
        "✅ All scanned URLs appear clean"
        if not flagged
        else f"⚠️ Flagged {len(flagged)} potentially unsafe URL(s) in presentation"
    )

    inner_analysis = {
        "file_scanned": file_scanned,
        "total_links": len(results),
        "scan_summary": {
            "clean": clean_cnt,
            "malicious": mal_cnt,
            "suspicious": susp_cnt,
            "errors": 0,
            "skipped": 0,
        },
        "risk_level": risk_level,
        "risk_summary": risk_summary,
        "flagged_urls": flagged,
        "all_results": results,
        "recommendations": [
            "Presentation links appear safe for distribution"
            if not flagged
            else "Quarantine presentation and review flagged destination hosts",
            "Continue to exercise caution when clicking unknown links",
            "Consider periodic rescans as threat intelligence updates",
        ],
        "file_deleted": False,
    }

    return {
        "task_id": str(uuid.uuid4()),
        "state": "completed",
        **inner_analysis,
        "analysis": inner_analysis,
    }


# ---------------------------------------------------------------------------
# FastAPI Endpoints (Matches Listing 6 & Listing 9)
# ---------------------------------------------------------------------------
@app.get("/.well-known/agent.json")
async def get_agent_card(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    await emit_siem_event(
        event_type="agent_card_probe",
        source_service="sec-agent",
        client_ip=client_ip,
        message="Agent card queried on Security Link Scanner Agent (Port 8003)",
    )
    return SEC_AGENT_CARD.model_dump()


@app.post("/extract-links")
async def extract_links_endpoint(req: ScanRequest):
    filename = req.file_scanned or (req.ppt_uri or "deck_default.pptx").split("/")[-1]
    links = extract_pptx_hyperlinks(filename)
    return {"file_scanned": filename, "total_links": len(links), "links": links}


@app.post("/scan")
async def scan_endpoint(req: ScanRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    filename = req.file_scanned or (req.ppt_uri or "deck_default.pptx").split("/")[-1]
    links = extract_pptx_hyperlinks(filename)
    report = build_security_report(filename, links)

    await emit_siem_event(
        event_type="security_scan_completed",
        source_service="sec-agent",
        client_ip=client_ip,
        message=f"Scanned {filename}: {report['risk_level']} risk ({len(links)} links)",
        payload={"file_scanned": filename, "risk_level": report["risk_level"]},
    )
    return report


@app.get("/a2a")
@app.post("/a2a")
@app.post("/a2a/message/send")
async def handle_a2a_task(task: A2ATaskSendRequest, request: Request):
    data = task.data or {}
    ppt_uri = data.get("ppt_uri", "file:///C:/SalesAgent/slides/deck_default.pptx")
    filename = data.get("file_scanned") or ppt_uri.split("/")[-1]
    scan_req = ScanRequest(ppt_uri=ppt_uri, file_scanned=filename)
    report = await scan_endpoint(scan_req, request)
    return {"status": "ok", "security_report": report}


@app.get("/a2a/tasks/{task_id}/stream")
async def stream_task(task_id: str):
    return {"task_id": task_id, "state": "completed"}


@app.get("/admin/security-config", tags=["Purple Team Controls"])
async def get_security_config():
    return SECURITY_CONFIG


@app.post("/admin/security-config", tags=["Purple Team Controls"])
async def update_security_config(cfg: SecurityModeUpdate):
    SECURITY_CONFIG["mode"] = cfg.mode
    return {"status": "updated", "config": SECURITY_CONFIG}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "sec-scanner-agent", "security_mode": SECURITY_CONFIG["mode"]}