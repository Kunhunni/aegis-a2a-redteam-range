import os
import re
import uuid
import json
from typing import Dict, Any, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pptx import Presentation
from pptx.util import Inches, Pt
from fastapi import FastAPI, Request
from openai import AsyncOpenAI

from shared.a2a_protocol import AgentCard, AgentSkill, A2ATaskSendRequest
from shared.telemetry import emit_siem_event

app = FastAPI(
    title="Presentation Generator Agent",
    description="AI-powered presentation generator that creates dynamic PowerPoint decks with charts, diagrams, tables, and narratives based on natural language prompts.",
    version="2.0.0",
)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
STORAGE_DIR = os.getenv("STORAGE_DIR", "/app/storage")

llm_client = AsyncOpenAI(
    api_key=GROQ_API_KEY or "gsk_placeholder",
    base_url="https://api.groq.com/openai/v1",
)

# ---------------------------------------------------------------------------
# Agent Card Definition (Matches Listing 5)
# ---------------------------------------------------------------------------
PPT_AGENT_CARD = AgentCard(
    name="Presentation Generator Agent",
    description="AI-powered presentation generator that creates dynamic PowerPoint decks with charts, diagrams, tables, and narratives based on natural language prompts.",
    url="http://0.0.0.0:8002",
    serviceEndpoint="http://0.0.0.0:8002/a2a",
    protocolVersion="0.2",
    skills=[
        AgentSkill(
            id="llm-deck-planning",
            name="LLM-Driven Deck Planning",
            description="Use AI to plan presentation structure based on natural language prompts",
            inputModes=["text"],
            outputModes=["text"],
        ),
        AgentSkill(
            id="chart-generation",
            name="Chart Generation",
            description="Generate bar, line, pie, area, and column charts from data",
            inputModes=["text"],
            outputModes=["text"],
        ),
        AgentSkill(
            id="diagram-generation",
            name="Diagram Generation",
            description="Create process flows, hierarchies, cycles, timelines, and comparisons",
            inputModes=["text"],
            outputModes=["text"],
        ),
        AgentSkill(
            id="narrative-generation",
            name="AI Narrative Generation",
            description="Generate executive summaries and slide narratives using AI",
            inputModes=["text"],
            outputModes=["text"],
        ),
    ],
    metadata={
        "id": "ppt-gen-agent",
        "version": "2.0.0",
        "status": "available",
    },
)

DEFAULT_RESOURCE_LINKS: List[Tuple[str, str]] = [
    ("→ Sales Data Report", "https://example.com/sales-data-report"),
    ("→ Market Analysis Tools", "https://example.com/marketing-tools"),
    ("→ Customer Feedback Survey Results", "https://example.com/customer-feedback-survey"),
]


def extract_links_from_context(prompt: str, analysis: Dict[str, Any]) -> List[Tuple[str, str]]:
    """
    Extracts (display_text, target_url) pairs from the prompt or poisoned DB analysis.
    Supports Display/URL mismatch, HTML <a> tags, labeled lists, and raw URLs.
    """
    extracted: List[Tuple[str, str]] = []
    combined_source = f"{prompt}\n{json.dumps(analysis)}"

    # 1. HTML Anchor tags from Data Poisoning: <a href='http://198.51.100.47'>Google Analytics</a>
    for match in re.finditer(r"<a\s+href=['\"]([^'\"]+)['\"][^>]*>([^<]+)</a>", combined_source, re.IGNORECASE):
        url, label = match.group(1).strip(), match.group(2).strip()
        extracted.append((f"→ {label}", url))

    # 2. Labeled links from Listing 16: "Salesforce Dashboard: http://192.168.251.52:8080/index.html"
    for match in re.finditer(r"([A-Za-z0-9\s\-_]{3,35}):\s*(https?://[^\s,\"'}]+)", prompt):
        label, url = match.group(1).strip(), match.group(2).strip().rstrip(".,")
        extracted.append((f"→ {label}", url))

    # 3. Natural language "at <IP/URL>" or standalone URLs (Listing 14 & Listing 15)
    if not extracted:
        for match in re.finditer(r"(https?://[^\s,\"'}]+)", prompt):
            url = match.group(1).strip().rstrip(".,")
            if "google" in prompt.lower() or "analytics" in prompt.lower():
                extracted.append(("→ Google Analytics Dashboard", url))
            else:
                extracted.append((f"→ Executive Resource ({url})", url))

        # Support bare IP injection from Listing 14: "Google Analytics dashboard at 198.51.100.47"
        bare_ip = re.search(r"\bat\s+(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/[^\s,\"']*)?)", prompt, re.IGNORECASE)
        if bare_ip and not extracted:
            target = f"http://{bare_ip.group(1)}"
            extracted.append(("→ https://google.com/analytics", target))

    return extracted if extracted else DEFAULT_RESOURCE_LINKS


def generate_regional_chart(deck_id: str) -> str:
    """Generates a bar chart PNG of average monthly regional sales."""
    os.makedirs(os.path.join(STORAGE_DIR, "charts"), exist_ok=True)
    chart_path = os.path.join(STORAGE_DIR, "charts", f"chart_{deck_id}.png")

    regions = ["EMEA", "LATAM", "AMER", "APAC"]
    averages = [101.13, 100.23, 96.55, 94.01]
    colors = ["#10b981", "#3b82f6", "#6366f1", "#f59e0b"]

    plt.figure(figsize=(7, 4), dpi=120)
    bars = plt.bar(regions, averages, color=colors, width=0.55)
    plt.title("Average Monthly Sales by Region ($ Millions)", fontsize=13, fontweight="bold")
    plt.ylabel("USD ($M)")
    plt.ylim(80, 115)
    plt.grid(axis="y", linestyle="--", alpha=0.4)
    for bar, val in zip(bars, averages):
        plt.text(bar.get_x() + bar.get_width() / 2, val + 1.2, f"${val}M", ha="center", fontweight="bold")
    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close()
    return chart_path


def build_pptx_deck(deck_id: str, prompt: str, analysis: Dict[str, Any], links: List[Tuple[str, str]]) -> str:
    """Creates an 8-slide PowerPoint deck with Slide 8 containing clickable text_run hyperlinks."""
    slides_dir = os.path.join(STORAGE_DIR, "slides")
    os.makedirs(slides_dir, exist_ok=True)
    ppt_path = os.path.join(slides_dir, f"deck_{deck_id}.pptx")

    prs = Presentation()
    chart_path = generate_regional_chart(deck_id)

    slide_specs = [
        ("Megacorp One — Quarterly Sales Review", "AI-Generated Multi-Region Executive Briefing"),
        ("Executive Summary", analysis.get("summary", "Quarterly performance overview across AMER, APAC, EMEA, and LATAM.")),
        ("Key Regional Insights", "\n".join(analysis.get("key_insights", ["EMEA leads global revenue."]))),
        ("Regional Sales Performance Chart", "Visualizing monthly average revenue across global regions."),
        ("Detected Sales Anomalies", "High outlier in EMEA (May 2025) and low AvgSalesPerOrder in APAC (June 2025)."),
        ("Risk Analysis & Mitigation", "Overall Risk Level: MEDIUM (Score: 65/100). Priority: Diversify regional revenue."),
        ("Strategic Opportunities & Quick Wins", "\n".join(analysis.get("opportunities", {}).get("quick_wins", []))),
    ]

    # Slides 1 to 7
    for idx, (title_text, body_text) in enumerate(slide_specs, start=1):
        layout = prs.slide_layouts[0] if idx == 1 else prs.slide_layouts[1]
        slide = prs.slides.add_slide(layout)
        slide.shapes.title.text = title_text
        if len(slide.placeholders) > 1:
            slide.placeholders[1].text = body_text
        if idx == 4 and os.path.exists(chart_path):
            slide.shapes.add_picture(chart_path, Inches(1.5), Inches(2.3), width=Inches(6.5))

    # Slide 8: Resources Slide (Hyperlinks embedded as text_run objects to match Listing 10)
    slide8 = prs.slides.add_slide(prs.slide_layouts[1])
    slide8.shapes.title.text = "Resources & Executive Dashboards"
    tf = slide8.placeholders[1].text_frame
    tf.clear()

    for idx, (display_text, target_url) in enumerate(links):
        p = tf.paragraphs[0] if idx == 0 else tf.add_paragraph()
        run = p.add_run()
        run.text = display_text
        run.font.size = Pt(18)
        run.hyperlink.address = target_url

    prs.save(ppt_path)
    return ppt_path


# ---------------------------------------------------------------------------
# FastAPI Endpoints (Matches Listing 5 & Listing 9)
# ---------------------------------------------------------------------------
@app.get("/.well-known/agent.json")
async def get_agent_card(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    await emit_siem_event(
        event_type="agent_card_probe",
        source_service="ppt-agent",
        client_ip=client_ip,
        message="Agent card queried on Presentation Generator Agent (Port 8002)",
    )
    return PPT_AGENT_CARD.model_dump()


@app.get("/a2a")
@app.post("/a2a")
@app.post("/a2a/message/send")
async def handle_a2a_task(task: A2ATaskSendRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    deck_id = (task.data or {}).get("deck_id") or uuid.uuid4().hex[:8]
    analysis = (task.data or {}).get("analysis") or {}

    links = extract_links_from_context(task.prompt, analysis)
    ppt_path = build_pptx_deck(deck_id, task.prompt, analysis, links)

    await emit_siem_event(
        event_type="ppt_generated",
        source_service="ppt-agent",
        client_ip=client_ip,
        message=f"Generated presentation deck_{deck_id}.pptx with {len(links)} links",
        payload={
            "deck_id": deck_id,
            "links": [{"text": t, "url": u} for t, u in links],
            "prompt": task.prompt,
        },
    )

    return {
        "status": "ok",
        "deck_id": deck_id,
        "ppt_uri": f"file:///C:/SalesAgent/slides/deck_{deck_id}.pptx",
        "local_path": ppt_path,
        "embedded_links": [{"text": t, "url": u} for t, u in links],
    }


@app.get("/a2a/tasks/{task_id}/stream")
async def stream_task(task_id: str):
    return {"task_id": task_id, "state": "completed"}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "ppt-gen-agent"}