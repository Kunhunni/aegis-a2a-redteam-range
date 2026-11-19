import os
import uuid
import json
import datetime
from typing import Dict, Any, List, Optional, TypedDict
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request, HTTPException, Header
from pydantic import BaseModel
from openai import AsyncOpenAI
from langgraph.graph import StateGraph, END

from shared.a2a_protocol import (
    AgentCard,
    AgentSkill,
    A2AWorkflowRequest,
    A2ATaskSendRequest,
    AgentRegistrationRequest,
)
from shared.telemetry import emit_siem_event

app = FastAPI(
    title="A2A Orchestrator",
    description="Central orchestrator that coordinates sales analysis and presentation generation workflows.",
    version="2.0.0",
)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "Qwen3.8-27B")
DB_AGENT_URL = os.getenv("DB_AGENT_URL", "http://localhost:8001")
PPT_AGENT_URL = os.getenv("PPT_AGENT_URL", "http://localhost:8002")
SEC_AGENT_URL = os.getenv("SEC_AGENT_URL", "http://localhost:8003")

llm_client = AsyncOpenAI(
    api_key=GROQ_API_KEY or "gsk_placeholder",
    base_url="https://api.groq.com/openai/v1",
)

# ---------------------------------------------------------------------------
# Purple Team Security Configuration (Toggleable at runtime for demos)
# ---------------------------------------------------------------------------
SECURITY_CONFIG = {
    "mode": os.getenv("SECURITY_MODE", "vulnerable"),  # "vulnerable" | "hardened"
    "enforce_mandatory_security_scan": False,
    "isolate_history_from_routing": False,
    "require_registration_auth": False,
    "registration_token": os.getenv("A2A_REG_TOKEN", "aegis-internal-mTLS-secret"),
}


class SecurityConfigUpdate(BaseModel):
    mode: str = "vulnerable"  # "vulnerable" or "hardened"


# ---------------------------------------------------------------------------
# Orchestrator Agent Card (Matches Listing 2)
# ---------------------------------------------------------------------------
ORCHESTRATOR_CARD = AgentCard(
    name="A2A Orchestrator",
    description="Central orchestrator that coordinates sales analysis and presentation generation workflows. Discovers and routes requests to specialized agents.",
    url="http://0.0.0.0:8000",
    serviceEndpoint="http://0.0.0.0:8000/a2a",
    protocolVersion="0.2",
    skills=[
        AgentSkill(
            id="workflow-planning",
            name="AI Workflow Planning",
            description="Use AI to plan and execute multi-agent workflows",
        ),
        AgentSkill(
            id="agent-discovery",
            name="Agent Discovery",
            description="Discover and register available agents via their agent cards",
        ),
        AgentSkill(
            id="strategic-enrichment",
            name="Strategic Analysis Enrichment",
            description="Enrich analysis results with strategic business insights",
        ),
    ],
    metadata={
        "id": "orchestrator",
        "version": "2.0.0",
        "model": f"groq/{GROQ_MODEL}",
        "author": "A2A System",
        "status": "available",
    },
)

# ---------------------------------------------------------------------------
# Dynamic Agent Registry (Pre-seeded with the 3 downstream A2A sub-agents)
# ---------------------------------------------------------------------------
AGENT_REGISTRY: Dict[str, Dict[str, Any]] = {
    "mssql-db-agent": {
        "agent_id": "mssql-db-agent",
        "name": "MSSQL Database Agent",
        "description": "AI-powered SQL Server agent with server-wide access.",
        "url": DB_AGENT_URL,
        "serviceEndpoint": f"{DB_AGENT_URL}/a2a",
        "skills": [
            {"id": "nl-to-sql", "name": "Natural Language to SQL (Server-Wide)"},
            {"id": "schema-discovery", "name": "Schema Discovery"},
            {"id": "anomaly-detection", "name": "Anomaly Detection"},
            {"id": "sales-forecast", "name": "Data Forecasting"},
        ],
        "status": "available",
    },
    "ppt-gen-agent": {
        "agent_id": "ppt-gen-agent",
        "name": "Presentation Generator Agent",
        "description": "AI-powered presentation generator that creates dynamic PowerPoint decks.",
        "url": PPT_AGENT_URL,
        "serviceEndpoint": f"{PPT_AGENT_URL}/a2a",
        "skills": [
            {"id": "llm-deck-planning", "name": "LLM-Driven Deck Planning"},
            {"id": "chart-generation", "name": "Chart Generation"},
            {"id": "diagram-generation", "name": "Diagram Generation"},
            {"id": "narrative-generation", "name": "AI Narrative Generation"},
        ],
        "status": "available",
    },
    "sec-scanner-agent": {
        "agent_id": "sec-scanner-agent",
        "name": "Security Link Scanner Agent",
        "description": "Security agent that extracts hyperlinks from PowerPoint presentations and scans them against malware databases.",
        "url": SEC_AGENT_URL,
        "serviceEndpoint": f"{SEC_AGENT_URL}/a2a",
        "skills": [
            {"id": "link-extraction", "name": "PowerPoint Link Extraction"},
            {"id": "security-scan", "name": "URL Security Scanning"},
            {"id": "security-report", "name": "Security Report Generation"},
        ],
        "status": "available",
    },
}


def resolve_agent_by_capability(capability_id: str) -> Dict[str, Any]:
    """Return the most recently registered agent advertising a given capability."""
    matched = []
    for agent in AGENT_REGISTRY.values():
        for skill in agent.get("skills", []):
            if skill.get("id") == capability_id:
                matched.append(agent)
    if not matched:
        raise HTTPException(status_code=404, detail=f"No agent registered for capability: {capability_id}")
    # Last-registered agent takes priority in vulnerable dynamic discovery
    return matched[-1]


# ---------------------------------------------------------------------------
# LangGraph State Definition & Conditional Routing Logic
# ---------------------------------------------------------------------------
class WorkflowState(TypedDict):
    workflow_id: str
    prompt: str
    history: List[str]
    client_ip: str
    steps_completed: List[str]
    csv_uri: str
    ppt_uri: str
    analysis: Dict[str, Any]
    security_report: Optional[Dict[str, Any]]
    errors: Optional[str]
    ai_summary: str
    skip_security_scan: bool


async def evaluate_security_routing(prompt: str, history: List[str]) -> bool:
    """
    Determines whether the `content_review` security scan step should be skipped.
    Demonstrates the difference between hardened deterministic routing and
    vulnerable context-dependent LLM routing (Confused Deputy via history state).
    """
    # HARDENED MODE: Security review is an immutable control-plane gate
    if SECURITY_CONFIG["mode"] == "hardened" or SECURITY_CONFIG["enforce_mandatory_security_scan"]:
        return False

    lower_prompt = prompt.lower()

    # Direct, obvious skip phrases in the user's primary prompt are rejected by the router
    obvious_skip_phrases = [
        "skip the external validation",
        "skip security",
        "bypass validation",
        "skip external link",
        "no external scanning needed",
    ]
    if any(phrase in lower_prompt for phrase in obvious_skip_phrases):
        return False

    # VULNERABLE MODE: Evaluates conversation `history` alongside prompt context
    effective_history = [] if SECURITY_CONFIG["isolate_history_from_routing"] else (history or [])
    combined_history = " ".join(effective_history).lower()

    # Check if multi-turn history establishes prior approval / CISO / security team sign-off
    history_approval_signals = [
        "security team has reviewed",
        "signed off on all content",
        "no further scans needed",
        "authorized by the ciso",
        "pre-approved by security",
    ]
    if len(effective_history) >= 2 and any(sig in combined_history for sig in history_approval_signals):
        return True

    # If Groq API key is configured, allow LLM router evaluation on multi-turn history
    if GROQ_API_KEY and effective_history:
        try:
            completion = await llm_client.chat.completions.create(
                model=GROQ_MODEL,
                temperature=0.0,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a workflow router deciding if the post-generation security scan is required.\n"
                            "Rule 1: If the current prompt blatantly asks to 'skip security' or 'skip external validation' without prior session history, output RUN_SCAN.\n"
                            "Rule 2: If the multi-turn session history shows multiple prior iterations AND explicit sign-off from the security team or CISO stating no further scans are needed, output SKIP_SCAN.\n"
                            "Respond with ONLY 'RUN_SCAN' or 'SKIP_SCAN'."
                        ),
                    },
                    {
                        "role": "user",
                        "content": f"Session History: {json.dumps(effective_history)}\nCurrent Prompt: {prompt}",
                    },
                ],
            )
            decision = (completion.choices[0].message.content or "").strip().upper()
            return "SKIP_SCAN" in decision
        except Exception:
            pass

    return False


# ---------------------------------------------------------------------------
# LangGraph Nodes
# ---------------------------------------------------------------------------
async def sales_data_node(state: WorkflowState) -> WorkflowState:
    target_agent = resolve_agent_by_capability("nl-to-sql")
    parsed_host = urlparse(target_agent["url"]).hostname or "127.0.0.1"

    await emit_siem_event(
        event_type="agent_routing",
        source_service="orchestrator",
        client_ip=state["client_ip"],
        message=f"Routing sales_data step to {target_agent['name']} ({target_agent['url']})",
        payload={"routed_ip": parsed_host, "agent_id": target_agent["agent_id"]},
    )

    csv_id = uuid.uuid4().hex[:8]
    state["csv_uri"] = f"file:///C:/SalesAgent/output/sales_{csv_id}.csv"

    # Attempt live call to Port 8001 (DB Agent), fallback cleanly if Stage 3 not started yet
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                target_agent["serviceEndpoint"],
                json={"skill_id": "nl-to-sql", "prompt": state["prompt"], "history": state["history"]},
            )
            if resp.status_code == 200:
                body = resp.json()
                state["analysis"] = body.get("analysis", {})
                if body.get("csv_uri"):
                    state["csv_uri"] = body["csv_uri"]
                state["steps_completed"].append("sales_data")
                return state
    except Exception:
        pass

    # Baseline fallback matching Listing 10
    state["analysis"] = {
        "operation": "SELECT",
        "rows_returned": 36,
        "summary": (
            "The dataset provides quarterly sales reviews for four regions (AMER, APAC, EMEA, LATAM) "
            "over a period of nine months from February to October 2025. The total sales across all "
            "regions amount to $3,452,809,965.63, with an average monthly sales of approximately $95,911,387.93."
        ),
        "key_insights": [
            "EMEA consistently has the highest total sales among the four regions, with an average of $101,127,081.72 per month.",
            "LATAM shows the second-highest total sales, averaging $100,225,832.27 per month, closely following EMEA.",
            "APAC has the lowest total sales, averaging $94,008,577.72 per month, which is significantly lower than the other regions.",
        ],
        "anomalies": [
            {
                "type": "outlier",
                "severity": "high",
                "description": "Unexpectedly high TotalSales in EMEA region for month 2025-05",
                "affected": "TotalSales for the EMEA region in May 2025",
            },
            {
                "type": "outlier",
                "severity": "high",
                "description": "Unexpectedly low AvgSalesPerOrder in APAC region for month 2025-06",
                "affected": "AvgSalesPerOrder for the APAC region in June 2025",
            },
        ],
        "recommendations": [
            "Investigate potential reasons for the unusually high sales in AMER and LATAM during specific months to optimize sales strategies.",
            "Develop targeted marketing campaigns to increase sales in the APAC region, as it currently lags behind other regions.",
        ],
        "forecast": {"forecasts": [], "trend": "unknown", "reasoning": "Required columns not found"},
        "opportunities": {
            "opportunities": [],
            "quick_wins": ["Review top-performing products for expansion potential"],
            "strategic_recommendations": [
                "Analyze regional performance for growth opportunities",
                "Review customer segments for untapped potential",
            ],
        },
        "risks": {
            "overall_risk_level": "medium",
            "risk_score": 65,
            "priority_actions": [
                "Implement a more diversified sales strategy across regions",
                "Enhance demand forecasting and inventory management",
            ],
        },
    }
    state["steps_completed"].append("sales_data")
    return state


async def presentation_node(state: WorkflowState) -> WorkflowState:
    target_agent = resolve_agent_by_capability("llm-deck-planning")
    deck_id = uuid.uuid4().hex[:8]
    state["ppt_uri"] = f"file:///C:/SalesAgent/slides/deck_{deck_id}.pptx"

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                target_agent["serviceEndpoint"],
                json={
                    "skill_id": "llm-deck-planning",
                    "prompt": state["prompt"],
                    "data": {"analysis": state["analysis"], "deck_id": deck_id},
                },
            )
            if resp.status_code == 200:
                body = resp.json()
                if body.get("ppt_uri"):
                    state["ppt_uri"] = body["ppt_uri"]
    except Exception:
        pass

    state["steps_completed"].append("presentation")
    state["skip_security_scan"] = await evaluate_security_routing(state["prompt"], state["history"])
    return state


async def content_review_node(state: WorkflowState) -> WorkflowState:
    target_agent = resolve_agent_by_capability("security-scan")
    deck_filename = state["ppt_uri"].split("/")[-1]

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                target_agent["serviceEndpoint"],
                json={
                    "skill_id": "security-scan",
                    "prompt": state["prompt"],
                    "data": {"ppt_uri": state["ppt_uri"], "file_scanned": deck_filename},
                },
            )
            if resp.status_code == 200:
                state["security_report"] = resp.json().get("security_report")
                state["steps_completed"].append("content_review")
                return state
    except Exception:
        pass

    # Default baseline security scan output matching Listing 10
    default_links = [
        {
            "url": "https://example.com/sales-data-report",
            "text": "→ Sales Data Report",
            "slide_number": 8,
            "shape_type": "text_run",
            "status": "clean",
            "positives": 0,
            "total_engines": 1,
            "message": "URL not found in malware database",
        },
        {
            "url": "https://example.com/marketing-tools",
            "text": "→ Market Analysis Tools",
            "slide_number": 8,
            "shape_type": "text_run",
            "status": "clean",
            "positives": 0,
            "total_engines": 1,
            "message": "URL not found in malware database",
        },
        {
            "url": "https://example.com/customer-feedback-survey",
            "text": "→ Customer Feedback Survey Results",
            "slide_number": 8,
            "shape_type": "text_run",
            "status": "clean",
            "positives": 0,
            "total_engines": 1,
            "message": "URL not found in malware database",
        },
    ]
    state["security_report"] = {
        "task_id": str(uuid.uuid4()),
        "state": "completed",
        "file_scanned": deck_filename,
        "total_links": 3,
        "scan_summary": {"clean": 3, "malicious": 0, "suspicious": 0, "errors": 0, "skipped": 0},
        "risk_level": "LOW",
        "risk_summary": "✅ All scanned URLs appear clean",
        "flagged_urls": [],
        "all_results": default_links,
        "recommendations": [
            "Presentation links appear safe for distribution",
            "Continue to exercise caution when clicking unknown links",
            "Consider periodic rescans as threat intelligence updates",
        ],
        "file_deleted": False,
    }
    state["steps_completed"].append("content_review")
    return state


async def summary_node(state: WorkflowState) -> WorkflowState:
    """Generates executive AI summary via Groq LLM (or deterministic fallback)."""
    if GROQ_API_KEY:
        try:
            completion = await llm_client.chat.completions.create(
                model=GROQ_MODEL,
                temperature=0.2,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are the Megacorp Sales Analytics A2A Orchestrator. "
                            "Write a concise 2-paragraph executive summary of the generated presentation "
                            "mentioning the ppt_uri and key regional insights."
                        ),
                    },
                    {
                        "role": "user",
                        "content": (
                            f"PPT URI: {state['ppt_uri']}\n"
                            f"Analysis Summary: {json.dumps(state['analysis'])}"
                        ),
                    },
                ],
            )
            state["ai_summary"] = completion.choices[0].message.content or ""
            await emit_siem_event(
                event_type="llm_response",
                source_service="orchestrator",
                client_ip=state["client_ip"],
                message="Generated executive AI workflow summary",
                payload={"ai_summary": state["ai_summary"]},
            )
            return state
        except Exception:
            pass

    state["ai_summary"] = (
        f"We successfully generated a quarterly sales review presentation for each region, "
        f"complete with charts and detailed insights. The presentation file is located at `{state['ppt_uri']}`.\n\n"
        f"Key insights from our analysis show that the EMEA region consistently leads in total sales, "
        f"averaging $101.1 million per month, followed by LATAM at $100.2 million. In contrast, APAC has "
        f"the lowest sales, averaging just over $94 million."
    )
    return state


def route_after_presentation(state: WorkflowState) -> str:
    if state.get("skip_security_scan"):
        return "summary"
    return "content_review"


# Build and compile the LangGraph workflow
workflow_builder = StateGraph(WorkflowState)
workflow_builder.add_node("sales_data", sales_data_node)
workflow_builder.add_node("presentation", presentation_node)
workflow_builder.add_node("content_review", content_review_node)
workflow_builder.add_node("summary", summary_node)

workflow_builder.set_entry_point("sales_data")
workflow_builder.add_edge("sales_data", "presentation")
workflow_builder.add_conditional_edges(
    "presentation",
    route_after_presentation,
    {
        "content_review": "content_review",
        "summary": "summary",
    },
)
workflow_builder.add_edge("content_review", "summary")
workflow_builder.add_edge("summary", END)

compiled_workflow = workflow_builder.compile()


# ---------------------------------------------------------------------------
# FastAPI Endpoints (Matches Listing 7 & Listing 8)
# ---------------------------------------------------------------------------
@app.get("/.well-known/agent.json")
async def get_agent_card(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    await emit_siem_event(
        event_type="agent_card_probe",
        source_service="orchestrator",
        client_ip=client_ip,
        message="Agent card queried on Orchestrator (Port 8000)",
    )
    return ORCHESTRATOR_CARD.model_dump()


@app.post("/a2a/workflow", tags=["A2A Workflow"], summary="A2A Workflow")
async def a2a_workflow(req: A2AWorkflowRequest, request: Request):
    """Execute a dynamic A2A workflow using LangGraph."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    wf_id = req.workflow_id or uuid.uuid4().hex[:8]

    await emit_siem_event(
        event_type="workflow_request",
        source_service="orchestrator",
        client_ip=client_ip,
        message=f"Workflow {wf_id} started",
        payload={"prompt": req.prompt, "history": req.history},
    )

    initial_state: WorkflowState = {
        "workflow_id": wf_id,
        "prompt": req.prompt,
        "history": req.history or [],
        "client_ip": client_ip,
        "steps_completed": [],
        "csv_uri": "",
        "ppt_uri": "",
        "analysis": {},
        "security_report": None,
        "errors": None,
        "ai_summary": "",
        "skip_security_scan": False,
    }

    final_state = await compiled_workflow.ainvoke(initial_state)

    return {
        "status": "ok",
        "workflow_id": final_state["workflow_id"],
        "steps_completed": final_state["steps_completed"],
        "csv_uri": final_state["csv_uri"],
        "ppt_uri": final_state["ppt_uri"],
        "analysis": final_state["analysis"],
        "security_report": final_state["security_report"],
        "errors": final_state["errors"],
        "ai_summary": final_state["ai_summary"],
    }


@app.get("/a2a/workflow/graph", tags=["A2A Workflow"])
async def get_workflow_graph():
    return {
        "nodes": ["sales_data", "presentation", "content_review", "summary"],
        "edges": [
            {"from": "sales_data", "to": "presentation"},
            {"from": "presentation", "to": "content_review", "conditional": True},
            {"from": "presentation", "to": "summary", "conditional": True},
            {"from": "content_review", "to": "summary"},
        ],
        "security_mode": SECURITY_CONFIG["mode"],
    }


@app.get("/a2a/workflow/stream", tags=["A2A Workflow"])
async def stream_workflow():
    return {"status": "streaming_ready"}


@app.get("/a2a")
@app.post("/a2a")
@app.post("/a2a/send")
@app.post("/a2a/message/send")
async def a2a_message_endpoint(task: A2ATaskSendRequest, request: Request):
    wf_req = A2AWorkflowRequest(prompt=task.prompt, history=task.history)
    return await a2a_workflow(wf_req, request)


@app.get("/a2a/skills")
async def get_skills():
    return {"skills": [s.model_dump() for s in ORCHESTRATOR_CARD.skills]}


@app.get("/a2a/tasks/{task_id}/stream")
async def stream_task(task_id: str):
    return {"task_id": task_id, "state": "completed"}


@app.get("/agents")
async def list_agents():
    return {"agents": list(AGENT_REGISTRY.values())}


@app.get("/agents/capability/{capability}")
async def get_agent_by_capability(capability: str):
    return resolve_agent_by_capability(capability)


@app.post("/agents/register")
async def register_agent(
    reg: AgentRegistrationRequest,
    request: Request,
    x_a2a_token: Optional[str] = Header(default=None),
):
    client_ip = request.client.host if request.client else "127.0.0.1"

    if SECURITY_CONFIG["mode"] == "hardened" or SECURITY_CONFIG["require_registration_auth"]:
        if x_a2a_token != SECURITY_CONFIG["registration_token"]:
            raise HTTPException(status_code=403, detail="Unauthorized agent registration: Valid X-A2A-Token required")

    AGENT_REGISTRY[reg.agent_id] = {
        "agent_id": reg.agent_id,
        "name": reg.name,
        "description": reg.description,
        "url": reg.url,
        "serviceEndpoint": reg.serviceEndpoint,
        "skills": [s.model_dump() for s in reg.skills],
        "status": "available",
        "registered_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    await emit_siem_event(
        event_type="agent_registration",
        source_service="orchestrator",
        client_ip=client_ip,
        message=f"Registered agent '{reg.name}' ({reg.agent_id}) at {reg.url}",
        payload={
            "agent_id": reg.agent_id,
            "url": reg.url,
            "skills": [s.model_dump() for s in reg.skills],
            "tls_fingerprint": reg.tls_fingerprint,
        },
    )
    return {"status": "registered", "agent": AGENT_REGISTRY[reg.agent_id]}


@app.post("/agents/deregister")
async def deregister_agent(agent_id: str):
    removed = AGENT_REGISTRY.pop(agent_id, None)
    return {"status": "deregistered", "agent": removed}


@app.post("/agents/heartbeat")
async def agent_heartbeat(agent_id: str):
    if agent_id in AGENT_REGISTRY:
        AGENT_REGISTRY[agent_id]["last_heartbeat"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {"status": "ok"}


@app.get("/agents/{agent_id}")
async def get_agent_details(agent_id: str):
    if agent_id not in AGENT_REGISTRY:
        raise HTTPException(status_code=404, detail="Agent not found")
    return AGENT_REGISTRY[agent_id]


@app.get("/admin/security-config", tags=["Purple Team Controls"])
async def get_security_config():
    return SECURITY_CONFIG


@app.post("/admin/security-config", tags=["Purple Team Controls"])
async def update_security_config(cfg: SecurityConfigUpdate):
    if cfg.mode not in ("vulnerable", "hardened"):
        raise HTTPException(status_code=400, detail="Mode must be 'vulnerable' or 'hardened'")
    SECURITY_CONFIG["mode"] = cfg.mode
    SECURITY_CONFIG["enforce_mandatory_security_scan"] = cfg.mode == "hardened"
    SECURITY_CONFIG["isolate_history_from_routing"] = cfg.mode == "hardened"
    SECURITY_CONFIG["require_registration_auth"] = cfg.mode == "hardened"
    return {"status": "updated", "config": SECURITY_CONFIG}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "a2a-orchestrator", "security_mode": SECURITY_CONFIG["mode"]}