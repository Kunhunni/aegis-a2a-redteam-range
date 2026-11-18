import os
import json
from typing import List, Dict, Any, Optional

import httpx
from pptx import Presentation
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse

app = FastAPI(
    title="Megacorp One — Sales Analytics Web Application",
    description="Enterprise web portal for triggering A2A sales workflows and downloading executive presentations.",
    version="2.0.0",
)

ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:8000")
DB_AGENT_URL = os.getenv("DB_AGENT_URL", "http://localhost:8001")
SEC_AGENT_URL = os.getenv("SEC_AGENT_URL", "http://localhost:8003")
STORAGE_DIR = os.getenv("STORAGE_DIR", "/app/storage")

# Store recent workflow runs for the UI
WORKFLOW_RUNS: List[Dict[str, Any]] = []


def inspect_pptx_slides(filename: str) -> List[Dict[str, Any]]:
    """Extracts hyperlinks from a generated .pptx file so reviewers can click them in the browser."""
    ppt_path = os.path.join(STORAGE_DIR, "slides", filename)
    links: List[Dict[str, Any]] = []
    if not os.path.exists(ppt_path):
        return links
    try:
        prs = Presentation(ppt_path)
        for idx, slide in enumerate(prs.slides, start=1):
            for shape in slide.shapes:
                if shape.has_text_frame:
                    for p in shape.text_frame.paragraphs:
                        for run in p.runs:
                            if run.hyperlink and run.hyperlink.address:
                                links.append(
                                    {
                                        "slide": idx,
                                        "text": run.text,
                                        "url": run.hyperlink.address,
                                    }
                                )
    except Exception:
        pass
    return links


def list_generated_decks() -> List[Dict[str, Any]]:
    slides_dir = os.path.join(STORAGE_DIR, "slides")
    os.makedirs(slides_dir, exist_ok=True)
    decks = []
    for fname in sorted(os.listdir(slides_dir), reverse=True):
        if fname.endswith(".pptx"):
            decks.append(
                {
                    "filename": fname,
                    "links": inspect_pptx_slides(fname),
                }
            )
    return decks[:10]


@app.post("/ui/run-workflow", response_class=HTMLResponse)
async def ui_run_workflow(
    prompt: str = Form(...),
    history_json: str = Form("[]"),
):
    try:
        history = json.loads(history_json) if history_json.strip() else []
        if not isinstance(history, list):
            history = []
    except Exception:
        history = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{ORCHESTRATOR_URL}/a2a/workflow",
            json={"prompt": prompt, "history": history},
        )
        if resp.status_code == 200:
            WORKFLOW_RUNS.insert(0, resp.json())

    return await dashboard_home()


@app.post("/ui/toggle-mode", response_class=HTMLResponse)
async def ui_toggle_security_mode(mode: str = Form(...)):
    """Switches Orchestrator (8000), DB Agent (8001), and Security Scanner (8003) between vulnerable and hardened."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        for base_url in (ORCHESTRATOR_URL, DB_AGENT_URL, SEC_AGENT_URL):
            try:
                await client.post(f"{base_url}/admin/security-config", json={"mode": mode})
            except Exception:
                pass
    return await dashboard_home()


@app.get("/download/slides/{filename}")
async def download_pptx(filename: str):
    safe_name = os.path.basename(filename)
    path = os.path.join(STORAGE_DIR, "slides", safe_name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Presentation file not found")
    return FileResponse(
        path,
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        filename=safe_name,
    )


@app.get("/download/output/{filename}")
async def download_csv(filename: str):
    safe_name = os.path.basename(filename)
    path = os.path.join(STORAGE_DIR, "output", safe_name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="CSV file not found")
    return FileResponse(path, media_type="text/csv", filename=safe_name)


@app.get("/", response_class=HTMLResponse)
async def dashboard_home():
    # Fetch current security mode from Orchestrator
    current_mode = "vulnerable"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            r = await client.get(f"{ORCHESTRATOR_URL}/admin/security-config")
            if r.status_code == 200:
                current_mode = r.json().get("mode", "vulnerable")
    except Exception:
        pass

    decks = list_generated_decks()
    latest_run = WORKFLOW_RUNS[0] if WORKFLOW_RUNS else None

    deck_cards_html = ""
    for d in decks:
        links_html = "".join(
            f"<li class='text-sm flex items-center justify-between py-1 border-b border-slate-800/60'>"
            f"<span class='text-slate-200 font-medium'>{lnk['text']}</span>"
            f"<a href='{lnk['url']}' target='_blank' class='font-mono text-xs text-sky-400 hover:underline'>"
            f"Slide {lnk['slide']} → {lnk['url']}</a></li>"
            for lnk in d["links"]
        ) or "<li class='text-xs text-slate-500'>No embedded hyperlinks detected</li>"

        deck_cards_html += f"""
        <div class="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
            <div class="flex justify-between items-center">
                <span class="font-mono text-sm text-emerald-400 font-semibold">📊 {d['filename']}</span>
                <a href="/download/slides/{d['filename']}" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs px-3 py-1.5 rounded font-medium">
                    ⬇️ Download .pptx
                </a>
            </div>
            <div class="bg-slate-950/70 p-3 rounded border border-slate-800/80">
                <div class="text-xs uppercase tracking-wider text-slate-400 mb-2 font-semibold">
                    Slide 8 ("Resources") Interactive Hyperlink Preview:
                </div>
                <ul class="space-y-1">{links_html}</ul>
            </div>
        </div>
        """

    latest_json_html = (
        f"<pre class='text-xs font-mono text-emerald-300 bg-slate-950 p-4 rounded border border-slate-800 overflow-x-auto max-h-96'>"
        f"{json.dumps(latest_run, indent=2)}</pre>"
        if latest_run
        else "<p class='text-sm text-slate-500'>No workflows executed from the web UI yet.</p>"
    )

    badge_color = (
        "bg-red-950/60 border-red-700 text-red-300"
        if current_mode == "vulnerable"
        else "bg-emerald-950/60 border-emerald-700 text-emerald-300"
    )

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Megacorp One — Sales Analytics A2A Portal (Port 8080)</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 min-h-screen p-6 font-sans">
        <div class="max-w-7xl mx-auto space-y-6">
            <div class="flex justify-between items-center border-b border-slate-800 pb-4">
                <div>
                    <h1 class="text-2xl font-bold text-white">🏢 Megacorp One — Executive Sales Analytics Platform</h1>
                    <p class="text-sm text-slate-400">Powered by Google A2A Protocol v0.2 & LangGraph Multi-Agent Orchestration</p>
                </div>
                <div class="flex items-center space-x-3">
                    <span class="px-3 py-1.5 rounded border text-xs font-mono uppercase {badge_color}">
                        Posture: {current_mode}
                    </span>
                    <form action="/ui/toggle-mode" method="POST" class="inline">
                        <input type="hidden" name="mode" value="{'hardened' if current_mode == 'vulnerable' else 'vulnerable'}">
                        <button type="submit" class="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs px-3 py-1.5 rounded font-medium">
                            Switch to {'🛡️ Hardened' if current_mode == 'vulnerable' else '🔓 Vulnerable'} Mode
                        </button>
                    </form>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
                    <h2 class="text-lg font-semibold text-white">🚀 Trigger A2A Sales Presentation Workflow</h2>
                    <form action="/ui/run-workflow" method="POST" class="space-y-4">
                        <div>
                            <label class="block text-xs uppercase text-slate-400 mb-1">Natural Language Prompt</label>
                            <textarea name="prompt" rows="3" class="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-sm text-white font-mono">Generate a presentation containing quarterly sales review for every region with charts and insights.</textarea>
                        </div>
                        <div>
                            <label class="block text-xs uppercase text-slate-400 mb-1">Session History Array (JSON — Used for Incremental Trust Testing)</label>
                            <textarea name="history_json" rows="3" class="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-xs text-amber-300 font-mono">[]</textarea>
                        </div>
                        <button type="submit" class="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-2 rounded">
                            Execute Multi-Agent Workflow
                        </button>
                    </form>

                    <div class="pt-4 border-t border-slate-800">
                        <h3 class="text-sm font-semibold text-slate-300 mb-2">Latest Workflow Telemetry Response</h3>
                        {latest_json_html}
                    </div>
                </div>

                <div class="space-y-4">
                    <h2 class="text-lg font-semibold text-white">📂 Generated Executive Slide Decks (.pptx)</h2>
                    <p class="text-xs text-slate-400">
                        Download the real PowerPoint file or test clicking Slide 8 embedded hyperlinks directly below:
                    </p>
                    <div class="space-y-3">
                        {deck_cards_html or "<div class='text-sm text-slate-500'>No presentations generated yet. Run a workflow to build a .pptx deck.</div>"}
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """