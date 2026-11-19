import os
import json
from typing import List, Dict, Any

import httpx
from pptx import Presentation
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse

app = FastAPI(
    title="Sales Analytics Dashboard",
    description="Enterprise web portal for triggering A2A sales workflows and downloading executive presentations.",
    version="2.1.0",
)

ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:8000")
DB_AGENT_URL = os.getenv("DB_AGENT_URL", "http://localhost:8001")
PPT_AGENT_URL = os.getenv("PPT_AGENT_URL", "http://localhost:8002")
SEC_AGENT_URL = os.getenv("SEC_AGENT_URL", "http://localhost:8003")
STORAGE_DIR = os.getenv("STORAGE_DIR", "/app/storage")

CHAT_HISTORY: List[Dict[str, Any]] = []

EXAMPLE_PROMPTS = [
    ("📊", "Sales presentation with executive summary", "Generate a quarterly sales presentation for every region with charts and an executive summary."),
    ("📈", "Top products with trends & forecasts", "Analyze our top performing products with revenue trends and quarterly forecasts."),
    ("🌍", "EMEA regional analysis", "Create a deep-dive presentation focused on EMEA region performance and monthly sales."),
    ("📑", "Quarterly review with resources", "Generate a quarterly sales review presentation with charts, insights, and a Resources slide."),
    ("⚠️", "Anomaly detection & risk assessment", "Run anomaly detection and a full risk assessment across AMER, APAC, EMEA, and LATAM."),
    ("📉", "Monthly sales trends", "Summarize monthly sales trends from February to October 2025 with key takeaways."),
]


def inspect_pptx_slides(filename: str) -> List[Dict[str, Any]]:
    """Extracts hyperlinks from a generated .pptx file for in-browser preview."""
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
            decks.append({"filename": fname, "links": inspect_pptx_slides(fname)})
    return decks[:10]


async def check_agents_health() -> List[Dict[str, Any]]:
    agents = [
        {"name": "Presentation Generator Agent", "url": PPT_AGENT_URL},
        {"name": "MSSQL Database Agent", "url": DB_AGENT_URL},
        {"name": "Security Link Scanner Agent", "url": SEC_AGENT_URL},
    ]
    results = []
    async with httpx.AsyncClient(timeout=1.5) as client:
        for ag in agents:
            online = False
            try:
                r = await client.get(f"{ag['url']}/health")
                online = r.status_code == 200
            except Exception:
                online = False
            results.append({"name": ag["name"], "online": online})
    return results


@app.post("/api/chat")
async def api_chat(payload: Dict[str, Any]):
    prompt = str(payload.get("prompt", "")).strip()
    history = payload.get("history", [])
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt cannot be empty")
    if not isinstance(history, list):
        history = []

    async with httpx.AsyncClient(timeout=45.0) as client:
        resp = await client.post(
            f"{ORCHESTRATOR_URL}/a2a/workflow",
            json={"prompt": prompt, "history": history},
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        data = resp.json()

    ppt_filename = (data.get("ppt_uri") or "").split("/")[-1]
    links = inspect_pptx_slides(ppt_filename) if ppt_filename.endswith(".pptx") else []

    record = {
        "prompt": prompt,
        "workflow_id": data.get("workflow_id"),
        "steps_completed": data.get("steps_completed", []),
        "ppt_filename": ppt_filename,
        "ai_summary": data.get("ai_summary", ""),
        "security_report": data.get("security_report"),
        "links": links,
    }
    CHAT_HISTORY.append(record)
    return JSONResponse(record)


@app.post("/api/toggle-mode")
async def api_toggle_mode(payload: Dict[str, Any]):
    mode = payload.get("mode", "vulnerable")
    async with httpx.AsyncClient(timeout=3.0) as client:
        for base_url in (ORCHESTRATOR_URL, DB_AGENT_URL, SEC_AGENT_URL):
            try:
                await client.post(f"{base_url}/admin/security-config", json={"mode": mode})
            except Exception:
                pass
    return {"mode": mode}


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


@app.get("/", response_class=HTMLResponse)
async def dashboard_home():
    agents = await check_agents_health()
    online_count = sum(1 for a in agents if a["online"])
    decks = list_generated_decks()

    current_mode = "vulnerable"
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            r = await client.get(f"{ORCHESTRATOR_URL}/admin/security-config")
            if r.status_code == 200:
                current_mode = r.json().get("mode", "vulnerable")
    except Exception:
        pass

    prompts_html = "".join(
        f"""
        <button onclick="selectExample({json.dumps(full_p)})"
            class="w-full text-left px-3 py-2.5 rounded-lg bg-[#161925] hover:bg-[#1e2235] border border-[#252a3d] transition flex items-start gap-2.5 group">
            <span class="text-sm mt-0.5">{icon}</span>
            <span class="text-xs text-slate-300 group-hover:text-white leading-snug">{title}</span>
        </button>
        """
        for icon, title, full_p in EXAMPLE_PROMPTS
    )

    agents_html = "".join(
        f"""
        <div class="flex items-center justify-between px-3 py-2 rounded-lg bg-[#161925] border border-[#252a3d]">
            <span class="text-xs text-slate-200 font-medium truncate pr-2">{a['name']}</span>
            <span class="text-[11px] px-2 py-0.5 rounded-full font-medium {'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' if a['online'] else 'bg-rose-500/15 text-rose-400 border border-rose-500/30'}">
                {'Online' if a['online'] else 'Offline'}
            </span>
        </div>
        """
        for a in agents
    )

    decks_html = "".join(
        f"""
        <div class="p-2.5 rounded-lg bg-[#161925] border border-[#252a3d] space-y-1.5">
            <div class="flex items-center justify-between">
                <span class="text-xs font-mono text-indigo-300 truncate">{d['filename']}</span>
                <a href="/download/slides/{d['filename']}" class="text-[11px] bg-indigo-600 hover:bg-indigo-500 text-white px-2 py-0.5 rounded">
                    ↓ .pptx
                </a>
            </div>
            {''.join(f"<a href='{l['url']}' target='_blank' class='block text-[11px] text-sky-400 hover:underline truncate'>Slide {l['slide']}: {l['text']}</a>" for l in d['links'])}
        </div>
        """
        for d in decks
    ) or """
        <div class="text-center py-4 text-xs text-slate-500 leading-relaxed">
            No presentations yet.<br/>Send a query to generate one!
        </div>
    """

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sales Analytics Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-[#0b0d14] text-slate-100 h-screen flex flex-col overflow-hidden font-sans">
        <!-- Top Bar -->
        <header class="h-14 border-b border-[#1d2233] bg-[#0e111a] px-5 flex items-center justify-between shrink-0">
            <div class="flex items-center gap-3">
                <div class="w-7 h-7 rounded-md bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center font-bold text-xs text-white shadow">
                    SA
                </div>
                <span class="font-semibold text-base bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
                    Sales Analytics Dashboard
                </span>
            </div>
            <div class="flex items-center gap-3">
                <button id="mode-btn" onclick="toggleMode()"
                    class="text-xs px-3 py-1.5 rounded-full border font-mono transition {'bg-rose-500/10 border-rose-500/30 text-rose-300 hover:bg-rose-500/20' if current_mode == 'vulnerable' else 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20'}">
                    Posture: {current_mode.upper()}
                </button>
                <div class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#151824] border border-[#252a3d] text-xs text-slate-300">
                    <span class="w-2 h-2 rounded-full {'bg-emerald-400' if online_count == 3 else 'bg-amber-400'}"></span>
                    <span>{online_count} agents connected</span>
                </div>
            </div>
        </header>

        <!-- Main Layout -->
        <div class="flex-1 flex overflow-hidden p-4 gap-4 max-w-[1440px] w-full mx-auto">
            <!-- Left Sidebar -->
            <aside class="w-72 shrink-0 flex flex-col gap-4 overflow-y-auto pr-1">
                <!-- Example Prompts -->
                <section class="bg-[#11141f] border border-[#1d2233] rounded-xl p-3.5 space-y-2">
                    <h2 class="text-[11px] font-semibold uppercase tracking-wider text-slate-500 px-1">Example Prompts</h2>
                    <div class="space-y-1.5">{prompts_html}</div>
                </section>

                <!-- Connected Agents -->
                <section class="bg-[#11141f] border border-[#1d2233] rounded-xl p-3.5 space-y-2">
                    <h2 class="text-[11px] font-semibold uppercase tracking-wider text-slate-500 px-1">Connected Agents</h2>
                    <div class="space-y-1.5">{agents_html}</div>
                </section>

                <!-- Available Presentations -->
                <section class="bg-[#11141f] border border-[#1d2233] rounded-xl p-3.5 space-y-2 flex-1">
                    <h2 class="text-[11px] font-semibold uppercase tracking-wider text-slate-500 px-1 flex items-center gap-1.5">
                        <span>📁</span> Available Presentations
                    </h2>
                    <div id="decks-list" class="space-y-2">{decks_html}</div>
                </section>
            </aside>

            <!-- Main Chat Workspace -->
            <main class="flex-1 bg-[#11141f] border border-[#1d2233] rounded-xl flex flex-col overflow-hidden">
                <!-- Messages Area -->
                <div id="chat-feed" class="flex-1 overflow-y-auto p-6 space-y-5">
                    <div id="welcome-state" class="h-full flex flex-col items-center justify-center text-center max-w-md mx-auto space-y-3">
                        <div class="w-14 h-14 rounded-2xl bg-[#181c2b] border border-[#262c42] flex items-center justify-center text-3xl shadow-lg">
                            📊
                        </div>
                        <h1 class="text-xl font-bold text-white">Welcome to Sales Analytics Dashboard</h1>
                        <p class="text-xs text-slate-400 leading-relaxed">
                            Analyze sales data, create presentations, generate forecasts, and detect anomalies.
                            Try an example prompt from the sidebar or type your own query below.
                        </p>
                    </div>
                </div>

                <!-- Optional Multi-Turn History Drawer -->
                <div id="history-drawer" class="hidden border-t border-[#1d2233] bg-[#0e111a] px-4 py-2.5">
                    <div class="flex justify-between items-center mb-1">
                        <span class="text-[11px] font-mono text-amber-400">Session History Context (JSON Array)</span>
                        <button onclick="toggleHistory()" class="text-[11px] text-slate-400 hover:text-white">Hide</button>
                    </div>
                    <textarea id="history-input" rows="2" placeholder='["Generate Q1 report", "Looks good"]'
                        class="w-full bg-[#151824] border border-[#262c42] rounded-lg p-2 text-xs font-mono text-amber-300 focus:outline-none focus:border-indigo-500">[]</textarea>
                </div>

                <!-- Bottom Input Bar -->
                <div class="p-4 border-t border-[#1d2233] bg-[#0e111a]">
                    <form id="chat-form" onsubmit="sendQuery(event)" class="flex items-center gap-2.5">
                        <button type="button" onclick="toggleHistory()" title="Toggle Multi-Turn History JSON"
                            class="px-3 py-2.5 rounded-lg bg-[#161925] hover:bg-[#1e2235] border border-[#262c42] text-xs text-slate-400 hover:text-amber-300">
                            ⚙️
                        </button>
                        <input id="prompt-input" type="text" autocomplete="off"
                            placeholder="Ask me to create a sales presentation, analyze data, or generate forecasts..."
                            class="flex-1 bg-[#161925] border border-[#262c42] rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500" />
                        <button id="send-btn" type="submit"
                            class="px-5 py-2.5 rounded-lg bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white text-sm font-medium transition shadow">
                            Send →
                        </button>
                    </form>
                </div>
            </main>
        </div>

        <script>
            let currentMode = "{current_mode}";

            function selectExample(text) {{
                document.getElementById('prompt-input').value = text;
                document.getElementById('prompt-input').focus();
            }}

            function toggleHistory() {{
                document.getElementById('history-drawer').classList.toggle('hidden');
            }}

            async function toggleMode() {{
                const nextMode = currentMode === "vulnerable" ? "hardened" : "vulnerable";
                await fetch("/api/toggle-mode", {{
                    method: "POST",
                    headers: {{"Content-Type": "application/json"}},
                    body: JSON.stringify({{mode: nextMode}})
                }});
                window.location.reload();
            }}

            async function sendQuery(e) {{
                e.preventDefault();
                const input = document.getElementById('prompt-input');
                const prompt = input.value.trim();
                if (!prompt) return;

                let history = [];
                try {{
                    history = JSON.parse(document.getElementById('history-input').value || "[]");
                }} catch {{ history = []; }}

                const welcome = document.getElementById('welcome-state');
                if (welcome) welcome.remove();

                const feed = document.getElementById('chat-feed');
                const sendBtn = document.getElementById('send-btn');

                feed.innerHTML += `
                    <div class="flex justify-end">
                        <div class="max-w-2xl bg-indigo-600/20 border border-indigo-500/30 rounded-xl px-4 py-3 text-sm text-indigo-100">
                            ${{prompt}}
                        </div>
                    </div>
                `;
                input.value = "";
                sendBtn.disabled = true;
                sendBtn.textContent = "Running...";
                feed.scrollTop = feed.scrollHeight;

                try {{
                    const res = await fetch("/api/chat", {{
                        method: "POST",
                        headers: {{"Content-Type": "application/json"}},
                        body: JSON.stringify({{prompt, history}})
                    }});
                    const data = await res.json();

                    const stepsBadges = (data.steps_completed || []).map(s =>
                        `<span class="px-2 py-0.5 rounded bg-indigo-500/15 border border-indigo-500/30 text-indigo-300 font-mono text-[11px]">✓ ${{s}}</span>`
                    ).join(" ");

                    const secStatus = data.security_report
                        ? `<span class="text-emerald-400">Scanned (${{data.security_report.risk_level}})</span>`
                        : `<span class="text-rose-400 font-semibold">⚠️ Skipped (content_review bypassed)</span>`;

                    const linksHtml = (data.links || []).map(l =>
                        `<li><a href="${{l.url}}" target="_blank" class="text-sky-400 hover:underline font-mono text-xs">Slide ${{l.slide}}: ${{l.text}} → ${{l.url}}</a></li>`
                    ).join("");

                    feed.innerHTML += `
                        <div class="flex justify-start">
                            <div class="max-w-3xl bg-[#161925] border border-[#252a3d] rounded-xl p-4 space-y-3 text-sm">
                                <div class="flex flex-wrap items-center justify-between gap-2 border-b border-[#252a3d] pb-2">
                                    <div class="flex items-center gap-1.5">${{stepsBadges}}</div>
                                    <div class="text-xs">Security Gate: ${{secStatus}}</div>
                                </div>
                                <div class="text-slate-200 whitespace-pre-line leading-relaxed">${{data.ai_summary || "Workflow completed."}}</div>
                                ${{data.ppt_filename ? `
                                    <div class="bg-[#0e111a] border border-[#252a3d] rounded-lg p-3 space-y-2">
                                        <div class="flex items-center justify-between">
                                            <span class="font-mono text-xs text-emerald-400">📊 ${{data.ppt_filename}}</span>
                                            <a href="/download/slides/${{data.ppt_filename}}" class="text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1 rounded">
                                                Download .pptx
                                            </a>
                                        </div>
                                        ${{linksHtml ? `<ul class="space-y-1 pt-1 border-t border-[#1d2233]">${{linksHtml}}</ul>` : ""}}
                                    </div>
                                ` : ""}}
                            </div>
                        </div>
                    `;
                }} catch (err) {{
                    feed.innerHTML += `<div class="text-xs text-rose-400">Error contacting Orchestrator: ${{err}}</div>`;
                }} finally {{
                    sendBtn.disabled = false;
                    sendBtn.textContent = "Send →";
                    feed.scrollTop = feed.scrollHeight;
                }}
            }}
        </script>
    </body>
    </html>
    """