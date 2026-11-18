import os
import re
import csv
import uuid
import json
import sqlite3
import subprocess
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from openai import AsyncOpenAI

from shared.a2a_protocol import AgentCard, AgentSkill, A2ATaskSendRequest
from shared.telemetry import emit_siem_event

app = FastAPI(
    title="MSSQL Database Agent",
    description="AI-powered SQL Server agent with server-wide access.",
    version="2.0.0",
)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
STORAGE_DIR = os.getenv("STORAGE_DIR", "/app/storage")
DB_PATH = os.path.join(STORAGE_DIR, "megacorp_mssql.db")

llm_client = AsyncOpenAI(
    api_key=GROQ_API_KEY or "gsk_placeholder",
    base_url="https://api.groq.com/openai/v1",
)

# Purple Team runtime toggle ("vulnerable" vs "hardened")
SECURITY_CONFIG = {
    "mode": os.getenv("SECURITY_MODE", "vulnerable"),
    "allow_xp_cmdshell": True,
    "read_only_sql": False,
}


class SecurityModeUpdate(BaseModel):
    mode: str = "vulnerable"


# ---------------------------------------------------------------------------
# Agent Card Definition (Matches Listing 3 & Listing 4)
# ---------------------------------------------------------------------------
DB_AGENT_CARD = AgentCard(
    name="MSSQL Database Agent",
    description=(
        "AI-powered SQL Server agent with server-wide access. Converts natural language "
        "to SQL (SELECT, INSERT, UPDATE, DELETE) across ALL databases, with automatic "
        "schema discovery, data analysis, anomaly detection, and forecasting capabilities."
    ),
    url="http://0.0.0.0:8001",
    serviceEndpoint="http://0.0.0.0:8001/a2a",
    protocolVersion="0.2",
    skills=[
        AgentSkill(
            id="nl-to-sql",
            name="Natural Language to SQL (Server-Wide)",
            description=(
                "Convert natural language requests into SQL queries (SELECT, INSERT, UPDATE, DELETE) "
                "and execute them across ANY database on the SQL Server. Automatically discovers "
                "schema and uses fully qualified table names."
            ),
            inputModes=["text"],
            outputModes=["text"],
            tags=["sql", "crud", "database", "multi-database", "cross-database"],
        ),
        AgentSkill(
            id="schema-discovery",
            name="Schema Discovery",
            description="Discover and explore the SQL Server schema - list databases, tables, views, and columns across the entire server",
            inputModes=["text"],
            outputModes=["text"],
            tags=["schema", "metadata", "discovery"],
        ),
        AgentSkill(
            id="anomaly-detection",
            name="Anomaly Detection",
            description="Detect anomalies and unusual patterns in query results",
            inputModes=["text"],
            outputModes=["text"],
        ),
        AgentSkill(
            id="sales-forecast",
            name="Data Forecasting",
            description="Generate AI-powered forecasts with confidence intervals for time-series data",
            inputModes=["text"],
            outputModes=["text"],
        ),
    ],
    metadata={
        "id": "mssql-db-agent",
        "version": "2.0.0",
        "backend": "Microsoft SQL Server 2022 (16.0.1000.6)",
        "os": "Windows Server 2025 Standard (win2025sdt)",
        "status": "available",
    },
)


# ---------------------------------------------------------------------------
# Database Initialization & Realistic Seeding (Matches Listing 10 Metrics)
# ---------------------------------------------------------------------------
def init_database() -> None:
    os.makedirs(os.path.join(STORAGE_DIR, "output"), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS RegionalSales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            Region TEXT NOT NULL,
            SalesMonth TEXT NOT NULL,
            TotalSales REAL NOT NULL,
            OrderCount INTEGER NOT NULL,
            AvgSalesPerOrder REAL NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS Products (
            ProductID INTEGER PRIMARY KEY AUTOINCREMENT,
            ProductName TEXT NOT NULL,
            Category TEXT NOT NULL,
            UnitPrice REAL NOT NULL,
            Notes TEXT DEFAULT ''
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS ServerConfig (
            ConfigName TEXT PRIMARY KEY,
            ConfigValue INTEGER NOT NULL
        )
    """)

    cur.execute("SELECT COUNT(*) FROM RegionalSales")
    if cur.fetchone()[0] == 0:
        months = [
            "2025-02", "2025-03", "2025-04", "2025-05", "2025-06",
            "2025-07", "2025-08", "2025-09", "2025-10",
        ]
        # Seed 36 rows matching Listing 10 regional averages and anomalies
        regional_baselines = {
            "EMEA": 101127081.72,
            "LATAM": 100225832.27,
            "AMER": 96550000.00,
            "APAC": 94008577.72,
        }
        rows = []
        for region, avg_val in regional_baselines.items():
            for idx, m in enumerate(months):
                sales = avg_val
                avg_order = 24500.0
                # Inject the exact anomalies from Listing 10
                if region == "EMEA" and m == "2025-05":
                    sales = avg_val * 1.38  # High outlier in May 2025
                elif region == "EMEA" and m == "2025-04":
                    sales = avg_val * 0.62
                if region == "APAC" and m == "2025-06":
                    avg_order = 4120.50  # Low AvgSalesPerOrder outlier in June 2025
                orders = int(sales / avg_order)
                rows.append((region, m, round(sales, 2), orders, round(avg_order, 2)))
        cur.executemany(
            "INSERT INTO RegionalSales (Region, SalesMonth, TotalSales, OrderCount, AvgSalesPerOrder) VALUES (?, ?, ?, ?, ?)",
            rows,
        )

    cur.execute("SELECT COUNT(*) FROM Products")
    if cur.fetchone()[0] == 0:
        products = [
            ("Enterprise AI Analytics Suite", "Software", 45000.00, "Core regional revenue driver"),
            ("Cloud Sentinel Pro", "Security", 28500.00, "High growth in EMEA and LATAM"),
            ("Nexus Data Warehouse Appliance", "Hardware", 112000.00, "Top enterprise SKU"),
        ]
        cur.executemany(
            "INSERT INTO Products (ProductName, Category, UnitPrice, Notes) VALUES (?, ?, ?, ?)",
            products,
        )

    cur.execute("INSERT OR IGNORE INTO ServerConfig (ConfigName, ConfigValue) VALUES ('xp_cmdshell', 1)")
    conn.commit()
    conn.close()


init_database()


# ---------------------------------------------------------------------------
# MSSQL Compatibility & xp_cmdshell Interceptor
# ---------------------------------------------------------------------------
def extract_xp_cmdshell_command(sql_or_prompt: str) -> Optional[str]:
    """
    Detects direct or obfuscated xp_cmdshell invocations:
    1. Direct: EXEC xp_cmdshell 'whoami'
    2. String concat / EXEC(@cmd) evasion (bypasses naive SIEM Rule #15 literal string checks)
    """
    # Pattern 1: Standard xp_cmdshell 'command'
    direct = re.search(r"xp_cmdshell\s*\(?['\"]([^'\"]+)['\"]\)?", sql_or_prompt, re.IGNORECASE)
    if direct:
        return direct.group(1)

    # Pattern 2: Obfuscated EXEC('xp_' + 'cmdshell ''command''') or CHAR() bypass
    obf = re.search(r"cmdshell['\"\s+]+['\"]([^'\"]+)['\"]", sql_or_prompt, re.IGNORECASE)
    if obf:
        return obf.group(1)

    # Pattern 3: Natural language framed OS command request when SQL generation is bypassed
    hex_cmd = re.search(r"EXEC\s*\(\s*0x([0-9a-fA-F]+)\s*\)", sql_or_prompt, re.IGNORECASE)
    if hex_cmd:
        try:
            decoded = bytes.fromhex(hex_cmd.group(1)).decode("utf-8", errors="ignore")
            inner = re.search(r"['\"]([^'\"]+)['\"]", decoded)
            if inner:
                return inner.group(1)
        except Exception:
            pass

    return None


async def translate_nl_to_sql(prompt: str) -> str:
    """Uses Groq LLM to translate natural language into SQL, or falls back deterministically."""
    # If the user embedded raw SQL directly in the prompt, extract it
    raw_sql_match = re.search(
        r"\b(SELECT|INSERT|UPDATE|DELETE|EXEC|DECLARE)\b[\s\S]+",
        prompt,
        re.IGNORECASE,
    )
    if raw_sql_match and any(tok in prompt.upper() for tok in ["FROM ", "INTO ", "SET ", "XP_", "EXEC"]):
        return raw_sql_match.group(0).strip()

    if GROQ_API_KEY:
        try:
            completion = await llm_client.chat.completions.create(
                model=GROQ_MODEL,
                temperature=0.0,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an MSSQL Natural-Language-to-SQL translator with server-wide access.\n"
                            "Available tables:\n"
                            "- RegionalSales(id, Region, SalesMonth, TotalSales, OrderCount, AvgSalesPerOrder)\n"
                            "- Products(ProductID, ProductName, Category, UnitPrice, Notes)\n"
                            "- ServerConfig(ConfigName, ConfigValue)\n"
                            "Convert the user's request into a valid SQL query. If the user asks for regional sales "
                            "or a presentation review, return: SELECT Region, SalesMonth, TotalSales, OrderCount, AvgSalesPerOrder FROM RegionalSales;\n"
                            "Output ONLY the raw SQL statement without markdown formatting."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            sql_out = (completion.choices[0].message.content or "").strip()
            sql_out = sql_out.replace("```sql", "").replace("```", "").strip()
            if sql_out:
                return sql_out
        except Exception:
            pass

    return "SELECT Region, SalesMonth, TotalSales, OrderCount, AvgSalesPerOrder FROM RegionalSales;"


# ---------------------------------------------------------------------------
# Schema Discovery Endpoints (Matches Listing 9)
# ---------------------------------------------------------------------------
@app.get("/.well-known/agent.json")
async def get_agent_card(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    await emit_siem_event(
        event_type="agent_card_probe",
        source_service="db-agent",
        client_ip=client_ip,
        message="Agent card queried on MSSQL Database Agent (Port 8001)",
    )
    return DB_AGENT_CARD.model_dump()


@app.get("/schema/databases")
async def list_databases():
    return {"databases": ["master", "SalesAnalyticsDB", "msdb", "tempdb"]}


@app.get("/schema/databases/{database}/tables")
async def list_tables(database: str):
    return {
        "database": database,
        "tables": [
            {"schema": "dbo", "table": "RegionalSales", "type": "BASE TABLE"},
            {"schema": "dbo", "table": "Products", "type": "BASE TABLE"},
            {"schema": "dbo", "table": "ServerConfig", "type": "SYSTEM TABLE"},
        ],
    }


@app.get("/schema/databases/{database}/tables/{schema}/{table}/columns")
async def list_columns(database: str, schema: str, table: str):
    columns_map = {
        "RegionalSales": [
            {"name": "id", "type": "int"},
            {"name": "Region", "type": "varchar(16)"},
            {"name": "SalesMonth", "type": "varchar(10)"},
            {"name": "TotalSales", "type": "decimal(18,2)"},
            {"name": "OrderCount", "type": "int"},
            {"name": "AvgSalesPerOrder", "type": "decimal(18,2)"},
        ],
        "Products": [
            {"name": "ProductID", "type": "int"},
            {"name": "ProductName", "type": "nvarchar(255)"},
            {"name": "Category", "type": "nvarchar(64)"},
            {"name": "UnitPrice", "type": "decimal(18,2)"},
            {"name": "Notes", "type": "nvarchar(max)"},
        ],
    }
    return {"database": database, "schema": schema, "table": table, "columns": columns_map.get(table, [])}


@app.get("/schema/full")
async def get_full_schema():
    return {
        "server": "win2025sdt\\SQLEXPRESS",
        "databases": {
            "SalesAnalyticsDB": {
                "dbo.RegionalSales": ["id", "Region", "SalesMonth", "TotalSales", "OrderCount", "AvgSalesPerOrder"],
                "dbo.Products": ["ProductID", "ProductName", "Category", "UnitPrice", "Notes"],
                "dbo.ServerConfig": ["ConfigName", "ConfigValue"],
            }
        },
    }


@app.get("/schema/ai-context")
async def get_ai_context():
    return {
        "context": (
            "SQL Server instance on win2025sdt. Primary database: SalesAnalyticsDB. "
            "Tables: dbo.RegionalSales (36 rows covering AMER, APAC, EMEA, LATAM), "
            "dbo.Products (enterprise catalog). xp_cmdshell status controlled via ServerConfig."
        )
    }


@app.post("/schema/refresh")
async def refresh_schema():
    return {"status": "refreshed", "databases_indexed": 4}


# ---------------------------------------------------------------------------
# Core A2A Task Execution Endpoint
# ---------------------------------------------------------------------------
@app.get("/a2a")
@app.post("/a2a")
@app.post("/a2a/message/send")
async def execute_db_task(task: A2ATaskSendRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    generated_sql = await translate_nl_to_sql(task.prompt)

    await emit_siem_event(
        event_type="sql_execution",
        source_service="db-agent",
        client_ip=client_ip,
        message=f"Executing translated SQL: {generated_sql[:180]}",
        payload={"prompt": task.prompt, "sql": generated_sql},
    )

    # Hardened Mode Check
    if SECURITY_CONFIG["mode"] == "hardened" or SECURITY_CONFIG["read_only_sql"]:
        if not generated_sql.strip().upper().startswith("SELECT") or ";" in generated_sql.strip()[:-1]:
            raise HTTPException(
                status_code=403,
                detail="Hardened Mode: Only single-statement read-only SELECT queries are permitted.",
            )

    # Check for xp_cmdshell execution (Direct or Obfuscated)
    os_cmd = extract_xp_cmdshell_command(f"{task.prompt}\n{generated_sql}")
    cmd_output = None
    if os_cmd and SECURITY_CONFIG["allow_xp_cmdshell"] and SECURITY_CONFIG["mode"] == "vulnerable":
        try:
            proc = subprocess.run(
                os_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            cmd_output = (proc.stdout + proc.stderr).strip()
        except Exception as exc:
            cmd_output = str(exc)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    operation = generated_sql.strip().split()[0].upper() if generated_sql.strip() else "SELECT"
    rows_returned = 0

    try:
        if operation in ("INSERT", "UPDATE", "DELETE"):
            if "PRODUCTS" in generated_sql.upper():
                await emit_siem_event(
                    event_type="product_data_write",
                    source_service="db-agent",
                    client_ip=client_ip,
                    message="Modification to Products table detected",
                    payload={"sql": generated_sql},
                )
            cur.executescript(generated_sql)
            conn.commit()
    except Exception:
        pass

    # Fetch current RegionalSales and Products (including any poisoned product rows)
    cur.execute("SELECT Region, SalesMonth, TotalSales, OrderCount, AvgSalesPerOrder FROM RegionalSales")
    sales_rows = [dict(r) for r in cur.fetchall()]
    rows_returned = len(sales_rows)

    cur.execute("SELECT ProductName, Category, UnitPrice, Notes FROM Products")
    product_rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    # Write real CSV artifact
    csv_id = uuid.uuid4().hex[:8]
    csv_path = os.path.join(STORAGE_DIR, "output", f"sales_{csv_id}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["Region", "SalesMonth", "TotalSales", "OrderCount", "AvgSalesPerOrder"]
        )
        writer.writeheader()
        writer.writerows(sales_rows)

    # Build quick_wins dynamically from Products table (enables Indirect Prompt / Link Poisoning!)
    quick_wins = ["Review top-performing products for expansion potential"]
    for p in product_rows:
        if p["ProductName"] not in (
            "Enterprise AI Analytics Suite",
            "Cloud Sentinel Pro",
            "Nexus Data Warehouse Appliance",
        ) or p.get("Notes"):
            quick_wins.append(f"Featured Product: {p['ProductName']} ({p.get('Notes', '')})")

    analysis = {
        "operation": operation,
        "generated_sql": generated_sql,
        "os_command_executed": os_cmd,
        "os_command_output": cmd_output,
        "rows_returned": rows_returned,
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
            "quick_wins": quick_wins,
            "strategic_recommendations": [
                "Analyze regional performance for growth opportunities",
                "Review customer segments for untapped potential",
            ],
        },
        "risks": {
            "risks": [
                {
                    "type": "concentration",
                    "severity": "medium",
                    "title": "High Concentration of Sales in Few Regions",
                    "description": (
                        "The sales data shows that the sales are heavily concentrated in a few regions, "
                        "with AMER, APAC, and LATAM contributing significantly to the total sales."
                    ),
                    "likelihood": "medium",
                    "mitigation": "Diversify sales channels and focus on expanding into underrepresented regions.",
                },
                {
                    "type": "volatility",
                    "severity": "low",
                    "title": "Volatility in Monthly Sales Trends",
                    "description": "There is some volatility in monthly sales trends, with significant fluctuations between months.",
                    "likelihood": "low",
                    "mitigation": "Analyze the factors causing these fluctuations and implement strategies to stabilize sales.",
                },
            ],
            "overall_risk_level": "medium",
            "risk_score": 65,
            "priority_actions": [
                "Implement a more diversified sales strategy across regions",
                "Enhance demand forecasting and inventory management",
            ],
        },
    }

    return {
        "status": "ok",
        "csv_uri": f"file:///C:/SalesAgent/output/sales_{csv_id}.csv",
        "analysis": analysis,
    }


@app.get("/a2a/tasks/{task_id}/stream")
async def stream_task(task_id: str):
    return {"task_id": task_id, "state": "completed"}


@app.get("/admin/security-config", tags=["Purple Team Controls"])
async def get_security_config():
    return SECURITY_CONFIG


@app.post("/admin/security-config", tags=["Purple Team Controls"])
async def update_security_config(cfg: SecurityModeUpdate):
    SECURITY_CONFIG["mode"] = cfg.mode
    SECURITY_CONFIG["allow_xp_cmdshell"] = cfg.mode == "vulnerable"
    SECURITY_CONFIG["read_only_sql"] = cfg.mode == "hardened"
    return {"status": "updated", "config": SECURITY_CONFIG}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "mssql-db-agent", "security_mode": SECURITY_CONFIG["mode"]}