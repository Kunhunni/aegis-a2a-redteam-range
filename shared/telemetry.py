import os
import datetime
import httpx
from typing import Dict, Any, Optional

SIEM_URL = os.getenv("SIEM_URL", "http://localhost:5601")


async def emit_siem_event(
    event_type: str,
    source_service: str,
    client_ip: str = "127.0.0.1",
    message: str = "",
    payload: Optional[Dict[str, Any]] = None,
    simulated_hour: Optional[int] = None,
) -> None:
    """Asynchronously ship A2A telemetry events to the Port 5601 SIEM Sentinel."""
    event = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": event_type,
        "source_service": source_service,
        "client_ip": client_ip,
        "message": message,
        "payload": payload or {},
        "simulated_hour": simulated_hour,
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(f"{SIEM_URL}/api/ingest", json=event)
    except Exception:
        # Fail open so agent workflows continue even if SIEM is restarting
        pass