import json
import logging
import os
import time
from typing import Dict, Any, List
from fastapi import FastAPI, Request
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("webhook_receiver")

app = FastAPI(title="SecOps Alert Webhook Receiver", version="1.0.0")

RECEIVED_ALERTS: List[Dict[str, Any]] = []
LOG_DIR = "/var/log/alerts"
os.makedirs(LOG_DIR, exist_ok=True)
ALERTS_LOG_FILE = os.path.join(LOG_DIR, "received_webhooks.jsonl")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "webhook_receiver", "total_alerts_received": len(RECEIVED_ALERTS)}

@app.post("/alerts")
async def receive_alert(request: Request):
    payload = await request.json()
    now_ts = time.time()
    
    alert_record = {
        "received_at": now_ts,
        "received_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts)),
        "alert": payload
    }
    
    # Calculate latency if event_timestamp is present
    event_ts = payload.get("event_timestamp") or payload.get("@timestamp")
    if event_ts:
        try:
            # If timestamp is numeric epoch
            if isinstance(event_ts, (int, float)):
                alert_record["latency_seconds"] = round(now_ts - event_ts, 3)
        except Exception:
            pass

    RECEIVED_ALERTS.append(alert_record)
    
    logger.warning(
        f"🚨 [WEBHOOK-ALERT] Rule: '{payload.get('rule_name', 'Unknown')}' | "
        f"Severity: {payload.get('severity', 'UNKNOWN')} | "
        f"Src: {payload.get('src_ip', 'N/A')} -> Dst: {payload.get('dest_ip', 'N/A')} | "
        f"MITRE: {payload.get('mitre_attack_id', 'N/A')}"
    )

    with open(ALERTS_LOG_FILE, "a") as f:
        f.write(json.dumps(alert_record) + "\n")

    return {
        "status": "alert_acknowledged",
        "alert_id": payload.get("alert_id", "gen-" + str(len(RECEIVED_ALERTS))),
        "received_at": alert_record["received_iso"]
    }

@app.get("/alerts")
async def get_alerts():
    return {
        "count": len(RECEIVED_ALERTS),
        "alerts": RECEIVED_ALERTS
    }

@app.get("/alerts/summary")
async def get_summary():
    severities: Dict[str, int] = {}
    rules: Dict[str, int] = {}
    for item in RECEIVED_ALERTS:
        a = item.get("alert", {})
        sev = str(a.get("severity", "UNKNOWN"))
        r = str(a.get("rule_name", "UNKNOWN"))
        severities[sev] = severities.get(sev, 0) + 1
        rules[r] = rules.get(r, 0) + 1
        
    return {
        "total_alerts": len(RECEIVED_ALERTS),
        "severity_breakdown": severities,
        "rules_triggered": rules
    }

@app.delete("/alerts")
async def clear_alerts():
    RECEIVED_ALERTS.clear()
    if os.path.exists(ALERTS_LOG_FILE):
        open(ALERTS_LOG_FILE, "w").close()
    return {"status": "cleared"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9090, log_level="info")
