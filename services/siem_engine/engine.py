import os
import time
import json
import uuid
import logging
import requests
from typing import Dict, Any, List
from opensearchpy import OpenSearch, RequestsHttpConnection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SIEM-ENGINE] %(message)s"
)
logger = logging.getLogger("siem_engine")

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://172.28.0.10:9200")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "http://172.28.0.30:9090/alerts")
SURICATA_EVE_PATH = os.environ.get("SURICATA_EVE_PATH", "/var/log/suricata/eve.json")
ZEEK_LOG_DIR = os.environ.get("ZEEK_LOG_DIR", "/var/log/zeek")
RULES_PATH = os.environ.get("RULES_PATH", "/app/rules/wazuh_opensearch/rules.json")

def get_opensearch_client() -> OpenSearch:
    return OpenSearch(
        hosts=[OPENSEARCH_URL],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        connection_class=RequestsHttpConnection,
        timeout=30,
        max_retries=5,
        retry_on_timeout=True
    )

def init_opensearch(client: OpenSearch):
    logger.info("Initializing OpenSearch indices and mappings...")
    indices = {
        "siem-alerts-v1": {
            "mappings": {
                "properties": {
                    "alert_id": {"type": "keyword"},
                    "rule_id": {"type": "integer"},
                    "rule_name": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "level": {"type": "integer"},
                    "mitre_attack_id": {"type": "keyword"},
                    "mitre_tactic": {"type": "keyword"},
                    "mitre_technique": {"type": "text"},
                    "src_ip": {"type": "ip"},
                    "dest_ip": {"type": "ip"},
                    "dest_port": {"type": "integer"},
                    "payload_preview": {"type": "text"},
                    "event_timestamp": {"type": "date"},
                    "indexed_at": {"type": "date"},
                    "dispatch_latency_ms": {"type": "float"}
                }
            }
        },
        "suricata-eve-v1": {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "event_type": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "dest_ip": {"type": "ip"},
                    "dest_port": {"type": "integer"}
                }
            }
        },
        "zeek-telemetry-v1": {
            "mappings": {
                "properties": {
                    "ts": {"type": "date"},
                    "orig_h": {"type": "ip"},
                    "resp_h": {"type": "ip"},
                    "resp_p": {"type": "integer"},
                    "method": {"type": "keyword"},
                    "uri": {"type": "text"}
                }
            }
        }
    }
    for idx, body in indices.items():
        if not client.indices.exists(index=idx):
            client.indices.create(index=idx, body=body)
            logger.info(f"Created OpenSearch index: {idx}")
        else:
            logger.info(f"Index {idx} already exists.")

def load_rules() -> List[Dict[str, Any]]:
    try:
        with open(RULES_PATH, "r") as f:
            rules = json.load(f)
            logger.info(f"Loaded {len(rules)} correlation rules from {RULES_PATH}")
            return rules
    except Exception as e:
        logger.error(f"Failed to load rules: {e}")
        return []

def match_rule(event: Dict[str, Any], rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    alert_info = event.get("alert", {})
    sig_id = alert_info.get("signature_id")
    if not sig_id:
        return None
    
    for rule in rules:
        if sig_id in rule.get("matching_signatures", []):
            return rule
    return None

def process_suricata_event(line: str, client: OpenSearch, rules: List[Dict[str, Any]]):
    try:
        event = json.loads(line.strip())
    except Exception:
        return

    # Index raw EVE
    try:
        client.index(index="suricata-eve-v1", body=event)
    except Exception as e:
        logger.debug(f"OpenSearch index eve error: {e}")

    # Check alert
    if event.get("event_type") == "alert":
        matched_rule = match_rule(event, rules)
        now_ts = time.time()
        
        # Calculate latency
        event_time_str = event.get("timestamp")
        event_epoch = now_ts
        try:
            # Suricata ISO format: 2026-09-27T03:55:00.123456+0000
            import dateutil.parser
            dt = dateutil.parser.parse(event_time_str)
            event_epoch = dt.timestamp()
        except Exception:
            pass

        latency_ms = max(0.0, (now_ts - event_epoch) * 1000.0)

        alert_doc = {
            "alert_id": f"alert-{uuid.uuid4().hex[:12]}",
            "rule_id": matched_rule.get("rule_id", 999999) if matched_rule else 999999,
            "rule_name": matched_rule.get("name", event.get("alert", {}).get("signature", "GENERIC_SURICATA_ALERT")) if matched_rule else event.get("alert", {}).get("signature", "GENERIC_ALERT"),
            "severity": matched_rule.get("severity", "HIGH") if matched_rule else "MEDIUM",
            "level": matched_rule.get("level", 8) if matched_rule else 8,
            "mitre_attack_id": matched_rule.get("mitre_attack_id", "T1059") if matched_rule else "T1059",
            "mitre_tactic": matched_rule.get("mitre_tactic", "Execution") if matched_rule else "Execution",
            "mitre_technique": matched_rule.get("mitre_technique", "Generic Attack") if matched_rule else "Generic Attack",
            "src_ip": event.get("src_ip", "127.0.0.1"),
            "dest_ip": event.get("dest_ip", "127.0.0.1"),
            "dest_port": event.get("dest_port", 8000),
            "payload_preview": event.get("payload_printable", event.get("alert", {}).get("signature", ""))[:200],
            "event_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event_epoch)),
            "indexed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts)),
            "dispatch_latency_ms": round(latency_ms, 2)
        }

        # Index into siem-alerts-v1
        try:
            client.index(index="siem-alerts-v1", body=alert_doc)
            logger.info(f"🚨 [SIEM-INDEXED] Alert '{alert_doc['rule_name']}' [ID: {alert_doc['rule_id']}] indexed into OpenSearch")
        except Exception as e:
            logger.error(f"Failed to index alert into OpenSearch: {e}")

        # Dispatch Webhook
        try:
            resp = requests.post(WEBHOOK_URL, json=alert_doc, timeout=5)
            logger.info(f"📤 [WEBHOOK-DISPATCHED] Alert sent to {WEBHOOK_URL} (Status: {resp.status_code})")
        except Exception as e:
            logger.error(f"Failed to dispatch webhook: {e}")

def main():
    logger.info("Starting Open-Source SIEM Ingestion & Correlation Engine...")
    
    # Wait for OpenSearch
    client = None
    for attempt in range(30):
        try:
            client = get_opensearch_client()
            if client.ping():
                logger.info("Connected to OpenSearch successfully.")
                break
        except Exception as e:
            logger.info(f"Waiting for OpenSearch... ({attempt+1}/30) - {e}")
        time.sleep(3)
        
    if not client or not client.ping():
        logger.error("Could not connect to OpenSearch after 90 seconds. Exiting.")
        return

    init_opensearch(client)
    rules = load_rules()

    # File watcher / tailing for Suricata EVE JSON
    logger.info(f"Tailing Suricata EVE log at {SURICATA_EVE_PATH}...")
    
    # Ensure file exists
    eve_dir = os.path.dirname(SURICATA_EVE_PATH)
    os.makedirs(eve_dir, exist_ok=True)
    if not os.path.exists(SURICATA_EVE_PATH):
        open(SURICATA_EVE_PATH, "a").close()

    with open(SURICATA_EVE_PATH, "r") as f:
        # Seek to end
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                process_suricata_event(line, client, rules)
            else:
                time.sleep(0.2)

if __name__ == "__main__":
    main()
