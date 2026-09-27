# Lab 3: Open-Source SIEM & Security Pipeline for AI Workloads

[![CI/CD Security Pipeline](https://github.com/Namanbhatt-01/siem-security-ai-workloads-lab/actions/workflows/siem_ci.yml/badge.svg)](https://github.com/Namanbhatt-01/siem-security-ai-workloads-lab/actions/workflows/siem_ci.yml)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-2.11-005EC4?logo=opensearch&logoColor=white)](https://opensearch.org/)
[![Suricata](https://img.shields.io/badge/Suricata-7.0_DPI-EF3B24?logo=suricata&logoColor=white)](https://suricata.io/)
[![Zeek](https://img.shields.io/badge/Zeek-6.0_IDS-772953)](https://zeek.org/)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Architecture](https://img.shields.io/badge/Architecture-ARM64_%2F_M1_Optimized-FF6F00)]()
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **Enterprise NetDevOps & SecOps Portfolio — Laboratory 3 of 6**  
> *Containerized threat detection, deep packet inspection, and behavioral security analytics pipeline targeting AI/LLM infrastructure, prompt injection payloads, and vector database exfiltration.*

---

## 📑 Executive Overview

Modern enterprise AI infrastructure exposes new, highly specialized attack vectors:
1. **Adversarial Prompt Injection & Jailbreaks** (Overriding system instructions, exfiltrating internal prompts, or disabling guardrails).
2. **Credential & Secret Harvesting** (Extraction of API keys, AWS credentials, and environment tokens via prompt crafting).
3. **Rogue Vector Database Harvesting** (Unauthorized collection dumps from Qdrant, Milvus, or ChromaDB instances).
4. **High-Volume Token & Weight Exfiltration** (High-throughput egress spikes streaming sensitive embeddings or weights to unapproved endpoints).

This laboratory deploys a **100% open-source, lightweight containerized security pipeline** utilizing **Suricata 7 (Deep Packet Inspection)**, **Zeek (Network Protocol Analysis)**, and **OpenSearch / Wazuh-compatible SIEM Correlation Engine**. The stack monitors live AI workload telemetry, evaluates custom detection rules, indexes incident events, and dispatches automated webhook notifications within a strict **< 10-second SLA**.

---

## 🏛️ End-to-End System Architecture

```
+--------------------------------------------------------------------------------------------------------------------+
|                                    AI WORKLOAD THREAT DETECTION TOPOLOGY                                           |
+--------------------------------------------------------------------------------------------------------------------+

     [ Adversarial Attacker / Client ]
                    |
                    | (HTTP POST /v1/chat/completions, GET /collections/dump)
                    v
    +========================================================================================+
    |                         CONTAINER NETWORK INGRESS (Docker Bridge)                      |
    |                                                                                        |
    |  +------------------------------------+      +--------------------------------------+  |
    |  |       Mock LLM Inference GW        |      |       Mock Vector Database           |  |
    |  |     (Port 8000: vLLM / OpenAI API) |      |    (Port 6333: Qdrant / Milvus)      |  |
    |  +------------------------------------+      +--------------------------------------+  |
    |                     ^                                           ^                      |
    |                     |                                           |                      |
    |  +------------------+-------------------------------------------+-------------------+  |
    |  |                           NETWORK NAMESPACE SIDECAR                              |  |
    |  |                                                                                  |  |
    |  |   +------------------------------------+      +-------------------------------+  |  |
    |  |   |           Suricata 7 DPI           |      |            Zeek IDS           |  |  |
    |  |   |  - Layer 7 Regex Signature Engine  |      |  - HTTP / API Transaction Log |  |  |
    |  |   |  - Custom AI / Prompt Rules        |      |  - Custom `llm_traffic.zeek`  |  |  |
    |  |   +------------------------------------+      +-------------------------------+  |  |
    |  +------------------|-------------------------------------------|-------------------+  |
    +=====================|===========================================|======================+
                          | (`eve.json`)                              | (`llm_inference.log`)
                          v                                           v
    +========================================================================================+
    |                         SECOPS SIEM INGESTION & CORRELATION ENGINE                     |
    |                                                                                        |
    |   +--------------------------------------------------------------------------------+   |
    |   |  Python SIEM Correlation Engine (`services/siem_engine/engine.py`)             |   |
    |   |  - Real-time Log Streaming & Parsing                                           |   |
    |   |  - Wazuh XML / JSON Rule Evaluation (MITRE ATT&CK Tagging)                     |   |
    |   |  - Latency Measurement & Anomaly Classification                                |   |
    |   +---------------------------------------+----------------------------------------+   |
    |                                           |                                            |
    |                      +--------------------+--------------------+                       |
    |                      |                                         |                       |
    |                      v                                         v                       |
    |     +----------------------------------+     +----------------------------------+      |
    |     |       OpenSearch 2.11 Node       |     |     SecOps Webhook Receiver      |      |
    |     |  - Index: `siem-alerts-v1`       |     |  - Automated Incident Paging     |      |
    |     |  - Index: `suricata-eve-v1`      |     |  - Latency SLA Assertion (<10s)  |      |
    |     |  - JVM Capped @ 768 MB (M1 Spec) |     |  - Port 9090                     |      |
    |     +----------------------------------+     +----------------------------------+      |
    +========================================================================================+
```

---

## 🎯 Threat Detection Rules & MITRE ATT&CK Mapping

| Rule ID | Severity | Name / Classification | MITRE ATT&CK | Detection Vector & Payload Trigger |
| :--- | :--- | :--- | :--- | :--- |
| **`100101`** | `CRITICAL` | `AI_PROMPT_INJECTION_OVERRIDE` | **T1059.006** | `Ignore previous instructions`, `DAN Mode enabled`, `AWS_SECRET_ACCESS_KEY` |
| **`100102`** | `HIGH` | `AI_LLM_HIGH_VOLUME_EXFILTRATION` | **T1048.003** | TCP egress burst > 60 KB on LLM inference endpoint |
| **`100103`** | `CRITICAL` | `AI_VECTOR_DB_UNAUTHORIZED_HARVEST` | **T1530** | Unauthorized `GET /collections/{name}/dump` on port 6333 |
| **`100104`** | `MEDIUM` | `AI_SHADOW_LLM_GATEWAY_EGRESS` | **T1071.001** | Rogue HTTP Host header `api.unauthorized-ai-proxy.org` |

---

## 📊 Live Telemetry & Verification Proof

When executing `python3 attack_simulation/run_all_attacks.py`, the pipeline evaluates all adversarial vectors and validates end-to-end alerting:

```text
==============================================================================
                    PHASE 1: HEALTH & READINESS INSPECTION                    
==============================================================================
  [+] OpenSearch SIEM Storage        -> ONLINE (HTTP 200)
  [+] Mock LLM Gateway               -> ONLINE (HTTP 200)
  [+] Mock Vector Database           -> ONLINE (HTTP 200)
  [+] SecOps Webhook Receiver        -> ONLINE (HTTP 200)

==============================================================================
                   PHASE 2: ADVERSARIAL ATTACK INJECTION                      
==============================================================================
[1/5] Injecting Benign LLM Request (Control Baseline)...
[2/5] Injecting Attack 1: Direct System Prompt Override...
[3/5] Injecting Attack 2: Jailbreak DAN Mode Persona...
[4/5] Injecting Attack 3: Unauthorized Vector Database Harvest...
[5/5] Injecting Attack 4: High-Volume Payload Exfiltration Spike (>60KB)...

⏳ Awaiting SIEM correlation, OpenSearch indexing, and automated webhook dispatch (5s)...

==============================================================================
              PHASE 3: SECOPS TELEMETRY & ALERT VERIFICATION                  
==============================================================================
Total Dispatched Alerts Captured by Webhook: 4
Total Alerts Indexed into OpenSearch (siem-alerts-v1): 4

------------------------------------------------------------------------------
Rule Name                           | Severity | MITRE      | Latency  | Status
------------------------------------------------------------------------------
AI_PROMPT_INJECTION_OVERRIDE        | CRITICAL | T1059.006  | 0.18s    | PASSED (<10s SLA)
AI_PROMPT_INJECTION_OVERRIDE        | CRITICAL | T1059.006  | 0.19s    | PASSED (<10s SLA)
AI_VECTOR_DB_UNAUTHORIZED_HARVEST   | CRITICAL | T1530      | 0.22s    | PASSED (<10s SLA)
AI_LLM_HIGH_VOLUME_EXFILTRATION     | HIGH     | T1048.003  | 0.28s    | PASSED (<10s SLA)
------------------------------------------------------------------------------

==============================================================================
  AUTOMATED VERIFICATION ASSERTIONS
==============================================================================
  [✅ PASS] OpenSearch Cluster Active & Healthy
  [✅ PASS] Suricata / Zeek AI Signatures Active
  [✅ PASS] Prompt Injection Override Triggered
  [✅ PASS] Vector DB Exfiltration Detected
  [✅ PASS] High-Volume Egress Spike Detected
  [✅ PASS] Webhook Latency < 10.0s SLA
  [✅ PASS] OpenSearch Document Indexing Verified
==============================================================================

🎉 ALL LAB 3 SECURITY ASSERTIONS PASSED SUCCESSFULLY!
```

---

## 🔬 Enterprise Translation: Cisco / Splunk vs. Open-Source

| Capability | Cisco Secure Firewall + Splunk ES | Lab 3 Open-Source Pipeline |
| :--- | :--- | :--- |
| **Deep Packet Inspection** | Cisco Firepower (FTD) / Snort 3 | Suricata 7.x Multi-Threaded DPI |
| **Behavioral Flow Telemetry** | Cisco NetFlow / eStreamer API | Zeek IDS (`http.log`, `llm_inference.log`) |
| **SIEM & Rule Correlation** | Splunk Enterprise Security (SPL) | OpenSearch 2.11 + Wazuh XML/JSON Rules |
| **Alert Notification** | Splunk Alert Manager / Webhooks | Direct Async SIEM Webhook Dispatcher |
| **Hardware Footprint** | 16–32 GB RAM (Heavy Enterprise Footprint) | **< 2.0 GB RAM total (Optimized for Apple M1)** |
| **Licensing** | Enterprise Proprietary ($/GB index license) | **$0 / 100% Open Standards (Apache 2.0 / GPL)** |

*For deep architectural analysis, see [docs/cisco_splunk_vs_wazuh_memo.md](docs/cisco_splunk_vs_wazuh_memo.md).*  
*For a production incident response post-mortem walkthrough, see [docs/incident_post_mortem.md](docs/incident_post_mortem.md).*

---

## 🚀 Quickstart & Reproduction

### Prerequisites
- Docker & Docker Compose (Docker Desktop for Mac / Linux)
- Python 3.11+
- `curl` and `jq`

### 1. Launch the Pipeline
```bash
git clone https://github.com/Namanbhatt-01/siem-security-ai-workloads-lab.git
cd siem-security-ai-workloads-lab

# Run automated build and launch
make up
```

### 2. Execute Attack Simulation & Verify Telemetry
```bash
# Run complete test suite and assert <10s trigger latency
make test
```

### 3. Query OpenSearch Index & Webhook State
```bash
# Inspect OpenSearch indexed alerts
curl -s http://localhost:9200/siem-alerts-v1/_search?pretty | jq .

# Inspect Webhook Alert Receiver Summary
curl -s http://localhost:9090/alerts/summary | jq .
```

### 4. Clean Teardown
```bash
make clean
```

---

## 📂 Repository Structure

```
├── .github/
│   └── workflows/
│       └── siem_ci.yml                   # Automated CI/CD pipeline running attack suite
├── attack_simulation/
│   ├── run_all_attacks.py               # Master assertion runner & latency benchmark
│   ├── simulate_prompt_injection.py     # Adversarial prompt injection attacks
│   └── simulate_llm_exfiltration.py     # Bulk weight exfil & vector dump simulation
├── config/
│   └── suricata/
│       └── suricata.yaml                # Suricata engine config with HTTP DPI enabled
├── docker/
│   ├── Dockerfile.mock_llm              # FastAPI mock LLM gateway & Vector DB
│   ├── Dockerfile.siem                  # Python SIEM ingestion & correlation engine
│   ├── Dockerfile.webhook               # SecOps alert webhook receiver
│   └── Dockerfile.zeek                  # Zeek container definition
├── docs/
│   ├── cisco_splunk_vs_wazuh_memo.md    # Comparative engineering analysis memo
│   └── incident_post_mortem.md          # P1 SecOps incident post-mortem report
├── rules/
│   ├── suricata/
│   │   ├── prompt_injection.rules       # Suricata Layer 7 prompt override signatures
│   │   └── llm_exfiltration.rules       # Vector DB dump & egress spike signatures
│   └── wazuh_opensearch/
│       ├── rules.json                   # SIEM correlation rules with MITRE metadata
│       └── rules.xml                    # Wazuh XML standard rule definitions
├── scripts/
│   └── zeek/
│       └── llm_traffic.zeek             # Zeek protocol script logging LLM transactions
├── services/
│   ├── mock_llm/main.py                 # Mock LLM API & Vector DB endpoint logic
│   ├── siem_engine/engine.py            # Stream ingestion, correlation & indexing
│   └── webhook_receiver/main.py         # Webhook receiver & latency calculator
├── docker-compose.yml                   # Multi-service security orchestration stack
├── Makefile                             # One-command lifecycle targets
├── run_lab3_experiment.sh               # Local end-to-end execution script
└── README.md                            # Portfolio documentation & proofs
```

---

## 🛡️ License

This project is open-source software licensed under the [Apache-2.0 License](LICENSE).
