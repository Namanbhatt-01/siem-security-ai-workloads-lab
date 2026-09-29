# LAB 04: AI Workload Security & SIEM Detection Engineering

[![CI/CD Pipeline](https://github.com/Namanbhatt-01/siem-security-ai-workloads-lab/actions/workflows/siem_ci.yml/badge.svg)](https://github.com/Namanbhatt-01/siem-security-ai-workloads-lab/actions/workflows/siem_ci.yml)
[![Suricata](https://img.shields.io/badge/NIDS-Suricata_v7.0-red?logo=suricata&logoColor=white)](https://suricata.io/)
[![Zeek](https://img.shields.io/badge/NSM-Zeek_v6.0-blue)](https://zeek.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A reproducible reference laboratory for **AI Workload Detection Engineering**, monitoring network-layer flow anomalies, unauthorized vector database exfiltration, and rogue LLM interactions using Suricata, Zeek, and OpenSearch.

---

## 1. Problem Statement

Enterprise AI deployments introduce unique attack vectors that traditional IT network security monitoring often overlooks:
1. **Vector Database Exfiltration**: High-volume, unauthorized extraction of vectorized embeddings from internal Qdrant/Milvus clusters.
2. **Network-Layer Prompt Injection**: Attackers embedding delimiter escapes or system prompt exfiltration commands inside unencrypted internal HTTP POST request payloads.
3. **Rogue GPU Cluster Egress**: Unauthorized outbound API calls from compromised inference containers to external LLM providers.

This repository implements **Detection-as-Code** specifications for AI infrastructure workloads.

---

## 2. Detection-as-Code Specifications

Detection rules are structured in `detections/*.yaml` with complete provenance, logic, false-positive handling, and test fixtures:

| Detection ID | Rule Name | Severity | Data Sources | Monitored Target |
| :--- | :--- | :--- | :--- | :--- |
| **`AI-EXFIL-001`** | Unusual Vector Database Bulk Egress Flow | High | `zeek.conn`, `suricata.eve` | Qdrant/Milvus Vector DB Ports (6333, 19530) |
| **`AI-INJECT-002`** | Network-Layer Prompt Injection Directive | Medium | `zeek.http`, `suricata.http` | HTTP POST `/v1/chat/completions` |
| **`AI-UNAUTH-003`** | Rogue GPU Worker Outbound API Egress | High | `zeek.dns`, `zeek.ssl` | External SaaS LLM Endpoints |

---

## 3. Architecture

```
┌────────────────────────────────────────────────────────┐
│             TRAFFIC SOURCES & AI WORKLOADS             │
│  - Vector DB (Qdrant)  - Inference Proxy  - Attack Sim │
└───────────────────────────┬────────────────────────────┘
                            │ Raw Ethernet Packets / TAP
                            ▼
┌────────────────────────────────────────────────────────┐
│             NETWORK SENSING PLANE (Zeek / Suricata)    │
│  - Suricata IPS/IDS: Signature & Rule Evaluation       │
│  - Zeek NSM: Protocol Extraction (HTTP, DNS, Conn)     │
└───────────────────────────┬────────────────────────────┘
                            │ Structured JSON Logs (EVE / Zeek TSV)
                            ▼
┌────────────────────────────────────────────────────────┐
│             SIEM CORRELATION & DETECTION ENGINE        │
│  - Matches against `detections/*.yaml` rules           │
│  - Generates Alert Records & Evidence Envelopes        │
└────────────────────────────────────────────────────────┘
```

---

## 4. Evidence Envelope Output

The verification suite runs detection test fixtures and outputs `poc/evidence.json`:

```json
{
  "schema_version": "1.0",
  "experiment": {
    "id": "siem-detection-001",
    "name": "AI Workload Threat Detection Engineering & Correlation"
  },
  "execution": {
    "run_id": "siem-20260929-152000",
    "timestamp": "2026-09-29T15:20:00Z",
    "environment": "docker-compose",
    "platform": "darwin-arm64"
  },
  "measurements": [
    { "metric": "active_detection_rules_loaded", "value": 2, "mode": "measured" },
    { "metric": "simulated_threats_detected", "value": 2, "mode": "measured" }
  ],
  "assertions": [
    { "id": "SIEM-ASSERT-001", "name": "Vector Database Exfiltration Detection", "passed": true },
    { "id": "SIEM-ASSERT-002", "name": "Network Layer Prompt Injection Detection", "passed": true }
  ],
  "result": "passed"
}
```

---

## 5. Quickstart & Local Execution

### Prerequisites
- Docker & Docker Compose
- Python 3.11+

### Execute Verification Suite
```bash
# 1. Run detection rule assertions & test cases
python3 scripts/verify_siem_detections.py

# 2. Or start full containerized sensor stack
make up
```

---

## 6. Threat Research & Malware Forensics

- **Track 1C — Sample Forensics & Provenance Evidence Sheet**: [`docs/track1c_sample_forensics_evidence_sheet.md`](docs/track1c_sample_forensics_evidence_sheet.md)  
  *Architectural continuity analysis comparing the 9-sample candidate corpus across GITSHELLPAD (Golang) and RUSTYSHADE (Rust) implants using GitHub private repository file-as-protocol C2 channels.*

---

## 7. Known Limitations

1. **Cleartext Inspection Boundary**: Network-layer prompt injection detection requires TLS termination at an ingress reverse proxy (or eBPF uprobes); end-to-end encrypted HTTPS traffic cannot be inspected by raw packet sniffers without intermediate decryption.
2. **Detection Logic Format**: Rules are implemented as YAML specifications evaluated by the Python test engine; production deployments would translate these rules into Sigma / Suricata `.rules` / ElastAlert / OpenSearch Query DSL.

---

## 8. License

MIT License. See [LICENSE](LICENSE) for details.

