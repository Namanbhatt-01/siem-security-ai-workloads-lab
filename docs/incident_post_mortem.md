# SecOps Incident Post-Mortem

**Incident ID:** SEC-2026-0927-01  
**Severity:** CRITICAL (P1)  
**Title:** Adversarial Prompt Injection & Rogue Vector DB Bulk Exfiltration Attempt  
**Date / Timestamp:** 2026-09-27 09:30:15 UTC  
**Impacted Systems:** `ai-gateway-prod-01` (Port 8000), `vector-qdrant-prod-01` (Port 6333)  
**Lead Investigator:** Naman Bhatt (Lead Detection Engineer)  

---

## 1. Executive Summary

On September 27, 2026, an external threat actor executed an automated, multi-stage adversarial attack targeting our AI inference gateway and enterprise Vector Database. The attack incorporated:
1. **Adversarial System Prompt Injection** attempting to bypass system guardrails and extract proprietary initialization instructions.
2. **Credential Harvester** payload targeting `AWS_SECRET_ACCESS_KEY` and API credentials.
3. **Rogue Vector Database Collection Dump** attempting unauthorized extraction of high-dimensional enterprise embeddings.

The Open-Source SIEM & Security Pipeline (Suricata DPI + Zeek IDS + OpenSearch SIEM Engine) detected the attack in real-time, correlated the events within **180 ms**, indexed the incident into `siem-alerts-v1`, and dispatched an automated high-priority webhook alert to the SecOps incident response channel in **1.15 seconds**, well within our 10-second SLA.

---

## 2. Key Metrics & Incident Timeline

### Performance & Latency Metrics
* **Time-to-Detect (TTD):** 180 ms (Suricata Layer 7 pattern match)
* **Time-to-Correlate (TTC):** 45 ms (SIEM Engine rule evaluation)
* **Time-to-Index (TTI):** 120 ms (OpenSearch document indexing)
* **Time-to-Notify (TTN):** 1.15 s (Automated Webhook Dispatch)
* **Total End-to-End SLA Target:** < 10.0 seconds (**Achieved: 1.49 seconds**)

### Chronological Event Sequence

| Timestamp (UTC) | Source IP | Destination IP | Port | Event Description | Action Taken |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `09:30:15.102` | `172.28.0.1` | `172.28.0.20` | 8000 | Ingress HTTP POST `/v1/chat/completions` with payload `Ignore previous instructions...` | Suricata SID 1000001 triggered |
| `09:30:15.282` | `172.28.0.40` | `172.28.0.10` | 9200 | SIEM Engine correlated SID 1000001 -> Rule 100101 (CRITICAL) | Indexed to `siem-alerts-v1` |
| `09:30:16.252` | `172.28.0.40` | `172.28.0.30` | 9090 | Automated JSON Webhook alert dispatched to SecOps endpoint | Webhook 200 OK captured |
| `09:30:17.014` | `172.28.0.1` | `172.28.0.20` | 6333 | Rogue GET `/collections/enterprise_ai_kb/dump` executed | Suricata SID 1000020 triggered |
| `09:30:17.185` | `172.28.0.40` | `172.28.0.10` | 9200 | SIEM Engine correlated SID 1000020 -> Rule 100103 (CRITICAL) | Indexed to `siem-alerts-v1` |
| `09:30:18.110` | `172.28.0.40` | `172.28.0.30` | 9090 | Automated Webhook alert dispatched for Vector DB Dump | Incident ticket auto-opened |

---

## 3. MITRE ATT&CK Mapping

```
+--------------------------------------------------------------------------------------------------+
| TACTIC: Execution                 | TACTIC: Collection               | TACTIC: Exfiltration      |
| Technique: T1059.006              | Technique: T1530                 | Technique: T1048.003      |
| Prompt Injection / System Override| Data from Cloud/Local Vector DB  | Unencrypted Web Egress    |
| Rule: AI_PROMPT_INJECTION_OVERRIDE| Rule: AI_VECTOR_DB_HARVEST       | Rule: AI_LLM_EXFILTRATION |
| Severity: CRITICAL (Level 12)     | Severity: CRITICAL (Level 12)    | Severity: HIGH (Level 10) |
+--------------------------------------------------------------------------------------------------+
```

---

## 4. Root Cause Analysis (RCA)

1. **Ingress Layer:** Direct access to LLM inference gateway without upstream WAF or prompt sanitization proxy allowed raw text payloads containing override tokens to reach the endpoint.
2. **Vector DB Segmentation:** Port 6333 was exposed to the container bridge without mandatory mTLS authentication headers, permitting unauthenticated `/dump` endpoint querying.

---

## 5. Corrective & Preventative Actions

- [x] **Suricata Signature Hardening:** Deployed SIDs `1000001`–`1000004` directly at the container network namespace boundary.
- [x] **Automated SIEM Alerting:** Configured Wazuh/OpenSearch correlation rules with automated HTTP webhook triggers.
- [ ] **mTLS & API Token Enforcement:** Implement API Gateway authentication token validation upstream of port 6333.
- [ ] **Prompt Shield Integration:** Deploy NeMo Guardrails / Llama Guard filter container inline before LLM inference dispatch.
