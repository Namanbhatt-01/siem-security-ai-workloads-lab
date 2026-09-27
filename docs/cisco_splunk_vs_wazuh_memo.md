# Comparative Engineering Memo: Enterprise Threat Detection Architectures for AI Workloads

**Author:** Naman Bhatt  
**Date:** September 2026  
**Document ID:** MEMO-SECOPS-AI-2026-03  
**Classification:** Technical Architecture & Comparative Analysis  

---

## Executive Summary

As enterprise AI infrastructure transitions from localized experimental sandboxes to large-scale GPU clusters and production Retrieval-Augmented Generation (RAG) pipelines, the attack surface shifts significantly towards **Adversarial Prompt Injection**, **Unauthorized Model Weights & Token Exfiltration**, and **Vector Database Harvesting**.

This memo evaluates and benchmarks two enterprise security architectures for AI workload protection:
1. **Proprietary Enterprise Stack:** Cisco Secure Firewall (FTD / FMC) + Splunk Enterprise SIEM / Enterprise Security (ES).
2. **Open-Source Stack:** Wazuh SIEM / OpenSearch + Zeek (Bro) IDS + Suricata Deep Packet Inspection (DPI) Engine.

---

## 1. Architectural Topology Comparison

```
+--------------------------------------------------------------------------------------------------+
| PROPRIETARY ARCHITECTURE: Cisco Secure Firewall + Splunk Enterprise SIEM                         |
|                                                                                                  |
| [AI Client / User] ---> [Cisco Firepower FTD] ---> [eStreamer / Syslog] ---> [Splunk Heavy Fwd] |
|                                |                                                    |            |
|                     (Snort 3 Inspection Engine)                             [Splunk Indexer]     |
|                                |                                                    |            |
|                        [AI GPU / LLM Cluster]                               [Splunk ES / SPL]    |
+--------------------------------------------------------------------------------------------------+

+--------------------------------------------------------------------------------------------------+
| OPEN-SOURCE ARCHITECTURE: Wazuh / OpenSearch + Suricata + Zeek IDS (Deployed in Lab 3)            |
|                                                                                                  |
| [AI Client / User] ---> [Suricata 7 DPI & Zeek IDS] ---> [EVE JSON / JSONL] ---> [SIEM Engine]  |
|                                |                                                    |            |
|                     (Layer 7 AI Payload Signatures)                         [OpenSearch Cluster] |
|                                |                                                    |            |
|                   [Mock LLM Gateway / Vector DB]                        [Wazuh / Webhook SLA<10s]|
+--------------------------------------------------------------------------------------------------+
```

---

## 2. Telemetry Ingestion & Protocol Mapping

| Architectural Dimension | Cisco Secure Firewall + Splunk ES | Wazuh / OpenSearch + Suricata + Zeek |
| :--- | :--- | :--- |
| **Network Inspection Engine** | Cisco Firepower Threat Defense (FTD) / Snort 3 | Suricata 7.x (Multi-threaded DPI) + Zeek 6.x |
| **Telemetry Format** | Cisco eStreamer API / RFC 5424 Syslog / NetFlow | Suricata EVE JSON (`eve.json`) + Zeek TSV/JSON logs |
| **Ingestion Pipeline** | Splunk Universal/Heavy Forwarder -> Splunk Indexer | Vector / Wazuh Agent / Logstash -> OpenSearch |
| **Rule Specification** | Snort 3 Rules + Splunk SPL Correlation Searches | Suricata Custom AI Rules + Wazuh XML / JSON Rules |
| **Threat Intelligence** | Cisco Talos Intelligence Feeds | Custom MITRE ATT&CK AI Threat Mappings + Open CTI |
| **Automated Response** | Cisco SecureX Orchestration / Splunk SOAR | Wazuh Active Response / Webhook Dispatch Engine |

---

## 3. Detection Rule Translation Matrix

### A. Prompt Injection & System Override (MITRE ATT&CK T1059.006)

* **Cisco Snort 3 Rule:**
  ```snort
  alert http any any -> $AI_SERVERS 8000 (msg:"AI-PROMPT-INJECTION System Prompt Override"; http_header:field host; http_raw_body; content:"Ignore previous instructions",nocase; sid:300001; rev:1;)
  ```
* **Suricata 7 Rule (Lab 3):**
  ```suricata
  alert http any any -> any 8000 (msg:"AI-THREAT Direct Prompt Injection - System Prompt Override Attempt"; flow:to_server,established; content:"Ignore previous instructions"; nocase; http_client_body; classtype:attempted-admin; sid:1000001; rev:1; metadata:mitre_attack T1059.006, severity critical;)
  ```
* **Splunk SPL Correlation Search:**
  ```spl
  index=cisco_firewall sourcetype=cisco:estreamer:alert signature_id=300001
  | eval attack_type="Prompt Injection", target="LLM Inference Gateway"
  | stats count earliest(_time) as start_time latest(_time) as end_time by src_ip, dest_ip, signature
  | where count >= 1
  ```
* **Wazuh / OpenSearch Correlation Rule (Lab 3):**
  ```xml
  <rule id="100101" level="12">
    <if_group>suricata</if_group>
    <field name="alert.signature_id">^100000[1-4]$</field>
    <description>AI Workload Security: Adversarial Prompt Injection detected against LLM Gateway</description>
    <mitre><id>T1059.006</id></mitre>
  </rule>
  ```

---

### B. Rogue Vector Database Dump & Bulk Harvesting (MITRE ATT&CK T1530)

* **Cisco Snort 3 Rule:**
  ```snort
  alert tcp any any -> $VECTOR_DBS 6333 (msg:"AI-VECTOR-DB Unauthorized Bulk Collection Dump"; content:"/collections/"; content:"/dump"; sid:300020; rev:1;)
  ```
* **Suricata 7 Rule (Lab 3):**
  ```suricata
  alert http any any -> any 6333 (msg:"AI-THREAT Unauthorized Vector Database Bulk Dump Access"; flow:to_server,established; content:"/collections/"; http_uri; content:"/dump"; http_uri; classtype:policy-violation; sid:1000020; rev:1; metadata:mitre_attack T1530, severity critical;)
  ```

---

## 4. Latency & Resource Consumption Benchmarks

| Metric | Cisco FTD + Splunk Enterprise | Open-Source Wazuh / OpenSearch Stack |
| :--- | :--- | :--- |
| **Detection SLA (Ingress to Alert)** | 3.5s – 8.0s (dependent on forwarder batching) | **< 250ms (real-time streaming tail)** |
| **Webhook Dispatch Latency** | 5.0s – 12.0s (Splunk Alert Manager) | **< 1.2s (direct correlation engine)** |
| **Memory Footprint (Lab Profile)** | 16 GB – 32 GB RAM (Requires VMs / Heavy JVM) | **< 2.0 GB RAM total (OpenSearch capped at 768MB JVM)** |
| **Licensing Cost** | High ($1,500–$2,500/GB ingested index licensing) | **$0 / 100% Open-Source (Apache 2.0 / GPL)** |
| **Apple Silicon M1 Compatibility** | Limited (requires x86 emulation/cloud instances) | **Native ARM64 Docker Containers** |

---

## 5. Architectural Recommendations

1. **Layered DPI at the Ingress Controller:** Suricata sidecar or gateway deployment provides sub-millisecond Layer 7 regex matching on AI inference payloads without incurring full application gateway overhead.
2. **Behavioral Protocol Enrichment via Zeek:** Zeek extracts transaction-level metadata (HTTP headers, payload size, model ID, response status) into indexed logs without logging raw sensitive PII if privacy filters are configured.
3. **Open Standards Portability:** Rules authored in Suricata and Wazuh formats map directly to Snort 3 and Splunk ES searches, providing enterprise transferability without proprietary vendor lock-in.
