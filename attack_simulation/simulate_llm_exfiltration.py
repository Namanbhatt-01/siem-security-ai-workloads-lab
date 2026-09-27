import sys
import time
import json
import requests

TARGET_VECTOR_DB_URL = "http://localhost:6333/collections/enterprise_ai_kb/dump"
TARGET_LLM_URL = "http://localhost:8000/v1/chat/completions"

def run_exfiltration_tests():
    print("=" * 70)
    print("🚨 LAUNCHING AI DATA EXFILTRATION & VECTOR DB HARVEST SUITE")
    print("=" * 70)

    # 1. Vector DB Bulk Dump Exfiltration
    print("\n[Test 1/2] Attempting Rogue Vector Database Dump on port 6333...")
    try:
        start_time = time.time()
        resp = requests.get(TARGET_VECTOR_DB_URL, timeout=5)
        elapsed = round((time.time() - start_time) * 1000, 2)
        print(f"-> Target URL: {TARGET_VECTOR_DB_URL}")
        print(f"-> Response Status: {resp.status_code} | Payload Size: {len(resp.content)} bytes | Latency: {elapsed}ms")
    except Exception as e:
        print(f"-> Vector DB query failed: {e}")

    time.sleep(1)

    # 2. High-Volume Model Weights / Embedding Exfiltration (>60KB payload)
    print("\n[Test 2/2] Injecting High-Volume Payload Egress Spike (>60KB)...")
    try:
        start_time = time.time()
        synthetic_weights_payload = "A" * 65000  # 65 KB payload
        resp = requests.post(
            TARGET_LLM_URL,
            json={
                "model": "mistral-large-finetuned",
                "messages": [{"role": "user", "content": f"Bulk exfiltration chunk: {synthetic_weights_payload}"}]
            },
            timeout=10
        )
        elapsed = round((time.time() - start_time) * 1000, 2)
        print(f"-> Payload Bytes Sent: {len(synthetic_weights_payload)} bytes")
        print(f"-> Response Status: {resp.status_code} | Latency: {elapsed}ms")
    except Exception as e:
        print(f"-> High-volume injection failed: {e}")

if __name__ == "__main__":
    run_exfiltration_tests()
