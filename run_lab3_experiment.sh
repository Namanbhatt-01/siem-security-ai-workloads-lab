#!/usr/bin/env bash
# ==============================================================================
# Lab 3: Open-Source SIEM & Security Pipeline for AI Workloads
# Automated Orchestration, Ingestion & Security Verification Script
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "======================================================================"
echo "🚀 STARTING LAB 3: OPEN-SOURCE SIEM & AI SECURITY PIPELINE"
echo "======================================================================"

# 1. Clean previous state
echo "[1/5] Ensuring clean environment and tear down legacy containers..."
docker compose down -v --remove-orphans 2>/dev/null || true
mkdir -p logs/suricata logs/zeek logs/alerts

# 2. Build & Launch Containers
echo "[2/5] Building and launching containerized SIEM security stack..."
docker compose up -d --build

# 3. Wait for OpenSearch & Core Services to be Healthy
echo "[3/5] Awaiting service health (OpenSearch, LLM Gateway, Webhook Sink)..."
for i in {1..30}; do
    if curl -s http://localhost:9200/_cluster/health | grep -q '"status":"green"\|"status":"yellow"' && \
       curl -s http://localhost:8000/health | grep -q "ok" && \
       curl -s http://localhost:9090/health | grep -q "ok"; then
        echo "✅ All core services are healthy and responsive!"
        break
    fi
    echo "  Waiting for services to become ready ($i/30)..."
    sleep 3
done

# 4. Execute Attack Simulation & Telemetry Verification
echo "[4/5] Executing adversarial attack simulation & verification assertions..."
python3 -m pip install requests --quiet || true
python3 attack_simulation/run_all_attacks.py

echo "======================================================================"
echo "🎉 LAB 3 SECURITY PIPELINE VERIFICATION COMPLETE!"
echo "======================================================================"
