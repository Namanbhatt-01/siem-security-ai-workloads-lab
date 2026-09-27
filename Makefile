.PHONY: up down restart test attack logs clean status

all: test

up:
	@echo "Starting Lab 3 SIEM Security Stack..."
	docker compose up -d --build

down:
	@echo "Stopping Lab 3 Stack..."
	docker compose down -v --remove-orphans

restart: down up

attack:
	@echo "Executing attack simulation..."
	python3 attack_simulation/run_all_attacks.py

test: up
	@echo "Waiting for services and running end-to-end verification..."
	@sleep 10
	python3 attack_simulation/run_all_attacks.py

logs:
	docker compose logs -f

status:
	@docker compose ps
	@echo "\nOpenSearch Health:"
	@curl -s http://localhost:9200/_cluster/health | jq . || true
	@echo "\nWebhook Alerts Summary:"
	@curl -s http://localhost:9090/alerts/summary | jq . || true

clean:
	docker compose down -v --remove-orphans
	rm -rf logs/suricata/* logs/zeek/* logs/alerts/*
