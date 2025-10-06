.PHONY: dev test demo compose-up compose-down k8s-apply k8s-delete k8s-logs

dev:
	docker build -t qasp .
	docker run -p 8000:8000 qasp

test:
	docker build -t qasp-test .
	docker run --rm qasp-test pytest tests/

demo:
	docker build -t qasp-demo .
	docker run --rm qasp-demo python src/client/demo_client.py

# Docker Compose deployment
compose-up:
	docker compose -f infra/deploy/compose.yaml up -d

compose-down:
	docker compose -f infra/deploy/compose.yaml down

# Kubernetes deployment
k8s-apply:
	kubectl apply -f infra/deploy/k8s/

k8s-delete:
	kubectl delete -f infra/deploy/k8s/

k8s-logs:
	kubectl logs -l app=qasp-server --tail=-1 -f
