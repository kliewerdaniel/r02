.PHONY: dev test demo

dev:
	docker build -t qasp .
	docker run -p 8000:8000 qasp

test:
	docker build -t qasp-test .
	docker run --rm qasp-test pytest tests/

demo:
	docker build -t qasp-demo .
	docker run --rm qasp-demo python src/client/demo_client.py
