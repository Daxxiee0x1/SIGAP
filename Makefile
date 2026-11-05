SIGAP := ./build/sigap
TRUST := ./build/demo/trust_store.json
INJECT := docker compose exec sensor-01 python3 /opt/sigap/simulation/inject_anomaly.py

.PHONY: build test up down logs inject-% demo tamper-demo offline release site clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(SIGAP) ./cmd/sigap

test: build
	go vet ./...
	go test ./...
	python3 -m pytest -q

up:
	docker compose up -d --build
	@echo "Dashboard: http://127.0.0.1:8000"

down:
	docker compose down -v

logs:
	docker compose logs -f sensor-01 vault

# make inject-reverse_shell | inject-egress | inject-listen_port | inject-config_change | inject-cpu_spike | inject-tmp_exec
inject-%:
	$(INJECT) $*

# Full recorded demo, scene by scene. Needs only Docker + curl.
demo:
	bash ./scripts/demo.sh

# Verify the newest bundle offline and run every manipulation, without Go or Python on the host.
tamper-demo:
	mkdir -p build/demo
	docker compose cp sensor-01:/data/trust/trust_store.json $(TRUST)
	docker compose exec -T sensor-01 sh -c 'ls -t /var/lib/sigap/outbox/sent/*.zip /var/lib/sigap/outbox/*.zip 2>/dev/null | head -1' | tr -d '\r' | xargs -I{} docker compose cp sensor-01:{} build/demo/bundle.zip
	chmod a+r build/demo/*
	docker run --rm --network none --user "$$(id -u):$$(id -g)" -v "$$PWD:/w" -w /w python:3.12-slim-bookworm python3 tools/make_tampered.py build/demo/bundle.zip build/demo/tampered
	for f in build/demo/bundle.zip build/demo/tampered/*.zip; do docker run --rm --network none -v "$$PWD/build/demo:/demo:ro" sigap-vault sigap verify --trust /demo/trust_store.json /demo/$${f#build/demo/} || true; done

offline:
	sh ./offline/build-offline.sh

# GitHub Release assets: binaries for Linux/macOS/Windows + judge kit (dist/release/).
# VERSION=v1.0.0 make release
release:
	sh scripts/build-release.sh $(or $(VERSION),dev)

# Online try-it site for GitHub Pages (dist/site/): WebAssembly verifier + sample bundles.
site:
	sh scripts/build-site.sh

clean:
	rm -rf build dist
