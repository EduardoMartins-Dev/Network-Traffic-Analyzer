# Network Traffic Analyzer — atalhos de uso comum.
# Cada target chama o script correspondente em scripts/.

.PHONY: help install quickstart up up-fg down build agent test smoke clean dash install-server install-agent

help:
	@echo "Network Traffic Analyzer — targets:"
	@echo ""
	@echo "  make install                instala deps (server + agente) e builda"
	@echo "  make install-server         só servidor (docker compose + python)"
	@echo "  make install-agent          só agente (compilador + libpcap)"
	@echo "  make quickstart             install + up + smoke (zero a rodando)"
	@echo "  make build                  compila o agente C (cmake + make)"
	@echo "  make up                     sobe stack + ingestor (background)"
	@echo "  make up-fg                  igual, ingestor em foreground"
	@echo "  make down                   derruba stack + mata ingestor"
	@echo "  make agent IFACE=eth0       roda o agente na interface (sudo)"
	@echo "  make smoke                  build + replay suite"
	@echo "  make test                   alias para smoke"
	@echo "  make dash NAME=x DESC=...   gera dashboard Grafana via Groq"
	@echo "  make clean                  remove build/ e caches"

install:
	./scripts/install.sh

install-server:
	./scripts/install.sh --server-only

install-agent:
	./scripts/install.sh --agent-only

quickstart:
	./scripts/quickstart.sh

build:
	cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
	cmake --build build -j$$(nproc 2>/dev/null || echo 2)

up:
	./scripts/up.sh

up-fg:
	./scripts/up.sh --foreground

down:
	./scripts/down.sh

agent:
	@if [ -z "$(IFACE)" ]; then echo "uso: make agent IFACE=<interface>"; exit 2; fi
	sudo ./build/NetworkTrafficAnalyzer $(IFACE)

smoke:
	./scripts/smoke-test.sh

test: smoke

dash:
	@if [ -z "$(NAME)" ] || [ -z "$(DESC)" ]; then \
		echo "uso: make dash NAME=<slug> DESC=\"<descrição>\""; exit 2; \
	fi
	./scripts/dash_gen.py --name "$(NAME)" --desc "$(DESC)"

clean:
	rm -rf build/ src/ingestor/__pycache__ scripts/__pycache__
