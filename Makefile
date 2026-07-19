# OpenMalLab - one-command sovereign live stack (Phase 1).
#
#   make live   # build images + provision the local model + bring the WHOLE stack
#               # up air-gapped: deterministic engines + the AI-analyst plane.
#
# Console: http://localhost:8090   API: http://localhost:8080
# On a corporate pip index, set MAL_PIP_CONF (see .env.example) so the Python
# images build. The model is served by a local Ollama container on a no-egress
# network; it is provisioned once (needs egress) into a named volume.

COMPOSE := docker compose -f deploy/compose.yaml -f deploy/compose.ai.yaml
MODEL   ?= llama3.2:3b

.PHONY: help live build bootstrap-model up down e2e e2e-live ps logs

help:
	@echo "OpenMalLab:"
	@echo "  make live             build + provision the model + bring the full sovereign stack up"
	@echo "  make build            build all images (set MAL_PIP_CONF for a private pip index)"
	@echo "  make bootstrap-model  pull the sovereign model into its volume (one-time, needs egress)"
	@echo "  make up / make down   bring the stack up / stop it"
	@echo "  make e2e-live         run the live end-to-end proof (submit -> verdict -> enrich -> HITL)"
	@echo "  make e2e              run the deterministic-only end-to-end proof"
	@echo "  make ps / make logs   status / follow logs"

# the full sovereign live bring-up, in order: images, then the model into its
# volume (the no-egress runtime cannot pull), then the stack.
live: build bootstrap-model up
	@echo ""
	@echo "OpenMalLab is live. Console: http://localhost:8090   API: http://localhost:8080"
	@echo "Prove it: make e2e-live"

build:
	MAL_PIP_CONF="$(MAL_PIP_CONF)" $(COMPOSE) build

bootstrap-model:
	MAL_MODEL_NAME="$(MODEL)" $(COMPOSE) --profile bootstrap run --rm model-bootstrap

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

e2e-live:
	deploy/proof/e2e-live.sh

e2e:
	deploy/proof/e2e.sh

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f --tail=100
