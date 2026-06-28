.PHONY: deploy up down logs status build ob-login ob-setup test lint

# --- deploy (run on the server, repo at /opt/fenced-obsidian-sync-mcp) ---------
deploy:        ## git pull + rebuild + restart
	git pull && docker compose up -d --build

up:            ## start (no rebuild)
	docker compose up -d

down:          ## stop and remove containers
	docker compose down

build:         ## build the image
	docker compose build

logs:          ## follow logs
	docker compose logs -f --tail=100

status:        ## show container status
	docker compose ps

# --- one-time obsidian-headless setup (persists in ob_config/ob_data volumes) --
ob-login:      ## interactive `ob login` (email, password, MFA)
	docker compose run --rm --entrypoint ob fenced-obsidian-sync-mcp login

ob-setup:      ## link the remote vault: make ob-setup VAULT="My Vault"
	docker compose run --rm --entrypoint ob fenced-obsidian-sync-mcp \
		sync-setup --vault "$(VAULT)" --path /vault

# --- local dev ----------------------------------------------------------------
test:          ## run the test suite
	pytest -q

lint:          ## run ruff
	ruff check .
