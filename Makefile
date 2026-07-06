# ARGUS dev shortcuts. Run `make <target>`.
.PHONY: up down stop test lint seed mitre run

up:            ## start Postgres (data persists)
	docker compose up -d db

stop:          ## stop containers, KEEP data
	docker compose stop

down:          ## stop + remove containers, KEEP data (no -v!)
	docker compose down

run:           ## run the API locally
	uv run uvicorn argus.main:app --reload --host 0.0.0.0 --port 8000

test:          ## full test suite
	uv run pytest -q

lint:          ## ruff lint
	uv run ruff check .

seed:          ## provision home-lab tenant + print token
	uv run python scripts/seed_dev.py

mitre:         ## load the ATT&CK catalog
	uv run python scripts/load_mitre_attack.py

# NOTE: there is deliberately NO target that runs `docker compose down -v`.
# That command destroys the database. Run it by hand only for a clean slate.
