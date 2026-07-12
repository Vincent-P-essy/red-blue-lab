.PHONY: install run test cov lint docker

install:
	pip install -r requirements.txt

run:
	python -m lab.runner

test:
	pytest

cov:
	pytest --cov=lab --cov-report=term-missing

lint:
	ruff check lab tests

docker:
	docker compose up --build
