.PHONY: start stop restart tests

start:
	docker-compose -f ./deploy/docker-compose.yaml up -d --build

stop:
	docker-compose -f ./deploy/docker-compose.yaml down

restart: stop start

# run all tests (unit, integration, end-to-end) in docker
tests: 
	@echo 'not implemented yet'

# run only unit tests locallly
unit-tests:
	@cargo test --lib