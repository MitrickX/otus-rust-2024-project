.PHONY: start stop restart tests

start:
	docker-compose -f ./server/deploy/docker-compose.yaml up -d --build

stop:
	docker-compose -f ./server/deploy/docker-compose.yaml down

restart: start stop

# run all tests (unit, integration, end-to-end) in docker
tests: 
	@echo 'not implemented yet'

# run only unit tests locallly
unit-tests:
	@cargo test --lib