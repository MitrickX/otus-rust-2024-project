.PHONY: start stop restart tests

start:
	@docker-compose -f ./deploy/docker-compose.yaml up --build

stop:
	@docker-compose -f ./deploy/docker-compose.yaml down

restart: stop start

# run all tests (unit, integration, end-to-end) locally
tests-localhost:
	@DB_HOST=127.0.0.1 DB_USER=otus DB_NAME=auth DB_PASSWORD=1234 DB_CONNECTION_RETRIES=10 DB_CONNECTION_TIMEOUT=10 API_CONNECTOIN_RETRIES=2 API_CONNECTION_TIMEOUT=10 API_SERVER_URL=http://[::1]:50051 cargo test

# run all tests (unit, integration, end-to-end) in docker
tests:
	@set -e ;\
	tests_status_code=0 ;\
	docker-compose -f ./deploy/docker-compose-tests.yaml down ;\
	docker-compose -f ./deploy/docker-compose-tests.yaml up -d --build;\
	docker-compose -f ./deploy/docker-compose-tests.yaml run tests ./test_server && \
	docker-compose -f ./deploy/docker-compose-tests.yaml run tests ./test_integration_test_ip_list && \
	docker-compose -f ./deploy/docker-compose-tests.yaml run tests ./test_behavioral_test_ip || \
	tests_status_code=$$? ;\
	exit $$tests_status_code ;\

# run only unit tests locallly
unit-tests:
	@cargo test --lib