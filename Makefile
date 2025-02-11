.PHONY: start stop restart tests

start:
	@docker compose -f ./deploy/docker-compose.yaml up --build

stop:
	@docker compose -f ./deploy/docker-compose.yaml down

restart: stop start

# run all tests (unit, integration, end-to-end) in docker
tests:
	@set -e ;\
	tests_status_code=0 ;\
	docker compose -f ./deploy/docker-compose-tests.yaml down ;\
	docker compose -f ./deploy/docker-compose-tests.yaml up -d --build;\
	docker compose -f ./deploy/docker-compose-tests.yaml run tests ./test_server && \
	docker compose -f ./deploy/docker-compose-tests.yaml run tests ./test_test_ip_list && \
	docker compose -f ./deploy/docker-compose-tests.yaml run tests ./test_test_api || \
	tests_status_code=$$? ;\
	exit $$tests_status_code ;\

tests-locally:
	DB_HOST=127.0.0.1 DB_USER=otus DB_NAME=auth DB_PASSWORD=1234 DB_CONNECTION_RETRIES=10 DB_CONNECTION_TIMEOUT=10 API_CONNECTOIN_RETRIES=2 API_CONNECTION_TIMEOUT=10 API_SERVER_URL=http://[::1]:50051 API_SERVER_CONFIG_PATH=configs/server.yaml API_TEST_BOT_LOGIN=api-test-bot API_TEST_BOT_PASSWORD=LspJDcG94BBUm2rYGP7vXa4c TOKENS_SIGNING_KEY=ez9KUMO9hY5GKLokRBDRTdp9rhiPCw5DYZnJir83MUAA1rrQB61LzPcSCJuN6NPy cargo test