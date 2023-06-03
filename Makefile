GOVERSION := $(shell go version | cut -d ' ' -f 3 | cut -d '.' -f 2)

.PHONY: run generate lint test help install
.DEFAULT_GOAL := build

run:
	CGO_ENABLED=0 go run ./example/basic/main.go

generate: ## run all go generate in the code base (including generating mock files)
	go generate ./...

lint: ## Run linters
	golangci-lint run

lint-fix:
	golangci-lint run --fix

test: ## Run tests
	@go test -race $(shell go list ./... | grep -v /vendor/ | grep -v /test/) -coverprofile=coverage.out -count 3

help:
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

