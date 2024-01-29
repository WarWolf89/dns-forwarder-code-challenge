# Image URL to use all building/pushing image targets
IMG ?= "ghcr.io/warwolf89/dns-forwarder-code-challenge:test"


# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

define GO_PRECOMMIT_DEPENDENCIES
	$(1) golang.org/x/tools/cmd/goimports@v0.11.1
	$(1) github.com/golangci/golangci-lint/cmd/golangci-lint@v1.54.1
endef

## Tool Binaries
DOCKER ?= $(shell which docker)

.PHONY: all
all: build

.PHONY: fmt
fmt: ## Run go fmt against code.
	gofmt -s -w .

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint run
	golangci-lint run

.PHONY: docker-build
docker-build: fmt vet
	docker build -t ${IMG} .

.PHONY: run-server
run-server: fmt vet #
	go run main.go

.PHONY: test
test: 
	go test -v