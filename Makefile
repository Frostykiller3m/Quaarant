SHELL := /bin/bash
.DEFAULT_GOAL := build

MODULE   := github.com/qt-dev/quarantine
BINARIES := qt qtd qt-agent
ARCHES   := amd64 arm64

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

GO      ?= go
GOFLAGS := -trimpath
export CGO_ENABLED ?= 0

BUF_VERSION                := v1.75.0
PROTOC_GEN_GO_VERSION      := v1.36.12
PROTOC_GEN_GO_GRPC_VERSION := v1.6.2

.PHONY: build build-linux test vet lint fmt tidy proto proto-check proto-lint tools agent-deps check clean help

build: ## Build all binaries for the host into bin/
	@mkdir -p bin
	$(foreach b,$(BINARIES),$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(b)$(shell $(GO) env GOEXE) ./cmd/$(b) &&) true

build-linux: ## Build static linux/amd64 and linux/arm64 binaries into bin/linux-<arch>/
	$(foreach a,$(ARCHES),$(foreach b,$(BINARIES), \
		GOOS=linux GOARCH=$(a) CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/linux-$(a)/$(b) ./cmd/$(b) &&)) true

test: ## Run unit tests with the race detector (needs cgo)
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

vet: ## Run go vet
	$(GO) vet ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

fmt: ## Format code
	golangci-lint fmt ./...

tidy: ## Tidy go.mod and fail if it changed
	$(GO) mod tidy
	git diff --exit-code go.mod go.sum

tools: ## Install pinned buf and protoc plugins into GOBIN
	$(GO) install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

proto: ## Regenerate Go code from proto/
	buf generate

proto-lint: ## Lint proto files
	buf lint

proto-check: proto-lint proto ## Fail if generated code is stale
	git diff --exit-code -- internal/api

agent-deps: ## qt-agent may only use the standard library and internal packages
	@bad=$$(GOOS=linux $(GO) list -deps ./cmd/qt-agent | grep '\.' | grep -v '^$(MODULE)/'); \
	if [ -n "$$bad" ]; then echo "qt-agent has third-party deps:"; echo "$$bad"; exit 1; fi; \
	echo "qt-agent: stdlib + internal only"

check: vet lint test agent-deps proto-check ## Everything CI runs

clean: ## Remove build output
	rm -rf bin dist

help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'
