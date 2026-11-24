SHELL := /bin/bash
.DEFAULT_GOAL := build

MODULE   := github.com/Frostykiller3m/Quaarant
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

PREFIX ?= /usr/local

.PHONY: build build-linux test itest vet lint fmt tidy proto proto-check proto-lint tools agent-deps check install uninstall clean help

build: ## Build all binaries for the host into bin/
	@mkdir -p bin
	$(foreach b,$(BINARIES),$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(b)$(shell $(GO) env GOEXE) ./cmd/$(b) &&) true

build-linux: ## Build static linux/amd64 and linux/arm64 binaries into bin/linux-<arch>/
	$(foreach a,$(ARCHES),$(foreach b,$(BINARIES), \
		GOOS=linux GOARCH=$(a) CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/linux-$(a)/$(b) ./cmd/$(b) &&)) true

test: ## Run unit tests with the race detector (needs cgo)
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

itest: ## Run integration tests too (as root, with runsc and network): sudo make itest
	QT_ITEST=1 $(GO) test -count=1 -v ./... 2>&1 | grep -E '^(=== RUN|--- |ok|FAIL|PASS|panic)|_test\.go' ; exit $${PIPESTATUS[0]}

install: ## Install bin/ (from `make build`) and the systemd unit, as root: sudo make install
	@test -x bin/qtd -a -x bin/qt-agent || { echo "run make build first"; exit 1; }
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib/quarantine $(DESTDIR)/etc/systemd/system
	install -m 0755 bin/qt bin/qtd $(DESTDIR)$(PREFIX)/bin/
	install -m 0755 bin/qt-agent $(DESTDIR)$(PREFIX)/lib/quarantine/qt-agent
	install -m 0644 contrib/systemd/qtd.service $(DESTDIR)/etc/systemd/system/qtd.service
	getent group quarantine >/dev/null || groupadd --system quarantine
	@echo "now: systemctl daemon-reload && systemctl enable --now qtd; usermod -aG quarantine <you>"

uninstall: ## Remove what install added (sandboxes and images in /var/lib/quarantine are kept)
	-systemctl disable --now qtd
	rm -f $(DESTDIR)$(PREFIX)/bin/qt $(DESTDIR)$(PREFIX)/bin/qtd $(DESTDIR)/etc/systemd/system/qtd.service
	rm -rf $(DESTDIR)$(PREFIX)/lib/quarantine

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

proto: ## Regenerate Go code from proto/ and the vendored gVisor protos
	buf generate
	buf generate --template buf.gen.gvisor.yaml

proto-lint: ## Lint proto files
	buf lint

proto-check: proto-lint proto ## Fail if generated code is stale
	git diff --exit-code -- internal/api internal/gvisorpb

agent-deps: ## qt-agent may only use the standard library and internal packages
	@bad=$$(GOOS=linux $(GO) list -deps ./cmd/qt-agent | grep '\.' | grep -v '^$(MODULE)/'); \
	if [ -n "$$bad" ]; then echo "qt-agent has third-party deps:"; echo "$$bad"; exit 1; fi; \
	echo "qt-agent: stdlib + internal only"

check: vet lint test agent-deps proto-check ## Everything CI runs

clean: ## Remove build output
	rm -rf bin dist

help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'
