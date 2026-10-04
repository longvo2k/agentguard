VERSION ?= 0.1.0
BIN     := bin/agentguard
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build install test test-short test-docker lint demo clean image release-snapshot

build: ## Build the agentguard binary into bin/
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/agentguard

install: ## Install agentguard into $GOPATH/bin
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/agentguard

test: ## All tests; Docker tests run when a daemon is available
	go test ./...

test-short: ## Unit tests only, no Docker
	go test -short ./...

test-docker: ## Docker integration tests (set AGENTGUARD_TEST_IMAGE to reuse an image)
	go test -count=1 -run 'Sandbox|Docker' -v ./internal/sandbox ./tests

lint: ## gofmt + go vet
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...

image: ## Build the sandbox image locally (what agentguard falls back to)
	docker build -t agentguard-sandbox:local - < internal/sandbox/Dockerfile

release-snapshot: ## Build release archives into dist/ without publishing
	goreleaser release --snapshot --clean

demo: build ## Run the demo
	./$(BIN) demo

clean:
	rm -rf bin/ dist/
